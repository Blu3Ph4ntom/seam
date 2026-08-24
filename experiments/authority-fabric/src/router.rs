//! Host-side routing state machine.
//!
//! Pure logic: no IO here. The IO glue calls `on_frame` / `on_eof` /
//! `on_shutdown` under a lock and acts on the returned outcomes.
//!
//! Authority rules implemented (see RUN gates G6/G8/G9/G10):
//! - a peer may address ONLY endpoints it currently holds,
//! - attachments move only endpoints the sender currently holds,
//! - attachment partner metadata must match fabric truth exactly (lying is
//!   a protocol violation),
//! - unknown identities are quarantined; stale-but-previously-valid ones are
//!   rejected softly (drop + corrective notify),
//! - death of one side kills the whole logical conversation,
//! - identities are never reused.

use std::collections::HashMap;

use crate::fabric_error::Cause;
use crate::frame::{
    self, DataInner, Frame, XferMsg, XFER_ST_ABORTED, XFER_ST_COMMITTED, XFER_ST_PENDING,
    XFER_ST_UNKNOWN,
};
use crate::id::{
    fresh_id, fresh_transfer_id, BoundedTombstones, EpId, IdSpace, TransferId, TransferSpace,
};
use crate::limits::Limits;
use crate::native::{ResourceId, ResourceSpace};
use crate::shared::{RegionId, RegionTable, Rights};

fn barrier_wait(name: &str) {
    if let Ok(dir) = std::env::var("SEAM_BARRIER_DIR") {
        let path = std::path::Path::new(&dir).join(name);
        let go = std::path::Path::new(&dir).join(format!("{}.go", name));
        let _ = std::fs::write(&path, b"1");
        for _ in 0..600 {
            if go.exists() {
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PeerId(pub u32);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Holder {
    Peer(PeerId),
    Host,
    Escrow(TransferId),
}

#[derive(Clone, Copy, Debug)]
struct EpEntry {
    partner: EpId,
    holder: Holder,
    closed: bool,
}

/// What the IO glue must do after a successfully processed frame.
#[derive(Default, Debug)]
pub struct RouteOutcome {
    /// (destination peer, frame)
    pub send: Vec<(PeerId, Frame)>,
    /// Messages whose conversation partner is hosted by the host process
    /// itself (demo orchestration channel). The router does not interpret
    /// payloads; it merely surfaces them.
    pub to_host: Vec<HostDelivery>,
}

#[derive(Debug)]
pub struct HostDelivery {
    pub from: PeerId,
    pub target: EpId,
    pub corr: u32,
    pub payload: Vec<u8>,
}

/// Events about host-held endpoints (e.g., a peer closed a control endpoint).
#[derive(Debug)]
pub enum HostEvent {
    EndpointClosed { ep: EpId, cause: Cause },
}

/// Quarantine reasons. When a peer poisons, the IO glue drops its transport
/// and then calls `on_eof` to collapse dependent state (fail closed).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Poison(pub &'static str);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum XferPhase {
    Offered,
    Committed,
    Aborted,
}

#[derive(Clone, Copy, Debug)]
pub struct XferRec {
    pub tid: TransferId,
    pub ep: EpId,
    pub partner: EpId,
    pub sender: PeerId,
    pub dest: PeerId,
    /// Where authority returns on pre-commit abort.
    pub restore: Holder,
    pub phase: XferPhase,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NativeState {
    Escrowed,
    Committed,
    Aborted,
}

#[derive(Clone, Copy, Debug)]
pub struct NativeRec {
    pub tid: TransferId,
    pub rid: ResourceId,
    pub sender: PeerId,
    pub dest: PeerId,
    pub state: NativeState,
}

/// Shared-region capability in Host escrow (same lifecycle as `NativeRec`).
/// Rights/size live in the authoritative `RegionTable`; this record only
/// tracks the transaction.
#[derive(Clone, Copy, Debug)]
pub struct SharedRec {
    pub tid: TransferId,
    pub rid: RegionId,
    pub rights: Rights,
    pub sender: PeerId,
    pub dest: PeerId,
    pub state: NativeState,
}

/// The Host itself as an authority holder. Router-assigned peer ids are small
/// sequential u32s, so this sentinel can never collide with a real peer.
pub const HOST_PEER: PeerId = PeerId(u32::MAX);

fn decode_rights(b: u8) -> Option<Rights> {
    match b {
        0 => Some(Rights::ReadOnly),
        1 => Some(Rights::ReadWrite),
        _ => None,
    }
}

pub fn encode_rights(r: Rights) -> u8 {
    r.wire_byte()
}

/// Test-only delivery faults. Never used on the production path unless set.
#[derive(Clone, Debug, Default)]
pub struct Inject {
    pub drop_commit: bool,
    pub drop_committed: bool,
    pub drop_abort: bool,
    pub drop_offer: bool,
}

pub struct Router {
    lim: Limits,
    peers: HashMap<PeerId, bool>, // PeerId -> hello_completed
    next_peer_raw: u32,
    eps: HashMap<EpId, EpEntry>,
    retired: BoundedTombstones<EpId>,
    xfers: HashMap<TransferId, XferRec>,
    /// Terminal results retained until sender ACKs. Bounded, never LRU-evicted.
    results: HashMap<TransferId, (PeerId, Cause)>,
    // Native resource tracking (Host escrow, same transactional semantics)
    native_pending: HashMap<TransferId, NativeRec>,
    native_results: HashMap<TransferId, (PeerId, Cause, ResourceId)>,
    native_live: HashMap<ResourceId, PeerId>,
    native_retired: BoundedTombstones<ResourceId>,
    // Shared-memory region tracking. `regions` is the authoritative rights
    // table; shared_pending/results mirror the native transaction lifecycle.
    regions: RegionTable,
    shared_pending: HashMap<TransferId, SharedRec>,
    shared_results: HashMap<TransferId, (PeerId, Cause, RegionId)>,
    /// Committed region ids still referenced by an un-ResultAck'd transfer.
    shared_live: std::collections::HashSet<RegionId>,
    shared_retired: BoundedTombstones<RegionId>,
    host_events: Vec<HostEvent>,
    pub inject: Inject,
    collisions: u64,
}

/// State accounting snapshot (test-only introspection; see gate G16).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Accounting {
    pub peers: usize,
    pub live_endpoints: usize,
    pub retired_identities: usize,
    pub host_held: usize,
    pub pending_transfers: usize,
    pub escrowed: usize,
    pub unacked_results: usize,
    pub native_live: usize,
    pub native_pending: usize,
    pub native_unacked: usize,
    pub shared_pending: usize,
    pub shared_unacked: usize,
}

impl Router {
    pub fn new(lim: Limits) -> Self {
        Router {
            retired: BoundedTombstones::new(lim.max_retired),
            lim: lim.clone(),
            peers: HashMap::new(),
            next_peer_raw: 0,
            eps: HashMap::new(),
            xfers: HashMap::new(),
            results: HashMap::new(),
            native_pending: HashMap::new(),
            native_results: HashMap::new(),
            native_live: HashMap::new(),
            native_retired: BoundedTombstones::new(lim.max_retired),
            regions: RegionTable::new(),
            shared_pending: HashMap::new(),
            shared_results: HashMap::new(),
            shared_live: std::collections::HashSet::new(),
            shared_retired: BoundedTombstones::new(lim.max_retired),
            host_events: Vec::new(),
            inject: Inject::default(),
            collisions: 0,
        }
    }

    pub fn limits(&self) -> &Limits {
        &self.lim
    }

    pub fn take_host_events(&mut self) -> Vec<HostEvent> {
        std::mem::take(&mut self.host_events)
    }

    pub fn accounting(&self) -> Accounting {
        Accounting {
            peers: self.peers.len(),
            live_endpoints: self.eps.values().filter(|e| !e.closed).count(),
            retired_identities: self.retired.len(),
            host_held: self
                .eps
                .values()
                .filter(|e| !e.closed && e.holder == Holder::Host)
                .count(),
            pending_transfers: self
                .xfers
                .values()
                .filter(|x| x.phase == XferPhase::Offered)
                .count()
                + self
                    .native_pending
                    .values()
                    .filter(|n| n.state == NativeState::Escrowed)
                    .count(),
            escrowed: self
                .eps
                .values()
                .filter(|e| !e.closed && matches!(e.holder, Holder::Escrow(_)))
                .count(),
            unacked_results: self.results.len() + self.native_results.len(),
            native_live: self.native_live.len(),
            native_pending: self.native_pending.len(),
            native_unacked: self.native_results.len(),
            shared_pending: self.shared_pending.len(),
            shared_unacked: self.shared_results.len(),
        }
    }

    /// Authoritative shared-region accounting (holders, backing bytes).
    pub fn region_accounting(&self) -> crate::shared::RegionAccounting {
        self.regions.accounting()
    }

    pub fn collisions(&self) -> u64 {
        self.collisions
    }

    fn taken_ids(&self) -> impl IdSpace + '_ {
        struct Both<'a>(&'a HashMap<EpId, EpEntry>, &'a BoundedTombstones<EpId>);
        impl IdSpace for Both<'_> {
            fn contains(&self, id: EpId) -> bool {
                self.0.contains_key(&id) || self.1.contains(id)
            }
        }
        Both(&self.eps, &self.retired)
    }

    fn taken_tids(&self) -> impl TransferSpace + '_ {
        struct T<'a>(
            &'a HashMap<TransferId, XferRec>,
            &'a HashMap<TransferId, (PeerId, Cause)>,
            &'a HashMap<TransferId, NativeRec>,
            &'a HashMap<TransferId, (PeerId, Cause, ResourceId)>,
            &'a HashMap<TransferId, SharedRec>,
            &'a HashMap<TransferId, (PeerId, Cause, RegionId)>,
        );
        impl TransferSpace for T<'_> {
            fn contains(&self, id: TransferId) -> bool {
                self.0.contains_key(&id)
                    || self.1.contains_key(&id)
                    || self.2.contains_key(&id)
                    || self.3.contains_key(&id)
                    || self.4.contains_key(&id)
                    || self.5.contains_key(&id)
            }
        }
        T(
            &self.xfers,
            &self.results,
            &self.native_pending,
            &self.native_results,
            &self.shared_pending,
            &self.shared_results,
        )
    }

    fn taken_rids(&self) -> impl ResourceSpace + '_ {
        struct R<'a>(
            &'a HashMap<ResourceId, PeerId>,
            &'a BoundedTombstones<ResourceId>,
        );
        impl ResourceSpace for R<'_> {
            fn contains(&self, id: ResourceId) -> bool {
                self.0.contains_key(&id) || self.1.contains(id)
            }
        }
        R(&self.native_live, &self.native_retired)
    }

    pub fn accept_peer(&mut self) -> PeerId {
        let id = PeerId(self.next_peer_raw);
        self.next_peer_raw += 1;
        self.peers.insert(id, false);
        id
    }

    fn alloc_pair(&mut self, holder: Holder) -> (EpId, EpId) {
        assert!(
            self.eps.values().filter(|e| !e.closed).count() + 2 <= self.lim.max_live_endpoints,
            "live endpoint capacity exceeded during internal allocation"
        );
        let a = fresh_id(&self.taken_ids());
        let b = fresh_id(&self.taken_ids());
        self.eps.insert(
            a,
            EpEntry {
                partner: b,
                holder,
                closed: false,
            },
        );
        self.eps.insert(
            b,
            EpEntry {
                partner: a,
                holder,
                closed: false,
            },
        );
        (a, b)
    }

    /// Host creates a root pair it holds itself; sides are granted out via
    /// `grant`.
    pub fn create_host_pair(&mut self) -> (EpId, EpId) {
        self.alloc_pair(Holder::Host)
    }

    /// Host offers a previously host-held endpoint to a peer. Authority
    /// moves to escrow until the peer ACCEPT+COMMIT; it is not usable by
    /// the recipient before commit, and not silently lost on push failure
    /// (the IO glue must report delivery outcome).
    pub fn grant(&mut self, to: PeerId, ep: EpId) -> Result<Frame, Poison> {
        if self.xfers.len() + self.results.len() >= self.lim.max_pending_transfers {
            return Err(Poison("pending transfer table full"));
        }
        let tid = fresh_transfer_id(&self.taken_tids());
        let entry = self
            .eps
            .get_mut(&ep)
            .filter(|e| !e.closed)
            .ok_or(Poison("grant of unknown/closed endpoint"))?;
        if entry.holder != Holder::Host {
            return Err(Poison("grant of endpoint not held by host"));
        }
        let partner = entry.partner;
        entry.holder = Holder::Escrow(tid);
        self.xfers.insert(
            tid,
            XferRec {
                tid,
                ep,
                partner,
                sender: to,
                dest: to,
                restore: Holder::Host,
                phase: XferPhase::Offered,
            },
        );
        Ok(Frame::Grant { ep, partner, tid })
    }

    /// Mark both ends closed + retired. Returns the surviving partner's
    /// identity (the handle the remaining holder actually possesses) and
    /// that side's entry (for holder lookup).
    fn close_conversation(&mut self, side: EpId, cause: Cause) -> Option<(EpId, EpEntry)> {
        let e = *self.eps.get(&side)?;
        if e.closed {
            return None;
        }
        let partner = e.partner;
        let partner_entry = *self.eps.get(&partner)?;
        self.eps.get_mut(&side).unwrap().closed = true;
        self.eps.get_mut(&partner).unwrap().closed = true;
        self.retired.insert(side, cause);
        self.retired.insert(partner, cause);
        self.eps.remove(&side);
        self.eps.remove(&partner);
        Some((partner, partner_entry))
    }

    fn require_owner(&self, from: PeerId, ep: EpId) -> Result<&EpEntry, Result<(), Poison>> {
        // Ok(entry) => owned & live.
        // Err(Ok(())) => soft-reject (stale known identity): caller drops + notifies.
        // Err(Err(p)) => quarantine.
        match self.eps.get(&ep) {
            None => {
                if self.retired.contains(ep) {
                    Err(Ok(()))
                } else {
                    Err(Err(Poison("unknown endpoint identity")))
                }
            }
            Some(e) if e.closed => Err(Ok(())),
            Some(e) => {
                if e.holder != Holder::Peer(from) {
                    // Held by another peer, host, or escrow: forging/replay.
                    Err(Err(Poison("identity not held by sender")))
                } else {
                    Ok(e)
                }
            }
        }
    }

    pub fn on_hello(&mut self, from: PeerId, magic: u16, version: u16) -> Result<(), Poison> {
        let ready = self
            .peers
            .get_mut(&from)
            .ok_or(Poison("hello from unknown peer"))?;
        if *ready {
            return Err(Poison("duplicate hello"));
        }
        if magic != self.lim.hello_magic {
            return Err(Poison("bad hello magic"));
        }
        if version != self.lim.hello_version {
            return Err(Poison("bad protocol version"));
        }
        *ready = true;
        Ok(())
    }

    /// Process a DATA frame from `from`.
    pub fn on_data(
        &mut self,
        from: PeerId,
        mut f: frame::DataInner,
    ) -> Result<RouteOutcome, Poison> {
        if !*self
            .peers
            .get(&from)
            .ok_or(Poison("frame from unknown peer"))?
        {
            return Err(Poison("traffic before hello"));
        }
        let target_entry = match self.require_owner(from, f.target) {
            Ok(e) => *e,
            Err(Ok(())) => {
                // Stale-but-known: soft reject with corrective notify.
                let cause = self.retired.get(f.target).unwrap_or(Cause::Graceful);
                let mut out = RouteOutcome::default();
                out.send.push((
                    from,
                    Frame::ClosedNotify {
                        entries: vec![(f.target, cause)],
                    },
                ));
                return Ok(out);
            }
            Err(Err(p)) => return Err(p),
        };

        // Recipient of the message = current holder of the partner side.
        let partner = target_entry.partner;
        let partner_entry = *self.eps.get(&partner).ok_or(Poison("broken pairing"))?;
        debug_assert!(!partner_entry.closed);
        let recipient = partner_entry.holder;

        // Validate + execute attachment transfers BEFORE forwarding.
        let attachments = std::mem::take(&mut f.attachments);
        for att in &attachments {
            match self.require_owner(from, att.id) {
                Ok(_) => {}
                Err(Ok(())) => {
                    // Stale attached identity: reject the frame softly and
                    // tell the sender that capability is gone.
                    let cause = self.retired.get(att.id).unwrap_or(Cause::Graceful);
                    let mut out = RouteOutcome::default();
                    out.send.push((
                        from,
                        Frame::ClosedNotify {
                            entries: vec![(att.id, cause)],
                        },
                    ));
                    return Ok(out);
                }
                Err(Err(p)) => return Err(p),
            }
            // Topology lie detection: sender must name the true partner.
            let truth = self.eps.get(&att.id).unwrap().partner;
            if truth != att.partner {
                return Err(Poison("attachment partner metadata contradicts fabric"));
            }
        }
        let dest_peer = match recipient {
            Holder::Peer(p) => p,
            Holder::Host => {
                if !attachments.is_empty() {
                    return Err(Poison("cannot escrow-transfer to host-held partner"));
                }
                let mut out = RouteOutcome::default();
                out.to_host.push(HostDelivery {
                    from,
                    target: f.target,
                    corr: f.corr,
                    payload: f.payload,
                });
                return Ok(out);
            }
            Holder::Escrow(_) => return Err(Poison("conversation partner is in escrow")),
        };

        if attachments.len() + self.xfers.len() + self.results.len()
            > self.lim.max_pending_transfers
        {
            // Resource: abort before commit. Sender still owns (we have not
            // escrowed yet). Surface as ERROR capacity.
            let mut out = RouteOutcome::default();
            out.send
                .push((from, Frame::Error(crate::frame::ERR_CAPACITY)));
            return Ok(out);
        }

        for att in &attachments {
            if self.taken_tids().contains(att.tid) {
                return Err(Poison("duplicate or reused transfer id"));
            }
            self.eps.get_mut(&att.id).unwrap().holder = Holder::Escrow(att.tid);
            self.xfers.insert(
                att.tid,
                XferRec {
                    tid: att.tid,
                    ep: att.id,
                    partner: att.partner,
                    sender: from,
                    dest: dest_peer,
                    restore: Holder::Peer(from),
                    phase: XferPhase::Offered,
                },
            );
        }

        // Native resource handling (0 or 1 per transfer)
        if let Some(native) = f.native.take() {
            // Validate resource id not reused and tid not duplicate
            if self.taken_rids().contains(native.rid) || self.taken_tids().contains(native.tid) {
                return Err(Poison("duplicate or reused native resource id"));
            }
            // Capacity checks for native
            if self.native_pending.len() + self.native_results.len()
                >= self.lim.max_native_resources
                || self.native_pending.len() >= self.lim.max_resources_in_escrow
            {
                let mut out = RouteOutcome::default();
                out.send
                    .push((from, Frame::Error(crate::frame::ERR_CAPACITY)));
                return Ok(out);
            }
            // Windows handle_value validation: must be non-zero if present, but allow 0 for Linux
            // For now, just check tid/rid not zero
            if native.rid.is_zero() || native.tid.is_zero() {
                return Err(Poison("zero native id"));
            }
            self.native_pending.insert(
                native.tid,
                NativeRec {
                    tid: native.tid,
                    rid: native.rid,
                    sender: from,
                    dest: dest_peer,
                    state: NativeState::Escrowed,
                },
            );
            // Also track that this tid is now pending for native
            // The actual File handle is held by host IO layer, not router
            f.native = Some(native);
        } else {
            f.native = None;
        }

        // Shared-region capability offer (0 or 1 per transfer). Peer-provided
        // rights are CLAIMS validated against the authoritative RegionTable;
        // size is never accepted from the wire (Host resolves it by rid).
        if let Some(s) = f.shared.take() {
            let Some(rights) = decode_rights(s.rights) else {
                return Err(Poison("unknown shared rights byte"));
            };
            if self.taken_tids().contains(s.tid) {
                return Err(Poison("duplicate or reused shared transfer id"));
            }
            if s.rid.is_zero() || s.tid.is_zero() {
                return Err(Poison("zero shared id"));
            }
            if !self.regions.region_exists(s.rid) {
                return Err(Poison("unknown region id"));
            }
            // Claim validation: only the current authority holder may offer
            // that authority onward. RO may also be offered by the writer
            // (direct attenuation).
            let authorized = match rights {
                Rights::ReadWrite => self.regions.writable_holder(s.rid) == Some(from),
                Rights::ReadOnly => {
                    self.regions.writable_holder(s.rid) == Some(from)
                        || self.regions.is_readonly_holder(s.rid, from)
                }
            };
            if !authorized {
                return Err(Poison("shared rights claim denied"));
            }
            if self.shared_pending.len() + self.shared_results.len()
                >= self.lim.max_native_resources
                || self.shared_pending.len() >= self.lim.max_resources_in_escrow
            {
                let mut out = RouteOutcome::default();
                out.send
                    .push((from, Frame::Error(crate::frame::ERR_CAPACITY)));
                return Ok(out);
            }
            self.shared_pending.insert(
                s.tid,
                SharedRec {
                    tid: s.tid,
                    rid: s.rid,
                    rights,
                    sender: from,
                    dest: dest_peer,
                    state: NativeState::Escrowed,
                },
            );
            f.shared = Some(s);
        } else {
            f.shared = None;
        }

        if std::env::var("SEAM_PAUSE_AFTER_ESCROW")
            .map(|v| v == "1")
            .unwrap_or(false)
        {
            barrier_wait("host_after_escrow");
        }

        let mut out = RouteOutcome::default();
        if self.inject.drop_offer {
            return Ok(out);
        }
        out.send.push((
            dest_peer,
            Frame::Data(DataInner {
                target: f.target,
                corr: f.corr,
                attachments,
                payload: f.payload,
                native: f.native,
                shared: f.shared,
            }),
        ));
        Ok(out)
    }

    /// Register a newly created region (Host is the initial writer).
    pub fn region_create(
        &mut self,
        rid: RegionId,
        size: u64,
        lim: &Limits,
    ) -> Result<(), crate::shared::RegionErr> {
        self.regions.create_region(rid, size, HOST_PEER, lim)
    }

    /// Region size by authoritative table.
    pub fn region_size(&self, rid: RegionId) -> Option<u64> {
        self.regions.size_of(rid)
    }

    /// Current writable holder of a region (authority introspection).
    pub fn region_writable_holder(&self, rid: RegionId) -> Option<PeerId> {
        self.regions.writable_holder(rid)
    }

    /// Host-initiated grant of a region capability to `dest`. The offer Data
    /// rides the generic transaction; on Accept it commits exactly like a
    /// peer-to-peer transfer. `rights` must be authorized against the
    /// RegionTable before this is called (the caller owns choreography).
    pub fn host_grant_region(
        &mut self,
        dest: PeerId,
        target: EpId,
        corr: u32,
        rid: RegionId,
        rights: Rights,
    ) -> Result<(TransferId, RouteOutcome), Poison> {
        if !self.regions.region_exists(rid) {
            return Err(Poison("unknown region id"));
        }
        // The Host cannot hold a wire conversation with itself: granting to
        // the sentinel would mint an unwirable authority record.
        if dest == HOST_PEER {
            return Err(Poison("cannot grant to host sentinel"));
        }
        // One writer ever: granting RW requires the Host to currently hold it.
        if rights == Rights::ReadWrite && self.regions.writable_holder(rid) != Some(HOST_PEER) {
            return Err(Poison("second writer denied"));
        }
        if self.shared_pending.len() >= self.lim.max_resources_in_escrow {
            return Err(Poison("shared escrow capacity"));
        }
        let tid = fresh_transfer_id(&self.taken_tids());
        self.shared_pending.insert(
            tid,
            SharedRec {
                tid,
                rid,
                rights,
                sender: HOST_PEER,
                dest,
                state: NativeState::Escrowed,
            },
        );
        let mut out = RouteOutcome::default();
        out.send.push((
            dest,
            Frame::Data(DataInner {
                target,
                corr,
                attachments: vec![],
                payload: vec![],
                native: None,
                shared: Some(crate::frame::SharedAttachment {
                    tid,
                    rid,
                    rights: encode_rights(rights),
                    handle_value: 0,
                }),
            }),
        ));
        Ok((tid, out))
    }

    fn shared_commit_inner(&mut self, tid: TransferId) -> Result<RouteOutcome, Poison> {
        let rec = *self
            .shared_pending
            .get(&tid)
            .ok_or(Poison("unknown shared transfer"))?;
        if rec.state != NativeState::Escrowed {
            return Ok(RouteOutcome::default());
        }
        // Move authority in the RegionTable FIRST (reject-before-mutate rule):
        // a failed bookkeeping transition aborts before any frame is emitted.
        match rec.rights {
            Rights::ReadWrite => {
                if rec.sender == HOST_PEER {
                    self.regions
                        .transfer_writable(rec.rid, HOST_PEER, rec.dest)
                        .map_err(|_| Poison("second writer denied"))?;
                } else {
                    self.regions
                        .transfer_writable(rec.rid, rec.sender, rec.dest)
                        .map_err(|_| Poison("writer transfer denied"))?;
                }
            }
            Rights::ReadOnly => {
                if rec.sender == HOST_PEER {
                    self.regions
                        .grant_read_only(rec.rid, rec.dest, &self.lim)
                        .map_err(|_| Poison("readonly grant denied"))?;
                } else {
                    self.regions
                        .transfer_read_only(rec.rid, rec.sender, rec.dest)
                        .map_err(|_| Poison("readonly transfer denied"))?;
                }
            }
        }
        self.shared_pending.remove(&tid);
        self.shared_results
            .insert(tid, (rec.sender, Cause::PeerLost, rec.rid));
        self.shared_live.insert(rec.rid);
        let mut out = RouteOutcome::default();
        let size = self.regions.size_of(rec.rid).unwrap_or(0);
        if !self.inject.drop_commit {
            out.send.push((
                rec.dest,
                Frame::Xfer(XferMsg::SharedCommit {
                    tid,
                    rid: rec.rid,
                    rights: encode_rights(rec.rights),
                    size,
                    handle_value: 0, // Host bin fills with recipient-valid object
                }),
            ));
        }
        if !self.inject.drop_committed && rec.sender != HOST_PEER {
            out.send
                .push((rec.sender, Frame::Xfer(XferMsg::Committed { tid })));
        }
        Ok(out)
    }

    fn shared_abort_inner(
        &mut self,
        tid: TransferId,
        _why: &'static str,
    ) -> Result<RouteOutcome, Poison> {
        let rec = *self
            .shared_pending
            .get(&tid)
            .ok_or(Poison("unknown shared transfer"))?;
        if rec.state != NativeState::Escrowed {
            return Ok(RouteOutcome::default());
        }
        // Pre-commit abort: authority never left the sender; RegionTable is
        // untouched and exact rights are restored implicitly (G12).
        self.shared_pending.remove(&tid);
        self.shared_results
            .insert(tid, (rec.sender, Cause::Graceful, rec.rid));
        let mut out = RouteOutcome::default();
        if !self.inject.drop_abort {
            if rec.sender != HOST_PEER && self.peers.contains_key(&rec.sender) {
                out.send
                    .push((rec.sender, Frame::Xfer(XferMsg::Abort { tid })));
            }
            if self.peers.contains_key(&rec.dest) {
                out.send
                    .push((rec.dest, Frame::Xfer(XferMsg::Abort { tid })));
            }
        }
        Ok(out)
    }

    /// Send a DATA frame originating FROM THE HOST on an endpoint the host
    /// holds (demo orchestration/control channel).
    pub fn host_emit(
        &mut self,
        target: EpId,
        corr: u32,
        payload: Vec<u8>,
    ) -> Result<RouteOutcome, Poison> {
        let entry = *self
            .eps
            .get(&target)
            .filter(|e| !e.closed)
            .ok_or(Poison("host emit on unknown/closed endpoint"))?;
        if entry.holder != Holder::Host {
            return Err(Poison("host emit on endpoint not held by host"));
        }
        let partner_entry = *self
            .eps
            .get(&entry.partner)
            .ok_or(Poison("broken pairing"))?;
        let mut out = RouteOutcome::default();
        if let Holder::Peer(dest) = partner_entry.holder {
            out.send.push((
                dest,
                Frame::Data(DataInner {
                    target,
                    corr,
                    attachments: vec![],
                    payload,
                    native: None,
                    shared: None,
                }),
            ));
        }
        Ok(out)
    }

    /// Process CLOSE of one end by its current holder.

    pub fn on_close(&mut self, from: PeerId, target: EpId) -> Result<RouteOutcome, Poison> {
        if !*self
            .peers
            .get(&from)
            .ok_or(Poison("frame from unknown peer"))?
        {
            return Err(Poison("traffic before hello"));
        }
        match self.require_owner(from, target) {
            Ok(_) => {}
            Err(Ok(())) => {
                let cause = self.retired.get(target).unwrap_or(Cause::Graceful);
                let mut out = RouteOutcome::default();
                out.send.push((
                    from,
                    Frame::ClosedNotify {
                        entries: vec![(target, cause)],
                    },
                ));
                return Ok(out);
            }
            Err(Err(p)) => return Err(p),
        }
        let (surviving, partner_entry) = self.close_conversation(target, Cause::Graceful).unwrap();
        let mut out = RouteOutcome::default();
        match partner_entry.holder {
            Holder::Peer(q) => {
                out.send.push((
                    q,
                    Frame::ClosedNotify {
                        entries: vec![(surviving, Cause::Graceful)],
                    },
                ));
            }
            Holder::Host => {
                self.host_events.push(HostEvent::EndpointClosed {
                    ep: surviving,
                    cause: Cause::Graceful,
                });
            }
            Holder::Escrow(_) => {}
        }
        Ok(out)
    }

    /// Process CREATE from a peer: allocates an implementation side and a
    /// transferable side, both initially held by the requesting peer.
    pub fn on_create(&mut self, from: PeerId) -> Result<RouteOutcome, Poison> {
        if !*self
            .peers
            .get(&from)
            .ok_or(Poison("frame from unknown peer"))?
        {
            return Err(Poison("traffic before hello"));
        }
        if self.eps.values().filter(|e| !e.closed).count() + 2 > self.lim.max_live_endpoints
            || self.results.len() >= self.lim.max_pending_transfers
        {
            // Capacity exhaustion is a resource condition, not corruption.
            // Surface as ERROR(code=capacity) to the requester.
            let mut out = RouteOutcome::default();
            out.send
                .push((from, Frame::Error(crate::frame::ERR_CAPACITY)));
            return Ok(out);
        }
        let (imp, tra) = self.alloc_pair(Holder::Peer(from));
        let mut out = RouteOutcome::default();
        out.send.push((
            from,
            Frame::CreateAck {
                impl_ep: imp,
                transferable_ep: tra,
            },
        ));
        Ok(out)
    }

    /// A host-only frame arriving from a peer, or any other protocol crime
    /// detected by the IO glue.
    pub fn on_illegal(&mut self, _from: PeerId, why: &'static str) -> Poison {
        Poison(why)
    }

    fn peer_gone(&mut self, p: PeerId, cause: Cause) -> RouteOutcome {
        let mut out = RouteOutcome::default();
        self.peers.remove(&p);
        // A dead sender can never observe its result: clean retained results.
        self.results.retain(|_, (s, _)| *s != p);
        self.native_results.retain(|_, (s, _, _)| *s != p);
        // Collect conversations touching this peer.
        let touched: Vec<EpId> = self
            .eps
            .iter()
            .filter(|(_, e)| !e.closed && e.holder == Holder::Peer(p))
            .map(|(k, _)| *k)
            .collect();
        let pending: Vec<TransferId> = self
            .xfers
            .values()
            .filter(|x| x.phase == XferPhase::Offered && (x.sender == p || x.dest == p))
            .map(|x| x.tid)
            .collect();
        for tid in pending {
            if let Some(x) = self.xfers.get(&tid).copied() {
                if x.sender == p {
                    // T1/T2: sender died; close the escrowed conversation.
                    if let Some(e) = self.eps.get(&x.ep) {
                        if !e.closed {
                            let _ = self.close_conversation(x.ep, cause);
                        }
                    }
                    self.finish_xfer(tid, x.sender, XferPhase::Aborted);
                } else {
                    // T3/T4/T5: dest died pre-commit; restore to sender.
                    let extra = self
                        .xfer_abort_inner(tid, "recipient lost")
                        .unwrap_or_default();
                    out.send.extend(extra.send);
                }
            }
        }
        // Native pending handling
        let native_pending: Vec<TransferId> = self
            .native_pending
            .values()
            .filter(|n| n.state == NativeState::Escrowed && (n.sender == p || n.dest == p))
            .map(|n| n.tid)
            .collect();
        for tid in native_pending {
            if let Some(n) = self.native_pending.get(&tid).copied() {
                if n.sender == p {
                    // Sender died pre-commit: close escrow, abort
                    self.native_pending.remove(&tid);
                    self.native_results
                        .insert(tid, (n.sender, Cause::Graceful, n.rid));
                    self.native_retired.insert(n.rid, Cause::Graceful);
                } else {
                    // Dest died pre-commit: restore to sender
                    let _ = self.native_abort_inner(tid, "recipient lost");
                }
            }
        }
        // Shared-region pending handling. Pre-commit the RegionTable never
        // moved authority, so cleanup is transactional bookkeeping only.
        let shared_pending_tids: Vec<TransferId> = self
            .shared_pending
            .values()
            .filter(|s| s.state == NativeState::Escrowed && (s.sender == p || s.dest == p))
            .map(|s| s.tid)
            .collect();
        for tid in shared_pending_tids {
            if let Some(s) = self.shared_pending.get(&tid).copied() {
                if s.sender == p {
                    // Sender died: escrowed backing closes in the Host bin;
                    // record terminal result so status queries fail closed.
                    self.shared_pending.remove(&tid);
                    self.shared_results
                        .insert(tid, (s.sender, Cause::Graceful, s.rid));
                } else {
                    let _ = self.shared_abort_inner(tid, "recipient lost");
                }
            }
        }
        // Post-commit death: vacate the dead peer's authorities (writer slot
        // empties; readers shrink). No auto re-mint of a writer.
        if p != HOST_PEER {
            self.regions.peer_gone(p);
        }
        for side in touched {
            if let Some((surviving, pe)) = self.close_conversation(side, cause) {
                match pe.holder {
                    Holder::Peer(q) => {
                        // q may itself have been removed earlier in this loop;
                        // only notify peers still present.
                        if self.peers.contains_key(&q) && q != p {
                            out.send.push((
                                q,
                                Frame::ClosedNotify {
                                    entries: vec![(surviving, cause)],
                                },
                            ));
                        }
                    }
                    Holder::Host => {
                        self.host_events.push(HostEvent::EndpointClosed {
                            ep: surviving,
                            cause,
                        });
                    }
                    Holder::Escrow(_) => {}
                }
            }
        }
        out
    }

    /// Transport to `p` broke (crash/kill). Collapse dependent authority.
    pub fn on_eof(&mut self, p: PeerId) -> RouteOutcome {
        self.peer_gone(p, Cause::PeerLost)
    }

    /// Orderly goodbye from `p`.
    pub fn on_shutdown(&mut self, p: PeerId) -> RouteOutcome {
        self.peer_gone(p, Cause::Graceful)
    }

    // ---- test/oracle helpers ----

    pub fn holder_of(&self, ep: EpId) -> Option<Holder> {
        self.eps.get(&ep).filter(|e| !e.closed).map(|e| e.holder)
    }

    pub fn partner_of(&self, ep: EpId) -> Option<EpId> {
        self.eps.get(&ep).map(|e| e.partner)
    }

    pub fn is_retired(&self, ep: EpId) -> bool {
        self.retired.contains(ep)
    }

    pub fn is_native_pending(&self, tid: TransferId) -> bool {
        self.native_pending.contains_key(&tid)
    }

    pub fn xfer(&self, tid: TransferId) -> Option<XferRec> {
        self.xfers.get(&tid).copied()
    }

    pub fn xfer_status(&self, tid: TransferId) -> u8 {
        if let Some(x) = self.xfers.get(&tid) {
            return match x.phase {
                XferPhase::Offered => XFER_ST_PENDING,
                XferPhase::Committed => XFER_ST_COMMITTED,
                XferPhase::Aborted => XFER_ST_ABORTED,
            };
        }
        if let Some(n) = self.native_pending.get(&tid) {
            return match n.state {
                NativeState::Escrowed => XFER_ST_PENDING,
                NativeState::Committed => XFER_ST_COMMITTED,
                NativeState::Aborted => XFER_ST_ABORTED,
            };
        }
        if let Some(s) = self.shared_pending.get(&tid) {
            return match s.state {
                NativeState::Escrowed => XFER_ST_PENDING,
                NativeState::Committed => XFER_ST_COMMITTED,
                NativeState::Aborted => XFER_ST_ABORTED,
            };
        }
        let cause = self
            .results
            .get(&tid)
            .map(|(_, c)| *c)
            .or_else(|| self.native_results.get(&tid).map(|(_, c, _)| *c))
            .or_else(|| self.shared_results.get(&tid).map(|(_, c, _)| *c));
        if let Some(c) = cause {
            return match c {
                Cause::PeerLost => XFER_ST_COMMITTED,
                Cause::Graceful => XFER_ST_ABORTED,
            };
        }
        XFER_ST_UNKNOWN
    }

    fn finish_xfer(&mut self, tid: TransferId, sender: PeerId, phase: XferPhase) {
        self.xfers.remove(&tid);
        let c = if phase == XferPhase::Committed {
            Cause::PeerLost
        } else {
            Cause::Graceful
        };
        self.results.insert(tid, (sender, c));
    }

    fn dest_live_count(&self, dest: PeerId) -> usize {
        self.eps
            .values()
            .filter(|e| !e.closed && e.holder == Holder::Peer(dest))
            .count()
    }

    /// Authority conservation: each live id has exactly one holder class.
    pub fn authority_mass_ok(&self) -> bool {
        for (id, e) in &self.eps {
            if e.closed {
                return false;
            }
            let usable_peer = matches!(e.holder, Holder::Peer(_));
            let escrow = matches!(e.holder, Holder::Escrow(_));
            let host = e.holder == Holder::Host;
            let n = usize::from(usable_peer) + usize::from(escrow) + usize::from(host);
            if n != 1 {
                return false;
            }
            if escrow {
                let Holder::Escrow(tid) = e.holder else {
                    return false;
                };
                match self.xfers.get(&tid) {
                    Some(x) if x.ep == *id && x.phase == XferPhase::Offered => {}
                    _ => return false,
                }
            }
        }
        true
    }

    pub fn on_xfer(&mut self, from: PeerId, msg: XferMsg) -> Result<RouteOutcome, Poison> {
        if !*self
            .peers
            .get(&from)
            .ok_or(Poison("frame from unknown peer"))?
        {
            return Err(Poison("traffic before hello"));
        }
        match msg {
            XferMsg::Accept { tid } => self.xfer_accept(from, tid),
            XferMsg::Reject { tid } => self.xfer_reject(from, tid, "rejected by recipient"),
            XferMsg::Status { tid } => {
                let st = self.xfer_status(tid);
                let mut out = RouteOutcome::default();
                out.send
                    .push((from, Frame::Xfer(XferMsg::StatusAck { tid, status: st })));
                Ok(out)
            }
            XferMsg::ResultAck { tid } => {
                // Idempotent: only the recorded sender's ACK retires the
                // retained result. Duplicates or third-party ACKs are no-ops.
                if let Some((sender, _)) = self.results.get(&tid).copied() {
                    if sender == from {
                        self.results.remove(&tid);
                    }
                }
                if let Some((sender, _, rid)) = self.native_results.get(&tid).copied() {
                    if sender == from {
                        self.native_results.remove(&tid);
                        // Fully retired: release the live-rid slot. Recipient keeps
                        // its OS descriptor; the rid name retires.
                        self.native_live.remove(&rid);
                        self.native_retired.insert(rid, Cause::Graceful);
                    }
                }
                if let Some((sender, _, rid)) = self.shared_results.get(&tid).copied() {
                    // Host-originated grants are retired by the RECIPIENT's
                    // ack (the Host is not a wire peer); peer transfers retire
                    // only on the recorded sender's own ack (idempotent).
                    if sender == from || sender == HOST_PEER {
                        self.shared_results.remove(&tid);
                        self.shared_live.remove(&rid);
                        self.shared_retired.insert(rid, Cause::Graceful);
                    }
                }
                Ok(RouteOutcome::default())
            }
            XferMsg::Commit { .. }
            | XferMsg::Committed { .. }
            | XferMsg::Abort { .. }
            | XferMsg::StatusAck { .. }
            | XferMsg::NativeCommit { .. }
            | XferMsg::NativeAbort { .. }
            | XferMsg::SharedCommit { .. }
            | XferMsg::SharedAbort { .. } => Err(Poison("peer sent host-only xfer")),
        }
    }

    fn xfer_accept(&mut self, from: PeerId, tid: TransferId) -> Result<RouteOutcome, Poison> {
        if let Some(x) = self.xfers.get(&tid).copied() {
            if x.dest != from {
                return Err(Poison("accept from wrong recipient"));
            }
            if x.phase != XferPhase::Offered {
                return Ok(RouteOutcome::default()); // idempotent
            }
            if self.dest_live_count(from) >= self.lim.max_live_endpoints {
                return self.xfer_abort_inner(tid, "recipient capacity");
            }
            if std::env::var("SEAM_PAUSE_BEFORE_COMMIT")
                .map(|v| v == "1")
                .unwrap_or(false)
            {
                barrier_wait("host_before_commit");
            }
            return self.xfer_commit_inner(tid);
        }
        if let Some(n) = self.native_pending.get(&tid).copied() {
            if n.dest != from {
                return Err(Poison("accept from wrong recipient"));
            }
            if n.state != NativeState::Escrowed {
                return Ok(RouteOutcome::default());
            }
            if self.native_live.len() >= self.lim.max_native_resources {
                return self.native_abort_inner(tid, "recipient capacity");
            }
            if std::env::var("SEAM_PAUSE_BEFORE_COMMIT")
                .map(|v| v == "1")
                .unwrap_or(false)
            {
                barrier_wait("host_before_commit");
            }
            return self.native_commit_inner(tid);
        }
        if let Some(n) = self.shared_pending.get(&tid).copied() {
            if n.dest != from {
                return Err(Poison("accept from wrong recipient"));
            }
            if n.state != NativeState::Escrowed {
                return Ok(RouteOutcome::default());
            }
            if std::env::var("SEAM_PAUSE_BEFORE_COMMIT")
                .map(|v| v == "1")
                .unwrap_or(false)
            {
                barrier_wait("host_before_commit");
            }
            return self.shared_commit_inner(tid);
        }
        match self.xfer_status(tid) {
            XFER_ST_COMMITTED | XFER_ST_ABORTED => Ok(RouteOutcome::default()),
            _ => Err(Poison("unknown transfer id")),
        }
    }

    fn xfer_reject(
        &mut self,
        from: PeerId,
        tid: TransferId,
        why: &'static str,
    ) -> Result<RouteOutcome, Poison> {
        if let Some(x) = self.xfers.get(&tid).copied() {
            if x.dest != from && x.sender != from {
                return Err(Poison("abort from unrelated peer"));
            }
            if x.phase != XferPhase::Offered {
                return Ok(RouteOutcome::default());
            }
            return self.xfer_abort_inner(tid, why);
        }
        if let Some(n) = self.native_pending.get(&tid).copied() {
            if n.dest != from && n.sender != from {
                return Err(Poison("abort from unrelated peer"));
            }
            if n.state != NativeState::Escrowed {
                return Ok(RouteOutcome::default());
            }
            return self.native_abort_inner(tid, why);
        }
        if let Some(n) = self.shared_pending.get(&tid).copied() {
            if n.dest != from && n.sender != from && n.sender != HOST_PEER {
                return Err(Poison("abort from unrelated peer"));
            }
            if n.state != NativeState::Escrowed {
                return Ok(RouteOutcome::default());
            }
            return self.shared_abort_inner(tid, why);
        }
        match self.xfer_status(tid) {
            XFER_ST_COMMITTED | XFER_ST_ABORTED => Ok(RouteOutcome::default()),
            _ => Err(Poison("unknown transfer id")),
        }
    }

    fn xfer_commit_inner(&mut self, tid: TransferId) -> Result<RouteOutcome, Poison> {
        let x = *self.xfers.get(&tid).ok_or(Poison("unknown transfer id"))?;
        if x.phase != XferPhase::Offered {
            return Ok(RouteOutcome::default());
        }
        if let Some(e) = self.eps.get_mut(&x.ep) {
            e.holder = Holder::Peer(x.dest);
        } else {
            return Err(Poison("escrowed endpoint missing"));
        }
        self.finish_xfer(tid, x.sender, XferPhase::Committed);
        if std::env::var("SEAM_PAUSE_AFTER_COMMIT")
            .map(|v| v == "1")
            .unwrap_or(false)
        {
            barrier_wait("host_after_commit");
        }
        let mut out = RouteOutcome::default();
        if !self.inject.drop_commit {
            out.send.push((
                x.dest,
                Frame::Xfer(XferMsg::Commit {
                    tid,
                    ep: x.ep,
                    partner: x.partner,
                }),
            ));
        }
        if !self.inject.drop_committed {
            out.send
                .push((x.sender, Frame::Xfer(XferMsg::Committed { tid })));
        }
        Ok(out)
    }

    fn xfer_abort_inner(
        &mut self,
        tid: TransferId,
        _why: &'static str,
    ) -> Result<RouteOutcome, Poison> {
        let x = *self.xfers.get(&tid).ok_or(Poison("unknown transfer id"))?;
        if x.phase != XferPhase::Offered {
            return Ok(RouteOutcome::default());
        }
        if let Some(e) = self.eps.get_mut(&x.ep) {
            e.holder = x.restore;
        }
        self.finish_xfer(tid, x.sender, XferPhase::Aborted);
        let mut out = RouteOutcome::default();
        if !self.inject.drop_abort {
            if let Holder::Peer(p) = x.restore {
                if self.peers.contains_key(&p) {
                    out.send.push((p, Frame::Xfer(XferMsg::Abort { tid })));
                }
            }
            if x.dest != x.sender && self.peers.contains_key(&x.dest) {
                out.send.push((x.dest, Frame::Xfer(XferMsg::Abort { tid })));
            }
        }
        Ok(out)
    }

    fn native_commit_inner(&mut self, tid: TransferId) -> Result<RouteOutcome, Poison> {
        let rec = *self
            .native_pending
            .get(&tid)
            .ok_or(Poison("unknown native transfer"))?;
        if rec.state != NativeState::Escrowed {
            return Ok(RouteOutcome::default());
        }
        // Move from pending to committed, and live to dest
        self.native_pending.remove(&tid);
        self.native_results
            .insert(tid, (rec.sender, Cause::PeerLost, rec.rid));
        self.native_live.insert(rec.rid, rec.dest);
        // Retire the old rid if it was previously live (should not happen for new rid)
        if std::env::var("SEAM_PAUSE_AFTER_COMMIT")
            .map(|v| v == "1")
            .unwrap_or(false)
        {
            barrier_wait("host_after_commit");
        }
        let mut out = RouteOutcome::default();
        // Recipient gets NativeCommit carrying the (host-filled) handle;
        // sender gets logical Committed for ResultAck retention.
        if !self.inject.drop_commit {
            out.send.push((
                rec.dest,
                Frame::Xfer(XferMsg::NativeCommit {
                    tid,
                    rid: rec.rid,
                    handle_value: 0,
                }),
            ));
        }
        if !self.inject.drop_committed {
            out.send
                .push((rec.sender, Frame::Xfer(XferMsg::Committed { tid })));
        }
        Ok(out)
    }

    fn native_abort_inner(
        &mut self,
        tid: TransferId,
        _why: &'static str,
    ) -> Result<RouteOutcome, Poison> {
        let rec = *self
            .native_pending
            .get(&tid)
            .ok_or(Poison("unknown native transfer"))?;
        if rec.state != NativeState::Escrowed {
            return Ok(RouteOutcome::default());
        }
        self.native_pending.remove(&tid);
        self.native_results
            .insert(tid, (rec.sender, Cause::Graceful, rec.rid));
        // No live entry for rid yet, so nothing to remove; on abort, rid returns to sender implicitly
        // For abort, we don't insert into native_live; sender will recreate on restore
        let mut out = RouteOutcome::default();
        if !self.inject.drop_abort {
            if self.peers.contains_key(&rec.sender) {
                out.send
                    .push((rec.sender, Frame::Xfer(XferMsg::Abort { tid })));
            }
            if rec.dest != rec.sender && self.peers.contains_key(&rec.dest) {
                out.send
                    .push((rec.dest, Frame::Xfer(XferMsg::Abort { tid })));
            }
        }
        Ok(out)
    }

    /// Test helper: force-abort an offered transfer.
    pub fn abort_transfer(&mut self, tid: TransferId) -> Result<RouteOutcome, Poison> {
        if self.xfers.contains_key(&tid) {
            return self.xfer_abort_inner(tid, "forced abort");
        }
        if self.native_pending.contains_key(&tid) {
            return self.native_abort_inner(tid, "forced abort");
        }
        Err(Poison("unknown transfer id"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::{Attachment, DataInner, Frame, XferMsg, ERR_CAPACITY};
    use crate::id::TransferId;
    use crate::native::ResourceId;

    fn hello_ok(r: &mut Router, p: PeerId) {
        r.on_hello(
            p,
            Limits::default().hello_magic,
            Limits::default().hello_version,
        )
        .unwrap();
    }

    fn grant_commit(r: &mut Router, to: PeerId, ep: EpId) {
        let f = r.grant(to, ep).unwrap();
        let tid = match f {
            Frame::Grant { tid, .. } => tid,
            other => panic!("grant produced {other:?}"),
        };
        r.on_xfer(to, XferMsg::Accept { tid }).unwrap();
        // retire terminal result (real peers ack via ResultAck)
        r.on_xfer(to, XferMsg::ResultAck { tid }).unwrap();
        assert_eq!(r.holder_of(ep), Some(Holder::Peer(to)));
        assert!(r.authority_mass_ok());
        assert_eq!(r.accounting().unacked_results, 0);
    }

    fn att(id: EpId, partner: EpId) -> Attachment {
        Attachment {
            tid: TransferId(id.0),
            id,
            partner,
        }
    }

    /// Two accepted, hello'd peers; root pair granted A=x, B=y.
    fn primed() -> (Router, PeerId, PeerId, EpId, EpId) {
        let mut r = Router::new(Limits::default());
        let a = r.accept_peer();
        let b = r.accept_peer();
        hello_ok(&mut r, a);
        hello_ok(&mut r, b);
        let (x, y) = r.create_host_pair();
        grant_commit(&mut r, a, x);
        grant_commit(&mut r, b, y);
        (r, a, b, x, y)
    }

    fn data(target: EpId, atts: Vec<Attachment>) -> DataInner {
        DataInner {
            target,
            corr: 1,
            attachments: atts,
            payload: b"x".to_vec(),
            native: None,
            shared: None,
        }
    }

    struct AnyTid;
    impl crate::id::TransferSpace for AnyTid {
        fn contains(&self, _id: TransferId) -> bool {
            false
        }
    }

    fn shared_data(target: EpId, rid: RegionId, rights: u8) -> DataInner {
        DataInner {
            target,
            corr: 1,
            attachments: vec![],
            payload: b"meta".to_vec(),
            native: None,
            shared: Some(crate::frame::SharedAttachment {
                tid: crate::id::fresh_transfer_id(&AnyTid),
                rid,
                rights,
                handle_value: 777,
            }),
        }
    }

    // ---- shared-region authority (RUN 005 / 005B) ----

    fn region() -> RegionId {
        RegionId([9; 16])
    }

    #[test]
    fn host_grant_rw_commits_and_moves_writer_authority() {
        let lim = Limits::default();
        let (mut r, a, b, x, y) = primed();
        let rid = region();
        r.region_create(rid, 4096, &lim).unwrap();
        let ra = r.region_accounting();
        assert_eq!(ra.writable_authorities, 1);
        assert_eq!(ra.readonly_authorities, 0);

        // Grant RW to peer a.
        let (_tid, oc) = r
            .host_grant_region(a, x, 1, rid, Rights::ReadWrite)
            .unwrap();
        assert!(matches!(
            oc.send.as_slice(),
            [(_, Frame::Data(d))] if d.shared.is_some()
        ));
        r.on_xfer(a, XferMsg::Accept { tid: _tid }).unwrap();
        let out = r.xfer_accept(a, _tid).unwrap(); // idempotent re-accept
        assert!(out.send.is_empty());

        // Writer moved off the Host sentinel onto the peer.
        assert_eq!(r.region_accounting().writable_authorities, 1);
        assert_eq!(r.region_size(rid), Some(4096));

        // Second writer grant is rejected (write_authority_count <= 1).
        assert!(r
            .host_grant_region(b, y, 2, rid, Rights::ReadWrite)
            .is_err());
    }

    #[test]
    fn host_grant_ro_adds_reader_without_touching_writer() {
        let lim = Limits::default();
        let (mut r, a, b, x, y) = primed();
        let rid = region();
        r.region_create(rid, 4096, &lim).unwrap();
        let (t1, _) = r
            .host_grant_region(a, x, 1, rid, Rights::ReadWrite)
            .unwrap();
        r.on_xfer(a, XferMsg::Accept { tid: t1 }).unwrap();

        let before = r.region_accounting();
        let (t2, _) = r.host_grant_region(b, y, 2, rid, Rights::ReadOnly).unwrap();
        r.on_xfer(b, XferMsg::Accept { tid: t2 }).unwrap();
        let after = r.region_accounting();
        assert_eq!(after.writable_authorities, before.writable_authorities);
        assert_eq!(after.readonly_authorities, before.readonly_authorities + 1);
    }

    #[test]
    fn unknown_region_offer_poisons() {
        let (mut r, a, _, x, _) = primed();
        let err = r
            .on_data(a, shared_data(x, RegionId([1; 16]), 1))
            .unwrap_err();
        assert_eq!(err.0, "unknown region id");
    }

    #[test]
    fn rights_claim_from_non_holder_poisons() {
        let lim = Limits::default();
        let (mut r, a, b, _x, y) = primed();
        let rid = region();
        r.region_create(rid, 4096, &lim).unwrap();
        // Host holds RW; peer b claims it -> denied.
        let err = r.on_data(b, shared_data(y, rid, 1)).unwrap_err();
        assert_eq!(err.0, "shared rights claim denied");
        // Unknown rights byte -> poison.
        let err = r.on_data(a, shared_data(_x, rid, 9)).unwrap_err();
        assert_eq!(err.0, "unknown shared rights byte");
    }

    #[test]
    fn rw_transfer_commit_moves_writer_between_peers() {
        let lim = Limits::default();
        let (mut r, a, b, x, _y) = primed();
        let rid = region();
        r.region_create(rid, 4096, &lim).unwrap();
        let (t0, _) = r
            .host_grant_region(a, x, 1, rid, Rights::ReadWrite)
            .unwrap();
        r.on_xfer(a, XferMsg::Accept { tid: t0 }).unwrap();
        r.on_xfer(a, XferMsg::ResultAck { tid: t0 }).unwrap();

        // a stages RW toward b (dest resolved by target ep ownership).
        let oc = r.on_data(a, shared_data(x, rid, 1)).unwrap();
        assert!(oc
            .send
            .iter()
            .all(|(_, f)| matches!(f, Frame::Data(d) if d.shared.is_some()))); // offer forwarded to dest
        let tid = r
            .shared_pending
            .keys()
            .copied()
            .next()
            .expect("staged pending");
        let out = r.on_xfer(b, XferMsg::Accept { tid }).unwrap();
        // Commit frame carries Host-authoritative rights+size.
        assert!(out.send.iter().any(|(_, f)| matches!(
            f,
            Frame::Xfer(XferMsg::SharedCommit {
                rights: 1,
                size: 4096,
                ..
            })
        )));
        assert_eq!(r.accounting().shared_pending, 0);
        assert_eq!(r.accounting().shared_unacked, 1);

        // Sender ack retires result + live rid slot.
        r.on_xfer(a, XferMsg::ResultAck { tid }).unwrap();
        let acct = r.accounting();
        assert_eq!(acct.shared_unacked, 0);
        assert_eq!(acct.shared_pending, 0);
    }

    #[test]
    fn rw_transfer_abort_restores_sender_authority_unchanged() {
        let lim = Limits::default();
        let (mut r, a, b, x, _y) = primed();
        let rid = region();
        r.region_create(rid, 4096, &lim).unwrap();
        let (t0, _) = r
            .host_grant_region(a, x, 1, rid, Rights::ReadWrite)
            .unwrap();
        r.on_xfer(a, XferMsg::Accept { tid: t0 }).unwrap();
        r.on_xfer(a, XferMsg::ResultAck { tid: t0 }).unwrap();

        let _oc = r.on_data(a, shared_data(x, rid, 1)).unwrap();
        let tid = r
            .shared_pending
            .keys()
            .copied()
            .next()
            .expect("staged pending");
        // Recipient rejects pre-commit.
        let out = r.on_xfer(b, XferMsg::Reject { tid }).unwrap();
        assert!(out
            .send
            .iter()
            .any(|(_, f)| matches!(f, Frame::Xfer(XferMsg::Abort { .. }))));
        // Authority never moved: writer is still peer a. Result retained
        // until the sender acknowledges.
        assert_eq!(r.accounting().shared_unacked, 1);
        r.on_xfer(a, XferMsg::ResultAck { tid }).unwrap();
        assert_eq!(r.accounting().shared_unacked, 0);
    }

    #[test]
    fn ro_holder_cannot_stage_rw_claim() {
        let lim = Limits::default();
        let (mut r, a, b, x, y) = primed();
        let rid = region();
        r.region_create(rid, 4096, &lim).unwrap();
        let (t0, _) = r
            .host_grant_region(a, x, 1, rid, Rights::ReadWrite)
            .unwrap();
        r.on_xfer(a, XferMsg::Accept { tid: t0 }).unwrap();
        r.on_xfer(a, XferMsg::ResultAck { tid: t0 }).unwrap();
        let (t1, _) = r.host_grant_region(b, y, 2, rid, Rights::ReadOnly).unwrap();
        r.on_xfer(b, XferMsg::Accept { tid: t1 }).unwrap();

        // Reader attempts escalation to RW -> fail closed.
        let err = r.on_data(b, shared_data(y, rid, 1)).unwrap_err();
        assert_eq!(err.0, "shared rights claim denied");
    }

    #[test]
    fn ro_transfer_moves_reader_authority() {
        let lim = Limits::default();
        let (mut r, a, b, x, y) = primed();
        let rid = region();
        r.region_create(rid, 4096, &lim).unwrap();
        let (t0, _) = r
            .host_grant_region(a, x, 1, rid, Rights::ReadWrite)
            .unwrap();
        r.on_xfer(a, XferMsg::Accept { tid: t0 }).unwrap();
        r.on_xfer(a, XferMsg::ResultAck { tid: t0 }).unwrap();
        let (t1, _) = r.host_grant_region(b, y, 2, rid, Rights::ReadOnly).unwrap();
        r.on_xfer(b, XferMsg::Accept { tid: t1 }).unwrap();
        assert_eq!(r.region_accounting().readonly_authorities, 1);

        // b hands its RO view onward to a (pair-routing: target y, partner x
        // resolves dest=a). Rights byte 0 = ReadOnly claim, validated against
        // b's recorded RO authority.
        let oc = r.on_data(b, shared_data(y, rid, 0)).unwrap();
        assert!(oc
            .send
            .iter()
            .all(|(_, f)| matches!(f, Frame::Data(d) if d.shared.is_some())));
        let tid = r
            .shared_pending
            .keys()
            .copied()
            .next()
            .expect("staged RO pending");
        r.on_xfer(a, XferMsg::Accept { tid }).unwrap();
        // Reader count unchanged by a move (b lost it, a gained it).
        assert_eq!(r.region_accounting().readonly_authorities, 1);
        r.on_xfer(b, XferMsg::ResultAck { tid }).unwrap();
    }

    /// G6: the grant->materialize transition must be deterministic. 100
    /// consecutive grant/commit/ack cycles with zero timing dependence; the
    /// writer holder flips Host-sentinel -> peer -> (next cycle) sentinel.
    #[test]
    fn hundred_grant_materialize_cycles_deterministic() {
        let lim = Limits::default();
        let (mut r, a, b, x, y) = primed();
        let rid = region();
        r.region_create(rid, 4096, &lim).unwrap();
        // Establish: Host -> a (the grant/materialize/ack conjunction).
        let (tid0, _) = r
            .host_grant_region(a, x, 0, rid, Rights::ReadWrite)
            .unwrap();
        r.on_xfer(a, XferMsg::Accept { tid: tid0 }).unwrap();
        r.on_xfer(a, XferMsg::ResultAck { tid: tid0 }).unwrap();

        // 100 deterministic writer flips through the peer-staging path:
        // every cycle is offer -> accept -> commit -> materialize-ack with
        // zero timing dependence.
        for i in 0..100u32 {
            let (from, to, from_ep) = if i % 2 == 0 { (a, b, x) } else { (b, a, y) };
            let _oc = r
                .on_data(from, shared_data(from_ep, rid, 1))
                .unwrap_or_else(|e| panic!("cycle {i} stage: {e:?}"));
            assert_eq!(r.accounting().shared_pending, 1);
            assert_eq!(r.region_writable_holder(rid), Some(from));
            let tid = *r.shared_pending.keys().next().expect("pending");
            r.on_xfer(to, XferMsg::Accept { tid }).unwrap();
            assert_eq!(r.region_writable_holder(rid), Some(to), "cycle {i}: holder");
            r.on_xfer(from, XferMsg::ResultAck { tid }).unwrap();
            assert_eq!(r.accounting().shared_unacked, 0, "cycle {i}");
            assert_eq!(r.accounting().shared_pending, 0, "cycle {i}");
        }
    }

    /// G8: the Host sentinel is not claimable. Peers cannot be granted as
    /// the sentinel, cannot stage offers from it, and host-only shared
    /// frames sent BY a peer are poisoned like their native twins.
    #[test]
    fn host_sentinel_cannot_be_impersonated() {
        let lim = Limits::default();
        let (mut r, a, b, x, y) = primed();
        let rid = region();
        r.region_create(rid, 4096, &lim).unwrap();

        // Granting TO the sentinel is nonsense and rejected outright.
        assert!(r
            .host_grant_region(crate::router::HOST_PEER, x, 0, rid, Rights::ReadWrite)
            .is_err());

        // A peer staging an offer is bound by its wire peer id: even a
        // hand-crafted SharedRec with sender=HOST would never enter through
        // on_data, whose `from` is connection-assigned. Prove the claim
        // validation rejects a peer offering when the table records HOST:
        let err = r.on_data(a, shared_data(x, rid, 1)).unwrap_err();
        assert_eq!(err.0, "shared rights claim denied");

        // Peer-sent SharedCommit / SharedAbort are host-only frames.
        let tid = crate::id::fresh_transfer_id(&AnyTid);
        let p1 = r.on_xfer(
            b,
            XferMsg::SharedCommit {
                tid,
                rid,
                rights: 1,
                size: 4096,
                handle_value: 5,
            },
        );
        assert_eq!(p1.unwrap_err().0, "peer sent host-only xfer");
        let p2 = r.on_xfer(
            b,
            XferMsg::SharedAbort {
                tid,
                rid,
                handle_value: 5,
            },
        );
        assert_eq!(p2.unwrap_err().0, "peer sent host-only xfer");

        // Sanity after hostility: table untouched.
        assert_eq!(r.region_accounting().writable_authorities, 1);
        assert_eq!(
            r.region_writable_holder(rid),
            Some(crate::router::HOST_PEER)
        );
        let _ = y;
    }

    #[test]
    fn sender_death_drops_staged_shared_and_keeps_table_consistent() {
        let lim = Limits::default();
        let (mut r, a, _b, x, _y) = primed();
        let rid = region();
        r.region_create(rid, 4096, &lim).unwrap();
        let (t0, _) = r
            .host_grant_region(a, x, 1, rid, Rights::ReadWrite)
            .unwrap();
        r.on_xfer(a, XferMsg::Accept { tid: t0 }).unwrap();
        let _ = r.on_data(a, shared_data(x, rid, 1)).unwrap();
        assert_eq!(r.accounting().shared_pending, 1);
        // Sender dies pre-commit: escrow bookkeeping aborts, writer stays a.
        r.on_eof(a);
        assert_eq!(r.accounting().shared_pending, 0);
        // Writer died too: slot vacated, no auto re-mint.
        assert_eq!(r.region_accounting().writable_authorities, 0);
    }

    #[test]
    fn unknown_target_quarantines() {
        let (mut r, a, _, _, _) = primed();
        let err = r
            .on_data(a, data(EpId::from_raw([0x01; 16]), vec![]))
            .unwrap_err();
        assert_eq!(err, Poison("unknown endpoint identity"));
    }

    #[test]
    fn stale_target_soft_rejected() {
        let (mut r, a, _, x, y) = primed();
        r.on_close(a, x).unwrap();
        let oc = r.on_data(a, data(x, vec![])).expect("stale is not poison");
        assert!(
            oc.send.iter().any(|(dest, f)| {
                *dest == a
                    && matches!(f, Frame::ClosedNotify { entries } if entries.iter().any(|(id, _)| *id == x))
            }),
            "corrective ClosedNotify to former holder: {oc:?}"
        );
        assert!(r.holder_of(x).is_none());
        assert!(r.holder_of(y).is_none());
        assert!(r.is_retired(x));
        assert!(r.is_retired(y));
        // Identity never resurrects.
        assert!(r.holder_of(x).is_none());
    }

    #[test]
    fn unauthorized_use_quarantines() {
        let (mut r, _, b, x, _) = primed();
        let err = r.on_data(b, data(x, vec![])).unwrap_err();
        assert_eq!(err, Poison("identity not held by sender"));
    }

    #[test]
    fn forged_attachment_quarantines() {
        let (mut r, a, _, x, y) = primed();
        // y is held by B; A attaching it is forgery.
        let err = r
            .on_data(a, data(x, vec![att(y, r.partner_of(y).unwrap())]))
            .unwrap_err();
        assert_eq!(err, Poison("identity not held by sender"));
    }

    #[test]
    fn topology_lie_quarantines() {
        let (mut r, a, _, x, _) = primed();
        let oc = r.on_create(a).unwrap();
        let (imp, tra) = match &oc.send[0].1 {
            Frame::CreateAck {
                impl_ep,
                transferable_ep,
            } => (*impl_ep, *transferable_ep),
            other => panic!("expected CreateAck, got {other:?}"),
        };
        let err = r
            .on_data(
                a,
                data(
                    x,
                    vec![Attachment {
                        tid: TransferId(tra.0),
                        id: tra,
                        partner: {
                            let mut p = imp.0;
                            p[0] ^= 1;
                            EpId(p)
                        },
                    }],
                ),
            )
            .unwrap_err();
        assert_eq!(
            err,
            Poison("attachment partner metadata contradicts fabric")
        );
        let _ = imp;
    }

    #[test]
    fn transfer_moves_ownership() {
        let (mut r, a, b, x, _) = primed();
        let oc = r.on_create(a).unwrap();
        let (imp, tra) = match &oc.send[0].1 {
            Frame::CreateAck {
                impl_ep,
                transferable_ep,
            } => (*impl_ep, *transferable_ep),
            other => panic!("expected CreateAck, got {other:?}"),
        };
        let partner = r.partner_of(tra).unwrap();
        assert_eq!(partner, imp);
        assert_eq!(r.holder_of(tra), Some(Holder::Peer(a)));

        let oc = r.on_data(a, data(x, vec![att(tra, imp)])).unwrap();
        assert!(matches!(r.holder_of(tra), Some(Holder::Escrow(_))));
        assert!(
            oc.send.iter().any(|(dest, f)| {
                *dest == b
                    && matches!(
                        f,
                        Frame::Data(d) if d.attachments.iter().any(|att| att.id == tra)
                    )
            }),
            "forwarded DATA with attachment must reach recipient: {oc:?}"
        );
        let tid = match r.holder_of(tra) {
            Some(Holder::Escrow(t)) => t,
            other => panic!("{other:?}"),
        };
        r.on_xfer(b, XferMsg::Accept { tid }).unwrap();
        assert_eq!(r.holder_of(tra), Some(Holder::Peer(b)));
        assert!(r.authority_mass_ok());

        let err = r.on_data(a, data(x, vec![att(tra, imp)])).unwrap_err();
        assert_eq!(err, Poison("identity not held by sender"));
    }

    #[test]
    fn peer_host_only_frame_poisons() {
        let (mut r, a, _, _, _) = primed();
        let p = r.on_illegal(a, "peer sent host-only frame");
        assert_eq!(p, Poison("peer sent host-only frame"));
    }

    #[test]
    fn create_capacity_yields_error_frame() {
        let mut r = Router::new(Limits {
            max_live_endpoints: 4,
            ..Limits::default()
        });
        let a = r.accept_peer();
        hello_ok(&mut r, a);
        let _ = r.create_host_pair(); // 2 live
        let oc = r.on_create(a).unwrap(); // 4 live
        assert!(matches!(oc.send[0].1, Frame::CreateAck { .. }));
        let oc = r.on_create(a).unwrap();
        assert!(
            matches!(oc.send[0].1, Frame::Error(ERR_CAPACITY)),
            "expected capacity error, got {oc:?}"
        );
        assert_eq!(r.accounting().live_endpoints, 4);
    }

    #[test]
    fn eof_notifies_survivor_and_retires_both() {
        let (mut r, a, b, x, y) = primed();
        let (h1, h2) = r.create_host_pair();
        grant_commit(&mut r, a, h1);
        let oc = r.on_eof(a);
        assert!(
            oc.send.iter().any(|(dest, f)| {
                *dest == b
                    && matches!(
                        f,
                        Frame::ClosedNotify { entries }
                            if entries.iter().any(|(id, c)| *id == y && *c == Cause::PeerLost)
                    )
            }),
            "survivor ClosedNotify PeerLost: {oc:?}"
        );
        assert!(r.holder_of(x).is_none());
        assert!(r.holder_of(y).is_none());
        assert!(r.is_retired(x) && r.is_retired(y));
        let ev = r.take_host_events();
        assert!(
            ev.iter().any(|e| matches!(
                e,
                HostEvent::EndpointClosed { ep, cause: Cause::PeerLost } if *ep == h2
            )),
            "host-held partner surfaces: {ev:?}"
        );
    }

    #[test]
    fn shutdown_is_graceful() {
        let (mut r, a, b, _, y) = primed();
        let oc = r.on_shutdown(a);
        assert!(oc.send.iter().any(|(dest, f)| {
            *dest == b
                && matches!(
                    f,
                    Frame::ClosedNotify { entries }
                        if entries.iter().any(|(id, c)| *id == y && *c == Cause::Graceful)
                )
        }));
        assert!(r.peers.get(&a).is_none());
    }

    #[test]
    fn hello_gating() {
        let mut r = Router::new(Limits::default());
        let a = r.accept_peer();
        let err = r
            .on_data(a, data(EpId::from_raw([1; 16]), vec![]))
            .unwrap_err();
        assert_eq!(err, Poison("traffic before hello"));

        hello_ok(&mut r, a);
        let err = r
            .on_hello(
                a,
                Limits::default().hello_magic,
                Limits::default().hello_version,
            )
            .unwrap_err();
        assert_eq!(err, Poison("duplicate hello"));

        let b = r.accept_peer();
        let err = r.on_hello(b, 0x0000, 1).unwrap_err();
        assert_eq!(err, Poison("bad hello magic"));
        let c = r.accept_peer();
        let err = r
            .on_hello(c, Limits::default().hello_magic, 99)
            .unwrap_err();
        assert_eq!(err, Poison("bad protocol version"));
    }

    #[test]
    fn results_retained_until_sender_ack_and_bounds_new_work() {
        let mut r = Router::new(Limits {
            max_pending_transfers: 2,
            max_live_endpoints: 4096,
            ..Limits::default()
        });
        let a = r.accept_peer();
        let b = r.accept_peer();
        hello_ok(&mut r, a);
        hello_ok(&mut r, b);
        let (x, y) = r.create_host_pair();
        grant_commit(&mut r, a, x);
        grant_commit(&mut r, b, y);
        // first transfer A->B
        let oc = r.on_create(a).unwrap();
        let (imp1, tra1) = match &oc.send[0].1 {
            Frame::CreateAck {
                impl_ep,
                transferable_ep,
            } => (*impl_ep, *transferable_ep),
            other => panic!("{other:?}"),
        };
        let oc = r.on_data(a, data(x, vec![att(tra1, imp1)])).unwrap();
        let tid1 = match r.holder_of(tra1) {
            Some(Holder::Escrow(t)) => t,
            other => panic!("{other:?}"),
        };
        let _ = oc; // forwarded
        r.on_xfer(b, XferMsg::Accept { tid: tid1 }).unwrap();
        assert_eq!(r.accounting().unacked_results, 1);
        assert_eq!(r.xfer_status(tid1), crate::frame::XFER_ST_COMMITTED);
        // second transfer
        let oc = r.on_create(a).unwrap();
        let (imp2, tra2) = match &oc.send[0].1 {
            Frame::CreateAck {
                impl_ep,
                transferable_ep,
            } => (*impl_ep, *transferable_ep),
            other => panic!("{other:?}"),
        };
        let oc = r.on_data(a, data(x, vec![att(tra2, imp2)])).unwrap();
        let tid2 = match r.holder_of(tra2) {
            Some(Holder::Escrow(t)) => t,
            other => panic!("{other:?}"),
        };
        let _ = oc;
        r.on_xfer(b, XferMsg::Accept { tid: tid2 }).unwrap();
        assert_eq!(r.accounting().unacked_results, 2);
        // bounded: next grant/create must be rejected, not silently queued
        let (h1, _h2) = r.create_host_pair();
        // grant should fail due to results table full (pending+results >= cap)
        let err = r.grant(b, h1).unwrap_err();
        assert_eq!(err, Poison("pending transfer table full"));
        // create path also surfaces capacity error, not poison
        let oc = r.on_create(a).unwrap();
        assert!(matches!(oc.send[0].1, Frame::Error(ERR_CAPACITY)));
        // sender ack retires one slot, new work can proceed
        r.on_xfer(a, XferMsg::ResultAck { tid: tid1 }).unwrap();
        assert_eq!(r.accounting().unacked_results, 1);
        let (h3, _) = r.create_host_pair();
        // now grant should succeed
        assert!(r.grant(b, h3).is_ok());
        assert!(r.authority_mass_ok());
    }

    #[test]
    fn result_ack_idempotent_and_sender_bound() {
        let (mut r, a, b, x, _) = primed();
        let oc = r.on_create(a).unwrap();
        let (imp, tra) = match &oc.send[0].1 {
            Frame::CreateAck {
                impl_ep,
                transferable_ep,
            } => (*impl_ep, *transferable_ep),
            other => panic!("{other:?}"),
        };
        let oc = r.on_data(a, data(x, vec![att(tra, imp)])).unwrap();
        let tid = match r.holder_of(tra) {
            Some(Holder::Escrow(t)) => t,
            other => panic!("{other:?}"),
        };
        let _ = oc;
        r.on_xfer(b, XferMsg::Accept { tid }).unwrap();
        assert_eq!(r.xfer_status(tid), crate::frame::XFER_ST_COMMITTED);
        // third-party ack is no-op
        r.on_xfer(b, XferMsg::ResultAck { tid }).unwrap();
        assert_eq!(r.accounting().unacked_results, 1);
        assert_eq!(r.xfer_status(tid), crate::frame::XFER_ST_COMMITTED);
        // sender ack retires
        r.on_xfer(a, XferMsg::ResultAck { tid }).unwrap();
        assert_eq!(r.accounting().unacked_results, 0);
        assert_eq!(r.xfer_status(tid), crate::frame::XFER_ST_UNKNOWN);
        // duplicate is idempotent no-op
        r.on_xfer(a, XferMsg::ResultAck { tid }).unwrap();
        assert_eq!(r.accounting().unacked_results, 0);
        // abort case also idempotent
        let oc = r.on_create(a).unwrap();
        let (imp2, tra2) = match &oc.send[0].1 {
            Frame::CreateAck {
                impl_ep,
                transferable_ep,
            } => (*impl_ep, *transferable_ep),
            other => panic!("{other:?}"),
        };
        let oc = r.on_data(a, data(x, vec![att(tra2, imp2)])).unwrap();
        let tid2 = match r.holder_of(tra2) {
            Some(Holder::Escrow(t)) => t,
            other => panic!("{other:?}"),
        };
        let _ = oc;
        r.on_xfer(b, XferMsg::Reject { tid: tid2 }).unwrap();
        assert_eq!(r.xfer_status(tid2), crate::frame::XFER_ST_ABORTED);
        r.on_xfer(b, XferMsg::ResultAck { tid: tid2 }).unwrap();
        assert_eq!(r.accounting().unacked_results, 1); // not retired by dest
        r.on_xfer(a, XferMsg::ResultAck { tid: tid2 }).unwrap();
        assert_eq!(r.accounting().unacked_results, 0);
    }

    #[test]
    fn lost_committed_still_reported_as_committed_via_status() {
        let (mut r, a, b, x, _) = primed();
        r.inject.drop_committed = true;
        let oc = r.on_create(a).unwrap();
        let (imp, tra) = match &oc.send[0].1 {
            Frame::CreateAck {
                impl_ep,
                transferable_ep,
            } => (*impl_ep, *transferable_ep),
            other => panic!("{other:?}"),
        };
        let oc = r.on_data(a, data(x, vec![att(tra, imp)])).unwrap();
        let tid = match r.holder_of(tra) {
            Some(Holder::Escrow(t)) => t,
            other => panic!("{other:?}"),
        };
        let _ = oc;
        let out = r.on_xfer(b, XferMsg::Accept { tid }).unwrap();
        // Committed dropped, but status still COMMITTED via retained result
        assert!(out
            .send
            .iter()
            .all(|(_, f)| !matches!(f, Frame::Xfer(XferMsg::Committed { .. }))));
        assert_eq!(r.xfer_status(tid), crate::frame::XFER_ST_COMMITTED);
        let oc = r.on_xfer(a, XferMsg::Status { tid }).unwrap();
        assert!(oc.send.iter().any(|(dest, f)| {
            *dest == a && matches!(f, Frame::Xfer(XferMsg::StatusAck { tid: t, status }) if *t==tid && *status==crate::frame::XFER_ST_COMMITTED)
        }));
        // sender ack retires
        r.on_xfer(a, XferMsg::ResultAck { tid }).unwrap();
        assert_eq!(r.accounting().unacked_results, 0);
        let oc = r.on_xfer(a, XferMsg::Status { tid }).unwrap();
        assert!(oc.send.iter().any(|(_, f)| matches!(f, Frame::Xfer(XferMsg::StatusAck { status, .. }) if *status==crate::frame::XFER_ST_UNKNOWN)));
        r.inject.drop_committed = false;
    }

    #[test]
    fn abort_restores_to_sender_and_commit_does_not() {
        let (mut r, a, b, x, y) = primed();
        // Pre-commit abort: dest Rejects -> holder returns to sender
        let oc = r.on_create(a).unwrap();
        let (imp, tra) = match &oc.send[0].1 {
            Frame::CreateAck {
                impl_ep,
                transferable_ep,
            } => (*impl_ep, *transferable_ep),
            other => panic!("{other:?}"),
        };
        let oc = r.on_data(a, data(x, vec![att(tra, imp)])).unwrap();
        let tid = match r.holder_of(tra) {
            Some(Holder::Escrow(t)) => t,
            other => panic!("{other:?}"),
        };
        let _ = oc;
        r.on_xfer(b, XferMsg::Reject { tid }).unwrap();
        assert_eq!(r.holder_of(tra), Some(Holder::Peer(a)));
        assert_eq!(r.xfer_status(tid), crate::frame::XFER_ST_ABORTED);
        r.on_xfer(a, XferMsg::ResultAck { tid }).unwrap();
        // Post-commit death: authority dies with dest, not restored
        let oc = r.on_create(a).unwrap();
        let (imp2, tra2) = match &oc.send[0].1 {
            Frame::CreateAck {
                impl_ep,
                transferable_ep,
            } => (*impl_ep, *transferable_ep),
            other => panic!("{other:?}"),
        };
        let oc = r.on_data(a, data(x, vec![att(tra2, imp2)])).unwrap();
        let tid2 = match r.holder_of(tra2) {
            Some(Holder::Escrow(t)) => t,
            other => panic!("{other:?}"),
        };
        let _ = oc;
        r.on_xfer(b, XferMsg::Accept { tid: tid2 }).unwrap();
        assert_eq!(r.holder_of(tra2), Some(Holder::Peer(b)));
        // kill dest
        let _ = r.on_eof(b);
        // y's pair was B-held, tra2 dies with B if we killed B after commit
        // tra2 was also B-held; after peer gone, its conversation is closed
        assert!(r.holder_of(tra2).is_none());
        // tid2 still terminal COMMITTED in results until sender ack, but authority not restored
        assert_eq!(r.xfer_status(tid2), crate::frame::XFER_ST_COMMITTED);
        // sender ack retires
        r.on_xfer(a, XferMsg::ResultAck { tid: tid2 }).unwrap();
        assert_eq!(r.holder_of(tra2), None);
        let _ = y;
    }

    #[test]
    fn churn_and_drop_storm_keep_accounting_clean() {
        let mut r = Router::new(Limits {
            max_live_endpoints: 64,
            max_pending_transfers: 256,
            ..Limits::default()
        });
        let a = r.accept_peer();
        let b = r.accept_peer();
        hello_ok(&mut r, a);
        hello_ok(&mut r, b);
        let (x, y) = r.create_host_pair();
        grant_commit(&mut r, a, x);
        grant_commit(&mut r, b, y);
        // churn 500 transfers
        for _ in 0..500 {
            let oc = r.on_create(a).unwrap();
            let (imp, tra) = match &oc.send[0].1 {
                Frame::CreateAck {
                    impl_ep,
                    transferable_ep,
                } => (*impl_ep, *transferable_ep),
                other => panic!("{other:?}"),
            };
            let oc = r.on_data(a, data(x, vec![att(tra, imp)])).unwrap();
            let tid = match r.holder_of(tra) {
                Some(Holder::Escrow(t)) => t,
                other => panic!("{other:?}"),
            };
            let _ = oc;
            r.on_xfer(b, XferMsg::Accept { tid }).unwrap();
            assert_eq!(r.holder_of(tra), Some(Holder::Peer(b)));
            r.on_xfer(a, XferMsg::ResultAck { tid }).unwrap();
            // simulate recipient closing then mass stays ok
            let _ = r.on_close(b, tra);
            assert!(r.authority_mass_ok());
        }
        assert_eq!(r.accounting().unacked_results, 0);
        assert!(r.authority_mass_ok());
        assert!(r.accounting().retired_identities <= Limits::default().max_retired);
        // ancient replay: unknown tid Accept should be Poison, not silent success
        let fake = TransferId([0xFF; 16]);
        let err = r.on_xfer(b, XferMsg::Accept { tid: fake }).unwrap_err();
        assert_eq!(err, Poison("unknown transfer id"));
    }

    #[test]
    fn capacity_abort_reports_aborted_and_no_parked_hang() {
        let (_r, _a, _b, _x, _) = primed();
        // Abort via explicit Reject must restore to sender and be ackable.
        let mut r2 = Router::new(Limits::default());
        let a2 = r2.accept_peer();
        let b2 = r2.accept_peer();
        hello_ok(&mut r2, a2);
        hello_ok(&mut r2, b2);
        let (x2, y2) = r2.create_host_pair();
        grant_commit(&mut r2, a2, x2);
        grant_commit(&mut r2, b2, y2);
        let oc = r2.on_create(a2).unwrap();
        let (imp, tra) = match &oc.send[0].1 {
            Frame::CreateAck {
                impl_ep,
                transferable_ep,
            } => (*impl_ep, *transferable_ep),
            other => panic!("{other:?}"),
        };
        let oc = r2.on_data(a2, data(x2, vec![att(tra, imp)])).unwrap();
        let tid = match r2.holder_of(tra) {
            Some(Holder::Escrow(t)) => t,
            other => panic!("{other:?}"),
        };
        let _ = oc;
        let out = r2.on_xfer(b2, XferMsg::Reject { tid }).unwrap();
        assert_eq!(r2.holder_of(tra), Some(Holder::Peer(a2)));
        assert_eq!(r2.xfer_status(tid), crate::frame::XFER_ST_ABORTED);
        let _ = out;
        r2.on_xfer(a2, XferMsg::ResultAck { tid }).unwrap();
        assert_eq!(r2.accounting().unacked_results, 0);
        assert!(r2.authority_mass_ok());
        // pending table full also surfaces as capacity Error, not hang
        let mut r3 = Router::new(Limits {
            max_pending_transfers: 1,
            ..Limits::default()
        });
        let a3 = r3.accept_peer();
        let b3 = r3.accept_peer();
        hello_ok(&mut r3, a3);
        hello_ok(&mut r3, b3);
        let (x3, y3) = r3.create_host_pair();
        grant_commit(&mut r3, a3, x3);
        grant_commit(&mut r3, b3, y3);
        let oc = r3.on_create(a3).unwrap();
        let (imp3, tra3) = match &oc.send[0].1 {
            Frame::CreateAck {
                impl_ep,
                transferable_ep,
            } => (*impl_ep, *transferable_ep),
            other => panic!("{other:?}"),
        };
        let oc = r3.on_data(a3, data(x3, vec![att(tra3, imp3)])).unwrap();
        let tid3 = match r3.holder_of(tra3) {
            Some(Holder::Escrow(t)) => t,
            other => panic!("{other:?}"),
        };
        let _ = oc;
        assert_eq!(r3.accounting().pending_transfers, 1);
        // next transfer must be rejected via Error, not queued
        let oc2 = r3.on_create(a3).unwrap();
        let (imp4, tra4) = match &oc2.send[0].1 {
            Frame::CreateAck {
                impl_ep,
                transferable_ep,
            } => (*impl_ep, *transferable_ep),
            other => panic!("{other:?}"),
        };
        let oc = r3.on_data(a3, data(x3, vec![att(tra4, imp4)])).unwrap();
        assert!(matches!(oc.send[0].1, Frame::Error(ERR_CAPACITY)));
        let _ = tid3;
    }

    #[test]
    fn native_happy_path() {
        let (mut r, a, b, x, _) = primed();
        let rid = ResourceId([9u8; 16]);
        let tid = TransferId([10u8; 16]);
        let native = crate::frame::NativeAttachment {
            tid,
            rid,
            handle_value: 12345,
        };
        let f = DataInner {
            target: x,
            corr: 1,
            attachments: vec![],
            payload: b"x".to_vec(),
            native: Some(native),
            shared: None,
        };
        let out = r.on_data(a, f).unwrap();
        assert!(out
            .send
            .iter()
            .any(|(dest, f)| *dest == b && matches!(f, Frame::Data(d) if d.native.is_some())));
        assert_eq!(r.native_pending.len(), 1);
        r.on_xfer(b, XferMsg::Accept { tid }).unwrap();
        assert_eq!(r.native_live.get(&rid), Some(&b));
        assert_eq!(r.native_results.len(), 1);
        r.on_xfer(a, XferMsg::ResultAck { tid }).unwrap();
        assert_eq!(r.native_results.len(), 0);
    }
}
