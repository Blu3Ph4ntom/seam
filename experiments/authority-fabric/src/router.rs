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
use crate::frame::{self, DataInner, Frame};
use crate::id::{fresh_id, EpId};
use crate::id::IdSpace;
use crate::limits::Limits;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PeerId(pub u32);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Holder {
    Peer(PeerId),
    Host,
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

pub struct Router {
    lim: Limits,
    peers: HashMap<PeerId, bool>, // PeerId -> hello_completed
    next_peer_raw: u32,
    eps: HashMap<EpId, EpEntry>,
    retired: HashMap<EpId, Cause>,
    host_events: Vec<HostEvent>,
}

/// State accounting snapshot (test-only introspection; see gate G16).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Accounting {
    pub peers: usize,
    pub live_endpoints: usize,
    pub retired_identities: usize,
    pub host_held: usize,
}

impl Router {
    pub fn new(lim: Limits) -> Self {
        Router {
            lim,
            peers: HashMap::new(),
            next_peer_raw: 0,
            eps: HashMap::new(),
            retired: HashMap::new(),
            host_events: Vec::new(),
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
        }
    }

    fn taken_ids(&self) -> impl IdSpace + '_ {
        struct Both<'a>(&'a HashMap<EpId, EpEntry>, &'a HashMap<EpId, Cause>);
        impl IdSpace for Both<'_> {
            fn contains(&self, v: u64) -> bool {
                self.0.contains_key(&EpId(v)) || self.1.contains_key(&EpId(v))
            }
        }
        Both(&self.eps, &self.retired)
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
        self.eps.insert(a, EpEntry { partner: b, holder, closed: false });
        self.eps.insert(b, EpEntry { partner: a, holder, closed: false });
        (a, b)
    }

    /// Host creates a root pair it holds itself; sides are granted out via
    /// `grant`.
    pub fn create_host_pair(&mut self) -> (EpId, EpId) {
        self.alloc_pair(Holder::Host)
    }

    /// Host hands one previously host-held endpoint to a peer.
    pub fn grant(&mut self, to: PeerId, ep: EpId) -> Result<Frame, Poison> {
        let entry = self
            .eps
            .get_mut(&ep)
            .filter(|e| !e.closed)
            .ok_or(Poison("grant of unknown/closed endpoint"))?;
        if entry.holder != Holder::Host {
            return Err(Poison("grant of endpoint not held by host"));
        }
        entry.holder = Holder::Peer(to);
        let partner = entry.partner;
        Ok(Frame::Grant { ep, partner })
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
        Some((partner, partner_entry))
    }

    fn require_owner(&self, from: PeerId, ep: EpId) -> Result<&EpEntry, Result<(), Poison>> {
        // Ok(entry) => owned & live.
        // Err(Ok(())) => soft-reject (stale known identity): caller drops + notifies.
        // Err(Err(p)) => quarantine.
        match self.eps.get(&ep) {
            None => {
                if self.retired.contains_key(&ep) {
                    Err(Ok(()))
                } else {
                    Err(Err(Poison("unknown endpoint identity")))
                }
            }
            Some(e) if e.closed => Err(Ok(())),
            Some(e) => {
                if e.holder != Holder::Peer(from) {
                    // Held by another peer or by the host: forging/replay.
                    Err(Err(Poison("identity not held by sender")))
                } else {
                    Ok(e)
                }
            }
        }
    }

    pub fn on_hello(&mut self, from: PeerId, magic: u16, version: u16) -> Result<(), Poison> {
        let ready = self.peers.get_mut(&from).ok_or(Poison("hello from unknown peer"))?;
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
    pub fn on_data(&mut self, from: PeerId, mut f: frame::DataInner) -> Result<RouteOutcome, Poison> {
        if !*self.peers.get(&from).ok_or(Poison("frame from unknown peer"))? {
            return Err(Poison("traffic before hello"));
        }
        let target_entry = match self.require_owner(from, f.target) {
            Ok(e) => *e,
            Err(Ok(())) => {
                // Stale-but-known: soft reject with corrective notify.
                let cause = self.retired.get(&f.target).copied().unwrap_or(Cause::Graceful);
                let mut out = RouteOutcome::default();
                out.send.push((
                    from,
                    Frame::ClosedNotify { entries: vec![(f.target, cause)] },
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
                    let cause = self.retired.get(&att.id).copied().unwrap_or(Cause::Graceful);
                    let mut out = RouteOutcome::default();
                    out.send.push((from, Frame::ClosedNotify { entries: vec![(att.id, cause)] }));
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
        // Reassign every attached identity to the message recipient.
        for att in &attachments {
            self.eps.get_mut(&att.id).unwrap().holder = recipient;
        }

        let mut out = RouteOutcome::default();
        match recipient {
            Holder::Peer(dest) => {
                out.send.push((dest, Frame::Data(DataInner {
                    target: f.target,
                    corr: f.corr,
                    attachments,
                    payload: f.payload,
                })));
            }
            Holder::Host => {
                out.to_host.push(HostDelivery {
                    from,
                    target: f.target,
                    corr: f.corr,
                    payload: f.payload,
                });
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
        let partner_entry = *self.eps.get(&entry.partner).ok_or(Poison("broken pairing"))?;
        let mut out = RouteOutcome::default();
        if let Holder::Peer(dest) = partner_entry.holder {
            out.send.push((dest, Frame::Data(DataInner {
                target,
                corr,
                attachments: vec![],
                payload,
            })));
        }
        Ok(out)
    }

    /// Process CLOSE of one end by its current holder.

    pub fn on_close(&mut self, from: PeerId, target: EpId) -> Result<RouteOutcome, Poison> {
        if !*self.peers.get(&from).ok_or(Poison("frame from unknown peer"))? {
            return Err(Poison("traffic before hello"));
        }
        match self.require_owner(from, target) {
            Ok(_) => {}
            Err(Ok(())) => {
                let cause = self.retired.get(&target).copied().unwrap_or(Cause::Graceful);
                let mut out = RouteOutcome::default();
                out.send.push((from, Frame::ClosedNotify { entries: vec![(target, cause)] }));
                return Ok(out);
            }
            Err(Err(p)) => return Err(p),
        }
        let (surviving, partner_entry) = self.close_conversation(target, Cause::Graceful).unwrap();
        let mut out = RouteOutcome::default();
        match partner_entry.holder {
            Holder::Peer(q) => {
                out.send.push((q, Frame::ClosedNotify { entries: vec![(surviving, Cause::Graceful)] }));
            }
            Holder::Host => {
                self.host_events
                    .push(HostEvent::EndpointClosed { ep: surviving, cause: Cause::Graceful });
            }
        }
        Ok(out)
    }

    /// Process CREATE from a peer: allocates an implementation side and a
    /// transferable side, both initially held by the requesting peer.
    pub fn on_create(&mut self, from: PeerId) -> Result<RouteOutcome, Poison> {
        if !*self.peers.get(&from).ok_or(Poison("frame from unknown peer"))? {
            return Err(Poison("traffic before hello"));
        }
        if self.eps.values().filter(|e| !e.closed).count() + 2 > self.lim.max_live_endpoints {
            // Capacity exhaustion is a resource condition, not corruption.
            // Surface as ERROR(code=capacity) to the requester.
            let mut out = RouteOutcome::default();
            out.send.push((from, Frame::Error(crate::frame::ERR_CAPACITY)));
            return Ok(out);
        }
        let (imp, tra) = self.alloc_pair(Holder::Peer(from));
        let mut out = RouteOutcome::default();
        out.send.push((from, Frame::CreateAck { impl_ep: imp, transferable_ep: tra }));
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
        // Collect conversations touching this peer.
        let touched: Vec<EpId> = self
            .eps
            .iter()
            .filter(|(_, e)| !e.closed && e.holder == Holder::Peer(p))
            .map(|(k, _)| *k)
            .collect();
        for side in touched {
            if let Some((surviving, pe)) = self.close_conversation(side, cause) {
                match pe.holder {
                    Holder::Peer(q) => {
                        // q may itself have been removed earlier in this loop;
                        // only notify peers still present.
                        if self.peers.contains_key(&q) && q != p {
                            out.send.push((q, Frame::ClosedNotify {
                                entries: vec![(surviving, cause)],
                            }));
                        }
                    }
                    Holder::Host => {
                        self.host_events.push(HostEvent::EndpointClosed { ep: surviving, cause });
                    }
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
        self.retired.contains_key(&ep)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::{Attachment, DataInner, Frame, ERR_CAPACITY};

    fn hello_ok(r: &mut Router, p: PeerId) {
        r.on_hello(p, Limits::default().hello_magic, Limits::default().hello_version)
            .unwrap();
    }

    /// Two accepted, hello'd peers; root pair granted A=x, B=y.
    fn primed() -> (Router, PeerId, PeerId, EpId, EpId) {
        let mut r = Router::new(Limits::default());
        let a = r.accept_peer();
        let b = r.accept_peer();
        hello_ok(&mut r, a);
        hello_ok(&mut r, b);
        let (x, y) = r.create_host_pair();
        r.grant(a, x).unwrap();
        r.grant(b, y).unwrap();
        (r, a, b, x, y)
    }

    fn data(target: EpId, atts: Vec<Attachment>) -> DataInner {
        DataInner {
            target,
            corr: 1,
            attachments: atts,
            payload: b"x".to_vec(),
        }
    }

    #[test]
    fn unknown_target_quarantines() {
        let (mut r, a, _, _, _) = primed();
        let err = r
            .on_data(a, data(EpId(0x0123_4567_89AB_CDEF), vec![]))
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
            .on_data(
                a,
                data(
                    x,
                    vec![Attachment {
                        id: y,
                        partner: r.partner_of(y).unwrap(),
                    }],
                ),
            )
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
                        id: tra,
                        partner: EpId(imp.0.wrapping_add(1)),
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

        let oc = r
            .on_data(
                a,
                data(x, vec![Attachment { id: tra, partner: imp }]),
            )
            .unwrap();
        assert_eq!(r.holder_of(tra), Some(Holder::Peer(b)));
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

        let err = r
            .on_data(
                a,
                data(x, vec![Attachment { id: tra, partner: imp }]),
            )
            .unwrap_err();
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
        r.grant(a, h1).unwrap();
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
            .on_data(a, data(EpId(1), vec![]))
            .unwrap_err();
        assert_eq!(err, Poison("traffic before hello"));

        hello_ok(&mut r, a);
        let err = r
            .on_hello(a, Limits::default().hello_magic, Limits::default().hello_version)
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
}
