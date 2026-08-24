//! Child-side runtime: connection to the host fabric, move-only endpoint
//! handles, request/reply with correlation, capability receipt and transfer,
//! deterministic failure surfacing.
//!
//! Concurrency model: one reader thread (transport -> state machine), one
//! writer thread (bounded outbound queue -> transport). A single state
//! mutex, never held across blocking IO.

use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::io::{Read, Write};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use crate::fabric_error::{Cause, FabError};
use crate::frame::{
    self, Attachment, DataInner, Frame, FrameError, SharedAttachment, XferMsg, ERR_CAPACITY,
};
use crate::id::{fresh_transfer_id, EpId, TransferId, TransferSpace};
use crate::limits::Limits;
use crate::native::NativeFile;
use crate::queue::{BoundedQueue, PopError};
use crate::shared::{RegionId, Rights, SharedRegion};

/// A message delivered to a locally-implemented endpoint.
#[derive(Debug)]
pub struct Inbound {
    /// The sender's endpoint identity (informational).
    pub from: EpId,
    /// Our own handle that received this message. Replies are sent ON THIS
    /// handle: pair-routing makes that symmetric.
    pub local: EpId,
    pub corr: u32,
    pub payload: Vec<u8>,
    /// Capabilities transferred inside this message. Possessing them IS the
    /// authority; they arrived only because someone transferred them.
    pub received: Vec<Endpoint>,
    pub received_native: Option<NativeFile>,
    /// Shared-memory capability materialized from a committed shared transfer.
    pub received_shared: Option<SharedRegion>,
}

/// Successful call result: response payload plus capabilities transferred
/// back inside the reply.
#[derive(Debug)]
pub struct CallResult {
    pub payload: Vec<u8>,
    pub received: Vec<Endpoint>,
    pub received_native: Option<NativeFile>,
    pub received_shared: Option<SharedRegion>,
}

/// Shared condvar cell used by every wait/slot table.
type WaitCell<T> = Arc<(Mutex<Option<T>>, Condvar)>;
/// Sender-side native hold slot: `None` = committed, `Some` = restored file.
type NativeSlotCell = WaitCell<Option<NativeFile>>;
/// Sender-side shared hold slot: `None` = committed, `Some` = restored region.
type SharedSlotCell = WaitCell<Option<SharedRegion>>;
/// Host-authoritative commit metadata joined with the backing + offer.
type SharedCommitMeta = (RegionId, Rights, u64);
/// Resolved reply cell for an in-flight call.
type ReplyCell = CallCell<Result<CallResult, FabError>>;
/// Status-query cell.
type StatusCell = WaitCell<u8>;
/// Caller wait cell.
pub(crate) type CallCell<T> = WaitCell<T>;

/// A message slot bound to one endpoint id, resolved by the reader thread.
pub(crate) struct WaitSlot {
    pub ep: EpId,
    inner: ReplyCell,
}

impl WaitSlot {
    fn new(ep: EpId) -> Self {
        WaitSlot {
            ep,
            inner: Arc::new((Mutex::new(None), Condvar::new())),
        }
    }
    fn resolve(self, res: Result<CallResult, FabError>) {
        let (m, cv) = &*self.inner;
        *m.lock().unwrap() = Some(res);
        cv.notify_all();
    }
    fn peek(&self) -> ReplyCell {
        self.inner.clone()
    }
}

enum CreateOutcome {
    Done(EpId, EpId),
    Failed(FabError),
}

#[derive(Clone, Copy, Debug)]
enum XferLocal {
    Committed,
    Aborted,
    Unknown,
}

/// Terminal, application-visible result of a transactional transfer.
#[derive(Debug)]
pub enum TransferOutcome {
    /// Authority now belongs to the recipient.
    Committed,
    /// Pre-commit abort: same logical authority restored, returned armed.
    Aborted(Vec<Endpoint>),
    /// Pre-commit abort of a NATIVE resource: restored, returned armed.
    NativeAborted(Vec<NativeFile>),
    /// Pre-commit abort of a SHARED region: same logical authority restored
    /// with exactly the rights it held before staging.
    SharedAborted(Vec<SharedRegion>),
    /// Restoration impossible (peer/runtime gone).
    AuthorityLost(Cause),
}

struct Parked {
    from: EpId,
    local: EpId,
    corr: u32,
    payload: Vec<u8>,
    remaining: std::collections::HashSet<TransferId>,
    got: Vec<Endpoint>,
    is_response: bool,
}

struct HState {
    partner: EpId,
    /// None = live.
    cause: Option<Cause>,
}

struct XferSlot {
    m: Mutex<Option<XferLocal>>,
    cv: Condvar,
    ep: EpId,
    partner: EpId,
}

/// Recipient-side native offer parked until COMMIT.
struct NativeParked {
    target: EpId,
    corr: u32,
    payload: Vec<u8>,
    rid: crate::native::ResourceId,
}

/// Recipient-side shared-region offer parked until COMMIT + backing join.
struct SharedParked {
    target: EpId,
    corr: u32,
    payload: Vec<u8>,
    rid: RegionId,
}

struct State {
    handles: HashMap<EpId, HState>,
    /// their-side id -> our-side handle (receive demux).
    partner_of_theirs: HashMap<EpId, EpId>,
    waiters: HashMap<u32, WaitSlot>,
    create_slot: Option<Arc<(Mutex<Option<CreateOutcome>>, Condvar)>>,
    next_corr: u32,
    terminal: Option<Cause>,
    dropped_after_close: u64,
    /// Grant/attachment arrival order. HashMap iteration is randomized, so
    /// `next_new_handle` would otherwise race which bootstrap grant is
    /// claimed first (root vs. control).
    arrival_order: Vec<EpId>,
    pending_offers: HashMap<TransferId, (EpId, EpId)>,
    xfer_wait: HashMap<TransferId, Arc<XferSlot>>,
    status_wait: HashMap<TransferId, StatusCell>,
    /// Native transfer waiters + source hold (source stays open until the
    /// host confirms staging/commit — no premature close).
    /// Slot value: None => committed; Some(file) => abort-restored file.
    native_wait: HashMap<TransferId, NativeSlotCell>,
    native_hold: HashMap<TransferId, NativeFile>,
    /// Recipient-side native offer parked until COMMIT + fd arrival.
    native_parked: HashMap<TransferId, NativeParked>,
    /// Lane-received kernel objects awaiting COMMIT (order-independent join).
    native_recv: HashMap<TransferId, NativeFile>,
    /// Commit observed but object not yet arrived.
    native_commit_seen: std::collections::HashSet<TransferId>,
    /// Shared-region join state (mirrors the native triple):
    /// parked offer metadata / received backing / observed commit metadata.
    shared_parked: HashMap<TransferId, SharedParked>,
    shared_recv: HashMap<TransferId, std::fs::File>,
    /// Host-authoritative commit metadata: rid/rights/size from SharedCommit.
    shared_commit_meta: HashMap<TransferId, SharedCommitMeta>,
    /// Sender-side hold + wait slot. Slot value: None => committed;
    /// Some(region) => abort-restored capability.
    shared_hold: HashMap<TransferId, SharedRegion>,
    shared_wait: HashMap<TransferId, SharedSlotCell>,
    parked: Vec<Parked>,
}

impl State {
    /// Marks the endpoint failed and wakes its waiters. Returns true if this
    /// call transitioned it.
    fn fail_handle(&mut self, ep: EpId, cause: Cause) -> bool {
        let held = match self.handles.get_mut(&ep) {
            Some(h) if h.cause.is_none() => {
                h.cause = Some(cause);
                true
            }
            _ => false,
        };
        if !held {
            return false;
        }
        let done: Vec<u32> = self
            .waiters
            .iter()
            .filter(|(_, s)| s.ep == ep)
            .map(|(k, _)| *k)
            .collect();
        for k in done {
            if let Some(slot) = self.waiters.remove(&k) {
                slot.resolve(Err(FabError::Closed(cause)));
            }
        }
        true
    }

    fn go_terminal(&mut self, cause: Cause) {
        if self.terminal.is_some() {
            return;
        }
        self.terminal = Some(cause);
        let live: Vec<EpId> = self
            .handles
            .iter()
            .filter(|(_, h)| h.cause.is_none())
            .map(|(k, _)| *k)
            .collect();
        for ep in live {
            self.fail_handle(ep, cause);
        }
    }
}

pub struct RuntimeInner {
    pub lim: Limits,
    st: Mutex<State>,
    out: BoundedQueue<Frame>,
    /// Internally synchronized; deliberately OUTSIDE the state mutex so
    /// consumers block on it without holding the lock.
    inbound: BoundedQueue<Inbound>,
    new_handle: Condvar,
    new_handle_m: Mutex<()>,
    broken: AtomicBool,
    pub sent_frames: AtomicU64,
    pub received_frames: AtomicU64,
    /// Sender-side native resource lane (unix). Set once at startup.
    #[cfg(unix)]
    native_lane: std::sync::Mutex<Option<std::os::unix::net::UnixStream>>,
    #[cfg(unix)]
    self_weak: std::sync::Mutex<std::sync::Weak<RuntimeInner>>,
}

const INBOUND_COST_OVERHEAD: usize = 96;

/// Benchmark-only stage tracing (SEAM_XFER_TRACE=1). Silent otherwise.
fn xfer_trace(stage: &'static str) {
    if std::env::var("SEAM_XFER_TRACE")
        .map(|v| v == "1")
        .unwrap_or(false)
    {
        eprintln!("XFER_TRACE {stage} t={:?}", std::time::SystemTime::now());
    }
}

fn resolve_slot(sl: &XferSlot, v: XferLocal) {
    *sl.m.lock().unwrap() = Some(v);
    sl.cv.notify_all();
}

fn decode_rights_byte(b: u8) -> Option<Rights> {
    match b {
        0 => Some(Rights::ReadOnly),
        1 => Some(Rights::ReadWrite),
        _ => None,
    }
}

fn barrier_wait(name: &str) {
    let Ok(dir) = std::env::var("SEAM_BARRIER_DIR") else {
        return;
    };
    let path = std::path::Path::new(&dir).join(name);
    let go = std::path::Path::new(&dir).join(format!("{name}.go"));
    let _ = std::fs::write(&path, b"1");
    for _ in 0..600 {
        if go.exists() {
            return;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

impl RuntimeInner {
    fn restore_local(self: &Arc<Self>, id: EpId, partner: EpId) -> Option<Endpoint> {
        let mut st = self.st.lock().unwrap();
        if st.terminal.is_some() {
            return None;
        }
        if let Entry::Vacant(e) = st.handles.entry(id) {
            e.insert(HState {
                partner,
                cause: None,
            });
            st.arrival_order.push(id);
        }
        st.partner_of_theirs.insert(partner, id);
        drop(st);
        let _g = self.new_handle_m.lock().unwrap();
        self.new_handle.notify_all();
        Some(Endpoint {
            id,
            shared: self.clone(),
            armed: true,
        })
    }
    fn new_inner(lim: Limits) -> Self {
        RuntimeInner {
            lim: lim.clone(),
            st: Mutex::new(State {
                handles: HashMap::new(),
                partner_of_theirs: HashMap::new(),
                waiters: HashMap::new(),
                create_slot: None,
                next_corr: 0,
                terminal: None,
                dropped_after_close: 0,
                arrival_order: Vec::new(),
                pending_offers: HashMap::new(),
                xfer_wait: HashMap::new(),
                status_wait: HashMap::new(),
                native_wait: HashMap::new(),
                native_hold: HashMap::new(),
                native_parked: HashMap::new(),
                native_recv: HashMap::new(),
                native_commit_seen: std::collections::HashSet::new(),
                shared_parked: HashMap::new(),
                shared_recv: HashMap::new(),
                shared_commit_meta: HashMap::new(),
                shared_hold: HashMap::new(),
                shared_wait: HashMap::new(),
                parked: Vec::new(),
            }),
            out: BoundedQueue::new(lim.queue_max_msgs, lim.queue_max_bytes),
            inbound: BoundedQueue::new(lim.queue_max_msgs, lim.queue_max_bytes),
            new_handle: Condvar::new(),
            new_handle_m: Mutex::new(()),
            broken: AtomicBool::new(false),
            sent_frames: AtomicU64::new(0),
            received_frames: AtomicU64::new(0),
            #[cfg(unix)]
            native_lane: std::sync::Mutex::new(None),
            #[cfg(unix)]
            self_weak: std::sync::Mutex::new(std::sync::Weak::new()),
        }
    }

    /// Same construction as `connect_as_child`, minus handshake and IO threads.
    #[doc(hidden)]
    pub fn __for_tests(lim: Limits) -> Arc<Self> {
        Arc::new(Self::new_inner(lim))
    }

    fn push_out(&self, f: Frame) -> Result<(), FabError> {
        let cost = f.cost();
        match self.out.try_push(f, cost) {
            Ok(()) => {
                self.sent_frames.fetch_add(1, Ordering::Relaxed);
                Ok(())
            }
            Err((_, backlog)) => Err(FabError::Backpressured {
                queued_msgs: backlog.msgs,
                queued_bytes: backlog.bytes,
            }),
        }
    }

    fn poison(&self) {
        // The fabric misbehaved at the framing level; fail closed.
        self.go_terminal_pub(Cause::PeerLost);
    }

    fn finish_parked(self: &Arc<Self>, p: Parked) {
        if p.is_response {
            xfer_trace("recipient_resolved_caller");
            let inner = {
                let mut st = self.st.lock().unwrap();
                st.waiters.remove(&p.corr).map(|s| s.peek())
            };
            let res = Ok(CallResult {
                payload: p.payload,
                received: p.got,
                received_native: None,
                received_shared: None,
            });
            if let Some(inner) = inner {
                let (m, cv) = &*inner;
                *m.lock().unwrap() = Some(res);
                cv.notify_all();
            }
            return;
        }
        let cost = p.payload.len() + INBOUND_COST_OVERHEAD;
        let mut item = Inbound {
            from: p.from,
            local: p.local,
            corr: p.corr,
            payload: p.payload,
            received: p.got,
            received_native: None,
            received_shared: None,
        };
        loop {
            match self.inbound.try_push(item, cost) {
                Ok(()) => return,
                Err((back, _)) => {
                    item = back;
                    if self.broken.load(Ordering::Relaxed) {
                        return;
                    }
                    std::thread::sleep(Duration::from_millis(2));
                }
            }
        }
    }

    /// Join a parked native offer with its arrived kernel object and deliver
    /// to the waiting caller (reply path) or the inbound queue.
    fn complete_native(&self, p: NativeParked, file: NativeFile) {
        let local = {
            let st = self.st.lock().unwrap();
            st.partner_of_theirs
                .get(&p.target)
                .copied()
                .unwrap_or(p.target)
        };
        if p.corr != 0 {
            let slot = {
                let mut st = self.st.lock().unwrap();
                let matches = st
                    .waiters
                    .get(&p.corr)
                    .map(|s| s.ep == local)
                    .unwrap_or(false);
                if matches {
                    st.waiters.remove(&p.corr)
                } else {
                    None
                }
            };
            if let Some(slot) = slot {
                slot.resolve(Ok(CallResult {
                    payload: p.payload,
                    received: vec![],
                    received_native: Some(file),
                    received_shared: None,
                }));
                return;
            }
        }
        let cost = p.payload.len() + INBOUND_COST_OVERHEAD;
        let mut item = Inbound {
            from: EpId([0; 16]),
            local,
            corr: p.corr,
            payload: p.payload,
            received: vec![],
            received_native: Some(file),
            received_shared: None,
        };
        loop {
            match self.inbound.try_push(item, cost) {
                Ok(()) => return,
                Err((back, _)) => {
                    item = back;
                    std::thread::sleep(Duration::from_millis(2));
                }
            }
        }
    }

    /// Join a parked shared-region offer with its arrived backing and the
    /// Host-authoritative commit metadata, then deliver the materialized
    /// `SharedRegion` to the waiting caller or the inbound queue.
    fn complete_shared(
        &self,
        p: SharedParked,
        meta_rid: RegionId,
        rights: Rights,
        size: u64,
        file: std::fs::File,
    ) {
        // Correlation guard: parked offer and commit metadata must agree on
        // the region identity (no "next backing belongs to next commit").
        if meta_rid != p.rid {
            return; // mismatched: backing closes via Drop
        }
        let local = {
            let st = self.st.lock().unwrap();
            st.partner_of_theirs
                .get(&p.target)
                .copied()
                .unwrap_or(p.target)
        };
        let region = SharedRegion::from_backing(meta_rid, rights, size, file);
        if p.corr != 0 {
            let slot = {
                let mut st = self.st.lock().unwrap();
                let matches = st
                    .waiters
                    .get(&p.corr)
                    .map(|s| s.ep == local)
                    .unwrap_or(false);
                if matches {
                    st.waiters.remove(&p.corr)
                } else {
                    None
                }
            };
            if let Some(slot) = slot {
                slot.resolve(Ok(CallResult {
                    payload: p.payload,
                    received: vec![],
                    received_native: None,
                    received_shared: Some(region),
                }));
                return;
            }
        }
        let cost = p.payload.len() + INBOUND_COST_OVERHEAD;
        let mut item = Inbound {
            from: EpId([0; 16]),
            local,
            corr: p.corr,
            payload: p.payload,
            received: vec![],
            received_native: None,
            received_shared: Some(region),
        };
        loop {
            match self.inbound.try_push(item, cost) {
                Ok(()) => return,
                Err((back, _)) => {
                    item = back;
                    std::thread::sleep(Duration::from_millis(2));
                }
            }
        }
    }

    /// Bind this runtime's native resource lane (unix only). Spawns the lane
    /// reader thread; every received descriptor is immediately RAII-wrapped
    /// and joined with parked metadata / commit state (order-independent).
    #[cfg(unix)]
    pub fn install_native_lane(&self, lane: std::os::unix::net::UnixStream) {
        use crate::native::{NativeFile as NF, LANE_KIND_RESTORE};
        // Keep a sender-side clone so reply_with_native can stage over it.
        *self.native_lane.lock().unwrap() = Some(lane.try_clone().expect("lane try_clone"));
        let sh = match self.self_weak.lock().unwrap().upgrade() {
            Some(a) => a,
            None => return,
        };
        std::thread::spawn(move || {
            loop {
                let msg = match crate::native::recv_lane_msg(&lane) {
                    Ok(m) => m,
                    Err(_) => return, // host death or lane close: EOF
                };
                let Some(fd) = msg.fd else { continue }; // malformed: closed inside recv
                                                         // ---- shared-region branch (checked before native) ----
                                                         // LaneMsg.rid is typed ResourceId but carries RegionId bytes
                                                         // for shared transfers ([u8;16] both; tid namespaces disjoint).
                let is_shared_restore = msg.kind == LANE_KIND_RESTORE;
                let mut st0 = sh.st.lock().unwrap();
                let shared_target_restore =
                    is_shared_restore && st0.shared_wait.contains_key(&msg.tid);
                let shared_target_deliver = !is_shared_restore
                    && (st0.shared_parked.contains_key(&msg.tid)
                        || st0.shared_commit_meta.contains_key(&msg.tid));
                if shared_target_restore {
                    let held = st0.shared_hold.remove(&msg.tid);
                    if let Some(held) = held {
                        let region = SharedRegion::from_backing(
                            held.id(),
                            held.rights(),
                            held.size(),
                            std::fs::File::from(fd),
                        );
                        if let Some(slot) = st0.shared_wait.remove(&msg.tid) {
                            let (m, cv) = &*slot;
                            *m.lock().unwrap() = Some(Some(region));
                            cv.notify_all();
                        }
                    }
                    drop(st0);
                    continue;
                }
                if shared_target_deliver {
                    if st0.shared_recv.len() >= sh.lim.max_native_resources {
                        drop(st0); // over capacity: backing closes via Drop
                        continue;
                    }
                    st0.shared_recv.insert(msg.tid, std::fs::File::from(fd));
                    // Join only when ALL THREE parts coexist; never consume a
                    // part we cannot immediately pair (the commit frame may
                    // still be in flight, or vice versa).
                    let ready = st0.shared_parked.contains_key(&msg.tid)
                        && st0.shared_commit_meta.contains_key(&msg.tid);
                    if ready {
                        if let (Some(p), Some((rid, rights, size))) = (
                            st0.shared_parked.remove(&msg.tid),
                            st0.shared_commit_meta.remove(&msg.tid),
                        ) {
                            if let Some(file) = st0.shared_recv.remove(&msg.tid) {
                                drop(st0);
                                sh.complete_shared(p, rid, rights, size, file);
                                continue;
                            }
                        }
                    }
                    drop(st0);
                    continue;
                }
                drop(st0);
                // ---- native branch (unchanged) ----
                let file = NF::restore(msg.rid, std::fs::File::from(fd));
                if msg.kind == LANE_KIND_RESTORE {
                    // Abort restoration: resolve sender wait slot.
                    let mut st = sh.st.lock().unwrap();
                    st.native_hold.remove(&msg.tid);
                    if let Some(slot) = st.native_wait.remove(&msg.tid) {
                        let (m, cv) = &*slot;
                        *m.lock().unwrap() = Some(Some(file));
                        cv.notify_all();
                    }
                    continue;
                }
                // Commit delivery: join with parked metadata / commit flag.
                let mut st = sh.st.lock().unwrap();
                if st.native_recv.len() >= sh.lim.max_native_resources {
                    drop(st); // over capacity: descriptor closes via Drop
                    continue;
                }
                if let Some(p) = st.native_parked.remove(&msg.tid) {
                    drop(st);
                    sh.complete_native(p, file);
                    continue;
                }
                if st.native_commit_seen.contains(&msg.tid) {
                    st.native_commit_seen.remove(&msg.tid);
                    drop(st);
                    // No parked metadata (e.g., late offer loss): object has
                    // no application destination — close it by dropping.
                    drop(file);
                    continue;
                }
                st.native_recv.insert(msg.tid, file);
            }
        });
    }
    fn go_terminal_pub(&self, cause: Cause) {
        {
            let mut st = self.st.lock().unwrap();
            st.go_terminal(cause);
        }
        self.broken.store(true, Ordering::SeqCst);
        self.out.close();
        self.inbound.close();
        let _g = self.new_handle_m.lock().unwrap();
        self.new_handle.notify_all();
    }

    /// Reader-thread entry for every frame arriving from the fabric.
    /// Returns false when the loop must stop.
    fn process(self: &Arc<Self>, f: Frame) -> bool {
        self.received_frames.fetch_add(1, Ordering::Relaxed);
        match f {
            Frame::Hello { .. } | Frame::Close { .. } => {
                // The host never re-handshakes a child, and peers (not the
                // host) emit Close. Either means wire-level confusion.
                self.poison();
                false
            }
            Frame::Grant { ep, partner, tid } => {
                // Offer: do not materialize until COMMIT. Auto-accept if we
                // have capacity; otherwise reject so sender can recover.
                let accept = {
                    let st = self.st.lock().unwrap();
                    st.handles.values().filter(|h| h.cause.is_none()).count()
                        < self.lim.max_live_endpoints
                        && st.terminal.is_none()
                };
                if accept {
                    let _ = self.push_out(Frame::Xfer(XferMsg::Accept { tid }));
                    let mut st = self.st.lock().unwrap();
                    st.pending_offers.insert(tid, (ep, partner));
                } else {
                    let _ = self.push_out(Frame::Xfer(XferMsg::Reject { tid }));
                }
                true
            }
            Frame::Data(d) => {
                self.process_data(d);
                true
            }
            Frame::ClosedNotify { entries } => {
                let mut st = self.st.lock().unwrap();
                for (id, cause) in entries {
                    if st.fail_handle(id, cause) {
                        if let Some(h) = st.handles.get(&id) {
                            let partner = h.partner;
                            st.partner_of_theirs.remove(&partner);
                        }
                    }
                }
                true
            }
            Frame::Create => true,
            Frame::CreateAck {
                impl_ep,
                transferable_ep,
            } => {
                let mut st = self.st.lock().unwrap();
                if let Some(slot) = st.create_slot.take() {
                    let (m, cv) = &*slot;
                    *m.lock().unwrap() = Some(CreateOutcome::Done(impl_ep, transferable_ep));
                    cv.notify_all();
                }
                true
            }
            Frame::Error(code) => {
                let mut st = self.st.lock().unwrap();
                if let Some(slot) = st.create_slot.take() {
                    let err = match code {
                        ERR_CAPACITY => FabError::Backpressured {
                            queued_msgs: 0,
                            queued_bytes: 0,
                        },
                        _ => FabError::ProtocolViolation("unknown error code"),
                    };
                    let (m, cv) = &*slot;
                    *m.lock().unwrap() = Some(CreateOutcome::Failed(err));
                    cv.notify_all();
                }
                true
            }
            Frame::Shutdown => {
                self.go_terminal_pub(Cause::Graceful);
                false
            }
            Frame::Xfer(x) => self.process_xfer(x),
        }
    }

    fn process_xfer(self: &Arc<Self>, x: XferMsg) -> bool {
        match x {
            XferMsg::Commit { tid, ep, partner } => {
                xfer_trace("recipient_commit_received");
                let mut ready: Vec<Parked> = Vec::new();
                let mut ack = false;
                {
                    let mut st = self.st.lock().unwrap();
                    st.pending_offers.remove(&tid);
                    if let Entry::Vacant(e) = st.handles.entry(ep) {
                        e.insert(HState {
                            partner,
                            cause: None,
                        });
                        st.arrival_order.push(ep);
                    }
                    st.partner_of_theirs.insert(partner, ep);
                    if let Some(slot) = st.xfer_wait.remove(&tid) {
                        resolve_slot(&slot, XferLocal::Committed);
                        ack = true;
                    }
                    for p in &mut st.parked {
                        if p.remaining.remove(&tid) {
                            p.got.push(Endpoint {
                                id: ep,
                                shared: self.clone(),
                                armed: true,
                            });
                        }
                    }
                    let mut i = 0;
                    while i < st.parked.len() {
                        if st.parked[i].remaining.is_empty() {
                            ready.push(st.parked.remove(i));
                        } else {
                            i += 1;
                        }
                    }
                }
                let _g = self.new_handle_m.lock().unwrap();
                self.new_handle.notify_all();
                for p in ready {
                    self.finish_parked(p);
                }
                // Host committed to us: acknowledge so it can retire the result.
                let _ = self.push_out(Frame::Xfer(XferMsg::ResultAck { tid }));
                let _ = ack;
                true
            }
            XferMsg::Committed { tid } => {
                let ack = {
                    let mut st = self.st.lock().unwrap();
                    if let Some(slot) = st.xfer_wait.remove(&tid) {
                        resolve_slot(&slot, XferLocal::Committed);
                        true
                    } else {
                        false
                    }
                };
                // Native: source authority may now be released (commit done).
                {
                    let mut st = self.st.lock().unwrap();
                    st.native_hold.remove(&tid);
                    if let Some(slot) = st.native_wait.remove(&tid) {
                        let (m, cv) = &*slot;
                        *m.lock().unwrap() = Some(None);
                        cv.notify_all();
                        drop(st);
                        let _ = self.push_out(Frame::Xfer(XferMsg::ResultAck { tid }));
                        return true;
                    }
                    // Shared: same release semantics for the staged source.
                    st.shared_hold.remove(&tid);
                    if let Some(slot) = st.shared_wait.remove(&tid) {
                        let (m, cv) = &*slot;
                        *m.lock().unwrap() = Some(None);
                        cv.notify_all();
                        drop(st);
                        let _ = self.push_out(Frame::Xfer(XferMsg::ResultAck { tid }));
                        return true;
                    }
                }
                if ack {
                    let _ = self.push_out(Frame::Xfer(XferMsg::ResultAck { tid }));
                }
                true
            }
            XferMsg::Abort { tid } => {
                let mut ack = false;
                let mut fail_waiters: Vec<u32> = Vec::new();
                {
                    let mut st = self.st.lock().unwrap();
                    st.pending_offers.remove(&tid);
                    // Aborted transaction: any parked offer metadata and any
                    // already-arrived backing must die together. A late lane
                    // delivery after this point finds no join state and its
                    // kernel object closes via Drop (T6).
                    if let Some(_p) = st.shared_parked.remove(&tid) {
                        let _file = st.shared_recv.remove(&tid);
                        st.shared_commit_meta.remove(&tid);
                    }
                    if st.native_parked.remove(&tid).is_some() {
                        let _file = st.native_recv.remove(&tid);
                        st.native_commit_seen.remove(&tid);
                    }
                    if let Some(slot) = st.xfer_wait.remove(&tid) {
                        resolve_slot(&slot, XferLocal::Aborted);
                        ack = true;
                    }
                    let mut i = 0;
                    while i < st.parked.len() {
                        if st.parked[i].remaining.remove(&tid) && st.parked[i].remaining.is_empty()
                        {
                            let p = st.parked.remove(i);
                            if p.is_response {
                                fail_waiters.push(p.corr);
                            }
                        } else {
                            i += 1;
                        }
                    }
                }
                for corr in fail_waiters {
                    let inner = {
                        let mut st = self.st.lock().unwrap();
                        st.waiters.remove(&corr).map(|s| s.peek())
                    };
                    if let Some(inner) = inner {
                        let (m, cv) = &*inner;
                        *m.lock().unwrap() =
                            Some(Err(FabError::TransferAborted("recipient rejected")));
                        cv.notify_all();
                    }
                }
                if ack {
                    let _ = self.push_out(Frame::Xfer(XferMsg::ResultAck { tid }));
                }
                true
            }
            XferMsg::StatusAck { tid, status } => {
                let mut st = self.st.lock().unwrap();
                if let Some(slot) = st.xfer_wait.remove(&tid) {
                    match status {
                        frame::XFER_ST_COMMITTED => resolve_slot(&slot, XferLocal::Committed),
                        frame::XFER_ST_ABORTED => resolve_slot(&slot, XferLocal::Aborted),
                        _ => {}
                    }
                }
                if let Some(sw) = st.status_wait.remove(&tid) {
                    *sw.0.lock().unwrap() = Some(status);
                    sw.1.notify_all();
                }
                true
            }
            XferMsg::NativeCommit {
                tid,
                rid,
                handle_value,
            } => {
                // Commit observed. The kernel object may arrive via lane
                // (unix) before or after this frame; join order-independently.
                let mut st = self.st.lock().unwrap();
                #[cfg(windows)]
                {
                    // Windows carries the duplicated value inline; materialize now.
                    let file = crate::native::windows::handle_to_file(handle_value);
                    st.native_recv.insert(tid, NativeFile::restore(rid, file));
                }
                #[cfg(not(windows))]
                {
                    let _ = (rid, handle_value);
                }
                st.native_commit_seen.insert(tid);
                if let Some(file) = st.native_recv.remove(&tid) {
                    if let Some(p) = st.native_parked.remove(&tid) {
                        drop(st);
                        // Correlation guard: parked offer and commit must
                        // agree on the resource identity; a mismatched pair
                        // closes the backing instead of minting authority.
                        if p.rid == rid {
                            self.complete_native(p, file);
                        }
                        return true;
                    }
                }
                true
            }
            XferMsg::NativeAbort {
                tid,
                rid,
                handle_value,
            } => {
                // Restoration (windows inline value; unix arrives via lane fd).
                #[cfg(windows)]
                {
                    let file = crate::native::windows::handle_to_file(handle_value);
                    let nf = NativeFile::restore(rid, file);
                    let mut st = self.st.lock().unwrap();
                    st.native_hold.remove(&tid); // old source closes here
                    if let Some(slot) = st.native_wait.remove(&tid) {
                        let (m, cv) = &*slot;
                        *m.lock().unwrap() = Some(Some(nf));
                        cv.notify_all();
                    }
                }
                #[cfg(not(windows))]
                {
                    let _ = (&tid, &rid, &handle_value);
                }
                true
            }
            XferMsg::ResultAck { .. } => true,
            XferMsg::Accept { .. } | XferMsg::Reject { .. } | XferMsg::Status { .. } => true,
            XferMsg::SharedCommit {
                tid,
                rid,
                rights,
                size,
                handle_value,
            } => {
                // Commit observed. Host-authoritative rights/size arrive here;
                // the kernel object arrives inline (Windows) or via the lane
                // (Linux). Join order-independently with the parked offer.
                let Some(rights) = decode_rights_byte(rights) else {
                    return true; // malformed: no authority is minted
                };
                let mut st = self.st.lock().unwrap();
                st.shared_commit_meta.insert(tid, (rid, rights, size));
                #[cfg(windows)]
                {
                    if handle_value != 0 {
                        // SAFETY boundary lives in native::windows::handle_to_file:
                        // sole ownership of a just-delivered target-valid HANDLE.
                        let file = crate::native::windows::handle_to_file(handle_value);
                        st.shared_recv.insert(tid, file);
                    }
                }
                if let Some(file) = st.shared_recv.remove(&tid) {
                    if let Some(p) = st.shared_parked.remove(&tid) {
                        drop(st);
                        self.complete_shared(p, rid, rights, size, file);
                        // Host committed to us: acknowledge so it can retire
                        // the retained result.
                        let _ = self.push_out(Frame::Xfer(XferMsg::ResultAck { tid }));
                        return true;
                    }
                }
                true
            }
            XferMsg::SharedAbort {
                tid,
                rid: _,
                handle_value,
            } => {
                // Restoration to sender. Rights/size come from the held
                // original (abort must never change rights).
                #[cfg(windows)]
                {
                    let mut st = self.st.lock().unwrap();
                    let held = st.shared_hold.remove(&tid);
                    if let Some(held) = held {
                        let (rid0, rights0, size0) = (held.id(), held.rights(), held.size());
                        let _ = held.into_backing(); // old wrapper closes
                        let file = crate::native::windows::handle_to_file(handle_value);
                        let restored = SharedRegion::from_backing(rid0, rights0, size0, file);
                        if let Some(slot) = st.shared_wait.remove(&tid) {
                            let (m, cv) = &*slot;
                            *m.lock().unwrap() = Some(Some(restored));
                            cv.notify_all();
                        } else {
                            drop(restored); // nobody waiting: capability closes
                        }
                    }
                }
                #[cfg(not(windows))]
                {
                    let _ = (&tid, &handle_value); // fd arrives via lane RESTORE
                }
                // Sender observed the terminal outcome: acknowledge so the
                // Host can retire the retained result (idempotent).
                let _ = self.push_out(Frame::Xfer(XferMsg::ResultAck { tid }));
                true
            }
        }
    }

    fn process_data(self: &Arc<Self>, d: DataInner) {
        // Shared-region OFFER: accept, park metadata until commit+backing join.
        if let Some(s) = d.shared.clone() {
            // Deterministic fault injection: park BEFORE accepting so a
            // supervisor can kill this process pre-accept (D6).
            if std::env::var("SEAM_PAUSE_SHARED_ACCEPT")
                .map(|v| v == "1")
                .unwrap_or(false)
            {
                let dir = std::env::var("SEAM_BARRIER_DIR").unwrap_or_default();
                let p = std::path::Path::new(&dir).join("peer_before_accept");
                let g = std::path::Path::new(&dir).join("peer_before_accept.go");
                let _ = std::fs::write(&p, b"1");
                // Long window: this gate exists to be killed at.
                for _ in 0..3000 {
                    if g.exists() || self.broken.load(Ordering::SeqCst) {
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
                if self.broken.load(Ordering::SeqCst) {
                    return;
                }
            }
            // Hostile/capacity drill: reject instead of accept.
            let reject_shared = std::env::var("SEAM_CLI_REJECT_SHARED")
                .map(|v| v == "1")
                .unwrap_or(false);
            if reject_shared {
                let _ = self.push_out(Frame::Xfer(XferMsg::Reject { tid: s.tid }));
                return;
            }
            let _ = self.push_out(Frame::Xfer(XferMsg::Accept { tid: s.tid }));
            let mut st = self.st.lock().unwrap();
            st.shared_parked.insert(
                s.tid,
                SharedParked {
                    target: d.target,
                    corr: d.corr,
                    payload: d.payload,
                    rid: s.rid,
                },
            );
            return;
        }
        // Native OFFER: accept, park metadata until commit+kernel-object join.
        if let Some(n) = d.native.clone() {
            // Hostile/capacity drill: reject instead of accept.
            let reject_native = std::env::var("SEAM_CLI_REJECT_NATIVE")
                .map(|v| v == "1")
                .unwrap_or(false);
            if reject_native {
                let _ = self.push_out(Frame::Xfer(XferMsg::Reject { tid: n.tid }));
                return;
            }
            let _ = self.push_out(Frame::Xfer(XferMsg::Accept { tid: n.tid }));
            let mut st = self.st.lock().unwrap();
            st.native_parked.insert(
                n.tid,
                NativeParked {
                    target: d.target,
                    corr: d.corr,
                    payload: d.payload,
                    rid: n.rid,
                },
            );
            return;
        }
        // Attachments are offers: ACCEPT if we have capacity, then wait for
        // COMMIT before the handle becomes usable.
        if !d.attachments.is_empty() {
            xfer_trace("recipient_offer_received");
            // Test-only barrier: pause before ACCEPT so supervisor can kill at known point.
            if std::env::var("SEAM_BARRIER_OFFER")
                .map(|v| v == "1")
                .unwrap_or(false)
            {
                barrier_wait("peer_at_offer");
                if self.broken.load(Ordering::SeqCst) {
                    return;
                }
            }
            let cap_ok = {
                let st = self.st.lock().unwrap();
                st.handles.values().filter(|h| h.cause.is_none()).count() + d.attachments.len()
                    <= self.lim.max_live_endpoints
                    && st.terminal.is_none()
            };
            if !cap_ok {
                for att in &d.attachments {
                    let _ = self.push_out(Frame::Xfer(XferMsg::Reject { tid: att.tid }));
                }
                // If this Data was a response to a waiting call, fail it
                // explicitly instead of leaving it to timeout.
                let mut st = self.st.lock().unwrap();
                let is_response = d.corr != 0
                    && st
                        .waiters
                        .get(&d.corr)
                        .map(|s| {
                            st.partner_of_theirs
                                .get(&d.target)
                                .copied()
                                .map(|local| s.ep == local)
                                .unwrap_or(false)
                        })
                        .unwrap_or(false);
                if is_response {
                    if let Some(slot) = st.waiters.remove(&d.corr) {
                        drop(st);
                        let inner = slot.peek();
                        let (m, cv) = &*inner;
                        *m.lock().unwrap() =
                            Some(Err(FabError::TransferAborted("recipient at capacity")));
                        cv.notify_all();
                    }
                }
                return;
            }
            let mut remaining = std::collections::HashSet::new();
            for att in &d.attachments {
                remaining.insert(att.tid);
                let _ = self.push_out(Frame::Xfer(XferMsg::Accept { tid: att.tid }));
            }
            let mut st = self.st.lock().unwrap();
            let is_response = d.corr != 0
                && st
                    .waiters
                    .get(&d.corr)
                    .map(|s| {
                        st.partner_of_theirs
                            .get(&d.target)
                            .copied()
                            .map(|local| s.ep == local)
                            .unwrap_or(false)
                    })
                    .unwrap_or(false);
            let Some(local) = st.partner_of_theirs.get(&d.target).copied() else {
                st.dropped_after_close += 1;
                return;
            };
            st.parked.push(Parked {
                from: d.target,
                local,
                corr: d.corr,
                payload: d.payload,
                remaining,
                got: Vec::new(),
                is_response,
            });
            return;
        }

        enum Next {
            Deliver(EpId),
            Respond(EpId),
        }
        let next = {
            let mut st = self.st.lock().unwrap();
            let Some(local) = st.partner_of_theirs.get(&d.target).copied() else {
                st.dropped_after_close += 1;
                return;
            };
            if st.handles.get(&local).and_then(|h| h.cause).is_some() {
                // Message raced past closure notification: counted, never
                // treated as success anywhere.
                st.dropped_after_close += 1;
                return;
            }
            if d.corr != 0 {
                let is_response = st
                    .waiters
                    .get(&d.corr)
                    .map(|s| s.ep == local)
                    .unwrap_or(false);
                if is_response {
                    Next::Respond(local)
                } else {
                    Next::Deliver(local)
                }
            } else {
                Next::Deliver(local)
            }
        };

        match next {
            Next::Respond(local) => {
                let received = d
                    .attachments
                    .iter()
                    .map(|a| Endpoint {
                        id: a.id,
                        shared: self.clone(),
                        armed: true,
                    })
                    .collect();
                let received_native = d.native.map(|n| {
                    let file = {
                        #[cfg(windows)]
                        {
                            if n.handle_value != 0 {
                                crate::native::windows::handle_to_file(n.handle_value)
                            } else {
                                std::fs::File::create(std::env::temp_dir().join("dummy_recv"))
                                    .unwrap()
                            }
                        }
                        #[cfg(unix)]
                        {
                            std::fs::File::create(std::env::temp_dir().join("dummy_recv")).unwrap()
                        }
                        #[cfg(not(any(windows, unix)))]
                        {
                            std::fs::File::create(std::env::temp_dir().join("dummy_recv")).unwrap()
                        }
                    };
                    NativeFile::restore(n.rid, file)
                });
                let inner = {
                    let mut st = self.st.lock().unwrap();
                    st.waiters.remove(&d.corr).map(|s| s.peek())
                };
                let res = Ok(CallResult {
                    payload: d.payload,
                    received,
                    received_native,
                    received_shared: None,
                });
                match inner {
                    Some(inner) => {
                        let (m, cv) = &*inner;
                        *m.lock().unwrap() = Some(res);
                        cv.notify_all();
                    }
                    None => {
                        // Late response after caller timeout: count it.
                        let mut st = self.st.lock().unwrap();
                        st.dropped_after_close += 1;
                        let _ = local;
                    }
                }
            }
            Next::Deliver(local) => {
                let received = d
                    .attachments
                    .iter()
                    .map(|a| Endpoint {
                        id: a.id,
                        shared: self.clone(),
                        armed: true,
                    })
                    .collect();
                let received_native = d.native.map(|n| {
                    let file = {
                        #[cfg(windows)]
                        {
                            if n.handle_value != 0 {
                                crate::native::windows::handle_to_file(n.handle_value)
                            } else {
                                std::fs::File::create(std::env::temp_dir().join("dummy_recv"))
                                    .unwrap()
                            }
                        }
                        #[cfg(unix)]
                        {
                            std::fs::File::create(std::env::temp_dir().join("dummy_recv")).unwrap()
                        }
                        #[cfg(not(any(windows, unix)))]
                        {
                            std::fs::File::create(std::env::temp_dir().join("dummy_recv")).unwrap()
                        }
                    };
                    NativeFile::restore(n.rid, file)
                });
                let cost = d.payload.len() + INBOUND_COST_OVERHEAD;
                let mut item = Inbound {
                    from: d.target,
                    local,
                    corr: d.corr,
                    payload: d.payload,
                    received,
                    received_native,
                    received_shared: None,
                };
                // Backpressure: retry WITHOUT holding the state lock; bounded
                // forever because the fabric eventually goes terminal.
                loop {
                    match self.inbound.try_push(item, cost) {
                        Ok(()) => return,
                        Err((back, _bl)) => {
                            item = back;
                            let dead = {
                                let st = self.st.lock().unwrap();
                                st.terminal.is_some()
                            } || self.broken.load(Ordering::Relaxed);
                            if dead {
                                let mut st = self.st.lock().unwrap();
                                st.dropped_after_close += 1;
                                return;
                            }
                            std::thread::sleep(Duration::from_millis(2));
                        }
                    }
                }
            }
        }
    }
}

/// Move-only authority handle. Deliberately NOT Clone/Copy: transferring or
/// closing consumes it (invariants I3/I4). The internal identity is private
/// and validated on every use. Dropping the last armed handle closes it.
pub struct Endpoint {
    id: EpId,
    shared: Arc<RuntimeInner>,
    /// When false, Drop must not emit Close (already transferred/closed).
    armed: bool,
}

impl std::fmt::Debug for Endpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Endpoint").field("id", &self.id.0).finish()
    }
}

impl Endpoint {
    /// Test-only constructor. Not an authority source.
    #[doc(hidden)]
    pub fn __unchecked(id: EpId, shared: Arc<RuntimeInner>) -> Self {
        Endpoint {
            id,
            shared,
            armed: true,
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }

    pub fn id(&self) -> EpId {
        self.id
    }

    /// Invoke the remote side. Blocks until reply, closure, or timeout.
    pub fn call(&self, payload: Vec<u8>, timeout: Duration) -> Result<CallResult, FabError> {
        let deadline = Instant::now() + timeout;
        let (corr, slot) = {
            let mut st = self.shared.st.lock().unwrap();
            if let Some(c) = st.handles.get(&self.id).and_then(|h| h.cause) {
                return Err(FabError::Closed(c));
            }
            if st.terminal.is_some() {
                return Err(FabError::FabricLost);
            }
            if st.waiters.len() >= self.shared.lim.max_outstanding_requests {
                return Err(FabError::Backpressured {
                    queued_msgs: st.waiters.len(),
                    queued_bytes: 0,
                });
            }
            st.next_corr += 1;
            let corr = st.next_corr;
            let slot = WaitSlot::new(self.id);
            st.waiters.insert(corr, slot);
            (corr, st.waiters.get(&corr).unwrap().peek())
        };

        self.shared
            .push_out(Frame::Data(DataInner {
                target: self.id,
                corr,
                attachments: vec![],
                payload,
                native: None,
                shared: None,
            }))
            .inspect_err(|_e| {
                let mut st = self.shared.st.lock().unwrap();
                st.waiters.remove(&corr);
            })?;

        let (m, cv) = &*slot;
        let mut g = m.lock().unwrap();
        loop {
            if let Some(res) = g.take() {
                let mut st = self.shared.st.lock().unwrap();
                st.waiters.remove(&corr);
                return res;
            }
            let now = Instant::now();
            if now >= deadline {
                let mut st = self.shared.st.lock().unwrap();
                st.waiters.remove(&corr);
                return Err(FabError::Timeout);
            }
            let (ng, _) = cv.wait_timeout(g, deadline - now).unwrap();
            g = ng;
        }
    }

    /// Call with native resource attachment (experimental).
    pub fn call_with_native(
        &self,
        payload: Vec<u8>,
        native: NativeFile,
        timeout: Duration,
    ) -> Result<CallResult, FabError> {
        // For now, delegate to normal call; real native FD/HANDLE passing is via host escrow
        // The NativeFile's handle_value will be sent in Data's native attachment with tid/rid
        let _ = native;
        self.call(payload, timeout)
    }

    /// Destroy this end deliberately. Consumes the authority.
    pub fn close(mut self) -> Result<(), FabError> {
        self.armed = false;
        self.release()
    }

    fn release(&self) -> Result<(), FabError> {
        xfer_trace("endpoint_release_emit");
        let res = self.shared.push_out(Frame::Close { target: self.id });
        let mut st = self.shared.st.lock().unwrap();
        st.fail_handle(self.id, Cause::Graceful);
        if let Some(h) = st.handles.get(&self.id) {
            let partner = h.partner;
            st.partner_of_theirs.remove(&partner);
        }
        res
    }
}

impl Drop for Endpoint {
    fn drop(&mut self) {
        if self.armed {
            self.armed = false;
            let _ = self.release();
        }
    }
}

fn reader_loop<R: Read>(sh: Arc<RuntimeInner>, mut rx: R, lim: Limits) {
    loop {
        if sh.broken.load(Ordering::SeqCst) {
            break;
        }
        match frame::read_frame(&mut rx, &lim) {
            Ok(f) => {
                if !sh.process(f) {
                    break;
                }
            }
            Err(FrameError::TooLarge { .. }) => {
                sh.poison();
                break;
            }
            Err(_) => {
                // Truncated / IO error: transport gone (host death shows up
                // here as EOF).
                sh.go_terminal_pub(Cause::PeerLost);
                break;
            }
        }
    }
}

fn writer_loop<W: Write>(sh: Arc<RuntimeInner>, mut tx: W) {
    loop {
        if sh.broken.load(Ordering::SeqCst) {
            break;
        }
        // Wake-driven: block until work or close. No periodic timer.
        match sh.out.pop_block() {
            Some(f) => {
                let mut buf = Vec::with_capacity(f.cost());
                frame::encode_into(&f, &mut buf);
                if tx.write_all(&buf).and_then(|_| tx.flush()).is_err() {
                    sh.go_terminal_pub(Cause::PeerLost);
                    break;
                }
            }
            None => break,
        }
    }
}

/// Test/demo introspection snapshot.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PeerAccounting {
    pub live_handles: usize,
    pub inbound_backlog_msgs: usize,
    pub dropped_after_close: u64,
    pub sent_frames: u64,
    pub received_frames: u64,
    pub terminal: bool,
}

pub struct Runtime {
    shared: Arc<RuntimeInner>,
    lim: Limits,
}

impl Runtime {
    /// Connect as a child over an established byte-stream channel (e.g., the
    /// stdin/stdout pipes a parent spawned us with). Performs the handshake
    /// synchronously, then starts IO threads.
    pub fn connect_as_child<R, W>(rx: R, mut tx: W, lim: Limits) -> std::io::Result<Runtime>
    where
        R: Read + Send + 'static,
        W: Write + Send + 'static,
    {
        let hello = Frame::Hello {
            magic: lim.hello_magic,
            version: lim.hello_version,
        };
        let mut buf = Vec::with_capacity(hello.cost());
        frame::encode_into(&hello, &mut buf);
        tx.write_all(&buf)?;
        tx.flush()?;

        let shared = Arc::new(RuntimeInner::new_inner(lim.clone()));
        #[cfg(unix)]
        {
            *shared.self_weak.lock().unwrap() = Arc::downgrade(&shared);
        }

        {
            let sh = shared.clone();
            let lim2 = lim.clone();
            std::thread::spawn(move || reader_loop(sh, rx, lim2));
        }
        {
            let sh = shared.clone();
            std::thread::spawn(move || writer_loop(sh, tx));
        }

        Ok(Runtime { shared, lim })
    }

    pub fn limits(&self) -> &Limits {
        &self.lim
    }

    /// Bind this runtime's native resource lane (unix). See RuntimeInner.
    #[cfg(unix)]
    pub fn install_native_lane(&self, lane: std::os::unix::net::UnixStream) {
        self.shared.install_native_lane(lane);
    }
    /// Blocks until a message arrives on any locally-implemented endpoint.
    pub fn wait_inbound(&self, timeout: Duration) -> Result<Inbound, FabError> {
        match self.shared.inbound.pop_deadline(Instant::now() + timeout) {
            Ok(item) => Ok(item),
            Err(PopError::Closed) => Err(FabError::FabricLost),
            Err(PopError::Timeout) => Err(FabError::Timeout),
        }
    }

    /// Reply to a request ON THE HANDLE THAT RECEIVED IT (pair-routing makes
    /// this symmetric). Consumes any capabilities attached to the reply:
    /// after this call the sender no longer holds them (I4).
    /// Returns the terminal outcome: Committed, or Aborted with restored endpoints.
    pub fn reply(
        &self,
        req: &Inbound,
        payload: Vec<u8>,
        caps: Vec<Endpoint>,
    ) -> Result<TransferOutcome, FabError> {
        struct EmptyTid;
        impl TransferSpace for EmptyTid {
            fn contains(&self, _id: TransferId) -> bool {
                false
            }
        }
        if caps.is_empty() {
            self.shared.push_out(Frame::Data(DataInner {
                target: req.local,
                corr: req.corr,
                attachments: vec![],
                payload,
                native: None,
                shared: None,
            }))?;
            return Ok(TransferOutcome::Committed);
        }
        let mut attachments = Vec::with_capacity(caps.len());
        let mut waiters: Vec<(TransferId, Arc<XferSlot>)> = Vec::new();
        {
            let mut st = self.shared.st.lock().unwrap();
            for mut cap in caps {
                if let Some(c) = st.handles.get(&cap.id).and_then(|h| h.cause) {
                    return Err(FabError::Closed(c));
                }
                let partner = st.handles.get(&cap.id).unwrap().partner;
                let tid = fresh_transfer_id(&EmptyTid);
                let slot = Arc::new(XferSlot {
                    m: Mutex::new(None),
                    cv: Condvar::new(),
                    ep: cap.id,
                    partner,
                });
                st.xfer_wait.insert(tid, slot.clone());
                attachments.push(Attachment {
                    tid,
                    id: cap.id,
                    partner,
                });
                st.handles.remove(&cap.id);
                cap.disarm();
                waiters.push((tid, slot));
            }
        }
        self.shared.push_out(Frame::Data(DataInner {
            target: req.local,
            corr: req.corr,
            attachments,
            payload,
            native: None,
            shared: None,
        }))?;
        xfer_trace("sender_reply_emitted");
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut aborted: Vec<Endpoint> = Vec::new();
        for (tid, slot) in waiters {
            let outcome = loop {
                {
                    let g = slot.m.lock().unwrap();
                    if let Some(v) = *g {
                        break v;
                    }
                }
                let now = Instant::now();
                if now >= deadline {
                    match self.transfer_status(tid, Duration::from_secs(2)) {
                        Ok(frame::XFER_ST_COMMITTED) => break XferLocal::Committed,
                        Ok(frame::XFER_ST_ABORTED) => break XferLocal::Aborted,
                        Ok(frame::XFER_ST_PENDING) => {
                            std::thread::sleep(Duration::from_millis(50));
                            continue;
                        }
                        _ => break XferLocal::Unknown,
                    }
                }
                let g = slot.m.lock().unwrap();
                let (ng, _) = slot.cv.wait_timeout(g, deadline - now).unwrap();
                drop(ng);
            };
            match outcome {
                XferLocal::Committed => {
                    xfer_trace("sender_saw_committed");
                    let _ = self
                        .shared
                        .push_out(Frame::Xfer(XferMsg::ResultAck { tid }));
                }
                XferLocal::Aborted => {
                    if let Some(ep) = self.shared.restore_local(slot.ep, slot.partner) {
                        aborted.push(ep);
                    } else {
                        return Ok(TransferOutcome::AuthorityLost(Cause::Graceful));
                    }
                    let _ = self
                        .shared
                        .push_out(Frame::Xfer(XferMsg::ResultAck { tid }));
                }
                XferLocal::Unknown => match self.transfer_status(tid, Duration::from_secs(2)) {
                    Ok(frame::XFER_ST_COMMITTED) => {
                        let _ = self
                            .shared
                            .push_out(Frame::Xfer(XferMsg::ResultAck { tid }));
                    }
                    Ok(frame::XFER_ST_ABORTED) => {
                        if let Some(ep) = self.shared.restore_local(slot.ep, slot.partner) {
                            aborted.push(ep);
                        } else {
                            return Ok(TransferOutcome::AuthorityLost(Cause::Graceful));
                        }
                        let _ = self
                            .shared
                            .push_out(Frame::Xfer(XferMsg::ResultAck { tid }));
                    }
                    _ => return Err(FabError::TransferUnknown),
                },
            }
        }
        if aborted.is_empty() {
            Ok(TransferOutcome::Committed)
        } else {
            Ok(TransferOutcome::Aborted(aborted))
        }
    }

    pub fn reply_with_native(
        &self,
        req: &Inbound,
        payload: Vec<u8>,
        native: Option<NativeFile>,
    ) -> Result<TransferOutcome, FabError> {
        if let Some(mut nf) = native {
            struct Empty;
            impl TransferSpace for Empty {
                fn contains(&self, _: TransferId) -> bool {
                    false
                }
            }
            let tid = fresh_transfer_id(&Empty);
            let rid = nf.id();
            #[cfg(windows)]
            let handle_value = {
                use std::os::windows::io::AsRawHandle;
                nf.file().as_raw_handle() as u64
            };
            #[cfg(not(windows))]
            let handle_value = 0u64;
            // Unix: send the real descriptor over our lane BEFORE the control
            // frame so the host's blocking stage read is deterministic. Host
            // validates tid/rid against the metadata it then receives.
            // Sender source stays open (N3): we only dup it via SCM_RIGHTS.
            #[cfg(unix)]
            {
                let lane_opt = self.shared.native_lane.lock().unwrap();
                if let Some(lane) = lane_opt.as_ref() {
                    if let Err(e) = crate::native::unix::send_lane_msg(
                        lane,
                        crate::native::LANE_KIND_STAGE,
                        tid,
                        rid,
                        nf.file(),
                    ) {
                        eprintln!("SEAM lane stage failed: {e}");
                        return Err(FabError::TransferUnknown);
                    }
                } else {
                    eprintln!("SEAM no native lane installed");
                    return Err(FabError::TransferUnknown);
                }
            }
            // Keep source alive until host confirms staging/commit (G41).
            let slot = Arc::new((Mutex::new(None::<Option<NativeFile>>), Condvar::new()));
            {
                let mut st = self.shared.st.lock().unwrap();
                if st.terminal.is_some() {
                    return Err(FabError::FabricLost);
                }
                st.native_hold.insert(tid, nf);
                st.native_wait.insert(tid, slot.clone());
            }
            let att = crate::frame::NativeAttachment {
                tid,
                rid,
                handle_value,
            };
            let pushed = self.shared.push_out(Frame::Data(DataInner {
                target: req.local,
                corr: req.corr,
                attachments: vec![],
                payload,
                native: Some(att),
                shared: None,
            }));
            if let Err(e) = pushed {
                let mut st = self.shared.st.lock().unwrap();
                st.native_hold.remove(&tid);
                st.native_wait.remove(&tid);
                return Err(e);
            }
            let deadline = Instant::now() + Duration::from_secs(10);
            let (m, cv) = &*slot;
            let mut g = m.lock().unwrap();
            let outcome = loop {
                if let Some(v) = g.take() {
                    break v;
                }
                let now = Instant::now();
                if now >= deadline {
                    match self.transfer_status(tid, Duration::from_secs(2)) {
                        Ok(frame::XFER_ST_COMMITTED) => break None,
                        _ => break None,
                    }
                }
                let (ng, _) = cv.wait_timeout(g, deadline - now).unwrap();
                g = ng;
            };
            match outcome {
                None => Ok(TransferOutcome::Committed),
                Some(file) => Ok(TransferOutcome::NativeAborted(vec![file])),
            }
        } else {
            self.reply(req, payload, vec![])
        }
    }

    /// Reply with a shared-memory region attached (sender side). Stages the
    /// backing through the native escrow path (Windows: raw handle value in
    /// the frame; Linux: SCM_RIGHTS over the lane), holds the source until
    /// commit, and returns the restored capability on pre-commit abort.
    pub fn reply_with_shared(
        &self,
        req: &Inbound,
        payload: Vec<u8>,
        region: Option<SharedRegion>,
    ) -> Result<TransferOutcome, FabError> {
        let Some(reg) = region else {
            return self.reply(req, payload, vec![]);
        };
        struct Empty;
        impl TransferSpace for Empty {
            fn contains(&self, _: TransferId) -> bool {
                false
            }
        }
        let tid = fresh_transfer_id(&Empty);
        let rid = reg.id();
        #[cfg(windows)]
        let handle_value = {
            use std::os::windows::io::AsRawHandle;
            reg.backing_ref().as_raw_handle() as u64
        };
        #[cfg(not(windows))]
        let handle_value = 0u64;
        // Unix: stage the descriptor BEFORE the control frame so the Host's
        // blocking stage read is deterministic. Sender source stays open.
        #[cfg(unix)]
        {
            let lane_opt = self.shared.native_lane.lock().unwrap();
            if let Some(lane) = lane_opt.as_ref() {
                // ponytail: RegionId reinterpreted as ResourceId bytes — same
                // [u8;16] layout; shared/native tables are tid-disjoint.
                let rid_native = crate::native::ResourceId(rid.0);
                if let Err(e) = crate::native::unix::send_lane_msg(
                    lane,
                    crate::native::LANE_KIND_STAGE,
                    tid,
                    rid_native,
                    reg.backing_ref(),
                ) {
                    eprintln!("SEAM lane stage failed: {e}");
                    return Err(FabError::TransferUnknown);
                }
            } else {
                eprintln!("SEAM no native lane installed");
                return Err(FabError::TransferUnknown);
            }
        }
        let slot = Arc::new((Mutex::new(None::<Option<SharedRegion>>), Condvar::new()));
        {
            let mut st = self.shared.st.lock().unwrap();
            if st.terminal.is_some() {
                return Err(FabError::FabricLost);
            }
            st.shared_hold.insert(tid, reg);
            st.shared_wait.insert(tid, slot.clone());
        }
        let att = SharedAttachment {
            tid,
            rid,
            rights: Rights::ReadWrite.wire_byte(),
            handle_value,
        };
        let pushed = self.shared.push_out(Frame::Data(DataInner {
            target: req.local,
            corr: req.corr,
            attachments: vec![],
            payload,
            native: None,
            shared: Some(att),
        }));
        if let Err(e) = pushed {
            let mut st = self.shared.st.lock().unwrap();
            st.shared_hold.remove(&tid);
            st.shared_wait.remove(&tid);
            return Err(e);
        }
        let deadline = Instant::now() + Duration::from_secs(10);
        let (m, cv) = &*slot;
        let mut g = m.lock().unwrap();
        let outcome = loop {
            if let Some(v) = g.take() {
                break v;
            }
            let now = Instant::now();
            if now >= deadline {
                match self.transfer_status(tid, Duration::from_secs(2)) {
                    Ok(frame::XFER_ST_COMMITTED) => break None,
                    _ => break None,
                }
            }
            let (ng, _) = cv.wait_timeout(g, deadline - now).unwrap();
            g = ng;
        };
        match outcome {
            None => Ok(TransferOutcome::Committed),
            Some(restored) => Ok(TransferOutcome::SharedAborted(vec![restored])),
        }
    }

    fn transfer_status(&self, tid: TransferId, timeout: Duration) -> Result<u8, FabError> {
        let sw = Arc::new((Mutex::new(None::<u8>), Condvar::new()));
        {
            let mut st = self.shared.st.lock().unwrap();
            if st.terminal.is_some() {
                return Err(FabError::FabricLost);
            }
            st.status_wait.insert(tid, sw.clone());
        }
        if let Err(e) = self.shared.push_out(Frame::Xfer(XferMsg::Status { tid })) {
            let mut st = self.shared.st.lock().unwrap();
            st.status_wait.remove(&tid);
            return Err(e);
        }
        let deadline = Instant::now() + timeout;
        let (m, cv) = &*sw;
        let mut g = m.lock().unwrap();
        loop {
            if let Some(s) = *g {
                return Ok(s);
            }
            let now = Instant::now();
            if now >= deadline {
                let mut st = self.shared.st.lock().unwrap();
                st.status_wait.remove(&tid);
                return Err(FabError::TransferUnknown);
            }
            let (ng, _) = cv.wait_timeout(g, deadline - now).unwrap();
            g = ng;
        }
    }

    /// Ask the fabric for a fresh endpoint pair: (implementation side,
    /// transferable side). Both are initially held by us; transferring the
    /// second one delegates invocation authority while implementation
    /// traffic keeps arriving on the first.
    pub fn create_endpoint(&self, timeout: Duration) -> Result<(Endpoint, Endpoint), FabError> {
        let deadline = Instant::now() + timeout;
        let slot = Arc::new((Mutex::new(None::<CreateOutcome>), Condvar::new()));
        {
            let mut st = self.shared.st.lock().unwrap();
            if st.terminal.is_some() {
                return Err(FabError::FabricLost);
            }
            if st.create_slot.is_some() {
                return Err(FabError::Backpressured {
                    queued_msgs: 0,
                    queued_bytes: 0,
                });
            }
            st.create_slot = Some(slot.clone());
        }
        if let Err(e) = self.shared.push_out(Frame::Create) {
            let mut st = self.shared.st.lock().unwrap();
            st.create_slot = None;
            return Err(e);
        }
        let (m, cv) = &*slot;
        let mut g = m.lock().unwrap();
        loop {
            match g.take() {
                Some(CreateOutcome::Done(imp, tra)) => {
                    let mut st = self.shared.st.lock().unwrap();
                    if let Entry::Vacant(e) = st.handles.entry(imp) {
                        e.insert(HState {
                            partner: tra,
                            cause: None,
                        });
                        st.arrival_order.push(imp);
                    }
                    if let Entry::Vacant(e) = st.handles.entry(tra) {
                        e.insert(HState {
                            partner: imp,
                            cause: None,
                        });
                        st.arrival_order.push(tra);
                    }
                    // Demux: a DATA addressed with the peer's handle (the
                    // partner id) must resolve to our local side.
                    st.partner_of_theirs.insert(tra, imp);
                    st.partner_of_theirs.insert(imp, tra);
                    return Ok((
                        Endpoint {
                            id: imp,
                            shared: self.shared.clone(),
                            armed: true,
                        },
                        Endpoint {
                            id: tra,
                            shared: self.shared.clone(),
                            armed: true,
                        },
                    ));
                }
                Some(CreateOutcome::Failed(e)) => return Err(e),
                None => {}
            }
            let now = Instant::now();
            if now >= deadline {
                let mut st = self.shared.st.lock().unwrap();
                st.create_slot = None;
                return Err(FabError::Timeout);
            }
            let (ng, _) = cv.wait_timeout(g, deadline - now).unwrap();
            g = ng;
        }
    }

    /// Wait until a handle exists that is not in `exclude`; returns its id.
    /// Used by roles that receive grants asynchronously.
    pub fn next_new_handle(&self, exclude: &[EpId], timeout: Duration) -> Result<EpId, FabError> {
        let deadline = Instant::now() + timeout;
        let mut g = self.shared.new_handle_m.lock().unwrap();
        loop {
            {
                let st = self.shared.st.lock().unwrap();
                let found = st.arrival_order.iter().copied().find(|id| {
                    !exclude.contains(id)
                        && st
                            .handles
                            .get(id)
                            .map(|h| h.cause.is_none())
                            .unwrap_or(false)
                });
                if let Some(id) = found {
                    return Ok(id);
                }
                if st.terminal.is_some() {
                    return Err(FabError::FabricLost);
                }
            }
            let now = Instant::now();
            if now >= deadline {
                return Err(FabError::Timeout);
            }
            let (ng, _) = self
                .shared
                .new_handle
                .wait_timeout(g, deadline - now)
                .unwrap();
            g = ng;
        }
    }

    pub fn live_handles(&self) -> Vec<EpId> {
        let st = self.shared.st.lock().unwrap();
        st.handles
            .iter()
            .filter(|(_, h)| h.cause.is_none())
            .map(|(k, _)| *k)
            .collect()
    }

    /// Materialize the public handle for an identity we already hold
    /// (grants arrive before we can observe them synchronously). Not an
    /// authority source: it fails unless the runtime currently records us
    /// as the holder.
    pub fn endpoint_for(&self, id: EpId) -> Option<Endpoint> {
        let st = self.shared.st.lock().unwrap();
        match st.handles.get(&id) {
            Some(h) if h.cause.is_none() => Some(Endpoint {
                id,
                shared: self.shared.clone(),
                armed: true,
            }),
            _ => None,
        }
    }

    pub fn fabric_terminal(&self) -> Option<Cause> {
        self.shared.st.lock().unwrap().terminal
    }

    pub fn accounting(&self) -> PeerAccounting {
        let st = self.shared.st.lock().unwrap();
        PeerAccounting {
            live_handles: st.handles.values().filter(|h| h.cause.is_none()).count(),
            inbound_backlog_msgs: self.shared.inbound.backlog().msgs,
            dropped_after_close: st.dropped_after_close,
            sent_frames: self.shared.sent_frames.load(Ordering::Relaxed),
            received_frames: self.shared.received_frames.load(Ordering::Relaxed),
            terminal: st.terminal.is_some(),
        }
    }

    /// Best-effort orderly goodbye: announce, give the writer a moment,
    /// then mark everything closed.
    pub fn shutdown(&self) {
        let _ = self.shared.push_out(Frame::Shutdown);
        std::thread::sleep(Duration::from_millis(40));
        self.shared.go_terminal_pub(Cause::Graceful);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::{DataInner, SharedAttachment};
    use crate::id::TransferId;
    use crate::limits::Limits;
    use crate::shared::{RegionId, Rights};

    fn offer_frame(tid: TransferId, rid: RegionId) -> Frame {
        Frame::Data(DataInner {
            target: EpId([9; 16]),
            corr: 0,
            attachments: vec![],
            payload: vec![b'm'],
            native: None,
            shared: Some(SharedAttachment {
                tid,
                rid,
                rights: Rights::ReadOnly.wire_byte(),
                handle_value: 0,
            }),
        })
    }

    /// T5/T6: aborting an offered shared transaction destroys the recipient's
    /// join state, so a late lane delivery cannot pair with anything and its
    /// backing closes without minting authority.
    #[test]
    fn abort_clears_shared_join_state() {
        let sh = RuntimeInner::__for_tests(Limits::default());
        let tid = TransferId([7; 16]);
        let rid = RegionId([8; 16]);
        assert!(sh.process(offer_frame(tid, rid)));
        {
            let st = sh.st.lock().unwrap();
            assert!(st.shared_parked.contains_key(&tid));
        }
        assert!(sh.process(Frame::Xfer(XferMsg::Abort { tid })));
        let st = sh.st.lock().unwrap();
        assert!(!st.shared_parked.contains_key(&tid));
        assert!(!st.shared_recv.contains_key(&tid));
        assert!(!st.shared_commit_meta.contains_key(&tid));
        // Native twin shares the same fate.
        assert!(st.native_parked.is_empty());
        assert!(st.native_recv.is_empty());
    }

    /// A second COMMIT for an already-materialized transaction must not mint
    /// a second authority: the first join consumed the parked metadata.
    #[cfg(windows)]
    #[test]
    fn duplicate_commit_mints_one_authority() {
        let sh = RuntimeInner::__for_tests(Limits::default());
        let tid = TransferId([3; 16]);
        let rid = RegionId([4; 16]);
        assert!(sh.process(offer_frame(tid, rid)));
        let commit = |hv| {
            Frame::Xfer(XferMsg::SharedCommit {
                tid,
                rid,
                rights: Rights::ReadOnly.wire_byte(),
                size: 4096,
                handle_value: hv,
            })
        };
        assert!(sh.process(commit(0x1111)));
        assert!(sh.process(commit(0x2222)));
        // Exactly one inbound capability materialized.
        let first = sh
            .inbound
            .pop_deadline(Instant::now() + Duration::from_secs(1));
        assert!(first.is_ok(), "first delivery expected");
        let second = sh
            .inbound
            .pop_deadline(Instant::now() + Duration::from_millis(50));
        assert!(second.is_err(), "no duplicate authority");
    }
}
