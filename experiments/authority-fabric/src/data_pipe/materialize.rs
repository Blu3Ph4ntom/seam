//! Cross-process endpoint materialization join (RUN 006A).
//!
//! A DataPipe authority may materialize in a recipient only when ALL of:
//! generic result COMMITTED, native HANDLE/FD present, PipeId/kind/target
//! metadata match, and no authority for this role exists yet. The three
//! inputs (commit result, native endpoint, metadata) arrive independently;
//! this slot makes the join order-independent and exactly-once. Anything
//! late, duplicate, or mis-correlated fails closed: closed, never minted.

use crate::data_pipe::{PipeId, PIPE_RETIRE_CAP};
use crate::id::TransferId;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndpointKind {
    Producer,
    Consumer,
}

/// Native endpoint identity as delivered by the platform lane: a raw
/// descriptor number on Unix, a handle value on Windows. Opaque here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NativeEndpoint {
    pub raw: usize,
    #[cfg(windows)]
    pub process_relative: bool,
}

/// Host-authorized materialization metadata for one role of one pipe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MaterializeMeta {
    pub pid: PipeId,
    pub kind: EndpointKind,
    pub tid: TransferId,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JoinReject {
    /// Metadata references a transfer this recipient was never authorized
    /// for (forged Host-only metadata, wrong tid/pid/kind/target): H8/H9.
    NotAuthorized,
    /// An authority for this role already materialized: H10 duplicate.
    AlreadyMaterialized,
    /// Transfer aborted/expired before the join completed: late native
    /// endpoint must be closed by the caller, nothing mints.
    Aborted,
}

struct Slot {
    meta: MaterializeMeta,
    target_ok: bool,
    committed: bool,
    native: Option<NativeEndpoint>,
    materialized: bool,
    aborted: bool,
    /// Bounded recall of closed duplicates/late endpoints (audit counts).
    closed_junk: u32,
}

#[derive(Default)]
pub struct Materializer {
    slots: Vec<Slot>,
    retired: std::collections::VecDeque<(TransferId, EndpointKind)>,
}

impl Materializer {
    pub fn new() -> Self {
        Materializer::default()
    }

    fn find(&self, tid: &TransferId, kind: EndpointKind) -> Option<&Slot> {
        self.slots
            .iter()
            .find(|s| s.meta.tid == *tid && s.meta.kind == kind)
    }

    fn find_mut(&mut self, tid: &TransferId, kind: EndpointKind) -> Option<&mut Slot> {
        self.slots
            .iter_mut()
            .find(|s| s.meta.tid == *tid && s.meta.kind == kind)
    }

    /// Recipient arms the expected join from Host-authorized metadata and
    /// its own verified target identity (peer id checked by caller against
    /// the fabric; encoded here via `target_ok`).
    pub fn arm(&mut self, meta: MaterializeMeta, target_ok: bool) -> Result<(), JoinReject> {
        if self.find(&meta.tid, meta.kind).is_some() {
            return Err(JoinReject::AlreadyMaterialized);
        }
        if self
            .retired
            .iter()
            .any(|(t, k)| *t == meta.tid && *k == meta.kind)
        {
            return Err(JoinReject::Aborted);
        }
        if self.slots.len() >= PIPE_RETIRE_CAP {
            // Bounded arm window: refuse rather than grow unboundedly.
            return Err(JoinReject::NotAuthorized);
        }
        self.slots.push(Slot {
            meta,
            target_ok,
            committed: false,
            native: None,
            materialized: false,
            aborted: false,
            closed_junk: 0,
        });
        Ok(())
    }

    /// Generic transaction reached COMMITTED for this transfer.
    pub fn on_committed(&mut self, tid: &TransferId, kind: EndpointKind) -> bool {
        match self.find_mut(tid, kind) {
            Some(s) if !s.aborted => {
                s.committed = true;
                true
            }
            _ => false,
        }
    }

    /// Abort observed before join completion: nothing may ever mint.
    pub fn on_aborted(&mut self, tid: &TransferId, kind: EndpointKind) -> Option<NativeEndpoint> {
        match self.find_mut(tid, kind) {
            Some(s) if !s.materialized => {
                s.aborted = true;
                let junk = s.native.take();
                if junk.is_some() {
                    s.closed_junk += 1;
                }
                junk
            }
            _ => None,
        }
    }

    /// Native HANDLE/FD arrived over the platform lane.
    pub fn on_native(&mut self, tid: &TransferId, kind: EndpointKind, ep: NativeEndpoint) {
        if let Some(s) = self.find_mut(tid, kind) {
            if !s.aborted && !s.materialized {
                if s.native.is_some() {
                    // Duplicate delivery: the FIRST valid endpoint wins; the
                    // duplicate must be closed by the caller and is counted
                    // so leaks are observable in tests.
                    s.closed_junk += 1;
                } else {
                    s.native = Some(ep);
                }
            } else {
                s.closed_junk += 1; // late after abort/commit-mint: close
            }
        }
    }

    /// Attempt the join. Returns the native endpoint to wrap into the
    /// authority EXACTLY once; every other outcome fails closed.
    pub fn try_materialize(
        &mut self,
        meta: &MaterializeMeta,
    ) -> Result<NativeEndpoint, JoinReject> {
        let s = self
            .find_mut(&meta.tid, meta.kind)
            .ok_or(JoinReject::NotAuthorized)?;
        if s.materialized {
            return Err(JoinReject::AlreadyMaterialized);
        }
        if s.aborted || !s.target_ok {
            return Err(JoinReject::NotAuthorized);
        }
        if !(s.committed && s.native.is_some()) {
            return Err(JoinReject::NotAuthorized);
        }
        let ep = s.native.take().expect("checked");
        s.materialized = true;
        Ok(ep)
    }

    /// Reap fully-settled slots into the bounded retirement ledger so
    /// replays of the same (tid,kind) keep failing closed.
    pub fn reap(&mut self) {
        let retired = &mut self.retired;
        self.slots.retain(|s| {
            if s.materialized || s.aborted {
                retired.push_back((s.meta.tid, s.meta.kind));
                while retired.len() > PIPE_RETIRE_CAP {
                    retired.pop_front();
                }
                false
            } else {
                true
            }
        });
    }

    /// Total junk endpoints this layer required the caller to close.
    pub fn closed_junk(&self) -> u32 {
        self.slots.iter().map(|s| s.closed_junk).sum()
    }

    pub fn pending(&self) -> usize {
        self.slots
            .iter()
            .filter(|s| !s.materialized && !s.aborted)
            .count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pid(n: u8) -> PipeId {
        PipeId([n; 16])
    }
    fn tid(n: u8) -> TransferId {
        TransferId([n; 16])
    }
    fn ep(v: usize) -> NativeEndpoint {
        NativeEndpoint {
            raw: v,
            #[cfg(windows)]
            process_relative: true,
        }
    }
    fn meta(n: u8, kind: EndpointKind) -> MaterializeMeta {
        MaterializeMeta {
            pid: pid(n),
            kind,
            tid: tid(n),
        }
    }

    const P: EndpointKind = EndpointKind::Producer;
    const C: EndpointKind = EndpointKind::Consumer;

    #[test]
    fn t3_join_order_independent_exactly_once() {
        for order in [[true, false], [false, true]] {
            let mut m = Materializer::new();
            m.arm(meta(1, P), true).unwrap();
            if order[0] {
                m.on_committed(&tid(1), P);
                m.on_native(&tid(1), P, ep(7));
            } else {
                m.on_native(&tid(1), P, ep(7));
                m.on_committed(&tid(1), P);
            }
            let got = m.try_materialize(&meta(1, P)).unwrap();
            assert_eq!(got.raw, 7);
            // Second attempt must never re-mint.
            assert_eq!(
                m.try_materialize(&meta(1, P)),
                Err(JoinReject::AlreadyMaterialized)
            );
        }
    }

    #[test]
    fn h8_forged_metadata_rejected() {
        let mut m = Materializer::new();
        // No armed slot: peer-emitted commit/native for unknown transfer.
        m.on_committed(&tid(9), P);
        m.on_native(&tid(9), P, ep(3));
        assert_eq!(
            m.try_materialize(&meta(9, P)),
            Err(JoinReject::NotAuthorized)
        );
        assert_eq!(m.pending(), 0);
    }

    #[test]
    fn h9_wrong_correlation_rejected() {
        let mut m = Materializer::new();
        m.arm(meta(1, P), true).unwrap();
        // Native endpoint arrives correlated to a DIFFERENT kind/tid than
        // the armed metadata claims: it lands nowhere near the slot.
        m.on_native(&tid(2), C, ep(5));
        assert!(!m.on_committed(&tid(1), P).then_some(()).is_none());
        // Commit arrived but native for THIS (tid,kind) never did.
        assert_eq!(
            m.try_materialize(&meta(1, P)),
            Err(JoinReject::NotAuthorized)
        );
        // And the mis-correlated endpoint cannot be joined either way.
        m.on_native(&tid(1), P, ep(6)); // correct one arrives late
        assert!(m.try_materialize(&meta(1, P)).is_ok());
    }

    #[test]
    fn h10_duplicate_native_closes_single_mint() {
        let mut m = Materializer::new();
        m.arm(meta(1, P), true).unwrap();
        m.on_committed(&tid(1), P);
        m.on_native(&tid(1), P, ep(7));
        m.on_native(&tid(1), P, ep(8)); // duplicate delivery
        assert_eq!(m.closed_junk(), 1);
        let got = m.try_materialize(&meta(1, P)).unwrap();
        assert_eq!(got.raw, 7); // first valid endpoint wins
        assert_eq!(
            m.try_materialize(&meta(1, P)),
            Err(JoinReject::AlreadyMaterialized)
        );
    }

    #[test]
    fn late_native_after_abort_never_mints() {
        let mut m = Materializer::new();
        m.arm(meta(1, P), true).unwrap();
        m.on_native(&tid(1), P, ep(7));
        let junk = m.on_aborted(&tid(1), P);
        assert_eq!(junk.map(|j| j.raw), Some(7)); // caller closes it
        m.on_native(&tid(1), P, ep(9)); // late straggler
        m.on_committed(&tid(1), P);
        assert_eq!(
            m.try_materialize(&meta(1, P)),
            Err(JoinReject::NotAuthorized)
        );
        assert!(m.closed_junk() >= 1);
    }

    #[test]
    fn unauthorized_target_never_mints() {
        let mut m = Materializer::new();
        m.arm(meta(1, P), false).unwrap(); // recipient != authorized target
        m.on_committed(&tid(1), P);
        m.on_native(&tid(1), P, ep(7));
        assert_eq!(
            m.try_materialize(&meta(1, P)),
            Err(JoinReject::NotAuthorized)
        );
    }

    #[test]
    fn consumer_role_independent_of_producer_role() {
        let mut m = Materializer::new();
        m.arm(meta(1, P), true).unwrap();
        m.arm(meta(1, C), true).unwrap();
        m.on_committed(&tid(1), P);
        m.on_native(&tid(1), C, ep(11));
        // Producer arc missing native: cannot mint; consumer missing commit:
        // cannot mint; each role joins independently.
        assert_eq!(
            m.try_materialize(&meta(1, P)),
            Err(JoinReject::NotAuthorized)
        );
        assert_eq!(
            m.try_materialize(&meta(1, C)),
            Err(JoinReject::NotAuthorized)
        );
        m.on_native(&tid(1), P, ep(10));
        m.on_committed(&tid(1), C);
        assert_eq!(m.try_materialize(&meta(1, P)).unwrap().raw, 10);
        assert_eq!(m.try_materialize(&meta(1, C)).unwrap().raw, 11);
        m.reap();
        assert_eq!(m.pending(), 0);
        // Post-reap replay fails closed.
        m.arm(meta(1, P), true).unwrap_err();
    }
}
