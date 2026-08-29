//! Materializer — per-attachment exactly-once join.
//! Key (TransferId, AttachmentIndex). No OS handles.

use std::collections::{HashMap, HashSet};

use crate::ids::{PeerId, TransferId};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Metadata {
    pub recipient: PeerId,
    pub object_id: [u8; 16],
    pub object_kind: u8,
    pub native_required: bool,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Action {
    Wait,
    Materialize {
        object_id: [u8; 16],
        object_kind: u8,
    },
    CloseNative,
    Reject(&'static str),
}

#[derive(Clone, Debug)]
struct Slot {
    metadata: Option<Metadata>,
    native_staged: bool,
    committed: bool,
    aborted: bool,
    materialized: bool,
    native_required: bool,
}

impl Slot {
    fn new() -> Self {
        Self {
            metadata: None,
            native_staged: false,
            committed: false,
            aborted: false,
            materialized: false,
            native_required: false,
        }
    }
}

pub struct Materializer {
    slots: HashMap<(TransferId, u16), Slot>,
    committed_tids: HashSet<TransferId>,
    aborted_tids: HashSet<TransferId>,
    // For duplicate detection, we track which tids are terminal
}

impl Materializer {
    pub fn new() -> Self {
        Self {
            slots: HashMap::new(),
            committed_tids: HashSet::new(),
            aborted_tids: HashSet::new(),
        }
    }

    /// Pure preflight: would authorize_metadata(tid, idx, meta) succeed without mutation?
    pub fn can_authorize(&self, tid: TransferId, idx: u16, meta: &Metadata) -> bool {
        if self.aborted_tids.contains(&tid) {
            return false;
        }
        match self.slots.get(&(tid, idx)) {
            None => true,
            Some(s) => {
                if s.materialized {
                    return false;
                }
                match &s.metadata {
                    None => true,
                    Some(m) => m == meta,
                }
            }
        }
    }

    pub fn authorize_metadata(&mut self, tid: TransferId, idx: u16, meta: Metadata) -> Action {
        let key = (tid, idx);
        // Wrong tid already aborted/committed? Still allow but will be rejected if mismatched
        if self.aborted_tids.contains(&tid) {
            return Action::Reject("aborted");
        }
        let slot = self.slots.entry(key).or_insert_with(|| {
            let mut s = Slot::new();
            s.committed = self.committed_tids.contains(&tid);
            s.aborted = self.aborted_tids.contains(&tid);
            s
        });
        if self.aborted_tids.contains(&tid) {
            // already handled above, but keep for slot case
        }
        if slot.metadata.is_some() {
            return Action::Reject("duplicate metadata");
        }
        if slot.materialized {
            return Action::Reject("already materialized");
        }
        slot.native_required = meta.native_required;
        slot.metadata = Some(meta.clone());
        // ensure committed flag reflects tid state
        if self.committed_tids.contains(&tid) {
            slot.committed = true;
        }
        self.try_materialize_slot(key)
    }

    pub fn stage_native(&mut self, tid: TransferId, idx: u16, native_required: bool) -> Action {
        let key = (tid, idx);
        if self.aborted_tids.contains(&tid) {
            return Action::CloseNative;
        }
        if self.committed_tids.contains(&tid) {
            // If already committed, we still need to check if already materialized
            // If slot already materialized, duplicate -> CloseNative
        }
        let slot = self.slots.entry(key).or_insert_with(|| {
            let mut s = Slot::new();
            s.committed = self.committed_tids.contains(&tid);
            s.aborted = self.aborted_tids.contains(&tid);
            s
        });
        // ensure flags reflect global tid state
        if self.committed_tids.contains(&tid) {
            slot.committed = true;
        }
        if self.aborted_tids.contains(&tid) {
            slot.aborted = true;
        }
        if slot.materialized {
            return Action::CloseNative;
        }
        if slot.aborted {
            return Action::CloseNative;
        }
        // If metadata exists and native_required mismatch, reject
        if let Some(m) = &slot.metadata {
            if m.native_required != native_required {
                return Action::Reject("native_required mismatch");
            }
        } else {
            // No metadata yet, store requirement for later check
            slot.native_required = native_required;
        }
        if slot.native_staged {
            return Action::CloseNative;
        }
        slot.native_staged = true;
        self.try_materialize_slot(key)
    }

    pub fn mark_committed(&mut self, tid: TransferId) {
        self.committed_tids.insert(tid);
        // Mark all slots for tid as committed
        for ((t, _), slot) in self.slots.iter_mut() {
            if *t == tid {
                slot.committed = true;
            }
        }
    }

    pub fn mark_aborted(&mut self, tid: TransferId) {
        self.aborted_tids.insert(tid);
        for ((t, _), slot) in self.slots.iter_mut() {
            if *t == tid {
                slot.aborted = true;
            }
        }
    }

    fn try_materialize_slot(&mut self, key: (TransferId, u16)) -> Action {
        let slot = self.slots.get_mut(&key).unwrap();
        if slot.materialized || slot.aborted {
            return Action::CloseNative;
        }
        if !slot.committed {
            return Action::Wait;
        }
        let meta = match &slot.metadata {
            Some(m) => m,
            None => return Action::Wait,
        };
        if meta.native_required && !slot.native_staged {
            return Action::Wait;
        }
        // Ready to materialize exactly once
        slot.materialized = true;
        Action::Materialize {
            object_id: meta.object_id,
            object_kind: meta.object_kind,
        }
    }

    /// Try to materialize after commit (call after mark_committed)
    pub fn try_materialize(&mut self, tid: TransferId, idx: u16) -> Action {
        let key = (tid, idx);
        if !self.slots.contains_key(&key) {
            return Action::Wait;
        }
        self.try_materialize_slot(key)
    }

    pub fn is_materialized(&self, tid: TransferId, idx: u16) -> bool {
        self.slots
            .get(&(tid, idx))
            .map(|s| s.materialized)
            .unwrap_or(false)
    }
}

impl Default for Materializer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ids::{PeerId, TransferId};

    fn tid(n: u8) -> TransferId {
        TransferId([n; 16])
    }
    fn peer(n: u8) -> PeerId {
        PeerId([n; 16])
    }

    fn meta(recipient: PeerId, native_required: bool) -> Metadata {
        Metadata {
            recipient,
            object_id: [7; 16],
            object_kind: 2,
            native_required,
        }
    }

    #[test]
    fn wait_then_materialize() {
        let mut m = Materializer::new();
        let t = tid(1);
        let p = peer(2);
        assert_eq!(m.authorize_metadata(t, 0, meta(p, true)), Action::Wait);
        assert_eq!(m.stage_native(t, 0, true), Action::Wait);
        m.mark_committed(t);
        assert_eq!(
            m.try_materialize(t, 0),
            Action::Materialize {
                object_id: [7; 16],
                object_kind: 2
            }
        );
        // Duplicate should close
        assert_eq!(m.stage_native(t, 0, true), Action::CloseNative);
    }

    #[test]
    fn native_before_metadata() {
        let mut m = Materializer::new();
        let t = tid(1);
        let p = peer(2);
        assert_eq!(m.stage_native(t, 0, true), Action::Wait);
        assert_eq!(m.authorize_metadata(t, 0, meta(p, true)), Action::Wait);
        m.mark_committed(t);
        assert_eq!(
            m.try_materialize(t, 0),
            Action::Materialize {
                object_id: [7; 16],
                object_kind: 2
            }
        );
    }

    #[test]
    fn commit_before_both() {
        let mut m = Materializer::new();
        let t = tid(1);
        let p = peer(2);
        m.mark_committed(t);
        assert_eq!(m.authorize_metadata(t, 0, meta(p, true)), Action::Wait);
        assert_eq!(
            m.stage_native(t, 0, true),
            Action::Materialize {
                object_id: [7; 16],
                object_kind: 2
            }
        );
    }

    #[test]
    fn duplicate_native_close() {
        let mut m = Materializer::new();
        let t = tid(1);
        assert_eq!(m.stage_native(t, 0, false), Action::Wait);
        assert_eq!(m.stage_native(t, 0, false), Action::CloseNative);
    }

    #[test]
    fn late_after_abort_close() {
        let mut m = Materializer::new();
        let t = tid(1);
        m.mark_aborted(t);
        assert_eq!(m.stage_native(t, 0, true), Action::CloseNative);
        assert_eq!(
            m.authorize_metadata(t, 0, meta(peer(2), true)),
            Action::Reject("aborted")
        );
    }

    #[test]
    fn wrong_native_required_reject() {
        let mut m = Materializer::new();
        let t = tid(1);
        m.authorize_metadata(t, 0, meta(peer(2), true));
        assert_eq!(
            m.stage_native(t, 0, false),
            Action::Reject("native_required mismatch")
        );
    }

    #[test]
    fn materialize_once() {
        let mut m = Materializer::new();
        let t = tid(1);
        let p = peer(2);
        m.authorize_metadata(t, 0, meta(p, false));
        m.mark_committed(t);
        assert_eq!(
            m.try_materialize(t, 0),
            Action::Materialize {
                object_id: [7; 16],
                object_kind: 2
            }
        );
        assert_eq!(m.try_materialize(t, 0), Action::CloseNative);
    }
}
