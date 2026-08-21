//! Endpoint and transfer identities.
//!
//! Endpoint identity ≠ authority. Authority is the runtime possession
//! record. Identities are 128-bit OS-random values used as unguessable
//! *names*; they are never chosen by the application and never reused
//! within one runtime lifetime (live + pending + recent retirement).
//!
//! Collision is checked, not claimed impossible.

use std::collections::{HashMap, HashSet, VecDeque};

use getrandom::fill;

use crate::fabric_error::Cause;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct EpId(pub [u8; 16]);

/// Transaction identity. Distinct type from `EpId` so it cannot be used
/// as application authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct TransferId(pub [u8; 16]);

impl EpId {
    pub fn from_raw(bytes: [u8; 16]) -> Self {
        EpId(bytes)
    }
    pub fn is_zero(self) -> bool {
        self.0.iter().all(|&b| b == 0)
    }
}

impl TransferId {
    pub fn from_raw(bytes: [u8; 16]) -> Self {
        TransferId(bytes)
    }
    pub fn is_zero(self) -> bool {
        self.0.iter().all(|&b| b == 0)
    }
}

pub trait IdSpace {
    fn contains(&self, id: EpId) -> bool;
}

pub trait TransferSpace {
    fn contains(&self, id: TransferId) -> bool;
}

fn draw16() -> [u8; 16] {
    let mut b = [0u8; 16];
    fill(&mut b).expect("OS entropy source failed");
    b
}

pub fn fresh_id(taken: &impl IdSpace) -> EpId {
    loop {
        let id = EpId(draw16());
        if !id.is_zero() && !taken.contains(id) {
            return id;
        }
    }
}

pub fn fresh_transfer_id(taken: &impl TransferSpace) -> TransferId {
    loop {
        let id = TransferId(draw16());
        if !id.is_zero() && !taken.contains(id) {
            return id;
        }
    }
}

impl IdSpace for HashSet<EpId> {
    fn contains(&self, id: EpId) -> bool {
        HashSet::contains(self, &id)
    }
}

impl TransferSpace for HashSet<TransferId> {
    fn contains(&self, id: TransferId) -> bool {
        HashSet::contains(self, &id)
    }
}

/// Bounded recent-retirement cache. Eviction turns "stale" into "unknown";
/// both fail closed. Size is independent of historical churn.
pub struct BoundedTombstones<K: Copy + Eq + std::hash::Hash> {
    cap: usize,
    map: HashMap<K, Cause>,
    order: VecDeque<K>,
}

impl<K: Copy + Eq + std::hash::Hash> BoundedTombstones<K> {
    pub fn new(cap: usize) -> Self {
        BoundedTombstones {
            cap: cap.max(1),
            map: HashMap::new(),
            order: VecDeque::new(),
        }
    }

    pub fn insert(&mut self, k: K, cause: Cause) {
        if self.map.contains_key(&k) {
            return;
        }
        while self.order.len() >= self.cap {
            if let Some(old) = self.order.pop_front() {
                self.map.remove(&old);
            }
        }
        self.order.push_back(k);
        self.map.insert(k, cause);
    }

    pub fn get(&self, k: K) -> Option<Cause> {
        self.map.get(&k).copied()
    }

    pub fn contains(&self, k: K) -> bool {
        self.map.contains_key(&k)
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    pub fn cap(&self) -> usize {
        self.cap
    }
}

/// Combined view used when drawing fresh ids.
pub struct IdOracle<'a> {
    pub extra: &'a HashSet<EpId>,
}

impl IdSpace for IdOracle<'_> {
    fn contains(&self, id: EpId) -> bool {
        self.extra.contains(&id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Empty;
    impl IdSpace for Empty {
        fn contains(&self, _id: EpId) -> bool {
            false
        }
    }

    #[test]
    fn fresh_ids_are_nonzero_and_distinct() {
        let mut seen = HashSet::new();
        for _ in 0..256 {
            let id = fresh_id(&Empty);
            assert!(!id.is_zero());
            assert!(seen.insert(id), "collision drawn from entropy");
        }
    }

    #[test]
    fn tombstones_evict_oldest_and_never_resurrect() {
        let mut t = BoundedTombstones::new(2);
        let a = EpId::from_raw([1; 16]);
        let b = EpId::from_raw([2; 16]);
        let c = EpId::from_raw([3; 16]);
        t.insert(a, Cause::Graceful);
        t.insert(b, Cause::PeerLost);
        assert_eq!(t.len(), 2);
        t.insert(c, Cause::Graceful);
        assert_eq!(t.len(), 2);
        assert!(!t.contains(a), "oldest evicted");
        assert!(t.contains(b) && t.contains(c));
        assert_eq!(t.cap(), 2);
    }

    #[test]
    fn transfer_ids_are_a_distinct_type() {
        let e = EpId::from_raw([9; 16]);
        let t = TransferId::from_raw([9; 16]);
        assert_eq!(e.0, t.0);
        // Distinct newtypes: cannot pass TransferId where EpId is required
        // without an explicit conversion (none is provided).
        let _ = (e, t);
    }
}
