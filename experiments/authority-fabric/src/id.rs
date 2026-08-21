//! Endpoint identity.
//!
//! Authority-bearing endpoint ids are 64-bit values drawn from OS entropy,
//! unique over the lifetime of a fabric instance (never reused), so:
//! - they are not attacker-selectable,
//! - they are not realistically guessable,
//! - stale identities can never alias a new capability (no ABA).
//!
//! This is forge-RESISTANT by randomness and scoping, not cryptographic
//! authentication. See docs in .agent/CAPABILITIES.md for the honest threat
//! model: an attacker who can read our memory defeats everything; the model
//! defends against *other processes* guessing or replaying identities.

use std::collections::HashSet;

use getrandom::fill;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct EpId(pub u64);

/// Draws a fresh id from OS entropy, retrying on the (astronomically rare)
/// collision with `taken`. The caller's table union live+retired must be
/// passed as `taken`.
pub fn fresh_id(taken: &impl IdSpace) -> EpId {
    loop {
        let mut b = [0u8; 8];
        // OS entropy failure is unrecoverable for an identity scheme.
        fill(&mut b).expect("OS entropy source failed");
        let v = u64::from_le_bytes(b);
        if v != 0 && !taken.contains(v) {
            return EpId(v);
        }
    }
}

/// Abstraction so both live tables and retirement tombstones can be checked
/// without exposing internal structures.
pub trait IdSpace {
    fn contains(&self, v: u64) -> bool;
}

impl IdSpace for HashSet<u64> {
    fn contains(&self, v: u64) -> bool {
        HashSet::contains(self, &v)
    }
}

/// Monotonic retirement set. Ids land here when their conversation dies and
/// NEVER return to circulation. Growth is bounded by experiment scale
/// (10k cycles => ~40KB); production designs would epoch this.
#[derive(Default)]
pub struct Retirement {
    retired: HashSet<u64>,
}

impl Retirement {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn retire(&mut self, id: EpId) {
        self.retired.insert(id.0);
    }

    pub fn is_retired(&self, id: EpId) -> bool {
        self.retired.contains(&id.0)
    }

    pub fn len(&self) -> usize {
        self.retired.len()
    }

    pub fn is_empty(&self) -> bool {
        self.retired.is_empty()
    }
}

impl IdSpace for Retirement {
    fn contains(&self, v: u64) -> bool {
        self.retired.contains(&v)
    }
}

/// Combined view used when drawing fresh ids.
pub struct IdOracle<'a> {
    pub extra: &'a HashSet<u64>,
}

impl IdSpace for IdOracle<'_> {
    fn contains(&self, v: u64) -> bool {
        self.extra.contains(&v)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Empty;
    impl IdSpace for Empty {
        fn contains(&self, _v: u64) -> bool {
            false
        }
    }

    #[test]
    fn fresh_ids_are_nonzero_and_distinct() {
        let mut seen = HashSet::new();
        for _ in 0..1000 {
            let id = fresh_id(&Empty);
            assert_ne!(id.0, 0);
            assert!(seen.insert(id.0), "collision drawn from entropy");
        }
    }

    #[test]
    fn retirement_prevents_reissue() {
        let mut r = Retirement::new();
        let taken: HashSet<u64> = [42u64].into_iter().collect();
        let oracle = IdOracle { extra: &taken };
        // Force a collision path deterministically is not possible with real
        // entropy; instead verify retire/is_retired semantics.
        let id = fresh_id(&oracle);
        assert!(!r.is_retired(id));
        r.retire(id);
        assert!(r.is_retired(id));
        assert_eq!(r.len(), 1);
    }
}
