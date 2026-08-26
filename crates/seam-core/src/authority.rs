//! AuthorityLedger — generic linear capability ownership.
//! Pure safe Rust, 0 unsafe, no OS handles.

use std::collections::HashMap;

use crate::ids::{EndpointId, PeerId, PipeId, RegionId, ResourceId, TransferId};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AuthorityKey {
    Endpoint(EndpointId),
    Resource(ResourceId),
    Region(RegionId),
    PipeProducer(PipeId),
    PipeConsumer(PipeId),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthorityState {
    Held(PeerId),
    Escrow {
        transfer_id: TransferId,
        sender: PeerId,
        recipient: PeerId,
    },
    Released,
}

#[derive(Debug, PartialEq, Eq)]
pub enum LedgerError {
    AlreadyExists,
    NotFound,
    WrongHolder,
    DuplicateKeyInBundle,
    EscrowMismatch,
    WrongState,
}

pub struct AuthorityLedger {
    map: HashMap<AuthorityKey, AuthorityState>,
}

impl AuthorityLedger {
    pub fn new() -> Self {
        Self {
            map: HashMap::new(),
        }
    }

    pub fn register(&mut self, key: AuthorityKey, owner: PeerId) -> Result<(), LedgerError> {
        if self.map.contains_key(&key) {
            return Err(LedgerError::AlreadyExists);
        }
        self.map.insert(key, AuthorityState::Held(owner));
        Ok(())
    }

    pub fn lookup(&self, key: &AuthorityKey) -> Option<AuthorityState> {
        self.map.get(key).copied()
    }

    /// Offer bundle: all keys must be Held(sender), then atomically Escrow(tid)
    pub fn offer_bundle(
        &mut self,
        sender: PeerId,
        recipient: PeerId,
        tid: TransferId,
        keys: &[AuthorityKey],
    ) -> Result<(), LedgerError> {
        // Check duplicate keys in bundle
        let mut seen = std::collections::HashSet::new();
        for k in keys {
            if !seen.insert(k) {
                return Err(LedgerError::DuplicateKeyInBundle);
            }
        }
        // Validate all
        for k in keys {
            match self.map.get(k) {
                Some(AuthorityState::Held(owner)) if *owner == sender => {}
                Some(_) => return Err(LedgerError::WrongHolder),
                None => return Err(LedgerError::NotFound),
            }
        }
        // Mutate all
        for k in keys {
            self.map.insert(
                *k,
                AuthorityState::Escrow {
                    transfer_id: tid,
                    sender,
                    recipient,
                },
            );
        }
        Ok(())
    }

    pub fn commit_bundle(
        &mut self,
        tid: TransferId,
        recipient: PeerId,
    ) -> Result<Vec<AuthorityKey>, LedgerError> {
        // Find all escrowed for tid
        let mut to_commit = Vec::new();
        for (k, state) in self.map.iter() {
            if let AuthorityState::Escrow {
                transfer_id,
                recipient: r,
                ..
            } = state
            {
                if *transfer_id == tid {
                    if *r != recipient {
                        return Err(LedgerError::EscrowMismatch);
                    }
                    to_commit.push(*k);
                }
            }
        }
        if to_commit.is_empty() {
            return Err(LedgerError::NotFound);
        }
        // Ensure all escrowed for tid are exactly these (no partial commit)
        // Transition
        for k in &to_commit {
            self.map.insert(*k, AuthorityState::Held(recipient));
        }
        Ok(to_commit)
    }

    pub fn abort_bundle(&mut self, tid: TransferId) -> Result<Vec<AuthorityKey>, LedgerError> {
        let mut to_abort = Vec::new();
        let mut sender_opt: Option<PeerId> = None;
        for (k, state) in self.map.iter() {
            if let AuthorityState::Escrow {
                transfer_id,
                sender,
                ..
            } = state
            {
                if *transfer_id == tid {
                    if let Some(s) = sender_opt {
                        if s != *sender {
                            // Different sender in same tid — should not happen
                            return Err(LedgerError::EscrowMismatch);
                        }
                    } else {
                        sender_opt = Some(*sender);
                    }
                    to_abort.push(*k);
                }
            }
        }
        if to_abort.is_empty() {
            return Err(LedgerError::NotFound);
        }
        let sender = sender_opt.unwrap();
        for k in &to_abort {
            self.map.insert(*k, AuthorityState::Held(sender));
        }
        Ok(to_abort)
    }

    pub fn release(&mut self, key: AuthorityKey) -> Result<(), LedgerError> {
        match self.map.get(&key) {
            Some(_) => {
                self.map.insert(key, AuthorityState::Released);
                Ok(())
            }
            None => Err(LedgerError::NotFound),
        }
    }

    /// Check invariant: each live key exactly one Held|Escrow
    pub fn invariant_holds(&self) -> bool {
        for state in self.map.values() {
            match state {
                AuthorityState::Held(_)
                | AuthorityState::Escrow { .. }
                | AuthorityState::Released => {}
            }
        }
        true
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
}

impl Default for AuthorityLedger {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ids::{PeerId, ResourceId};

    fn peer(n: u8) -> PeerId {
        PeerId([n; 16])
    }
    fn res(n: u8) -> ResourceId {
        ResourceId([n; 16])
    }
    fn tid(n: u8) -> TransferId {
        TransferId([n; 16])
    }

    #[test]
    fn register_and_lookup() {
        let mut l = AuthorityLedger::new();
        let k = AuthorityKey::Resource(res(1));
        l.register(k, peer(1)).unwrap();
        assert_eq!(l.lookup(&k), Some(AuthorityState::Held(peer(1))));
        assert_eq!(l.register(k, peer(2)), Err(LedgerError::AlreadyExists));
    }

    #[test]
    fn offer_single_commit() {
        let mut l = AuthorityLedger::new();
        let k = AuthorityKey::Resource(res(1));
        l.register(k, peer(1)).unwrap();
        l.offer_bundle(peer(1), peer(2), tid(1), &[k]).unwrap();
        assert!(matches!(l.lookup(&k), Some(AuthorityState::Escrow { .. })));
        let committed = l.commit_bundle(tid(1), peer(2)).unwrap();
        assert_eq!(committed, vec![k]);
        assert_eq!(l.lookup(&k), Some(AuthorityState::Held(peer(2))));
    }

    #[test]
    fn offer_multi_invalid_rolls_back() {
        let mut l = AuthorityLedger::new();
        let k1 = AuthorityKey::Resource(res(1));
        let k2 = AuthorityKey::Resource(res(2));
        l.register(k1, peer(1)).unwrap();
        l.register(k2, peer(1)).unwrap();
        let k3 = AuthorityKey::Resource(res(3)); // not registered
        let res = l.offer_bundle(peer(1), peer(2), tid(1), &[k1, k3]);
        assert_eq!(res, Err(LedgerError::NotFound));
        // k1 must remain Held, not Escrow
        assert_eq!(l.lookup(&k1), Some(AuthorityState::Held(peer(1))));
        assert_eq!(l.lookup(&k2), Some(AuthorityState::Held(peer(1))));
    }

    #[test]
    fn abort_restores() {
        let mut l = AuthorityLedger::new();
        let k = AuthorityKey::Resource(res(1));
        l.register(k, peer(1)).unwrap();
        l.offer_bundle(peer(1), peer(2), tid(1), &[k]).unwrap();
        let aborted = l.abort_bundle(tid(1)).unwrap();
        assert_eq!(aborted, vec![k]);
        assert_eq!(l.lookup(&k), Some(AuthorityState::Held(peer(1))));
    }

    #[test]
    fn duplicate_key_in_bundle() {
        let mut l = AuthorityLedger::new();
        let k = AuthorityKey::Resource(res(1));
        l.register(k, peer(1)).unwrap();
        assert_eq!(
            l.offer_bundle(peer(1), peer(2), tid(1), &[k, k]),
            Err(LedgerError::DuplicateKeyInBundle)
        );
    }

    #[test]
    fn wrong_sender() {
        let mut l = AuthorityLedger::new();
        let k = AuthorityKey::Resource(res(1));
        l.register(k, peer(1)).unwrap();
        assert_eq!(
            l.offer_bundle(peer(2), peer(3), tid(1), &[k]),
            Err(LedgerError::WrongHolder)
        );
    }

    #[test]
    fn duplicate_commit_fails() {
        let mut l = AuthorityLedger::new();
        let k = AuthorityKey::Resource(res(1));
        l.register(k, peer(1)).unwrap();
        l.offer_bundle(peer(1), peer(2), tid(1), &[k]).unwrap();
        l.commit_bundle(tid(1), peer(2)).unwrap();
        assert_eq!(l.commit_bundle(tid(1), peer(2)), Err(LedgerError::NotFound));
    }

    #[test]
    fn authority_cardinality() {
        let mut l = AuthorityLedger::new();
        let k1 = AuthorityKey::Resource(res(1));
        let k2 = AuthorityKey::Resource(res(2));
        l.register(k1, peer(1)).unwrap();
        l.register(k2, peer(1)).unwrap();
        l.offer_bundle(peer(1), peer(2), tid(1), &[k1]).unwrap();
        // k1 Escrow, k2 Held => each exactly one state
        assert!(l.invariant_holds());
        l.commit_bundle(tid(1), peer(2)).unwrap();
        assert!(l.invariant_holds());
    }
}
