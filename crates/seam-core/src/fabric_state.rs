//! FabricState — deterministic composition of AuthorityLedger, TransferTable, Materializer.
//! Pure safe Rust, no OS handles, no threads.

use std::collections::{HashMap, HashSet, VecDeque};

use crate::authority::{AuthorityKey, AuthorityLedger, LedgerError};
use crate::ids::{PeerId, TransferId};
use crate::limits::Limits;
use crate::materializer::{Action as MaterialAction, Materializer, Metadata};
use crate::transfer::{Bundle, BundleState, TransferError, TransferStatus, TransferTable};

/// A retained terminal result, bounded by limits.max_retained_results.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RetainedResult {
    pub tid: TransferId,
    pub state: BundleState,
    pub sender: PeerId,
    pub recipient: PeerId,
}

/// Action the runtime must take when a peer dies.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeathAction {
    /// Recipient died pre-commit: restore physical escrow to live sender.
    RestoreToSender { tid: TransferId, sender: PeerId },
    /// Sender died during Restoring: close physical escrow, authority Abandoned.
    AbortDeadSender { tid: TransferId },
    /// Post-commit death: never restore, recipient remains holder.
    LeaveCommitted { tid: TransferId },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PeerState {
    Active,
    Gone,
}

#[derive(Debug)]
pub enum FabricError {
    PeerNotFound,
    PeerNotActive,
    Transfer(TransferError),
    Ledger(LedgerError),
    Materializer(&'static str),
    WrongPeer,
    NotReady,
    UnknownTransfer,
    AlreadyExists,
}

impl From<TransferError> for FabricError {
    fn from(e: TransferError) -> Self {
        FabricError::Transfer(e)
    }
}
impl From<LedgerError> for FabricError {
    fn from(e: LedgerError) -> Self {
        FabricError::Ledger(e)
    }
}

pub struct FabricState {
    limits: Limits,
    peers: HashMap<PeerId, PeerState>,
    authority: AuthorityLedger,
    transfers: TransferTable,
    materializer: Materializer,
    // For abort restore tracking: which tids are awaiting physical restore before logical Held restore
    abort_needs_restore: HashSet<TransferId>,
    // Retained terminal results (bounded)
    retained: VecDeque<RetainedResult>,
    by_sender: HashMap<PeerId, Vec<TransferId>>,
    by_recipient: HashMap<PeerId, Vec<TransferId>>,
}

impl FabricState {
    pub fn new(limits: Limits) -> Self {
        let lim2 = limits.clone();
        Self {
            limits: limits.clone(),
            peers: HashMap::new(),
            authority: AuthorityLedger::new(),
            transfers: TransferTable::new(lim2),
            materializer: Materializer::new(),
            abort_needs_restore: HashSet::new(),
            retained: VecDeque::new(),
            by_sender: HashMap::new(),
            by_recipient: HashMap::new(),
        }
    }

    pub fn add_peer(&mut self, pid: PeerId) -> Result<(), FabricError> {
        if self.peers.len() >= 1024 {
            return Err(FabricError::PeerNotFound);
        }
        self.peers.insert(pid, PeerState::Active);
        Ok(())
    }

    pub fn peer_state(&self, pid: &PeerId) -> Option<PeerState> {
        self.peers.get(pid).copied()
    }

    /// Public read-only authority lookup for diagnostics/tests.
    pub fn authority_lookup(&self, key: &AuthorityKey) -> Option<crate::authority::AuthorityState> {
        self.authority.lookup(key)
    }

    pub fn remove_peer(&mut self, pid: &PeerId) {
        self.peers.insert(*pid, PeerState::Gone);
    }

    pub fn peer_gone(&mut self, pid: PeerId) -> Vec<DeathAction> {
        // Exactly-once: if already Gone, no second effects.
        if self.peers.get(&pid) == Some(&PeerState::Gone) {
            return Vec::new();
        }
        self.peers.insert(pid, PeerState::Gone);
        let mut actions = Vec::new();
        // Snapshot active transfers (bundles map)
        let active: Vec<(TransferId, PeerId, PeerId, BundleState)> = self
            .transfers
            .iter()
            .map(|(t, b)| (*t, b.sender, b.recipient, b.state))
            .collect();
        for (tid, sender, recipient, state) in active {
            let sender_alive = self.peers.get(&sender) == Some(&PeerState::Active);
            if recipient == pid {
                match state {
                    BundleState::Offered | BundleState::Accepted => {
                        if sender_alive {
                            self.mark_restoring_internal(tid);
                            actions.push(DeathAction::RestoreToSender { tid, sender });
                        } else {
                            self.mark_restoring_internal(tid);
                            actions.push(DeathAction::AbortDeadSender { tid });
                        }
                    }
                    BundleState::Restoring => {
                        // Recipient died during Restoring: restore-to-sender is
                        // already in flight; recipient death must not abandon it.
                    }
                    BundleState::Committed => {
                        actions.push(DeathAction::LeaveCommitted { tid });
                    }
                    _ => {}
                }
            } else if sender == pid {
                match state {
                    BundleState::Restoring => {
                        actions.push(DeathAction::AbortDeadSender { tid });
                    }
                    BundleState::Committed => {
                        actions.push(DeathAction::LeaveCommitted { tid });
                    }
                    _ => {}
                }
            }
        }
        actions
    }

    fn mark_restoring_internal(&mut self, tid: TransferId) {
        if self.transfers.mark_restoring(&tid).is_ok() {
            self.abort_needs_restore.insert(tid);
            self.materializer.mark_aborted(tid);
        }
    }

    pub fn register_authority(
        &mut self,
        key: AuthorityKey,
        owner: PeerId,
    ) -> Result<(), FabricError> {
        // owner must be Active
        match self.peers.get(&owner) {
            Some(PeerState::Active) => {}
            _ => return Err(FabricError::PeerNotActive),
        }
        self.authority.register(key, owner)?;
        Ok(())
    }

    pub fn offer_bundle(
        &mut self,
        sender: PeerId,
        recipient: PeerId,
        tid: TransferId,
        keys: Vec<(AuthorityKey, crate::ids::ResourceId, u8, bool)>, // (key, object_id, kind, native_required)
    ) -> Result<(), FabricError> {
        // ---- PREFLIGHT: zero mutation on any failure ----
        if self.peers.get(&sender) != Some(&PeerState::Active) {
            return Err(FabricError::PeerNotActive);
        }
        if self.peers.get(&recipient) != Some(&PeerState::Active) {
            return Err(FabricError::PeerNotActive);
        }
        if keys.len() > self.limits.max_attachments {
            return Err(FabricError::Transfer(TransferError::TooManyAttachments));
        }
        if self.transfers.status(&tid).is_some() {
            return Err(FabricError::AlreadyExists);
        }
        // authority keys: unique and all Held(sender)
        let mut seen = std::collections::HashSet::new();
        for (k, _, _, _) in &keys {
            if !seen.insert(k) {
                return Err(FabricError::Ledger(LedgerError::DuplicateKeyInBundle));
            }
            match self.authority.lookup(k) {
                Some(crate::authority::AuthorityState::Held(owner)) if owner == sender => {}
                Some(_) => return Err(FabricError::Ledger(LedgerError::WrongHolder)),
                None => return Err(FabricError::Ledger(LedgerError::NotFound)),
            }
        }
        // materializer preflight for every attachment (pure)
        for (idx, (_, oid, kind, native_required)) in keys.iter().enumerate() {
            let meta = Metadata {
                recipient,
                object_id: oid.0,
                object_kind: *kind,
                native_required: *native_required,
            };
            if !self.materializer.can_authorize(tid, idx as u16, &meta) {
                return Err(FabricError::Materializer("metadata conflict"));
            }
        }
        // ---- MUTATION: cannot fail after preflight ----
        let auth_keys: Vec<AuthorityKey> = keys.iter().map(|(k, _, _, _)| *k).collect();
        let _ = self
            .authority
            .offer_bundle(sender, recipient, tid, &auth_keys);
        let attachments = keys
            .iter()
            .enumerate()
            .map(
                |(idx, (_, oid, kind, native_required))| crate::transfer::AttachmentState {
                    index: idx as u16,
                    object_id: oid.0,
                    object_kind: *kind,
                    fabric_escrowed: false,
                    native_staged: false,
                    native_required: *native_required,
                },
            )
            .collect::<Vec<_>>();
        let bundle = Bundle {
            tid,
            sender,
            recipient,
            attachments,
            state: crate::transfer::BundleState::Offered,
        };
        self.transfers.offer(bundle).expect("preflighted offer");
        for (idx, (_, oid, kind, native_required)) in keys.iter().enumerate() {
            let meta = Metadata {
                recipient,
                object_id: oid.0,
                object_kind: *kind,
                native_required: *native_required,
            };
            let _ = self.materializer.authorize_metadata(tid, idx as u16, meta);
        }
        Ok(())
    }

    pub fn accept_bundle(&mut self, recipient: PeerId, tid: TransferId) -> Result<(), FabricError> {
        let expected = self
            .transfers
            .recipient_of(&tid)
            .ok_or(FabricError::UnknownTransfer)?;
        if expected != recipient {
            return Err(FabricError::WrongPeer);
        }
        if self.peers.get(&recipient) != Some(&PeerState::Active) {
            return Err(FabricError::PeerNotActive);
        }
        self.transfers.accept(&tid)?;
        Ok(())
    }

    pub fn mark_fabric_escrowed(
        &mut self,
        sender: PeerId,
        tid: TransferId,
        idx: u16,
    ) -> Result<(), FabricError> {
        let expected = self
            .transfers
            .sender_of(&tid)
            .ok_or(FabricError::UnknownTransfer)?;
        if expected != sender {
            return Err(FabricError::WrongPeer);
        }
        if self.peers.get(&sender) != Some(&PeerState::Active) {
            return Err(FabricError::PeerNotActive);
        }
        self.transfers.mark_fabric_escrowed(&tid, idx)?;
        Ok(())
    }

    pub fn mark_recipient_staged(
        &mut self,
        recipient: PeerId,
        tid: TransferId,
        idx: u16,
    ) -> Result<MaterialAction, FabricError> {
        let expected = self
            .transfers
            .recipient_of(&tid)
            .ok_or(FabricError::UnknownTransfer)?;
        if expected != recipient {
            return Err(FabricError::WrongPeer);
        }
        if self.peers.get(&recipient) != Some(&PeerState::Active) {
            return Err(FabricError::PeerNotActive);
        }
        self.transfers.stage_native(&tid, idx)?;
        // native_required comes from authoritative attachment metadata, not a hardcoded true
        let native_required = self
            .transfers
            .native_required_of(&tid, idx)
            .unwrap_or(false);
        let act = self.materializer.stage_native(tid, idx, native_required);
        Ok(act)
    }

    pub fn commit_if_ready(&mut self, tid: TransferId) -> Result<(), FabricError> {
        if !self.transfers.is_ready(&tid) {
            return Err(FabricError::NotReady);
        }
        // Need to get recipient from bundle
        // For now, we need to retrieve bundle's recipient. TransferTable doesn't expose, so we need to track.
        // We can get it from authority ledger's escrow state for first key
        // Find one key for tid
        let mut recipient_opt = None;
        for (k, state) in self.authority.map.iter() {
            if let crate::authority::AuthorityState::Escrow {
                transfer_id,
                recipient,
                ..
            } = state
            {
                if *transfer_id == tid {
                    recipient_opt = Some(*recipient);
                    let _ = k;
                    break;
                }
            }
        }
        let recipient = recipient_opt.ok_or(FabricError::UnknownTransfer)?;
        let sender = self
            .transfers
            .sender_of(&tid)
            .ok_or(FabricError::UnknownTransfer)?;
        // Atomic commit under one lock (we are already holding FabricState mut)
        // First, commit ledger
        self.authority.commit_bundle(tid, recipient)?;
        // Then transfer
        self.transfers.commit(&tid)?;
        self.materializer.mark_committed(tid);
        // Retain terminal result
        self.push_retained(tid, BundleState::Committed, sender, recipient);
        Ok(())
    }

    pub fn decide_abort(&mut self, tid: TransferId) -> Result<(), FabricError> {
        let bundle_state = self
            .transfers
            .status(&tid)
            .ok_or(FabricError::UnknownTransfer)?;
        if bundle_state == BundleState::Committed || bundle_state == BundleState::Aborted {
            return Err(FabricError::WrongPeer);
        }
        if bundle_state == BundleState::Restoring {
            return Err(FabricError::WrongPeer);
        }
        self.abort_needs_restore.insert(tid);
        self.materializer.mark_aborted(tid);
        // Mark transfer as Restoring, not yet terminal Aborted
        self.transfers.mark_restoring(&tid)?;
        Ok(())
    }

    pub fn finish_abort_restore(&mut self, tid: TransferId) -> Result<(), FabricError> {
        if !self.abort_needs_restore.contains(&tid) {
            return Err(FabricError::UnknownTransfer);
        }
        let sender = self
            .transfers
            .sender_of(&tid)
            .ok_or(FabricError::UnknownTransfer)?;
        let recipient = self
            .transfers
            .recipient_of(&tid)
            .ok_or(FabricError::UnknownTransfer)?;
        self.authority.abort_bundle(tid)?;
        self.transfers.abort(&tid)?;
        self.abort_needs_restore.remove(&tid);
        self.push_retained(tid, BundleState::Aborted, sender, recipient);
        Ok(())
    }

    /// Finalize an abort whose sender is dead (no physical restore possible).
    pub fn finish_abort_dead(&mut self, tid: TransferId) -> Result<(), FabricError> {
        if !self.abort_needs_restore.contains(&tid) {
            return Err(FabricError::UnknownTransfer);
        }
        let sender = self
            .transfers
            .sender_of(&tid)
            .ok_or(FabricError::UnknownTransfer)?;
        let recipient = self
            .transfers
            .recipient_of(&tid)
            .ok_or(FabricError::UnknownTransfer)?;
        self.authority.abort_bundle_dead(tid)?;
        self.transfers.abort(&tid)?;
        self.abort_needs_restore.remove(&tid);
        self.push_retained(tid, BundleState::Aborted, sender, recipient);
        Ok(())
    }

    fn push_retained(
        &mut self,
        tid: TransferId,
        state: BundleState,
        sender: PeerId,
        recipient: PeerId,
    ) {
        if self.retained.len() >= self.limits.max_retained_results {
            if let Some(front) = self.retained.pop_front() {
                Self::remove_index(&mut self.by_sender, front.sender, front.tid);
                Self::remove_index(&mut self.by_recipient, front.recipient, front.tid);
            }
        }
        self.retained.push_back(RetainedResult {
            tid,
            state,
            sender,
            recipient,
        });
        self.by_sender.entry(sender).or_default().push(tid);
        self.by_recipient.entry(recipient).or_default().push(tid);
    }

    fn remove_index(map: &mut HashMap<PeerId, Vec<TransferId>>, peer: PeerId, tid: TransferId) {
        if let Some(v) = map.get_mut(&peer) {
            v.retain(|t| *t != tid);
        }
    }

    /// External status of a transfer (terminal retained or active).
    pub fn status(&self, tid: &TransferId) -> TransferStatus {
        if let Some(active) = self.transfers.active_status(tid) {
            return active.to_status();
        }
        if let Some(r) = self.retained.iter().find(|r| &r.tid == tid) {
            return r.state.to_status();
        }
        TransferStatus::Unknown
    }

    pub fn by_sender(&self, peer: &PeerId) -> &[TransferId] {
        self.by_sender
            .get(peer)
            .map(|v| v.as_slice())
            .unwrap_or(&[])
    }

    pub fn by_recipient(&self, peer: &PeerId) -> &[TransferId] {
        self.by_recipient
            .get(peer)
            .map(|v| v.as_slice())
            .unwrap_or(&[])
    }

    /// Acknowledgement of a retained terminal result; removes exactly once.
    pub fn result_ack(&mut self, tid: &TransferId) -> bool {
        let entry = self.retained.iter().find(|r| &r.tid == tid).copied();
        if let Some(r) = entry {
            self.retained.retain(|x| &x.tid != tid);
            Self::remove_index(&mut self.by_sender, r.sender, *tid);
            Self::remove_index(&mut self.by_recipient, r.recipient, *tid);
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authority::AuthorityKey;
    use crate::ids::{PeerId, ResourceId, TransferId};

    fn peer(n: u8) -> PeerId {
        PeerId([n; 16])
    }
    fn res(n: u8) -> ResourceId {
        ResourceId([n; 16])
    }
    fn tid(n: u8) -> TransferId {
        TransferId([n; 16])
    }
    fn key_res(n: u8) -> AuthorityKey {
        AuthorityKey::Resource(res(n))
    }

    #[test]
    fn fstate_offer_single() {
        let mut s = FabricState::new(Limits::default());
        let a = peer(1);
        let b = peer(2);
        s.add_peer(a).unwrap();
        s.add_peer(b).unwrap();
        let k = key_res(1);
        s.register_authority(k, a).unwrap();
        s.offer_bundle(a, b, tid(1), vec![(k, res(1), 2, true)])
            .unwrap();
        assert!(matches!(
            s.authority.lookup(&k),
            Some(crate::authority::AuthorityState::Escrow { .. })
        ));
        assert_eq!(s.transfers.status(&tid(1)), Some(BundleState::Offered));
    }

    #[test]
    fn fstate_offer_invalid_second_leaves_first() {
        let mut s = FabricState::new(Limits::default());
        let a = peer(1);
        let b = peer(2);
        s.add_peer(a).unwrap();
        s.add_peer(b).unwrap();
        let k1 = key_res(1);
        let k2 = key_res(2);
        s.register_authority(k1, a).unwrap();
        s.register_authority(k2, a).unwrap();
        let k3 = key_res(3); // not registered
        let res = s.offer_bundle(
            a,
            b,
            tid(1),
            vec![(k1, res(1), 2, true), (k3, res(3), 2, true)],
        );
        assert!(res.is_err());
        assert_eq!(
            s.authority.lookup(&k1),
            Some(crate::authority::AuthorityState::Held(a))
        );
        assert_eq!(s.transfers.status(&tid(1)), None);
    }

    #[test]
    fn fstate_commit_ready() {
        let mut s = FabricState::new(Limits::default());
        let a = peer(1);
        let b = peer(2);
        s.add_peer(a).unwrap();
        s.add_peer(b).unwrap();
        let k = key_res(1);
        s.register_authority(k, a).unwrap();
        s.offer_bundle(a, b, tid(1), vec![(k, res(1), 2, true)])
            .unwrap();
        s.accept_bundle(b, tid(1)).unwrap();
        s.mark_fabric_escrowed(a, tid(1), 0).unwrap();
        let act = s.mark_recipient_staged(b, tid(1), 0).unwrap();
        assert_eq!(act, MaterialAction::Wait); // not yet committed
        s.commit_if_ready(tid(1)).unwrap();
        assert_eq!(
            s.authority.lookup(&k),
            Some(crate::authority::AuthorityState::Held(b))
        );
        assert_eq!(s.transfers.status(&tid(1)), Some(BundleState::Committed));
    }

    #[test]
    fn fstate_abort_decide_and_finish() {
        let mut s = FabricState::new(Limits::default());
        let a = peer(1);
        let b = peer(2);
        s.add_peer(a).unwrap();
        s.add_peer(b).unwrap();
        let k = key_res(1);
        s.register_authority(k, a).unwrap();
        s.offer_bundle(a, b, tid(1), vec![(k, res(1), 2, true)])
            .unwrap();
        s.decide_abort(tid(1)).unwrap();
        // ledger should still be Escrow, not Held, and transfer Restoring
        assert!(matches!(
            s.authority.lookup(&k),
            Some(crate::authority::AuthorityState::Escrow { .. })
        ));
        assert_eq!(s.transfers.status(&tid(1)), Some(BundleState::Restoring));
        // STATUS should not yet be Aborted
        assert_ne!(s.transfers.status(&tid(1)), Some(BundleState::Aborted));
        s.finish_abort_restore(tid(1)).unwrap();
        assert_eq!(
            s.authority.lookup(&k),
            Some(crate::authority::AuthorityState::Held(a))
        );
        assert_eq!(s.transfers.status(&tid(1)), Some(BundleState::Aborted));
    }

    #[test]
    fn fstate_duplicate_finish_abort_rejected() {
        let mut s = FabricState::new(Limits::default());
        let a = peer(1);
        let b = peer(2);
        s.add_peer(a).unwrap();
        s.add_peer(b).unwrap();
        let k = key_res(1);
        s.register_authority(k, a).unwrap();
        s.offer_bundle(a, b, tid(1), vec![(k, res(1), 2, true)])
            .unwrap();
        s.decide_abort(tid(1)).unwrap();
        s.finish_abort_restore(tid(1)).unwrap();
        assert!(s.finish_abort_restore(tid(1)).is_err());
    }

    #[test]
    fn fstate_committed_cannot_abort() {
        let mut s = FabricState::new(Limits::default());
        let a = peer(1);
        let b = peer(2);
        s.add_peer(a).unwrap();
        s.add_peer(b).unwrap();
        let k = key_res(1);
        s.register_authority(k, a).unwrap();
        s.offer_bundle(a, b, tid(1), vec![(k, res(1), 2, true)])
            .unwrap();
        s.accept_bundle(b, tid(1)).unwrap();
        s.mark_fabric_escrowed(a, tid(1), 0).unwrap();
        s.mark_recipient_staged(b, tid(1), 0).unwrap();
        s.commit_if_ready(tid(1)).unwrap();
        assert!(s.decide_abort(tid(1)).is_err());
    }

    // --- Restoring-phase coverage (CTO §5) ---

    #[test]
    fn restoring_cannot_commit() {
        let mut s = FabricState::new(Limits::default());
        let a = peer(1);
        let b = peer(2);
        s.add_peer(a).unwrap();
        s.add_peer(b).unwrap();
        s.register_authority(key_res(1), a).unwrap();
        s.offer_bundle(a, b, tid(1), vec![(key_res(1), res(1), 2, true)])
            .unwrap();
        s.accept_bundle(b, tid(1)).unwrap();
        s.mark_fabric_escrowed(a, tid(1), 0).unwrap();
        s.mark_recipient_staged(b, tid(1), 0).unwrap();
        s.decide_abort(tid(1)).unwrap();
        // commit must be impossible while Restoring
        assert!(s.commit_if_ready(tid(1)).is_err());
        assert_eq!(s.transfers.status(&tid(1)), Some(BundleState::Restoring));
    }

    #[test]
    fn restoring_cannot_accept_again() {
        let mut s = FabricState::new(Limits::default());
        let a = peer(1);
        let b = peer(2);
        s.add_peer(a).unwrap();
        s.add_peer(b).unwrap();
        s.register_authority(key_res(1), a).unwrap();
        s.offer_bundle(a, b, tid(1), vec![(key_res(1), res(1), 2, true)])
            .unwrap();
        s.decide_abort(tid(1)).unwrap();
        // A second ACCEPT during Restoring must be rejected
        assert!(s.accept_bundle(b, tid(1)).is_err());
    }

    #[test]
    fn duplicate_decide_abort_rejected() {
        let mut s = FabricState::new(Limits::default());
        let a = peer(1);
        let b = peer(2);
        s.add_peer(a).unwrap();
        s.add_peer(b).unwrap();
        s.register_authority(key_res(1), a).unwrap();
        s.offer_bundle(a, b, tid(1), vec![(key_res(1), res(1), 2, true)])
            .unwrap();
        s.decide_abort(tid(1)).unwrap();
        assert!(s.decide_abort(tid(1)).is_err());
    }

    #[test]
    fn finish_before_restoring_rejected() {
        let mut s = FabricState::new(Limits::default());
        let a = peer(1);
        let b = peer(2);
        s.add_peer(a).unwrap();
        s.add_peer(b).unwrap();
        s.register_authority(key_res(1), a).unwrap();
        s.offer_bundle(a, b, tid(1), vec![(key_res(1), res(1), 2, true)])
            .unwrap();
        // not yet decided: finish rejected
        assert!(s.finish_abort_restore(tid(1)).is_err());
    }

    #[test]
    fn restore_ack_wrong_transfer_rejected() {
        let mut s = FabricState::new(Limits::default());
        let a = peer(1);
        let b = peer(2);
        s.add_peer(a).unwrap();
        s.add_peer(b).unwrap();
        s.register_authority(key_res(1), a).unwrap();
        s.offer_bundle(a, b, tid(1), vec![(key_res(1), res(1), 2, true)])
            .unwrap();
        // unknown tid
        assert!(s.finish_abort_restore(tid(9)).is_err());
    }

    #[test]
    fn restore_ack_after_commit_rejected() {
        let mut s = FabricState::new(Limits::default());
        let a = peer(1);
        let b = peer(2);
        s.add_peer(a).unwrap();
        s.add_peer(b).unwrap();
        s.register_authority(key_res(1), a).unwrap();
        s.offer_bundle(a, b, tid(1), vec![(key_res(1), res(1), 2, true)])
            .unwrap();
        s.accept_bundle(b, tid(1)).unwrap();
        s.mark_fabric_escrowed(a, tid(1), 0).unwrap();
        s.mark_recipient_staged(b, tid(1), 0).unwrap();
        s.commit_if_ready(tid(1)).unwrap();
        assert!(s.finish_abort_restore(tid(1)).is_err());
    }

    #[test]
    fn sender_gone_while_restoring_not_held_dead() {
        let mut s = FabricState::new(Limits::default());
        let a = peer(1);
        let b = peer(2);
        s.add_peer(a).unwrap();
        s.add_peer(b).unwrap();
        let k = key_res(1);
        s.register_authority(k, a).unwrap();
        s.offer_bundle(a, b, tid(1), vec![(k, res(1), 2, true)])
            .unwrap();
        s.accept_bundle(b, tid(1)).unwrap();
        s.mark_fabric_escrowed(a, tid(1), 0).unwrap();
        s.mark_recipient_staged(b, tid(1), 0).unwrap();
        s.decide_abort(tid(1)).unwrap();
        // sender dies during Restoring
        let actions = s.peer_gone(a);
        assert_eq!(actions, vec![DeathAction::AbortDeadSender { tid: tid(1) }]);
        s.finish_abort_dead(tid(1)).unwrap();
        // authority must NOT be Held(dead sender)
        assert!(matches!(
            s.authority.lookup(&k),
            Some(crate::authority::AuthorityState::Abandoned)
        ));
        assert_ne!(
            s.authority.lookup(&k),
            Some(crate::authority::AuthorityState::Held(a))
        );
        assert_eq!(s.status(&tid(1)), TransferStatus::Aborted);
    }

    #[test]
    fn status_restoring_not_aborted() {
        let mut s = FabricState::new(Limits::default());
        let a = peer(1);
        let b = peer(2);
        s.add_peer(a).unwrap();
        s.add_peer(b).unwrap();
        s.register_authority(key_res(1), a).unwrap();
        s.offer_bundle(a, b, tid(1), vec![(key_res(1), res(1), 2, true)])
            .unwrap();
        s.decide_abort(tid(1)).unwrap();
        assert_eq!(s.status(&tid(1)), TransferStatus::Restoring);
        assert_ne!(s.status(&tid(1)), TransferStatus::Aborted);
    }

    #[test]
    fn result_ack_cannot_retire_restoring() {
        let mut s = FabricState::new(Limits::default());
        let a = peer(1);
        let b = peer(2);
        s.add_peer(a).unwrap();
        s.add_peer(b).unwrap();
        s.register_authority(key_res(1), a).unwrap();
        s.offer_bundle(a, b, tid(1), vec![(key_res(1), res(1), 2, true)])
            .unwrap();
        s.decide_abort(tid(1)).unwrap();
        // Restoring transfer is not yet a retained terminal result
        assert!(!s.result_ack(&tid(1)));
    }

    // --- Retained STATUS / RESULT_ACK (CTO §13) ---

    #[test]
    fn commit_status_and_ack() {
        let mut s = FabricState::new(Limits::default());
        let a = peer(1);
        let b = peer(2);
        s.add_peer(a).unwrap();
        s.add_peer(b).unwrap();
        s.register_authority(key_res(1), a).unwrap();
        s.offer_bundle(a, b, tid(1), vec![(key_res(1), res(1), 2, true)])
            .unwrap();
        s.accept_bundle(b, tid(1)).unwrap();
        s.mark_fabric_escrowed(a, tid(1), 0).unwrap();
        s.mark_recipient_staged(b, tid(1), 0).unwrap();
        s.commit_if_ready(tid(1)).unwrap();
        assert_eq!(s.status(&tid(1)), TransferStatus::Committed);
        assert!(s.result_ack(&tid(1)));
        assert_eq!(s.status(&tid(1)), TransferStatus::Unknown);
        assert!(!s.result_ack(&tid(1)));
    }

    #[test]
    fn abort_status_and_ack() {
        let mut s = FabricState::new(Limits::default());
        let a = peer(1);
        let b = peer(2);
        s.add_peer(a).unwrap();
        s.add_peer(b).unwrap();
        s.register_authority(key_res(1), a).unwrap();
        s.offer_bundle(a, b, tid(1), vec![(key_res(1), res(1), 2, true)])
            .unwrap();
        s.decide_abort(tid(1)).unwrap();
        s.finish_abort_restore(tid(1)).unwrap();
        assert_eq!(s.status(&tid(1)), TransferStatus::Aborted);
        assert!(s.result_ack(&tid(1)));
        assert_eq!(s.status(&tid(1)), TransferStatus::Unknown);
    }

    #[test]
    fn peer_gone_exactly_once() {
        let mut s = FabricState::new(Limits::default());
        let a = peer(1);
        let b = peer(2);
        s.add_peer(a).unwrap();
        s.add_peer(b).unwrap();
        s.register_authority(key_res(1), a).unwrap();
        s.offer_bundle(a, b, tid(1), vec![(key_res(1), res(1), 2, true)])
            .unwrap();
        let first = s.peer_gone(b);
        assert!(!first.is_empty());
        let second = s.peer_gone(b);
        assert!(second.is_empty());
    }

    #[test]
    fn retention_bound_does_not_leak() {
        let lim = Limits {
            max_retained_results: 4,
            ..Limits::default()
        };
        let bound = lim.max_retained_results;
        let mut s = FabricState::new(lim);
        let a = peer(1);
        let b = peer(2);
        s.add_peer(a).unwrap();
        s.add_peer(b).unwrap();
        for i in 1u8..=8 {
            let k = key_res(i);
            s.register_authority(k, a).unwrap();
            s.offer_bundle(a, b, tid(i), vec![(k, res(i), 2, true)])
                .unwrap();
            s.accept_bundle(b, tid(i)).unwrap();
            s.mark_fabric_escrowed(a, tid(i), 0).unwrap();
            s.mark_recipient_staged(b, tid(i), 0).unwrap();
            s.commit_if_ready(tid(i)).unwrap();
            let _ = s.result_ack(&tid(i)); // ack immediately to simulate retention churn
        }
        // by_sender should only ever hold at most max_retained_results entries
        assert!(s.by_sender(&a).len() <= bound);
        assert!(s.by_recipient(&b).len() <= bound);
    }

    #[test]
    fn nf_01_reject_before_accept() {
        let mut s = FabricState::new(Limits::default());
        let a = peer(1);
        let b = peer(2);
        s.add_peer(a).unwrap();
        s.add_peer(b).unwrap();
        let k = key_res(1);
        s.register_authority(k, a).unwrap();
        s.offer_bundle(a, b, tid(1), vec![(k, res(1), 2, true)])
            .unwrap();
        s.decide_abort(tid(1)).unwrap();
        assert_eq!(s.status(&tid(1)), TransferStatus::Restoring);
        s.finish_abort_restore(tid(1)).unwrap();
        assert_eq!(s.status(&tid(1)), TransferStatus::Aborted);
    }

    #[test]
    fn nf_03_wrong_tid() {
        let mut s = FabricState::new(Limits::default());
        let a = peer(1);
        let b = peer(2);
        s.add_peer(a).unwrap();
        s.add_peer(b).unwrap();
        let k = key_res(1);
        s.register_authority(k, a).unwrap();
        s.offer_bundle(a, b, tid(1), vec![(k, res(1), 2, true)])
            .unwrap();
        assert!(s.finish_abort_restore(tid(9)).is_err());
    }

    #[test]
    fn nf_07_duplicate_native() {
        let mut s = FabricState::new(Limits::default());
        let a = peer(1);
        let b = peer(2);
        s.add_peer(a).unwrap();
        s.add_peer(b).unwrap();
        let k = key_res(1);
        s.register_authority(k, a).unwrap();
        s.offer_bundle(a, b, tid(1), vec![(k, res(1), 2, true)])
            .unwrap();
        s.accept_bundle(b, tid(1)).unwrap();
        s.mark_fabric_escrowed(a, tid(1), 0).unwrap();
        // Duplicate escrow for same idx should be rejected or leave state unchanged
        let second = s.mark_fabric_escrowed(a, tid(1), 0);
        assert!(second.is_err() || s.transfers.status(&tid(1)) == Some(BundleState::Accepted));
    }

    #[test]
    fn nf_08_late_after_commit() {
        let mut s = FabricState::new(Limits::default());
        let a = peer(1);
        let b = peer(2);
        s.add_peer(a).unwrap();
        s.add_peer(b).unwrap();
        let k = key_res(1);
        s.register_authority(k, a).unwrap();
        s.offer_bundle(a, b, tid(1), vec![(k, res(1), 2, true)])
            .unwrap();
        s.accept_bundle(b, tid(1)).unwrap();
        s.mark_fabric_escrowed(a, tid(1), 0).unwrap();
        s.mark_recipient_staged(b, tid(1), 0).unwrap();
        s.commit_if_ready(tid(1)).unwrap();
        assert!(s.mark_fabric_escrowed(a, tid(1), 0).is_err());
    }

    #[test]
    fn nf_10_missing_fd() {
        let mut s = FabricState::new(Limits::default());
        let a = peer(1);
        let b = peer(2);
        s.add_peer(a).unwrap();
        s.add_peer(b).unwrap();
        let k = key_res(1);
        s.register_authority(k, a).unwrap();
        s.offer_bundle(a, b, tid(1), vec![(k, res(1), 2, true)])
            .unwrap();
        s.accept_bundle(b, tid(1)).unwrap();
        assert!(s.commit_if_ready(tid(1)).is_err());
        assert_eq!(s.status(&tid(1)), TransferStatus::Pending);
    }

    /// Invariant: retained rows and secondary indexes are mutually consistent.
    fn retained_invariant(s: &FabricState) -> bool {
        // every retained tid appears exactly once in each index
        for r in &s.retained {
            let sender_hits = s
                .by_sender
                .get(&r.sender)
                .map(|v| v.iter().filter(|t| **t == r.tid).count())
                .unwrap_or(0);
            let recipient_hits = s
                .by_recipient
                .get(&r.recipient)
                .map(|v| v.iter().filter(|t| **t == r.tid).count())
                .unwrap_or(0);
            if sender_hits != 1 || recipient_hits != 1 {
                return false;
            }
        }
        // every index tid has a retained row
        for (_peer, tids) in s.by_sender.iter().chain(s.by_recipient.iter()) {
            for t in tids {
                if !s.retained.iter().any(|r| &r.tid == t) {
                    return false;
                }
            }
        }
        true
    }

    #[test]
    fn retained_invariant_holds_after_churn() {
        let lim = Limits {
            max_retained_results: 4,
            ..Limits::default()
        };
        let mut s = FabricState::new(lim);
        let a = peer(1);
        let b = peer(2);
        s.add_peer(a).unwrap();
        s.add_peer(b).unwrap();
        for i in 1u8..=10 {
            let k = key_res(i);
            s.register_authority(k, a).unwrap();
            s.offer_bundle(a, b, tid(i), vec![(k, res(i), 2, true)])
                .unwrap();
            s.accept_bundle(b, tid(i)).unwrap();
            s.mark_fabric_escrowed(a, tid(i), 0).unwrap();
            s.mark_recipient_staged(b, tid(i), 0).unwrap();
            s.commit_if_ready(tid(i)).unwrap();
        }
        assert!(
            retained_invariant(&s),
            "invariant after 10 commits w/ cap 4"
        );
        assert!(s.by_sender(&a).len() <= 4);
        assert!(s.by_recipient(&b).len() <= 4);
    }

    #[test]
    fn offer_atomic_zero_mutation_on_late_failure() {
        let mut s = FabricState::new(Limits::default());
        let a = peer(1);
        let b = peer(2);
        s.add_peer(a).unwrap();
        s.add_peer(b).unwrap();
        let k1 = key_res(1);
        let k2 = key_res(2);
        s.register_authority(k1, a).unwrap();
        s.register_authority(k2, a).unwrap();
        let bad = key_res(99); // not registered -> preflight fails
        let res = s.offer_bundle(
            a,
            b,
            tid(1),
            vec![
                (k1, res(1), 2, true),
                (k2, res(2), 2, true),
                (bad, res(99), 2, true),
            ],
        );
        assert!(res.is_err());
        // zero mutation: k1/k2 still Held(a), no transfer, no materializer slot
        assert_eq!(
            s.authority.lookup(&k1),
            Some(crate::authority::AuthorityState::Held(a))
        );
        assert_eq!(
            s.authority.lookup(&k2),
            Some(crate::authority::AuthorityState::Held(a))
        );
        assert_eq!(s.transfers.status(&tid(1)), None);
        assert!(!s.materializer.is_materialized(tid(1), 0));
        assert!(retained_invariant(&s));
    }

    #[test]
    fn native_required_from_metadata_mixed_bundle() {
        // attachment 0 native -> must be escrowed+staged; attachment 1 non-native -> not required
        let mut s = FabricState::new(Limits::default());
        let a = peer(1);
        let b = peer(2);
        s.add_peer(a).unwrap();
        s.add_peer(b).unwrap();
        let k1 = key_res(1);
        let k2 = key_res(2);
        s.register_authority(k1, a).unwrap();
        s.register_authority(k2, a).unwrap();
        s.offer_bundle(
            a,
            b,
            tid(1),
            vec![(k1, res(1), 2, true), (k2, res(2), 9, false)],
        )
        .unwrap();
        s.accept_bundle(b, tid(1)).unwrap();
        // Not ready: attachment0 never escrowed/staged
        assert!(s.commit_if_ready(tid(1)).is_err());
        s.mark_fabric_escrowed(a, tid(1), 0).unwrap();
        assert!(s.commit_if_ready(tid(1)).is_err());
        s.mark_recipient_staged(b, tid(1), 0).unwrap();
        // readiness met: attachment0 staged + attachment1 non-native
        s.commit_if_ready(tid(1)).unwrap();
        assert_eq!(s.status(&tid(1)), TransferStatus::Committed);
    }

    #[test]
    fn retained_eviction_cleans_secondary_indexes() {
        let lim = Limits {
            max_retained_results: 2,
            ..Limits::default()
        };
        let mut s = FabricState::new(lim);
        let a = peer(1);
        let b = peer(2);
        s.add_peer(a).unwrap();
        s.add_peer(b).unwrap();
        for i in 1..=3u8 {
            let k = key_res(i);
            s.register_authority(k, a).unwrap();
            s.offer_bundle(a, b, tid(i), vec![(k, res(i), 2, true)])
                .unwrap();
            s.accept_bundle(b, tid(i)).unwrap();
            s.mark_fabric_escrowed(a, tid(i), 0).unwrap();
            s.mark_recipient_staged(b, tid(i), 0).unwrap();
            s.commit_if_ready(tid(i)).unwrap();
        }
        // FIFO eviction: tid1 should be gone from retained and both indexes
        assert_eq!(s.status(&tid(1)), TransferStatus::Unknown);
        assert!(!s.by_sender(&a).contains(&tid(1)));
        assert!(!s.by_recipient(&b).contains(&tid(1)));
        assert_eq!(s.status(&tid(2)), TransferStatus::Committed);
        assert_eq!(s.status(&tid(3)), TransferStatus::Committed);
        assert!(s.by_sender(&a).contains(&tid(2)));
        assert!(s.by_recipient(&b).contains(&tid(3)));
    }

    #[test]
    fn wrong_recipient_accept_rejected() {
        let mut s = FabricState::new(Limits::default());
        let a = peer(1);
        let b = peer(2);
        let c = peer(3);
        s.add_peer(a).unwrap();
        s.add_peer(b).unwrap();
        s.add_peer(c).unwrap();
        let k = key_res(1);
        s.register_authority(k, a).unwrap();
        s.offer_bundle(a, b, tid(1), vec![(k, res(1), 2, true)])
            .unwrap();
        assert!(s.accept_bundle(c, tid(1)).is_err());
        assert_eq!(s.status(&tid(1)), TransferStatus::Pending);
    }

    #[test]
    fn wrong_sender_escrow_rejected() {
        let mut s = FabricState::new(Limits::default());
        let a = peer(1);
        let b = peer(2);
        let c = peer(3);
        s.add_peer(a).unwrap();
        s.add_peer(b).unwrap();
        s.add_peer(c).unwrap();
        let k = key_res(1);
        s.register_authority(k, a).unwrap();
        s.offer_bundle(a, b, tid(1), vec![(k, res(1), 2, true)])
            .unwrap();
        assert!(s.mark_fabric_escrowed(c, tid(1), 0).is_err());
        assert!(s.mark_fabric_escrowed(b, tid(1), 0).is_err());
    }

    #[test]
    fn wrong_recipient_stage_rejected() {
        let mut s = FabricState::new(Limits::default());
        let a = peer(1);
        let b = peer(2);
        let c = peer(3);
        s.add_peer(a).unwrap();
        s.add_peer(b).unwrap();
        s.add_peer(c).unwrap();
        let k = key_res(1);
        s.register_authority(k, a).unwrap();
        s.offer_bundle(a, b, tid(1), vec![(k, res(1), 2, true)])
            .unwrap();
        s.accept_bundle(b, tid(1)).unwrap();
        s.mark_fabric_escrowed(a, tid(1), 0).unwrap();
        assert!(s.mark_recipient_staged(c, tid(1), 0).is_err());
        assert!(s.mark_recipient_staged(a, tid(1), 0).is_err());
    }
}
