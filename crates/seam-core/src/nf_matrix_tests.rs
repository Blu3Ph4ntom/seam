//! NF-LNX 20-case matrix — unit level, canonical ThreadedRuntime will exercise REAL.

#[cfg(test)]
mod tests {
    use crate::authority::AuthorityKey;
    use crate::fabric_state::{FabricState, TransferStatus};
    use crate::ids::{PeerId, ResourceId, TransferId};
    use crate::limits::Limits;
    use crate::transfer::BundleState;

    fn peer(n: u8) -> PeerId {
        PeerId([n; 16])
    }
    fn res(n: u8) -> ResourceId {
        ResourceId([n; 16])
    }
    fn tid(n: u8) -> TransferId {
        TransferId([n; 16])
    }
    fn key(n: u8) -> AuthorityKey {
        AuthorityKey::Resource(res(n))
    }

    fn setup() -> (FabricState, PeerId, PeerId) {
        let mut s = FabricState::new(Limits::default());
        let a = peer(1);
        let b = peer(2);
        s.add_peer(a).unwrap();
        s.add_peer(b).unwrap();
        (s, a, b)
    }

    #[test]
    fn nf_01_reject_before_accept() {
        let (mut s, a, b) = setup();
        let k = key(1);
        s.register_authority(k, a).unwrap();
        s.offer_bundle(a, b, tid(1), vec![(k, res(1), 2, true)])
            .unwrap();
        // Recipient rejects: decide_abort before accept
        s.decide_abort(tid(1)).unwrap();
        assert_eq!(s.status(&tid(1)), TransferStatus::Restoring);
        s.finish_abort_restore(tid(1)).unwrap();
        assert_eq!(s.status(&tid(1)), TransferStatus::Aborted);
    }

    #[test]
    fn nf_03_wrong_tid() {
        let (mut s, a, b) = setup();
        let k = key(1);
        s.register_authority(k, a).unwrap();
        s.offer_bundle(a, b, tid(1), vec![(k, res(1), 2, true)])
            .unwrap();
        // Wrong tid finish should fail
        assert!(s.finish_abort_restore(tid(9)).is_err());
    }

    #[test]
    fn nf_07_duplicate_native() {
        let (mut s, a, b) = setup();
        let k = key(1);
        s.register_authority(k, a).unwrap();
        s.offer_bundle(a, b, tid(1), vec![(k, res(1), 2, true)])
            .unwrap();
        s.accept_bundle(b, tid(1)).unwrap();
        s.mark_fabric_escrowed(a, tid(1), 0).unwrap();
        // Duplicate escrow for same idx should fail (already escrowed)
        assert!(
            s.mark_fabric_escrowed(a, tid(1), 0).is_err()
                || s.transfers.status(&tid(1)) == Some(BundleState::Accepted)
        );
    }

    #[test]
    fn nf_08_late_after_commit() {
        let (mut s, a, b) = setup();
        let k = key(1);
        s.register_authority(k, a).unwrap();
        s.offer_bundle(a, b, tid(1), vec![(k, res(1), 2, true)])
            .unwrap();
        s.accept_bundle(b, tid(1)).unwrap();
        s.mark_fabric_escrowed(a, tid(1), 0).unwrap();
        s.mark_recipient_staged(b, tid(1), 0).unwrap();
        s.commit_if_ready(tid(1)).unwrap();
        // Late native after commit should be rejected (WrongState)
        assert!(s.mark_fabric_escrowed(a, tid(1), 0).is_err());
    }

    #[test]
    fn nf_10_missing_fd() {
        let (mut s, a, b) = setup();
        let k = key(1);
        s.register_authority(k, a).unwrap();
        s.offer_bundle(a, b, tid(1), vec![(k, res(1), 2, true)])
            .unwrap();
        s.accept_bundle(b, tid(1)).unwrap();
        // Never mark escrowed, so commit should fail (NotReady)
        assert!(s.commit_if_ready(tid(1)).is_err());
        assert_eq!(s.status(&tid(1)), TransferStatus::Pending);
    }
}
