//! Fabric — embedded authority role (V1).
//! Owns PeerTable, TransferTable, and lifecycle. One control thread model.

use std::collections::HashMap;

use crate::ids::{PeerId, TransferId};
use crate::limits::Limits;
use crate::transfer::{Bundle, BundleState, TransferTable};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PeerState {
    Bootstrapping,
    Active,
    Gone,
}

pub struct Fabric {
    #[allow(dead_code)]
    limits: Limits,
    peers: HashMap<PeerId, PeerState>,
    transfers: TransferTable,
}

impl Fabric {
    pub fn new(limits: Limits) -> Self {
        Self {
            limits: limits.clone(),
            peers: HashMap::new(),
            transfers: TransferTable::new(limits),
        }
    }

    pub fn add_peer(&mut self, pid: PeerId) -> Result<(), &'static str> {
        if self.peers.len() >= 1024 {
            return Err("too many peers");
        }
        self.peers.insert(pid, PeerState::Active);
        Ok(())
    }

    pub fn peer_state(&self, pid: &PeerId) -> Option<PeerState> {
        self.peers.get(pid).copied()
    }

    pub fn remove_peer(&mut self, pid: &PeerId) {
        self.peers.remove(pid);
        self.transfers.peer_gone(pid);
        // purge retained results for empty fabric is handled inside transfer table
    }

    pub fn offer_bundle(&mut self, b: Bundle) -> Result<(), String> {
        self.transfers.offer(b).map_err(|e| format!("{:?}", e))
    }

    pub fn accept_bundle(&mut self, tid: &TransferId) -> Result<(), String> {
        self.transfers.accept(tid).map_err(|e| format!("{:?}", e))
    }

    pub fn stage_native(&mut self, tid: &TransferId, idx: u16) -> Result<(), String> {
        self.transfers
            .stage_native(tid, idx)
            .map_err(|e| format!("{:?}", e))
    }

    pub fn commit_bundle(&mut self, tid: &TransferId) -> Result<Bundle, String> {
        self.transfers.commit(tid).map_err(|e| format!("{:?}", e))
    }

    pub fn abort_bundle(&mut self, tid: &TransferId) -> Result<Bundle, String> {
        self.transfers.abort(tid).map_err(|e| format!("{:?}", e))
    }

    pub fn status(&self, tid: &TransferId) -> Option<BundleState> {
        self.transfers.status(tid)
    }

    pub fn ack(&mut self, tid: &TransferId) -> bool {
        self.transfers.result_ack(tid)
    }

    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ids::{PeerId, TransferId};
    use crate::transfer::{AttachmentState, Bundle, BundleState};
    fn pid(n: u8) -> PeerId {
        PeerId([n; 16])
    }
    fn tid(n: u8) -> TransferId {
        TransferId([n; 16])
    }
    #[test]
    fn fabric_peer_lifecycle() {
        let mut f = Fabric::new(Limits::default());
        let p = PeerId::fresh();
        f.add_peer(p).unwrap();
        assert_eq!(f.peer_state(&p), Some(PeerState::Active));
        f.remove_peer(&p);
        assert_eq!(f.peer_state(&p), None);
    }
    #[test]
    fn fabric_bundle_atomic() {
        let mut f = Fabric::new(Limits::default());
        let a = pid(1);
        let b = pid(2);
        f.add_peer(a).unwrap();
        f.add_peer(b).unwrap();
        let bundle = Bundle {
            tid: tid(1),
            sender: a,
            recipient: b,
            attachments: vec![
                AttachmentState {
                    index: 0,
                    object_id: [10; 16],
                    object_kind: 1,
                    native_staged: false,
                    native_required: true,
                },
                AttachmentState {
                    index: 1,
                    object_id: [11; 16],
                    object_kind: 2,
                    native_staged: false,
                    native_required: false,
                },
            ],
            state: BundleState::Offered,
        };
        f.offer_bundle(bundle).unwrap();
        f.accept_bundle(&tid(1)).unwrap();
        assert!(!f.transfers.is_ready(&tid(1)));
        f.stage_native(&tid(1), 0).unwrap();
        assert!(f.transfers.is_ready(&tid(1)));
        let committed = f.commit_bundle(&tid(1)).unwrap();
        assert_eq!(committed.state, BundleState::Committed);
    }
}
