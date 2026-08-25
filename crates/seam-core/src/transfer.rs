//! Generic TransferBundle engine — bundle-aware (CTO 1D).
//! One TransferId identifies 0..N attachments. COMMIT is atomic.

use std::collections::{HashMap, VecDeque};

use crate::ids::{PeerId, TransferId};
use crate::limits::Limits;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BundleState {
    Offered,
    Accepted,
    Committed,
    Aborted,
}

#[derive(Clone, Debug)]
pub struct AttachmentState {
    pub index: u16,
    pub object_id: [u8; 16],
    pub object_kind: u8,
    pub native_staged: bool,
    pub native_required: bool,
}

#[derive(Clone, Debug)]
pub struct Bundle {
    pub tid: TransferId,
    pub sender: PeerId,
    pub recipient: PeerId,
    pub attachments: Vec<AttachmentState>,
    pub state: BundleState,
}

#[derive(Debug)]
pub enum TransferError {
    UnknownTransfer,
    TooManyAttachments,
    TooManyTransfers,
    AlreadyExists,
    WrongState,
    NotReady,
    QuotaExceeded(&'static str),
}

pub struct TransferTable {
    bundles: HashMap<TransferId, Bundle>,
    retained: VecDeque<(TransferId, BundleState)>,
    limits: Limits,
}

impl TransferTable {
    pub fn new(limits: Limits) -> Self {
        Self {
            bundles: HashMap::new(),
            retained: VecDeque::new(),
            limits,
        }
    }

    pub fn offer(&mut self, b: Bundle) -> Result<(), TransferError> {
        if self.bundles.len() >= self.limits.max_transfers_in_flight {
            return Err(TransferError::TooManyTransfers);
        }
        if b.attachments.len() > self.limits.max_attachments {
            return Err(TransferError::TooManyAttachments);
        }
        if self.bundles.contains_key(&b.tid) {
            return Err(TransferError::AlreadyExists);
        }
        self.bundles.insert(b.tid, b);
        Ok(())
    }

    pub fn accept(&mut self, tid: &TransferId) -> Result<(), TransferError> {
        let b = self
            .bundles
            .get_mut(tid)
            .ok_or(TransferError::UnknownTransfer)?;
        if b.state != BundleState::Offered {
            return Err(TransferError::WrongState);
        }
        b.state = BundleState::Accepted;
        Ok(())
    }

    pub fn stage_native(&mut self, tid: &TransferId, index: u16) -> Result<(), TransferError> {
        let b = self
            .bundles
            .get_mut(tid)
            .ok_or(TransferError::UnknownTransfer)?;
        let a = b
            .attachments
            .iter_mut()
            .find(|a| a.index == index)
            .ok_or(TransferError::UnknownTransfer)?;
        a.native_staged = true;
        Ok(())
    }

    pub fn is_ready(&self, tid: &TransferId) -> bool {
        if let Some(b) = self.bundles.get(tid) {
            b.state == BundleState::Accepted
                && b.attachments
                    .iter()
                    .all(|a| !a.native_required || a.native_staged)
        } else {
            false
        }
    }

    pub fn commit(&mut self, tid: &TransferId) -> Result<Bundle, TransferError> {
        let b = self
            .bundles
            .get(tid)
            .ok_or(TransferError::UnknownTransfer)?;
        if b.state != BundleState::Accepted {
            return Err(TransferError::WrongState);
        }
        if !self.is_ready(tid) {
            return Err(TransferError::NotReady);
        }
        let mut b = self.bundles.remove(tid).unwrap();
        b.state = BundleState::Committed;
        self.retain(tid, BundleState::Committed);
        Ok(b)
    }

    pub fn abort(&mut self, tid: &TransferId) -> Result<Bundle, TransferError> {
        let b = self
            .bundles
            .get(tid)
            .ok_or(TransferError::UnknownTransfer)?;
        if b.state == BundleState::Committed {
            return Err(TransferError::WrongState);
        }
        let mut b = self.bundles.remove(tid).unwrap();
        b.state = BundleState::Aborted;
        self.retain(tid, BundleState::Aborted);
        Ok(b)
    }

    pub fn status(&self, tid: &TransferId) -> Option<BundleState> {
        self.bundles.get(tid).map(|b| b.state).or_else(|| {
            self.retained
                .iter()
                .find(|(t, _)| t == tid)
                .map(|(_, s)| *s)
        })
    }

    pub fn result_ack(&mut self, tid: &TransferId) -> bool {
        let before = self.retained.len();
        self.retained.retain(|(t, _)| t != tid);
        before != self.retained.len()
    }

    fn retain(&mut self, tid: &TransferId, s: BundleState) {
        if self.retained.len() >= self.limits.max_retained_results {
            self.retained.pop_front();
        }
        self.retained.push_back((*tid, s));
    }

    /// Purge retained results for a dead sender (peer_gone) + last-peer empty clear.
    pub fn peer_gone(&mut self, _peer: &PeerId) {
        // In this minimal core, TransferId retention is keyed only by tid, not sender.
        // Production Fabric maps tid→sender and purges there; this stub keeps the
        // bounded retention invariant. Full peer-indexed purge lives in seam crate.
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
    #[test]
    fn bundle_atomic_commit() {
        let mut t = TransferTable::new(Limits::default());
        let b = Bundle {
            tid: tid(1),
            sender: peer(1),
            recipient: peer(2),
            attachments: vec![
                AttachmentState {
                    index: 0,
                    object_id: [1; 16],
                    object_kind: 2,
                    native_staged: false,
                    native_required: true,
                },
                AttachmentState {
                    index: 1,
                    object_id: [2; 16],
                    object_kind: 4,
                    native_staged: false,
                    native_required: false,
                },
            ],
            state: BundleState::Offered,
        };
        t.offer(b).unwrap();
        t.accept(&tid(1)).unwrap();
        assert!(!t.is_ready(&tid(1)));
        t.stage_native(&tid(1), 0).unwrap();
        assert!(t.is_ready(&tid(1)));
        let committed = t.commit(&tid(1)).unwrap();
        assert_eq!(committed.state, BundleState::Committed);
        assert_eq!(t.status(&tid(1)), Some(BundleState::Committed));
        assert!(t.result_ack(&tid(1)));
        assert_eq!(t.status(&tid(1)), None);
    }
    #[test]
    fn abort_restores() {
        let mut t = TransferTable::new(Limits::default());
        let b = Bundle {
            tid: tid(2),
            sender: peer(1),
            recipient: peer(2),
            attachments: vec![],
            state: BundleState::Offered,
        };
        t.offer(b).unwrap();
        t.abort(&tid(2)).unwrap();
        assert_eq!(t.status(&tid(2)), Some(BundleState::Aborted));
    }
}
