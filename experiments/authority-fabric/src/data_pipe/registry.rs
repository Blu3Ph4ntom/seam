//! Host-authoritative pipe registry (RUN 006A).
//!
//! The Host stores METADATA ONLY: which peer holds the sole Producer, which
//! holds the sole Consumer, the Seam capacity, and per-role transfer state.
//! No payload bytes, no unread positions, no credit counters ever transit
//! the Host — those live with the endpoints themselves.
//!
//! Endpoint movement rides the SAME generic transaction identity as every
//! other authority (`TransferId`) through the standard
//! offer -> accept -> commit | abort arc, independently per role: both a
//! Producer and a Consumer arc may be in flight on one pipe at once.
//! Abort restores the sender with identical accounting; commit is the single
//! point where holders change. There is deliberately no second engine.

use std::collections::{HashMap, VecDeque};

use crate::data_pipe::{PipeId, MAX_PIPE_CAPACITY, PIPE_RETIRE_CAP};
use crate::id::TransferId;
use crate::router::PeerId;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PipeRole {
    Producer,
    Consumer,
}

/// One escrowed authority arc.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Flight {
    tid: TransferId,
    to: PeerId,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PipeReject(pub &'static str);

#[derive(Debug, Clone, Copy)]
struct Entry {
    capacity: usize,
    producer: Option<PeerId>,
    consumer: Option<PeerId>,
    prod_flight: Option<Flight>,
    cons_flight: Option<Flight>,
    retired: bool,
}

impl Entry {
    fn slot(self, role: PipeRole) -> Option<PeerId> {
        match role {
            PipeRole::Producer => self.producer,
            PipeRole::Consumer => self.consumer,
        }
    }
    fn flight(self, role: PipeRole) -> Option<Flight> {
        match role {
            PipeRole::Producer => self.prod_flight,
            PipeRole::Consumer => self.cons_flight,
        }
    }
}

#[derive(Default)]
pub struct PipeTable {
    entries: HashMap<PipeId, Entry>,
    /// Bounded retirement ledger: recent dead PipeIds so late/duplicate
    /// operations fail closed instead of resurrecting authority.
    retired: VecDeque<PipeId>,
}

/// Hard bound on simultaneously live pipes (resource-exhaustion gate).
pub const MAX_LIVE_PIPES: usize = 1024;

impl PipeTable {
    pub fn new() -> Self {
        PipeTable::default()
    }

    pub fn live(&self) -> usize {
        self.entries.iter().filter(|(_, e)| !e.retired).count()
    }

    pub fn capacity_of(&self, pid: &PipeId) -> Option<usize> {
        self.entries
            .get(pid)
            .map(|e| e.capacity)
            .filter(|_| !self.entries[pid].retired)
    }

    /// Visible holder of a role: present while not retired and that role is
    /// not itself escrowed (the OPPOSITE role's flight does not hide it).
    pub fn holder(&self, pid: &PipeId, role: PipeRole) -> Option<PeerId> {
        let e = self.entries.get(pid)?;
        if e.retired || e.flight(role).is_some() {
            return None;
        }
        e.slot(role)
    }

    pub fn producer_holder(&self, pid: &PipeId) -> Option<PeerId> {
        self.holder(pid, PipeRole::Producer)
    }

    pub fn consumer_holder(&self, pid: &PipeId) -> Option<PeerId> {
        self.holder(pid, PipeRole::Consumer)
    }

    pub fn in_transfer(&self, pid: &PipeId, role: PipeRole) -> Option<(TransferId, PeerId)> {
        let e = self.entries.get(pid)?;
        if e.retired {
            return None;
        }
        e.flight(role).map(|f| (f.tid, f.to))
    }

    /// Register a fresh active pipe. Fails closed on bad capacity or an
    /// exhausted table; nothing partial is created.
    pub fn create(
        &mut self,
        pid: PipeId,
        capacity: usize,
        producer: PeerId,
        consumer: PeerId,
    ) -> Result<(), PipeReject> {
        if capacity == 0 || capacity > MAX_PIPE_CAPACITY {
            return Err(PipeReject("capacity invalid"));
        }
        if self.live() >= MAX_LIVE_PIPES {
            return Err(PipeReject("pipe table full"));
        }
        if self.retired.contains(&pid) || self.entries.contains_key(&pid) {
            return Err(PipeReject("duplicate pipe id"));
        }
        self.entries.insert(
            pid,
            Entry {
                capacity,
                producer: Some(producer),
                consumer: Some(consumer),
                prod_flight: None,
                cons_flight: None,
                retired: false,
            },
        );
        Ok(())
    }

    /// Orderly retirement by either current holder (a peer whose role is
    /// mid-flight may also retire its own side's stream).
    pub fn retire(&mut self, pid: &PipeId, by: PeerId) -> Result<(), PipeReject> {
        let e = self
            .entries
            .get_mut(pid)
            .ok_or(PipeReject("unknown pipe"))?;
        if e.retired {
            return Err(PipeReject("already retired"));
        }
        let is_holder = e.producer == Some(by)
            || e.consumer == Some(by)
            || e.prod_flight.map(|f| f.to) == Some(by)
            || e.cons_flight.map(|f| f.to) == Some(by);
        if !is_holder {
            return Err(PipeReject("wrong holder"));
        }
        e.producer = None;
        e.consumer = None;
        e.prod_flight = None;
        e.cons_flight = None;
        e.retired = true;
        self.retired.push_back(*pid);
        while self.retired.len() > PIPE_RETIRE_CAP {
            self.retired.pop_front();
        }
        // Keep the entry only while it can still answer replay rejection;
        // past half the recall window the bounded ledger alone suffices.
        if self.retired.len() > PIPE_RETIRE_CAP / 2 {
            self.entries.remove(pid);
        }
        Ok(())
    }

    /// Escrow ONE role's authority into an in-flight generic transfer.
    pub fn offer_transfer(
        &mut self,
        pid: &PipeId,
        role: PipeRole,
        tid: TransferId,
        from: PeerId,
        to: PeerId,
    ) -> Result<(), PipeReject> {
        let e = self
            .entries
            .get_mut(pid)
            .ok_or(PipeReject("unknown pipe"))?;
        if e.retired {
            return Err(PipeReject("already retired"));
        }
        if e.flight(role).is_some() {
            return Err(PipeReject("stale or foreign transfer"));
        }
        if e.slot(role) != Some(from) {
            return Err(PipeReject(if e.slot(role).is_none() {
                "missing holder"
            } else {
                "wrong holder"
            }));
        }
        if to == from {
            return Err(PipeReject("wrong holder"));
        }
        // Clear the holder atomically with arming the flight: between these
        // there is no observable state where two holders could both act.
        match role {
            PipeRole::Producer => {
                e.producer = None;
                e.prod_flight = Some(Flight { tid, to });
            }
            PipeRole::Consumer => {
                e.consumer = None;
                e.cons_flight = Some(Flight { tid, to });
            }
        }
        Ok(())
    }

    fn find_by_tid(&self, role: PipeRole, tid: TransferId) -> Option<PipeId> {
        self.entries.iter().find_map(|(pid, e)| {
            (!e.retired && e.flight(role).map(|f| f.tid) == Some(tid)).then_some(*pid)
        })
    }

    /// Commit point: exactly one authority mint, order-independent with any
    /// transport/materialization join that references `tid`.
    pub fn commit_transfer(
        &mut self,
        role: PipeRole,
        tid: TransferId,
    ) -> Result<PipeId, PipeReject> {
        let pid = self
            .find_by_tid(role, tid)
            .ok_or(PipeReject("stale or foreign transfer"))?;
        let e = self.entries.get_mut(&pid).unwrap();
        let f = e.flight(role).unwrap();
        match role {
            PipeRole::Producer => {
                debug_assert!(e.producer.is_none());
                e.producer = Some(f.to);
                e.prod_flight = None;
            }
            PipeRole::Consumer => {
                debug_assert!(e.consumer.is_none());
                e.consumer = Some(f.to);
                e.cons_flight = None;
            }
        }
        Ok(pid)
    }

    /// Pre-commit abort: restore the SENDER as holder with identical state.
    /// Post-commit abort attempts find no flight and fail closed.
    pub fn abort_transfer(
        &mut self,
        role: PipeRole,
        tid: TransferId,
        sender: PeerId,
    ) -> Result<PipeId, PipeReject> {
        let pid = self
            .find_by_tid(role, tid)
            .ok_or(PipeReject("stale or foreign transfer"))?;
        let e = self.entries.get_mut(&pid).unwrap();
        match role {
            PipeRole::Producer => {
                debug_assert!(e.producer.is_none());
                e.producer = Some(sender);
                e.prod_flight = None;
            }
            PipeRole::Consumer => {
                debug_assert!(e.consumer.is_none());
                e.consumer = Some(sender);
                e.cons_flight = None;
            }
        }
        Ok(pid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pid(n: u8) -> PipeId {
        let mut b = [0u8; 16];
        b[0] = n;
        PipeId(b)
    }
    fn peer(n: u32) -> PeerId {
        PeerId(n)
    }
    fn tid(n: u8) -> TransferId {
        TransferId([n; 16])
    }

    const CAP: usize = 4096;

    #[test]
    fn create_registers_single_holders() {
        let mut t = PipeTable::new();
        t.create(pid(1), CAP, peer(1), peer(2)).unwrap();
        assert_eq!(t.producer_holder(&pid(1)), Some(peer(1)));
        assert_eq!(t.consumer_holder(&pid(1)), Some(peer(2)));
        assert_eq!(t.capacity_of(&pid(1)), Some(CAP));
        assert!(t.in_transfer(&pid(1), PipeRole::Producer).is_none());
    }

    #[test]
    fn h6_forged_capacity_rejected() {
        let mut t = PipeTable::new();
        assert!(t.create(pid(1), 0, peer(1), peer(2)).is_err());
        assert!(t
            .create(pid(1), MAX_PIPE_CAPACITY + 1, peer(1), peer(2))
            .is_err());
        assert!(t.capacity_of(&pid(1)).is_none());
    }

    #[test]
    fn h1_unknown_pipe_fails_closed() {
        let mut t = PipeTable::new();
        assert_eq!(
            t.offer_transfer(&pid(9), PipeRole::Producer, tid(1), peer(1), peer(2)),
            Err(PipeReject("unknown pipe"))
        );
        assert_eq!(
            t.commit_transfer(PipeRole::Producer, tid(42)),
            Err(PipeReject("stale or foreign transfer"))
        );
    }

    #[test]
    fn h2_h3_wrong_holder_rejected_no_state_change() {
        let mut t = PipeTable::new();
        t.create(pid(1), CAP, peer(1), peer(2)).unwrap();
        // Non-holder tries to offer the producer (H2).
        assert_eq!(
            t.offer_transfer(&pid(1), PipeRole::Producer, tid(1), peer(3), peer(4)),
            Err(PipeReject("wrong holder"))
        );
        // Consumer holder tries to offer the producer role (H3).
        assert_eq!(
            t.offer_transfer(&pid(1), PipeRole::Producer, tid(1), peer(2), peer(3)),
            Err(PipeReject("wrong holder"))
        );
        assert_eq!(t.producer_holder(&pid(1)), Some(peer(1)));
        assert!(t.in_transfer(&pid(1), PipeRole::Producer).is_none());
    }

    #[test]
    fn producer_transfer_moves_sole_authority() {
        let mut t = PipeTable::new();
        t.create(pid(1), CAP, peer(1), peer(2)).unwrap();
        t.offer_transfer(&pid(1), PipeRole::Producer, tid(7), peer(1), peer(3))
            .unwrap();
        // Sender lost it while escrowed.
        assert_eq!(t.producer_holder(&pid(1)), None);
        assert_eq!(
            t.in_transfer(&pid(1), PipeRole::Producer),
            Some((tid(7), peer(3)))
        );
        // Sender cannot re-offer while escrowed.
        assert_eq!(
            t.offer_transfer(&pid(1), PipeRole::Producer, tid(8), peer(1), peer(4)),
            Err(PipeReject("stale or foreign transfer"))
        );
        // Recipient commits: exactly one mint.
        assert_eq!(t.commit_transfer(PipeRole::Producer, tid(7)), Ok(pid(1)));
        assert_eq!(t.producer_holder(&pid(1)), Some(peer(3)));
        assert_eq!(t.consumer_holder(&pid(1)), Some(peer(2)));
    }

    #[test]
    fn abort_restores_sender_with_identical_state() {
        let mut t = PipeTable::new();
        t.create(pid(1), CAP, peer(1), peer(2)).unwrap();
        t.offer_transfer(&pid(1), PipeRole::Producer, tid(7), peer(1), peer(3))
            .unwrap();
        assert_eq!(
            t.abort_transfer(PipeRole::Producer, tid(7), peer(1)),
            Ok(pid(1))
        );
        assert_eq!(t.producer_holder(&pid(1)), Some(peer(1)));
        assert!(t.in_transfer(&pid(1), PipeRole::Producer).is_none());
        // Restored sender can re-offer under a fresh tid.
        t.offer_transfer(&pid(1), PipeRole::Producer, tid(8), peer(1), peer(4))
            .unwrap();
        assert_eq!(t.commit_transfer(PipeRole::Producer, tid(8)), Ok(pid(1)));
        assert_eq!(t.producer_holder(&pid(1)), Some(peer(4)));
    }

    #[test]
    fn post_commit_abort_finds_nothing() {
        let mut t = PipeTable::new();
        t.create(pid(1), CAP, peer(1), peer(2)).unwrap();
        t.offer_transfer(&pid(1), PipeRole::Consumer, tid(5), peer(2), peer(3))
            .unwrap();
        t.commit_transfer(PipeRole::Consumer, tid(5)).unwrap();
        // Commit point passed: neither late abort nor replay commits work.
        assert_eq!(
            t.abort_transfer(PipeRole::Consumer, tid(5), peer(2)),
            Err(PipeReject("stale or foreign transfer"))
        );
        assert_eq!(
            t.commit_transfer(PipeRole::Consumer, tid(5)),
            Err(PipeReject("stale or foreign transfer"))
        );
        assert_eq!(t.consumer_holder(&pid(1)), Some(peer(3)));
    }

    #[test]
    fn h7_stale_or_duplicate_commit_is_noop_failure() {
        let mut t = PipeTable::new();
        t.create(pid(1), CAP, peer(1), peer(2)).unwrap();
        t.offer_transfer(&pid(1), PipeRole::Consumer, tid(5), peer(2), peer(3))
            .unwrap();
        t.commit_transfer(PipeRole::Consumer, tid(5)).unwrap();
        assert_eq!(
            t.commit_transfer(PipeRole::Consumer, tid(5)),
            Err(PipeReject("stale or foreign transfer"))
        );
        assert_eq!(t.consumer_holder(&pid(1)), Some(peer(3)));
        assert_eq!(
            t.abort_transfer(PipeRole::Consumer, tid(6), peer(2)),
            Err(PipeReject("stale or foreign transfer"))
        );
    }

    #[test]
    fn late_operation_after_abort_cannot_mint() {
        let mut t = PipeTable::new();
        t.create(pid(1), CAP, peer(1), peer(2)).unwrap();
        t.offer_transfer(&pid(1), PipeRole::Producer, tid(9), peer(1), peer(3))
            .unwrap();
        t.abort_transfer(PipeRole::Producer, tid(9), peer(1))
            .unwrap();
        assert_eq!(
            t.commit_transfer(PipeRole::Producer, tid(9)),
            Err(PipeReject("stale or foreign transfer"))
        );
        assert_eq!(t.producer_holder(&pid(1)), Some(peer(1)));
    }

    #[test]
    fn retire_then_everything_fails_closed() {
        let mut t = PipeTable::new();
        t.create(pid(1), CAP, peer(1), peer(2)).unwrap();
        t.retire(&pid(1), peer(1)).unwrap();
        assert_eq!(t.producer_holder(&pid(1)), None);
        assert_eq!(t.consumer_holder(&pid(1)), None);
        assert_eq!(
            t.offer_transfer(&pid(1), PipeRole::Producer, tid(1), peer(1), peer(2)),
            Err(PipeReject("already retired"))
        );
    }

    #[test]
    fn non_holder_cannot_retire() {
        let mut t = PipeTable::new();
        t.create(pid(1), CAP, peer(1), peer(2)).unwrap();
        assert_eq!(t.retire(&pid(1), peer(9)), Err(PipeReject("wrong holder")));
        assert_eq!(t.producer_holder(&pid(1)), Some(peer(1)));
    }

    #[test]
    fn resource_exhaustion_bounded_table() {
        let mut t = PipeTable::new();
        for i in 0..MAX_LIVE_PIPES {
            let mut b = [0u8; 16];
            b[..4].copy_from_slice(&(i as u32).to_be_bytes());
            t.create(PipeId(b), CAP, peer(1), peer(2)).unwrap();
        }
        let mut b = [0u8; 16];
        b[..4].copy_from_slice(&u32::MAX.to_be_bytes());
        assert_eq!(
            t.create(PipeId(b), CAP, peer(1), peer(2)),
            Err(PipeReject("pipe table full"))
        );
        // Retirement frees room again.
        let mut b0 = [0u8; 16];
        b0[..4].copy_from_slice(&0u32.to_be_bytes());
        t.retire(&PipeId(b0), peer(1)).unwrap();
        assert_eq!(t.create(PipeId(b), CAP, peer(1), peer(2)), Ok(()));
    }

    #[test]
    fn concurrent_roles_transfer_independently() {
        let mut t = PipeTable::new();
        t.create(pid(1), CAP, peer(1), peer(2)).unwrap();
        t.offer_transfer(&pid(1), PipeRole::Producer, tid(1), peer(1), peer(3))
            .unwrap();
        // Consumer side stays fully visible/operable during producer flight.
        assert_eq!(t.consumer_holder(&pid(1)), Some(peer(2)));
        t.offer_transfer(&pid(1), PipeRole::Consumer, tid(2), peer(2), peer(4))
            .unwrap();
        assert_eq!(t.producer_holder(&pid(1)), None);
        // Commit in REVERSE order: join must be order-independent.
        t.commit_transfer(PipeRole::Consumer, tid(2)).unwrap();
        t.commit_transfer(PipeRole::Producer, tid(1)).unwrap();
        assert_eq!(
            (t.producer_holder(&pid(1)), t.consumer_holder(&pid(1))),
            (Some(peer(3)), Some(peer(4)))
        );
    }

    #[test]
    fn opposite_role_abort_preserves_other_flight() {
        let mut t = PipeTable::new();
        t.create(pid(1), CAP, peer(1), peer(2)).unwrap();
        t.offer_transfer(&pid(1), PipeRole::Producer, tid(1), peer(1), peer(3))
            .unwrap();
        t.offer_transfer(&pid(1), PipeRole::Consumer, tid(2), peer(2), peer(4))
            .unwrap();
        // Abort consumer only: producer arc must stay armed.
        t.abort_transfer(PipeRole::Consumer, tid(2), peer(2))
            .unwrap();
        assert_eq!(
            t.in_transfer(&pid(1), PipeRole::Producer),
            Some((tid(1), peer(3)))
        );
        t.commit_transfer(PipeRole::Producer, tid(1)).unwrap();
        assert_eq!(
            (t.producer_holder(&pid(1)), t.consumer_holder(&pid(1))),
            (Some(peer(3)), Some(peer(2)))
        );
    }

    #[test]
    fn duplicate_pipe_id_rejected_even_after_retire() {
        let mut t = PipeTable::new();
        t.create(pid(1), CAP, peer(1), peer(2)).unwrap();
        t.retire(&pid(1), peer(1)).unwrap();
        assert_eq!(
            t.create(pid(1), CAP, peer(1), peer(2)),
            Err(PipeReject("duplicate pipe id"))
        );
    }
}
