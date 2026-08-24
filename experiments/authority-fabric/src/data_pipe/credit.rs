//! Credit accounting: Seam-visible capacity independent of kernel buffering.
//!
//! OS stream transports accept bytes into platform buffers whose size is
//! unspecified and variable. Seam capacity is therefore enforced HERE: the
//! producer may only "accept" (physically write) bytes while
//! `outstanding < capacity`, and every consumed byte must be returned as a
//! credit. Forged or malformed credit returns are clamped/rejected so a
//! hostile peer cannot push `outstanding` past `capacity`.

#[derive(Debug)]
pub struct CreditTracker {
    capacity: usize,
    /// Bytes the producer may newly reserve.
    available: usize,
    /// Bytes held by in-progress physical writes.
    reserved: usize,
    outstanding: usize,
}

/// Why an input was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CreditError {
    /// Accept attempt exceeded remaining semantic capacity.
    WouldExceedCapacity,
    /// Peer returned more credit than it had consumed (protocol violation).
    ForgedCredit,
    /// Zero-value operation where a positive value is required.
    InvalidDelta,
}

impl CreditTracker {
    pub fn new(capacity: usize) -> Result<Self, CreditError> {
        if capacity == 0 {
            return Err(CreditError::InvalidDelta);
        }
        Ok(CreditTracker {
            capacity,
            available: capacity,
            reserved: 0,
            outstanding: 0,
        })
    }

    pub fn capacity(&self) -> usize {
        self.capacity
    }
    pub fn outstanding(&self) -> usize {
        self.outstanding
    }
    pub fn available_credit(&self) -> usize {
        self.capacity - self.outstanding - self.reserved
    }

    /// Pure query: how many of `want` bytes may be reserved right now.
    pub fn try_accept(&mut self, want: usize) -> Result<usize, CreditError> {
        Ok(want.min(self.available))
    }

    /// Legacy combined accept+commit: reserve then immediately commit.
    pub fn commit_accepted(&mut self, k: usize) -> Result<(), CreditError> {
        let n = self.reserve(k);
        if n != k {
            return Err(CreditError::WouldExceedCapacity);
        }
        self.commit(k, k)
    }

    /// Reserve up to `want` bytes for an in-flight physical write.
    /// Invariant after call: available + reserved + outstanding == capacity.
    pub fn reserve(&mut self, want: usize) -> usize {
        let n = want.min(self.available);
        self.available -= n;
        self.reserved += n;
        n
    }

    /// Physical write settled: `written` becomes outstanding; unused
    /// reservation returns to available.
    pub fn commit(&mut self, reserved_len: usize, written: usize) -> Result<(), CreditError> {
        if written > reserved_len || reserved_len > self.reserved {
            return Err(CreditError::WouldExceedCapacity);
        }
        self.reserved -= reserved_len;
        self.available += reserved_len - written;
        self.outstanding = self
            .outstanding
            .checked_add(written)
            .ok_or(CreditError::WouldExceedCapacity)?;
        debug_assert!(self.invariant_ok());
        Ok(())
    }

    /// Abort an unused reservation (write failed before any byte).
    pub fn abort(&mut self, reserved_len: usize) -> Result<(), CreditError> {
        if reserved_len > self.reserved {
            return Err(CreditError::WouldExceedCapacity);
        }
        self.reserved -= reserved_len;
        self.available += reserved_len;
        debug_assert!(self.invariant_ok());
        Ok(())
    }

    /// Invariant (debug/test): available + reserved + outstanding == capacity.
    pub fn invariant_ok(&self) -> bool {
        self.available + self.reserved + self.outstanding == self.capacity
    }

    pub fn available(&self) -> usize {
        self.available
    }

    pub fn reserved(&self) -> usize {
        self.reserved
    }

    /// Consumer read `k` bytes and returns credit. A forged return larger
    /// than the outstanding total is clamped to the real outstanding value
    /// and reported as an error so callers can log/tear down the connection;
    /// the boundedness invariant still holds either way.
    pub fn return_credit(&mut self, k: usize) -> Result<usize, CreditError> {
        // Forged/malformed reports are REJECTED without mutation: the
        // producer keeps its real outstanding count and tears down.
        if k > self.outstanding {
            return Err(CreditError::ForgedCredit);
        }
        self.outstanding -= k;
        self.available += k;
        debug_assert!(self.invariant_ok());
        Ok(k)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_up_to_capacity_then_blocks_independently_of_kernel() {
        let mut t = CreditTracker::new(64).unwrap();
        // Kernel buffers would happily take far more; the tracker refuses.
        assert_eq!(t.try_accept(1 << 20).unwrap(), 64);
        t.commit_accepted(64).unwrap();
        assert_eq!(t.available_credit(), 0);
        // Credit gate accepts NOTHING when full — even if the kernel buffer
        // below could physically take more. That is the whole point.
        assert_eq!(t.try_accept(10).unwrap(), 0);
    }

    #[test]
    fn partial_accept_at_boundary() {
        let mut t = CreditTracker::new(300).unwrap();
        assert_eq!(t.try_accept(1000).unwrap(), 300);
        t.commit_accepted(300).unwrap();
        assert_eq!(t.outstanding(), 300);
    }

    #[test]
    fn credits_restore_capacity_exactly() {
        let mut t = CreditTracker::new(64).unwrap();
        let n = t.try_accept(64).unwrap();
        t.commit_accepted(n).unwrap();
        for _ in 0..4 {
            t.return_credit(16).unwrap();
        }
        assert_eq!(t.available_credit(), 64);
    }

    #[test]
    fn forged_credit_is_clamped_and_reported() {
        let mut t = CreditTracker::new(64).unwrap();
        let n = t.try_accept(10).unwrap();
        t.commit_accepted(n).unwrap();
        // Hostile peer claims it read 100 bytes when only 10 were sent.
        assert_eq!(t.return_credit(100), Err(CreditError::ForgedCredit));
        // Invariant survived: outstanding unchanged by the forged report.
        assert_eq!(t.outstanding(), 10);
    }

    #[test]
    fn zero_capacity_rejected() {
        assert_eq!(CreditTracker::new(0).err(), Some(CreditError::InvalidDelta));
    }

    #[test]
    fn outstanding_never_exceeds_capacity_under_churn() {
        let mut t = CreditTracker::new(64).unwrap();
        for i in 0..10_000u32 {
            let want = ((i % 97) + 1) as usize;
            let n = t.try_accept(want).unwrap();
            t.commit_accepted(n).unwrap();
            // deterministic consumer drain
            let back = n.min(37);
            let _ = t.return_credit(back).unwrap_or_else(|e| match e {
                CreditError::ForgedCredit => 0,
                _ => 0,
            });
            debug_assert!(t.outstanding() <= t.capacity());
        }
    }

    // ---- reservation model (W1-W5, R1-R9) ----

    #[test]
    fn r1_reserve_moves_available_to_reserved() {
        let mut t = CreditTracker::new(64).unwrap();
        assert_eq!(t.reserve(16), 16);
        assert_eq!((t.available(), t.reserved(), t.outstanding()), (48, 16, 0));
        assert!(t.invariant_ok());
    }

    #[test]
    fn r2_full_commit_reserved_to_outstanding() {
        let mut t = CreditTracker::new(64).unwrap();
        let n = t.reserve(32);
        t.commit(n, n).unwrap();
        assert_eq!((t.available(), t.reserved(), t.outstanding()), (32, 0, 32));
        assert!(t.invariant_ok());
    }

    #[test]
    fn r3_partial_physical_write_restores_unused() {
        let mut t = CreditTracker::new(64).unwrap();
        let n = t.reserve(32);
        // physical write only managed 12 of the 32 reserved bytes
        t.commit(n, 12).unwrap();
        assert_eq!((t.available(), t.reserved(), t.outstanding()), (52, 0, 12));
        assert!(t.invariant_ok());
    }

    #[test]
    fn r4_failed_write_abort_restores_all() {
        let mut t = CreditTracker::new(64).unwrap();
        let n = t.reserve(24);
        t.abort(n).unwrap();
        assert_eq!((t.available(), t.reserved(), t.outstanding()), (64, 0, 0));
        assert!(t.invariant_ok());
    }

    #[test]
    fn r5_credit_return_races_active_reservation_safely() {
        let mut t = CreditTracker::new(64).unwrap();
        t.commit_accepted(16).unwrap(); // outstanding=16
        let n = t.reserve(32); // reserved=32 available=16
                               // consumer consumed 8 while a write is in flight
        t.return_credit(8).unwrap();
        assert_eq!((t.available(), t.reserved(), t.outstanding()), (24, 32, 8));
        assert!(t.invariant_ok());
        t.commit(n, n).unwrap();
        assert_eq!(t.outstanding(), 40);
        assert!(t.invariant_ok());
    }

    #[test]
    fn r6_sequential_reservations_cannot_exceed_capacity() {
        let mut t = CreditTracker::new(64).unwrap();
        let a = t.reserve(40);
        let b = t.reserve(40);
        assert_eq!(a + b, 64);
        assert!(t.invariant_ok());
    }

    #[test]
    fn r7_forged_credit_during_reservation_rejected_no_mutation() {
        let mut t = CreditTracker::new(64).unwrap();
        t.commit_accepted(10).unwrap();
        let rn = t.reserve(20);
        let snap = (t.available(), t.reserved(), t.outstanding());
        assert_eq!(t.return_credit(999), Err(CreditError::ForgedCredit));
        assert_eq!(snap, (t.available(), t.reserved(), t.outstanding()));
        t.abort(rn).unwrap();
        assert!(t.invariant_ok());
    }

    #[test]
    fn r9_bogus_oversized_commit_rejected_state_intact() {
        let mut t = CreditTracker::new(64).unwrap();
        let n = t.reserve(64);
        assert_eq!(
            t.commit(n, usize::MAX),
            Err(CreditError::WouldExceedCapacity)
        );
        assert_eq!(t.reserved(), 64);
        assert_eq!(t.outstanding(), 0);
        t.abort(n).unwrap();
        assert!(t.invariant_ok());
    }
}
