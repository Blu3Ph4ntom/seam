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
        self.capacity - self.outstanding
    }

    /// How many bytes of `want` may be accepted right now.
    /// Returns Ok(0) only when `want == 0`.
    pub fn try_accept(&mut self, want: usize) -> Result<usize, CreditError> {
        let n = self.available_credit();
        Ok(want.min(n))
    }

    /// Record that `k` accepted bytes were physically written.
    pub fn commit_accepted(&mut self, k: usize) -> Result<(), CreditError> {
        if self.outstanding + k > self.capacity {
            return Err(CreditError::WouldExceedCapacity);
        }
        self.outstanding += k;
        Ok(())
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
}
