//! CreditTracker — bounded flow-control for DataPipe.
//! Invariant: available + reserved + outstanding == capacity.
//! All ops return Result, never panic on adversarial input.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CreditTracker {
    capacity: usize,
    available: usize,
    reserved: usize,
    outstanding: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CreditError {
    Overflow,
    Underflow,
    InvalidCapacity,
    TooLarge,
}

impl CreditTracker {
    pub fn new(capacity: usize) -> Result<Self, CreditError> {
        if capacity == 0 || capacity > 16 * 1024 * 1024 {
            return Err(CreditError::InvalidCapacity);
        }
        Ok(Self {
            capacity,
            available: capacity,
            reserved: 0,
            outstanding: 0,
        })
    }

    pub fn capacity(&self) -> usize {
        self.capacity
    }
    pub fn available(&self) -> usize {
        self.available
    }
    pub fn reserved(&self) -> usize {
        self.reserved
    }
    pub fn outstanding(&self) -> usize {
        self.outstanding
    }

    pub fn invariant_holds(&self) -> bool {
        self.available
            .checked_add(self.reserved)
            .and_then(|v| v.checked_add(self.outstanding))
            == Some(self.capacity)
    }

    /// Reserve up to `want` bytes. Returns granted amount (min(want, available)).
    pub fn reserve(&mut self, want: usize) -> Result<usize, CreditError> {
        if want == 0 {
            return Ok(0);
        }
        if want > self.capacity {
            return Err(CreditError::TooLarge);
        }
        let grant = std::cmp::min(want, self.available);
        self.available -= grant;
        self.reserved = self
            .reserved
            .checked_add(grant)
            .ok_or(CreditError::Overflow)?;
        debug_assert!(self.invariant_holds());
        Ok(grant)
    }

    /// Commit a physical write of `actual` bytes (actual <= reserved).
    /// Unused reservation returns to available.
    pub fn commit(&mut self, actual: usize) -> Result<(), CreditError> {
        if actual > self.reserved {
            return Err(CreditError::Underflow);
        }
        self.reserved -= actual;
        self.outstanding = self
            .outstanding
            .checked_add(actual)
            .ok_or(CreditError::Overflow)?;
        // Return unused reservation
        // Actually, reserved is now `old_reserved - actual`, but we subtracted actual above.
        // The unused is already in reserved (which is old_reserved - actual). Wait, logic: reserve moves available -> reserved. commit moves reserved -> outstanding for actual, and reserved -> available for unused? Let's clarify: reserve(want) -> reserved = grant, available -= grant. commit(actual): reserved -= actual (the whole reserved is grant, actual <= grant, so 남은 = grant - actual stays in reserved? No, we did reserved -= actual, so reserved = grant - actual (unused). But per spec, unused should return to available, not stay reserved. So after commit, unused should go to available.
        // Fix: reserved -= grant, then outstanding += actual, available += grant - actual.
        // But we already did reserved -= actual, leaving reserved = grant - actual. Need to move that to available.
        let leftover = self.reserved;
        self.reserved = 0;
        self.available = self
            .available
            .checked_add(leftover)
            .ok_or(CreditError::Overflow)?;
        debug_assert!(self.invariant_holds());
        Ok(())
    }

    /// Abort a reservation entirely: reserved -> available.
    pub fn abort_reserve(&mut self, amount: usize) -> Result<(), CreditError> {
        if amount > self.reserved {
            return Err(CreditError::Underflow);
        }
        self.reserved -= amount;
        self.available = self
            .available
            .checked_add(amount)
            .ok_or(CreditError::Overflow)?;
        debug_assert!(self.invariant_holds());
        Ok(())
    }

    /// Application consumed `n` bytes: outstanding -> available.
    pub fn on_consumed(&mut self, n: usize) -> Result<(), CreditError> {
        if n == 0 {
            return Ok(());
        }
        if n > self.outstanding {
            return Err(CreditError::Underflow);
        }
        self.outstanding -= n;
        self.available = self.available.checked_add(n).ok_or(CreditError::Overflow)?;
        debug_assert!(self.invariant_holds());
        Ok(())
    }

    /// Return credit (forged excessive credit must be rejected if it would exceed capacity).
    pub fn return_credit(&mut self, n: usize) -> Result<(), CreditError> {
        if n > self.outstanding {
            return Err(CreditError::Underflow);
        }
        self.outstanding -= n;
        self.available = self.available.checked_add(n).ok_or(CreditError::Overflow)?;
        if self.available > self.capacity {
            return Err(CreditError::Overflow);
        }
        debug_assert!(self.invariant_holds());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_invariant() {
        let mut c = CreditTracker::new(4096).unwrap();
        assert!(c.invariant_holds());
        let g = c.reserve(1000).unwrap();
        assert_eq!(g, 1000);
        assert!(c.invariant_holds());
        c.commit(800).unwrap();
        assert!(c.invariant_holds());
        assert_eq!(c.available, 4096 - 800);
        assert_eq!(c.outstanding, 800);
        c.on_consumed(800).unwrap();
        assert_eq!(c.available, 4096);
    }

    #[test]
    fn clamp_and_partial() {
        let mut c = CreditTracker::new(1024).unwrap();
        let g = c.reserve(2048).unwrap();
        assert_eq!(g, 1024);
        c.commit(512).unwrap();
        assert_eq!(c.outstanding, 512);
        assert_eq!(c.available, 512);
    }

    #[test]
    fn abort_reservation() {
        let mut c = CreditTracker::new(1000).unwrap();
        c.reserve(600).unwrap();
        c.abort_reserve(600).unwrap();
        assert_eq!(c.available, 1000);
    }

    #[test]
    fn forged_excessive_rejected() {
        let mut c = CreditTracker::new(100).unwrap();
        c.reserve(100).unwrap();
        c.commit(100).unwrap();
        assert_eq!(c.return_credit(200), Err(CreditError::Underflow));
    }

    #[test]
    fn ten_k_randomized() {
        let mut c = CreditTracker::new(8192).unwrap();
        let mut rng = 0u64;
        for _ in 0..10_000 {
            rng = rng.wrapping_mul(6364136223846793005).wrapping_add(1);
            let op = (rng % 4) as u8;
            match op {
                0 => {
                    let _ = c.reserve((rng as usize) % 2048);
                }
                1 => {
                    let _ = c.commit((rng as usize) % (c.reserved + 1));
                }
                2 => {
                    let _ = c.on_consumed((rng as usize) % (c.outstanding + 1));
                }
                _ => {
                    let _ = c.abort_reserve((rng as usize) % (c.reserved + 1));
                }
            }
            assert!(c.invariant_holds());
        }
    }
}
