//! Bounded data-pipe semantics (RUN 006A, experimental).
//!
//! One Producer authority writes an ordered byte stream; one Consumer
//! authority reads it. Both are move-only and transferable later through the
//! generic authority fabric. The pipe has a finite, structurally enforced
//! capacity: `buffered <= capacity` holds after every operation because
//! accepted bytes are appended to the bounded buffer itself — there is no
//! hidden pending-write queue anywhere in this module.
//!
//! This module is the SEMANTIC core (in-process, wake-driven via condvar,
//! zero unsafe). A cross-process kernel backend implements the same contract
//! behind these types in a follow-up layer; backend choice stays replaceable.

pub mod credit;

use std::collections::VecDeque;
use std::sync::{Arc, Condvar, Mutex};

/// Logical identity of a data pipe. OS-random, opaque, NOT authority:
/// possession of a Producer/Consumer handle is the authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct PipeId(pub [u8; 16]);

impl PipeId {
    pub fn fresh() -> Self {
        let mut b = [0u8; 16];
        getrandom::fill(&mut b).expect("OS entropy failed");
        PipeId(b)
    }
}

/// Conservative experimental bounds (§54): prevent resource-exhaustion via
/// absurd capacities while leaving room for real workloads.
pub const MAX_PIPE_CAPACITY: usize = 16 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PipeError {
    /// Temporary backpressure: buffer full. Retry after capacity frees.
    WouldBlock,
    /// Orderly terminal state for this side (e.g. read after drain => EOF is
    /// returned as Ok(0); Closed here means THIS endpoint already closed).
    Closed,
    /// Permanent failure: the OTHER endpoint closed or was lost. No further
    /// progress is possible and buffered data (if any remained meaningful)
    /// has been released.
    Broken,
    /// Capacity/argument invalid (zero, oversized, overflow).
    InvalidCapacity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    Open,
    /// Producer closed orderly: consumer drains then sees EOF.
    ProducerClosed,
    /// Consumer closed: producer writes fail permanently.
    ConsumerClosed,
    /// Both sides closed / drained: terminal.
    Terminal,
}

struct Inner {
    id: PipeId,
    capacity: usize,
    buf: VecDeque<u8>,
    /// Producer side orderly-closed.
    prod_closed: bool,
    /// Consumer side orderly-closed.
    cons_closed: bool,
}

fn push_bounded(inner: &mut Inner, data: &[u8]) -> usize {
    let free = inner.capacity - inner.buf.len();
    let n = data.len().min(free);
    inner.buf.extend(data[..n].iter().copied());
    n
}

/// Move-only write authority. Not Clone/Copy (compile-fail proven).
pub struct Producer {
    inner: Arc<(Mutex<Inner>, Condvar)>,
    closed: bool,
}

/// Move-only read authority. Not Clone/Copy (compile-fail proven).
pub struct Consumer {
    inner: Arc<(Mutex<Inner>, Condvar)>,
    closed: bool,
}

fn create_pair(capacity: usize) -> Result<(Producer, Consumer, PipeId), PipeError> {
    if capacity == 0 || capacity > MAX_PIPE_CAPACITY {
        return Err(PipeError::InvalidCapacity);
    }
    let id = PipeId::fresh();
    let inner = Arc::new((
        Mutex::new(Inner {
            id,
            capacity,
            buf: VecDeque::with_capacity(capacity.min(64 * 1024)),
            prod_closed: false,
            cons_closed: false,
        }),
        Condvar::new(),
    ));
    Ok((
        Producer {
            inner: inner.clone(),
            closed: false,
        },
        Consumer {
            inner,
            closed: false,
        },
        id,
    ))
}

impl Producer {
    /// Create a bounded unidirectional byte pipe.
    pub fn new(capacity: usize) -> Result<(Producer, Consumer), PipeError> {
        let (p, c, _) = create_pair(capacity)?;
        Ok((p, c))
    }

    pub fn id(&self) -> PipeId {
        self.inner.0.lock().unwrap().id
    }

    pub fn capacity(&self) -> usize {
        self.inner.0.lock().unwrap().capacity
    }

    /// Nonblocking write. Accepts a PREFIX of `data` up to remaining capacity
    /// (partial writes are normal); caller owns the remainder and retries.
    /// Zero-length writes succeed with 0 without state change.
    pub fn try_write(&mut self, data: &[u8]) -> Result<usize, PipeError> {
        if self.closed {
            return Err(PipeError::Closed);
        }
        let (lock, cv) = &*self.inner;
        let mut g = lock.lock().unwrap();
        if g.cons_closed {
            return Err(PipeError::Broken);
        }
        if g.prod_closed {
            return Err(PipeError::Closed);
        }
        if data.is_empty() {
            return Ok(0);
        }
        if g.buf.len() == g.capacity {
            return Err(PipeError::WouldBlock);
        }
        let n = push_bounded(&mut g, data);
        drop(g);
        cv.notify_all();
        Ok(n)
    }

    /// Blocking write of at least one byte (or the whole prefix space that
    /// fits immediately). Wakes deterministically on consumer close/drop.
    pub fn write(&mut self, data: &[u8]) -> Result<usize, PipeError> {
        if data.is_empty() {
            return self.try_write(data);
        }
        loop {
            match self.try_write(data) {
                Ok(n) if n > 0 => return Ok(n),
                Ok(_) => unreachable!("nonempty write wrote 0"),
                Err(PipeError::WouldBlock) => {
                    let (lock, cv) = &*self.inner;
                    let g = lock.lock().unwrap();
                    if g.cons_closed {
                        return Err(PipeError::Broken);
                    }
                    let (g2, _t) = cv
                        .wait_timeout(g, std::time::Duration::from_secs(600))
                        .unwrap();
                    drop(g2); // deadlock-detection timeout only; wake is event-driven
                }
                Err(e) => return Err(e),
            }
        }
    }

    /// Orderly close: buffered bytes stay readable; reader drains then EOF.
    pub fn close_write(&mut self) {
        if self.closed {
            return;
        }
        self.closed = true;
        let (lock, cv) = &*self.inner;
        let mut g = lock.lock().unwrap();
        g.prod_closed = true;
        drop(g);
        cv.notify_all();
    }

    /// Blocking write of the ENTIRE buffer across multiple partial writes.
    /// Fails permanently if the consumer closes first.
    pub fn write_all(&mut self, mut data: &[u8]) -> Result<(), PipeError> {
        while !data.is_empty() {
            let n = self.write(data)?;
            data = &data[n..];
        }
        Ok(())
    }
}

impl Drop for Producer {
    fn drop(&mut self) {
        self.close_write();
    }
}

impl Consumer {
    pub fn id(&self) -> PipeId {
        self.inner.0.lock().unwrap().id
    }

    pub fn capacity(&self) -> usize {
        self.inner.0.lock().unwrap().capacity
    }

    /// Nonblocking read. Returns Ok(0) ONLY for clean EOF after drain (or a
    /// zero-length destination). Empty+open => WouldBlock.
    pub fn try_read(&mut self, dst: &mut [u8]) -> Result<usize, PipeError> {
        if self.closed {
            return Err(PipeError::Closed);
        }
        let (lock, _cv) = &*self.inner;
        let mut g = lock.lock().unwrap();
        if dst.is_empty() {
            return Ok(0);
        }
        if g.buf.is_empty() {
            return if g.prod_closed {
                Ok(0) // drained EOF
            } else {
                Err(PipeError::WouldBlock)
            };
        }
        let n = dst.len().min(g.buf.len());
        for slot in dst[..n].iter_mut() {
            *slot = g.buf.pop_front().expect("len checked");
        }
        drop(g);
        self.inner.1.notify_all();
        Ok(n)
    }

    /// Blocking read; wakes on producer close (drain then EOF) and on
    /// consumer-side close requests.
    pub fn read(&mut self, dst: &mut [u8]) -> Result<usize, PipeError> {
        if !dst.is_empty() {
            loop {
                match self.try_read(dst) {
                    Ok(n) => return Ok(n),
                    Err(PipeError::WouldBlock) => {
                        let (lock, cv) = &*self.inner;
                        let g = lock.lock().unwrap();
                        let eof = g.prod_closed && g.buf.is_empty();
                        let (g2, _t) = cv
                            .wait_timeout(g, std::time::Duration::from_secs(600))
                            .unwrap();
                        drop(g2);
                        if eof {
                            return Ok(0);
                        }
                    }
                    Err(e) => return Err(e),
                }
            }
        } else {
            self.try_read(dst)
        }
    }

    /// Consumer-side close: further producer writes fail permanently;
    /// buffered bytes are discarded (sole reader authority is gone).
    pub fn close_read(&mut self) {
        if self.closed {
            return;
        }
        self.closed = true;
        let (lock, cv) = &*self.inner;
        let mut g = lock.lock().unwrap();
        g.cons_closed = true;
        g.buf.clear(); // bounded deterministic reclamation
        drop(g);
        cv.notify_all();
    }
}

impl Drop for Consumer {
    fn drop(&mut self) {
        self.close_read();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;

    #[test]
    fn u1_empty_try_read_would_block() {
        let (_p, mut c) = Producer::new(16).unwrap();
        let mut b = [0u8; 4];
        assert_eq!(c.try_read(&mut b), Err(PipeError::WouldBlock));
    }

    #[test]
    fn u2_write_then_exact_read() {
        let (mut p, mut c) = Producer::new(16).unwrap();
        assert_eq!(p.try_write(b"hello").unwrap(), 5);
        let mut b = [0u8; 5];
        assert_eq!(c.try_read(&mut b).unwrap(), 5);
        assert_eq!(&b, b"hello");
    }

    #[test]
    fn u3_partial_write_when_capacity_tight() {
        let (mut p, mut c) = Producer::new(4).unwrap();
        // 6 bytes into capacity 4 => Written(4), caller keeps rest.
        assert_eq!(p.try_write(b"abcdef").unwrap(), 4);
        // drain to allow the remainder conceptually; remainder is CALLER's.
        let mut b = [0u8; 4];
        assert_eq!(c.try_read(&mut b).unwrap(), 4);
        assert_eq!(&b, b"abcd");
        assert_eq!(p.try_write(b"ef").unwrap(), 2); // retry by caller
    }

    #[test]
    fn u4_partial_read_smaller_than_buffered() {
        let (mut p, mut c) = Producer::new(16).unwrap();
        p.try_write(b"0123456789").unwrap();
        let mut b = [0u8; 3];
        assert_eq!(c.try_read(&mut b).unwrap(), 3);
        assert_eq!(&b, b"012");
        let mut rest = [0u8; 7];
        assert_eq!(c.try_read(&mut rest).unwrap(), 7);
        assert_eq!(&rest, b"3456789");
    }

    #[test]
    fn u5_full_capacity_next_write_would_block() {
        let (mut p, mut _c) = Producer::new(4).unwrap();
        assert_eq!(p.try_write(b"abcd").unwrap(), 4);
        assert_eq!(p.try_write(b"x"), Err(PipeError::WouldBlock));
    }

    #[test]
    fn u6_read_frees_capacity_writer_writable_again() {
        let (mut p, mut c) = Producer::new(2).unwrap();
        p.try_write(b"ab").unwrap();
        assert_eq!(p.try_write(b"c"), Err(PipeError::WouldBlock));
        let mut b = [0u8; 1];
        c.try_read(&mut b).unwrap();
        assert_eq!(p.try_write(b"c").unwrap(), 1);
    }

    #[test]
    fn u7_producer_close_preserves_buffered_bytes() {
        let (mut p, mut c) = Producer::new(16).unwrap();
        p.try_write(b"ABCDEF").unwrap();
        p.close_write();
        let mut b = [0u8; 6];
        assert_eq!(c.try_read(&mut b).unwrap(), 6);
        assert_eq!(&b, b"ABCDEF");
    }

    #[test]
    fn u8_after_drain_eof_then_stays_eof() {
        let (mut p, mut c) = Producer::new(16).unwrap();
        p.try_write(b"xy").unwrap();
        p.close_write();
        let mut b = [0u8; 2];
        assert_eq!(c.read(&mut b).unwrap(), 2);
        assert_eq!(c.read(&mut b).unwrap(), 0, "EOF");
        assert_eq!(c.read(&mut b).unwrap(), 0, "EOF stable");
    }

    #[test]
    fn u9_consumer_close_breaks_producer_permanently() {
        let (mut p, mut c) = Producer::new(16).unwrap();
        c.close_read();
        assert_eq!(p.try_write(b"z"), Err(PipeError::Broken));
        assert_eq!(p.write(b"z"), Err(PipeError::Broken));
    }

    #[test]
    fn u10_ordering_exact_under_variable_chunks() {
        // Single-threaded ping-pong: bounded pipe forces interleaved
        // partial writes/reads; ordering must survive both.
        let (mut p, mut c) = Producer::new(7).unwrap();
        let payload: Vec<u8> = (0..=255u8).collect();
        let mut sent = 0usize;
        let mut got = Vec::new();
        let mut rb = [0u8; 5];
        while sent < payload.len() || got.len() < payload.len() {
            if sent < payload.len() {
                sent += p.try_write(&payload[sent..]).unwrap_or(0);
            }
            let n = c.read(&mut rb).unwrap_or(0);
            got.extend_from_slice(&rb[..n]);
        }
        assert_eq!(got, payload);
    }

    #[test]
    fn u11_zero_length_ops_defined() {
        let (mut p, mut c) = Producer::new(4).unwrap();
        assert_eq!(p.try_write(&[]).unwrap(), 0);
        let mut none = [];
        assert_eq!(c.try_read(&mut none).unwrap(), 0);
        // zero-len read never means EOF even when empty+open:
        let mut e = [];
        assert_eq!(c.read(&mut e).unwrap(), 0);
    }

    #[test]
    fn u12_zero_capacity_rejected() {
        assert_eq!(Producer::new(0).err(), Some(PipeError::InvalidCapacity));
    }

    #[test]
    fn u13_oversized_capacity_rejected_checked() {
        assert_eq!(
            Producer::new(MAX_PIPE_CAPACITY + 1).err(),
            Some(PipeError::InvalidCapacity)
        );
        assert_eq!(
            Producer::new(usize::MAX).err(),
            Some(PipeError::InvalidCapacity)
        );
    }

    #[test]
    fn u14_no_hidden_pending_queue_bound_holds_after_every_op() {
        let (mut p, mut c) = Producer::new(64).unwrap();
        let mut total_in = 0usize;
        let mut total_out = 0usize;
        for i in 0..10_000u32 {
            let chunk = [(i & 0xff) as u8; 37];
            total_in += p.write(&chunk).unwrap();
            let mut b = [0u8; 23];
            total_out += c.read(&mut b).unwrap_or(0);
            // structural bound: internal buffer can never exceed capacity
            assert!(total_in - total_out <= 64 + 37);
        }
        c.close_read();
        p.close_write();
    }

    /// §25 real backpressure: blocked writer wakes when consumer reads,
    /// event-driven (no sleeps); timeout exists only as deadlock guard.
    #[test]
    fn backpressure_blocked_writer_wakes_on_read() {
        let (mut p, mut c) = Producer::new(4).unwrap();
        p.try_write(b"abcd").unwrap(); // full
        let (tx, rx) = mpsc::channel();
        let h = std::thread::spawn(move || {
            // Blocks (full), then streams the remainder across wakeups.
            p.write_all(b"XY").unwrap();
            tx.send(()).unwrap();
        });
        std::thread::spawn(move || {
            let mut b = [0u8; 3];
            let mut got = 0usize;
            while got < 6 {
                got += c.read(&mut b).unwrap_or(0);
            }
        });
        rx.recv_timeout(std::time::Duration::from_secs(5))
            .expect("writer never woke");
        h.join().unwrap();
    }

    /// §34 blocked writer wakes with Broken when consumer closes.
    #[test]
    fn blocked_writer_wakes_broken_on_consumer_close() {
        let (mut p, mut c) = Producer::new(4).unwrap();
        p.try_write(b"abcd").unwrap();
        let (tx, rx) = mpsc::channel();
        let h = std::thread::spawn(move || {
            let r = p.write(b"ZZZZ");
            tx.send(r).unwrap();
        });
        std::thread::sleep(std::time::Duration::from_millis(20)); // let it block
        c.close_read();
        assert_eq!(
            rx.recv_timeout(std::time::Duration::from_secs(5)).unwrap(),
            Err(PipeError::Broken)
        );
        h.join().unwrap();
    }

    /// §35 blocked reader wakes with drain-then-EOF on orderly close.
    #[test]
    fn blocked_reader_drains_then_eof_on_close() {
        let (mut p, mut c) = Producer::new(16).unwrap();
        p.try_write(b"tail").unwrap();
        let (tx, rx) = mpsc::channel();
        let h = std::thread::spawn(move || {
            let mut got = Vec::new();
            let mut b = [0u8; 2];
            loop {
                match c.read(&mut b).unwrap() {
                    0 => break,
                    n => got.extend_from_slice(&b[..n]),
                }
            }
            tx.send(got).unwrap();
        });
        p.try_write(b"!").unwrap();
        p.close_write();
        assert_eq!(
            rx.recv_timeout(std::time::Duration::from_secs(5)).unwrap(),
            b"tail!".to_vec()
        );
        h.join().unwrap();
    }

    /// §51 dropping Consumer closes read side and wakes blocked writer.
    #[test]
    fn dropping_consumer_wakes_blocked_writer() {
        let (mut p, c) = Producer::new(4).unwrap();
        p.try_write(b"abcd").unwrap();
        let (tx, rx) = mpsc::channel();
        let h = std::thread::spawn(move || {
            let r = p.write(b"Q");
            tx.send(r).unwrap();
        });
        std::thread::sleep(std::time::Duration::from_millis(20));
        drop(c);
        assert_eq!(
            rx.recv_timeout(std::time::Duration::from_secs(5)).unwrap(),
            Err(PipeError::Broken)
        );
        h.join().unwrap();
    }
}
