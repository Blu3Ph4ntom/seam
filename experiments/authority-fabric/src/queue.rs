//! Bounded double-accounted queue (message count + byte cost).
//!
//! Unbounded queues are forbidden. This is the only queue type the fabric
//! uses. `try_push` fails with current accounting instead of growing.

use std::collections::VecDeque;
use std::sync::Condvar;
use std::sync::Mutex;
use std::time::{Duration, Instant};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Backlog {
    pub msgs: usize,
    pub bytes: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PopError {
    Timeout,
    Closed,
}

struct Inner<T> {
    q: VecDeque<(T, usize)>,
    msgs: usize,
    bytes: usize,
    closed: bool,
}

pub struct BoundedQueue<T> {
    inner: Mutex<Inner<T>>,
    space: Condvar,
    max_msgs: usize,
    max_bytes: usize,
}

impl<T> BoundedQueue<T> {
    pub fn new(max_msgs: usize, max_bytes: usize) -> Self {
        BoundedQueue {
            inner: Mutex::new(Inner {
                q: VecDeque::new(),
                msgs: 0,
                bytes: 0,
                closed: false,
            }),
            space: Condvar::new(),
            max_msgs,
            max_bytes,
        }
    }

    /// Enqueue without blocking. Fails if either bound would be exceeded or
    /// the queue was closed; the item is returned untouched on failure.
    pub fn try_push(&self, item: T, cost: usize) -> Result<(), (T, Backlog)> {
        let mut g = self.inner.lock().unwrap();
        if g.closed {
            return Err((item, Backlog { msgs: g.msgs, bytes: g.bytes }));
        }
        if g.msgs >= self.max_msgs || g.bytes + cost > self.max_bytes {
            return Err((item, Backlog { msgs: g.msgs, bytes: g.bytes }));
        }
        g.q.push_back((item, cost));
        g.msgs += 1;
        g.bytes += cost;
        drop(g);
        self.space.notify_one();
        Ok(())
    }

    /// Pop with deadline.
    pub fn pop_deadline(&self, deadline: Instant) -> Result<T, PopError> {
        let mut g = self.inner.lock().unwrap();
        loop {
            if let Some((item, cost)) = g.q.pop_front() {
                g.msgs -= 1;
                g.bytes -= cost;
                drop(g);
                return Ok(item);
            }
            if g.closed {
                return Err(PopError::Closed);
            }
            let now = Instant::now();
            if now >= deadline {
                return Err(PopError::Timeout);
            }
            let wait = std::cmp::min(deadline - now, Duration::from_millis(50));
            let (ng, res) = self.space.wait_timeout(g, wait).unwrap();
            g = ng;
            if res.timed_out() && Instant::now() < deadline {
                continue; // spurious or periodic re-check for closure
            }
        }
    }

    pub fn close(&self) {
        let mut g = self.inner.lock().unwrap();
        g.closed = true;
        drop(g);
        self.space.notify_all();
    }

    /// Current accounting snapshot (for state tests).
    pub fn backlog(&self) -> Backlog {
        let g = self.inner.lock().unwrap();
        Backlog { msgs: g.msgs, bytes: g.bytes }
    }

    pub fn is_closed(&self) -> bool {
        self.inner.lock().unwrap().closed
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    #[test]
    fn enforces_message_bound() {
        let q = BoundedQueue::new(2, 1 << 20);
        assert!(q.try_push(1, 0).is_ok());
        assert!(q.try_push(2, 0).is_ok());
        let err = q.try_push(3, 0).unwrap_err();
        assert_eq!(err.0, 3);
        assert_eq!(err.1.msgs, 2);
    }

    #[test]
    fn enforces_byte_bound_and_unwinds_cleanly() {
        let q = BoundedQueue::<u32>::new(100, 8);
        assert!(q.try_push(1, 4).is_ok());
        assert!(q.try_push(2, 4).is_ok());
        let (item, bl) = q.try_push(3, 4).unwrap_err();
        assert_eq!(item, 3);
        assert_eq!(bl.bytes, 8);
        // pops restore accounting exactly
        assert_eq!(q.pop_deadline(Instant::now()).unwrap(), 1);
        assert!(q.try_push(3, 4).is_ok());
    }

    #[test]
    fn close_wakes_waiters() {
        let q = BoundedQueue::<u32>::new(1, 1024);
        let q2 = std::sync::Arc::new(q);
        let h = std::thread::spawn({
            let q = q2.clone();
            move || q.pop_deadline(Instant::now() + Duration::from_secs(10))
        });
        std::thread::sleep(Duration::from_millis(50));
        q2.close();
        assert_eq!(h.join().unwrap(), Err(PopError::Closed));
    }

    #[test]
    fn pop_times_out_when_empty() {
        let q = BoundedQueue::<u32>::new(1, 1024);
        let t0 = Instant::now();
        assert_eq!(
            q.pop_deadline(t0 + Duration::from_millis(60)),
            Err(PopError::Timeout)
        );
        assert!(t0.elapsed() >= Duration::from_millis(55));
    }

    #[test]
    fn push_after_close_fails() {
        let q = BoundedQueue::<u32>::new(1, 1024);
        q.close();
        assert!(q.try_push(1, 0).is_err());
    }
}
