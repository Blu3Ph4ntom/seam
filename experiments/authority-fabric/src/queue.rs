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
        self.space.notify_all();
        Ok(())
    }

    /// Enqueue, waiting until space exists or `deadline`. Control-plane
    /// frames use this so they are never silently dropped.
    pub fn push_deadline(&self, item: T, cost: usize, deadline: Instant) -> Result<(), (T, Backlog)> {
        let mut g = self.inner.lock().unwrap();
        loop {
            if g.closed {
                return Err((item, Backlog { msgs: g.msgs, bytes: g.bytes }));
            }
            if g.msgs < self.max_msgs && g.bytes + cost <= self.max_bytes {
                g.q.push_back((item, cost));
                g.msgs += 1;
                g.bytes += cost;
                drop(g);
                self.space.notify_one();
                return Ok(());
            }
            let now = Instant::now();
            if now >= deadline {
                return Err((item, Backlog { msgs: g.msgs, bytes: g.bytes }));
            }
            let wait = std::cmp::min(deadline - now, Duration::from_millis(50));
            let (ng, _) = self.space.wait_timeout(g, wait).unwrap();
            g = ng;
        }
    }

    pub fn try_pop(&self) -> Option<T> {
        let mut g = self.inner.lock().unwrap();
        if let Some((item, cost)) = g.q.pop_front() {
            g.msgs -= 1;
            g.bytes -= cost;
            drop(g);
            self.space.notify_all();
            Some(item)
        } else {
            None
        }
    }

    /// Wake-driven blocking pop: sleeps until an item arrives or the queue
    /// closes. No timers, no periodic re-check.
    pub fn pop_block(&self) -> Option<T> {
        let mut g = self.inner.lock().unwrap();
        loop {
            if let Some((item, cost)) = g.q.pop_front() {
                g.msgs -= 1;
                g.bytes -= cost;
                drop(g);
                self.space.notify_all();
                return Some(item);
            }
            if g.closed {
                return None;
            }
            g = self.space.wait(g).unwrap();
        }
    }

    /// Pop with deadline.
    pub fn pop_deadline(&self, deadline: Instant) -> Result<T, PopError> {
        let mut g = self.inner.lock().unwrap();
        loop {
            if let Some((item, cost)) = g.q.pop_front() {
                g.msgs -= 1;
                g.bytes -= cost;
                drop(g);
                self.space.notify_all();
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

/// Two-compartment bounded queue with ONE wake source. The writer blocks
/// forever on `pop_block` (no timers); a push to either compartment wakes
/// it. Control frames keep a reserved capacity so ordinary DATA can never
/// starve lifecycle traffic. Steady state: zero periodic polling.
pub struct DualQueue<T> {
    inner: Mutex<DualInner<T>>,
    space: Condvar,
    work: Condvar,
    max_data_msgs: usize,
    max_data_bytes: usize,
    max_ctrl_msgs: usize,
    max_ctrl_bytes: usize,
}

struct DualInner<T> {
    data: VecDeque<(T, usize)>,
    ctrl: VecDeque<(T, usize)>,
    d_msgs: usize,
    d_bytes: usize,
    c_msgs: usize,
    c_bytes: usize,
    closed: bool,
}

impl<T> DualQueue<T> {
    pub fn new(
        max_data_msgs: usize,
        max_data_bytes: usize,
        max_ctrl_msgs: usize,
        max_ctrl_bytes: usize,
    ) -> Self {
        DualQueue {
            inner: Mutex::new(DualInner {
                data: VecDeque::new(),
                ctrl: VecDeque::new(),
                d_msgs: 0,
                d_bytes: 0,
                c_msgs: 0,
                c_bytes: 0,
                closed: false,
            }),
            space: Condvar::new(),
            work: Condvar::new(),
            max_data_msgs,
            max_data_bytes,
            max_ctrl_msgs,
            max_ctrl_bytes,
        }
    }

    /// Ordinary application DATA. Never blocks; fails when DATA capacity is
    /// exhausted (backpressure is the caller's problem).
    pub fn push_data(&self, item: T, cost: usize) -> Result<(), (T, Backlog)> {
        let mut g = self.inner.lock().unwrap();
        if g.closed || g.d_msgs >= self.max_data_msgs || g.d_bytes + cost > self.max_data_bytes {
            return Err((item, g.backlog()));
        }
        g.data.push_back((item, cost));
        g.d_msgs += 1;
        g.d_bytes += cost;
        drop(g);
        self.work.notify_all();
        Ok(())
    }

    /// Lifecycle/control frame. Waits (bounded) for reserved capacity; the
    /// item is returned untouched on failure — silent loss is forbidden.
    pub fn push_ctrl(
        &self,
        item: T,
        cost: usize,
        deadline: Instant,
    ) -> Result<(), (T, Backlog)> {
        let mut g = self.inner.lock().unwrap();
        loop {
            if g.closed {
                return Err((item, g.backlog()));
            }
            if g.c_msgs < self.max_ctrl_msgs && g.c_bytes + cost <= self.max_ctrl_bytes {
                g.ctrl.push_back((item, cost));
                g.c_msgs += 1;
                g.c_bytes += cost;
                drop(g);
                self.work.notify_all();
                return Ok(());
            }
            let now = Instant::now();
            if now >= deadline {
                return Err((item, g.backlog()));
            }
            let wait = std::cmp::min(deadline - now, Duration::from_millis(20));
            let (ng, _) = self.space.wait_timeout(g, wait).unwrap();
            g = ng;
        }
    }

    /// Wake-driven pop: control first, then data. `None` only after close
    /// and drain. No timeout, no periodic re-check.
    pub fn pop_block(&self) -> Option<T> {
        let mut g = self.inner.lock().unwrap();
        loop {
            if let Some((item, cost)) = g.ctrl.pop_front() {
                g.c_msgs -= 1;
                g.c_bytes -= cost;
                drop(g);
                self.space.notify_all();
                return Some(item);
            }
            if let Some((item, cost)) = g.data.pop_front() {
                g.d_msgs -= 1;
                g.d_bytes -= cost;
                drop(g);
                self.space.notify_all();
                return Some(item);
            }
            if g.closed {
                return None;
            }
            g = self.work.wait(g).unwrap();
        }
    }

    /// Blocking pop for single-compartment use (child writer).
    pub fn close(&self) {
        let mut g = self.inner.lock().unwrap();
        g.closed = true;
        drop(g);
        self.work.notify_all();
        self.space.notify_all();
    }

    pub fn backlog(&self) -> Backlog {
        self.inner.lock().unwrap().backlog()
    }

    pub fn is_closed(&self) -> bool {
        self.inner.lock().unwrap().closed
    }
}

impl<T> DualInner<T> {
    fn backlog(&self) -> Backlog {
        Backlog {
            msgs: self.d_msgs + self.c_msgs,
            bytes: self.d_bytes + self.c_bytes,
        }
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
