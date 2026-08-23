//! In-memory byte-stream duplex pair. Test transport only: same blocking
//! byte-stream semantics as OS pipes, zero dependencies, works everywhere.

use std::collections::VecDeque;
use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};

struct LinkSide {
    q: Mutex<VecDeque<Vec<u8>>>,
    cv: Condvar,
}

impl LinkSide {
    #[allow(dead_code)]
    fn pop_chunk(&self) -> Option<Vec<u8>> {
        self.q.lock().unwrap().pop_front()
    }
    fn push_front_chunk(&self, c: Vec<u8>) {
        self.q.lock().unwrap().push_front(c);
        self.cv.notify_one();
    }
}

struct Link {
    a_to_b: LinkSide,
    b_to_a: LinkSide,
    closed: AtomicBool,
}

pub struct MemStream {
    link: Arc<Link>,
    /// Which queue this end reads from.
    read_a_to_b: bool,
}

pub fn mem_duplex() -> (MemStream, MemStream) {
    let link = Arc::new(Link {
        a_to_b: LinkSide {
            q: Mutex::new(VecDeque::new()),
            cv: Condvar::new(),
        },
        b_to_a: LinkSide {
            q: Mutex::new(VecDeque::new()),
            cv: Condvar::new(),
        },
        closed: AtomicBool::new(false),
    });
    (
        MemStream {
            link: link.clone(),
            read_a_to_b: true,
        },
        MemStream {
            link,
            read_a_to_b: false,
        },
    )
}

impl MemStream {
    fn my_read_side(&self) -> &LinkSide {
        if self.read_a_to_b {
            &self.link.a_to_b
        } else {
            &self.link.b_to_a
        }
    }
    fn peer_write_side(&self) -> &LinkSide {
        if self.read_a_to_b {
            &self.link.b_to_a
        } else {
            &self.link.a_to_b
        }
    }

    /// Break the link: both ends see EOF.
    pub fn close_link(&self) {
        self.link.closed.store(true, Ordering::SeqCst);
        self.my_read_side().cv.notify_all();
        self.peer_write_side().cv.notify_all();
    }
}

impl io::Read for MemStream {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        let side = self.my_read_side();
        let mut g = side.q.lock().unwrap();
        loop {
            if let Some(mut chunk) = g.pop_front() {
                let n = chunk.len().min(out.len());
                out[..n].copy_from_slice(&chunk[..n]);
                if chunk.len() > n {
                    drop(g);
                    side.push_front_chunk(chunk.split_off(n));
                    return Ok(n);
                }
                drop(g);
                side.cv.notify_one();
                return Ok(n);
            }
            if self.link.closed.load(Ordering::SeqCst) {
                return Ok(0);
            }
            let ng = side.cv.wait(g).unwrap();
            g = ng;
        }
    }
}

impl io::Write for MemStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.link.closed.load(Ordering::SeqCst) {
            return Err(io::Error::new(io::ErrorKind::BrokenPipe, "link closed"));
        }
        let side = self.peer_write_side();
        side.q.lock().unwrap().push_back(buf.to_vec());
        side.cv.notify_one();
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
