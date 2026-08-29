//! DataPipe physical — production Producer/Consumer over a full-duplex
//! UnixStream, direct peer-to-peer. Fabric is OFF the payload path.
//! Credit returns only on application consumption; producer blocks wake-driven
//! (Condvar + predicate loop), never polls, never sleeps for correctness.

#![cfg(unix)]

use std::collections::hash_map::DefaultHasher;
use std::hash::Hasher;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::sync::{Arc, Condvar, Mutex};

use seam_core::credit::CreditTracker;
use seam_core::datapipe::{decode_one, encode_close, encode_credit, encode_data, Decoded, Record};
use seam_core::ids::PipeId;

/// Shared semantic credit + wake coordination between Producer and its credit
/// reader thread.
struct Shared {
    credit: Mutex<CreditTracker>,
    cond: Condvar,
}

pub struct Producer {
    _pid: PipeId,
    stream: UnixStream, // DATA out (Producer->Consumer), CREDIT in
    shared: Arc<Shared>,
}

pub struct Consumer {
    _pid: PipeId,
    stream: UnixStream, // DATA in, CREDIT out
    shared: Arc<Shared>,
    framing: Vec<u8>, // raw stream bytes for the in-progress record
    pending: Vec<u8>, // delivered payload surplus not yet handed to app
    closed: bool,
}

pub struct DataPipe {
    _pid: PipeId,
}

impl DataPipe {
    pub fn new(pid: PipeId, capacity: usize) -> std::io::Result<(Producer, Consumer)> {
        let credit = CreditTracker::new(capacity)
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "bad capacity"))?;
        let shared = Arc::new(Shared {
            credit: Mutex::new(credit),
            cond: Condvar::new(),
        });
        let (p, c) = UnixStream::pair()?;
        // Producer-side credit reader thread: consumes CREDIT/CONSUMER_CLOSE
        // records from the Consumer->Producer direction.
        let shared_rx = Arc::clone(&shared);
        let mut rx = p.try_clone()?;
        std::thread::spawn(move || {
            let mut framing = Vec::new();
            let mut tmp = [0u8; 1];
            while let Ok(n) = rx.read(&mut tmp) {
                if n == 0 {
                    break;
                }
                framing.push(tmp[0]);
                loop {
                    match decode_one(&framing, 4096) {
                        Ok(Decoded::Complete { record, consumed }) => {
                            match record {
                                Record::Credit(delta) => {
                                    let mut g = shared_rx.credit.lock().unwrap();
                                    let _ = g.return_credit(delta as usize);
                                    shared_rx.cond.notify_all();
                                }
                                Record::ConsumerClose | Record::Close => {
                                    let mut g = shared_rx.credit.lock().unwrap();
                                    let o = g.outstanding();
                                    let _ = g.on_consumed(o);
                                    shared_rx.cond.notify_all();
                                    return;
                                }
                                _ => {}
                            }
                            framing.drain(..consumed);
                            if framing.is_empty() {
                                break;
                            }
                        }
                        Ok(Decoded::NeedMore) => break,
                        Err(_) => return,
                    }
                }
            }
        });
        Ok((
            Producer {
                _pid: pid,
                stream: p,
                shared: Arc::clone(&shared),
            },
            Consumer {
                _pid: pid,
                stream: c,
                shared,
                framing: Vec::new(),
                pending: Vec::new(),
                closed: false,
            },
        ))
    }
}

impl Producer {
    /// Write up to `want` bytes; returns bytes actually written (caller owns
    /// the remainder). Blocks wake-driven while semantic credit is exhausted.
    pub fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        let mut guard = self.shared.credit.lock().unwrap();
        while guard.available() == 0 {
            guard = self.shared.cond.wait(guard).unwrap();
        }
        let want = std::cmp::min(data.len(), guard.capacity());
        let grant = guard.reserve(want).unwrap_or(0);
        drop(guard);
        if grant == 0 {
            return Ok(0);
        }
        let enc = encode_data(&data[..grant], 1024 * 1024)
            .map_err(|e| std::io::Error::other(format!("{e:?}")))?;
        // Write the whole record (blocking); all granted bytes become outstanding.
        self.stream.write_all(&enc)?;
        let mut guard = self.shared.credit.lock().unwrap();
        let _ = guard.commit(grant);
        drop(guard);
        Ok(grant)
    }

    pub fn close(mut self) -> std::io::Result<()> {
        let enc = encode_close();
        self.stream.write_all(&enc)?;
        Ok(())
    }
}

impl Consumer {
    /// Deliver up to `want` application bytes. Surplus payload is buffered;
    /// credit is returned separately via consume().
    pub fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        if !self.pending.is_empty() {
            let take = std::cmp::min(self.pending.len(), out.len());
            out[..take].copy_from_slice(&self.pending[..take]);
            self.pending.drain(..take);
            return Ok(take);
        }
        loop {
            if self.framing.is_empty() {
                let mut tmp = [0u8; 256];
                let n = self.stream.read(&mut tmp)?;
                if n == 0 {
                    self.closed = true;
                    return Ok(0);
                }
                self.framing.extend_from_slice(&tmp[..n]);
            }
            match decode_one(&self.framing, 4096) {
                Ok(Decoded::Complete { record, consumed }) => {
                    self.framing.drain(..consumed);
                    match record {
                        Record::Data(payload) => {
                            let take = std::cmp::min(payload.len(), out.len());
                            out[..take].copy_from_slice(&payload[..take]);
                            if take < payload.len() {
                                self.pending.extend_from_slice(&payload[take..]);
                            }
                            return Ok(take);
                        }
                        Record::Close => {
                            self.closed = true;
                            return Ok(0);
                        }
                        _ => {
                            // unexpected record kind on DATA direction; error
                            return Err(std::io::Error::other("bad data record"));
                        }
                    }
                }
                Ok(Decoded::NeedMore) => {
                    // Need more bytes: top-up framing, then loop.
                    let mut tmp = [0u8; 256];
                    let n = self.stream.read(&mut tmp)?;
                    if n == 0 {
                        self.closed = true;
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::UnexpectedEof,
                            "truncated data record",
                        ));
                    }
                    self.framing.extend_from_slice(&tmp[..n]);
                }
                Err(e) => return Err(std::io::Error::other(format!("{e:?}"))),
            }
        }
    }

    /// Application consumption: return credit for `n` delivered bytes.
    pub fn consume(&mut self, n: usize) -> std::io::Result<()> {
        let enc = encode_credit(n as u32).map_err(|e| std::io::Error::other(format!("{e:?}")))?;
        self.stream.write_all(&enc)?;
        Ok(())
    }

    pub fn is_closed(&self) -> bool {
        self.closed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pid() -> PipeId {
        PipeId([1; 16])
    }

    #[test]
    fn dp_basic_32k_through_4k_flow_control() {
        let (mut producer, mut consumer) = DataPipe::new(pid(), 4096).unwrap();
        let handler = std::thread::spawn(move || {
            let mut produced = 0usize;
            let mut loc = 0u64;
            let mut hasher = DefaultHasher::new();
            while produced < 32768 {
                let mut block = [0u8; 512];
                for b in block.iter_mut() {
                    loc = loc.wrapping_mul(6364136223846793005).wrapping_add(1);
                    *b = (loc >> 33) as u8;
                }
                let n = producer.write(&block).unwrap();
                assert!(n > 0, "producer must never be permanently blocked");
                produced += n;
                hasher.write(&block[..n]);
            }
            producer.close().unwrap();
            hasher.finish()
        });
        let mut received = 0usize;
        let mut hasher = DefaultHasher::new();
        let mut buf = [0u8; 512];
        while received < 32768 {
            let n = consumer.read(&mut buf).unwrap();
            if n == 0 {
                continue; // blocking read will return bytes when available
            }
            received += n;
            hasher.write(&buf[..n]);
            consumer.consume(n).unwrap();
        }
        let prod_hash = handler.join().unwrap();
        assert_eq!(received, 32768);
        assert_eq!(hasher.finish(), prod_hash);
        // All credit returned after full application consumption.
        let g = consumer.shared.credit.lock().unwrap();
        assert_eq!(g.available(), 4096);
        assert_eq!(g.outstanding(), 0);
        assert!(g.invariant_holds());
    }
}
