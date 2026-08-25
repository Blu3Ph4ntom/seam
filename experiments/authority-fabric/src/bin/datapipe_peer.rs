//! DataPipe peer process (Windows direct data plane).
//!
//! Topology: the driver wires this binary's stdin/stdout as TWO kernel pipes.
//! For role=consumer: stdin = payload (DATA/CLOSE from producer), stdout =
//! control (CREDIT back to producer). For role=producer: stdin = control,
//! stdout = payload. Diagnostics go to stderr only.

use std::io::{BufRead, BufReader, Read, Write};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use authority_fabric::data_pipe::credit::CreditTracker;

fn marker(s: &str) {
    eprintln!("MARK {s}");
}

// ---- record codec (line header "kind len", DATA body follows) ----

const KIND_DATA: u32 = 1;
const KIND_CLOSE: u32 = 2;
const KIND_CREDIT: u32 = 3;
const KIND_CONSUMER_CLOSE: u32 = 4;

enum Rec {
    Data(Vec<u8>),
    Close,
    Credit(usize),
    ConsumerClose,
}

fn bad(m: &'static str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, m)
}

fn send(w: &mut dyn Write, kind: u32, len: usize) -> std::io::Result<()> {
    writeln!(w, "{kind} {len}")?;
    w.flush()
}

fn read_rec(r: &mut dyn BufRead, max: usize) -> std::io::Result<Option<Rec>> {
    let mut line = String::new();
    if r.read_line(&mut line)? == 0 {
        return Ok(None);
    }
    let mut it = line.split_whitespace();
    let kind: u32 = it
        .next()
        .ok_or_else(|| bad("kind"))?
        .parse()
        .map_err(|_| bad("kind"))?;
    let len: usize = it.next().unwrap_or("0").parse().map_err(|_| bad("len"))?;
    match kind {
        KIND_DATA => {
            if len == 0 || len > max {
                return Err(bad("data len out of bounds"));
            }
            let mut body = vec![0u8; len];
            r.read_exact(&mut body)?;
            Ok(Some(Rec::Data(body)))
        }
        KIND_CLOSE => Ok(Some(Rec::Close)),
        KIND_CREDIT => {
            if len == 0 || len > max {
                return Err(bad("credit delta out of bounds"));
            }
            Ok(Some(Rec::Credit(len)))
        }
        KIND_CONSUMER_CLOSE => Ok(Some(Rec::ConsumerClose)),
        _ => Err(bad("unknown kind")),
    }
}

fn fill(chunk: &mut [u8], seed: u64) {
    let mut s = seed | 1;
    for b in chunk.iter_mut() {
        s ^= s << 13;
        s ^= s >> 7;
        s ^= s << 17;
        *b = s as u8;
    }
}

struct Shared {
    tracker: Mutex<CreditTracker>,
    term: Mutex<bool>,
    cv: Condvar,
}

/// Producer role: writes irregular DATA chunks gated by credit reservation;
/// a control-reader thread consumes CREDIT/CONSUMER_CLOSE and wakes waits.
fn producer_role(cap: usize, total: usize) -> i32 {
    let sh = Arc::new(Shared {
        tracker: Mutex::new(CreditTracker::new(cap).expect("capacity")),
        term: Mutex::new(false),
        cv: Condvar::new(),
    });
    // control-reader thread over stdin
    {
        let sh = sh.clone();
        std::thread::spawn(move || {
            let mut ctrl = BufReader::new(std::io::stdin().lock());
            loop {
                match read_rec(&mut ctrl, cap) {
                    Ok(Some(Rec::Credit(k))) => {
                        let failed = sh.tracker.lock().unwrap().return_credit(k).is_err();
                        sh.cv.notify_all();
                        if failed {
                            marker("PRODUCER_FORGED_CREDIT");
                            *sh.term.lock().unwrap() = true;
                            return;
                        }
                    }
                    Ok(Some(Rec::ConsumerClose)) => {
                        marker("PRODUCER_SAW_CONSUMER_CLOSE");
                        *sh.term.lock().unwrap() = true;
                        sh.cv.notify_all();
                        return;
                    }
                    _ => {
                        // transport death without CONSUMER_CLOSE => PeerGone
                        marker("PRODUCER_PEER_GONE");
                        *sh.term.lock().unwrap() = true;
                        sh.cv.notify_all();
                        return;
                    }
                }
            }
        });
    }

    let out = std::io::stdout();
    let mut out = out.lock();
    let sizes = [
        1usize,
        7,
        17,
        511,
        4096,
        8191,
        32768,
        65535.min(cap),
        3,
        1000,
    ];
    let mut sent = 0usize;
    let mut seed = 0x1234_5678_9abc_def0u64;
    let mut chunk = vec![0u8; cap];
    while sent < total {
        let n = sizes[sent % sizes.len()].min(total - sent);
        fill(&mut chunk[..n], seed);
        seed ^= seed << 1;

        // reservation-safe blocking write
        let mut rem = &chunk[..n];
        while !rem.is_empty() {
            let k = {
                let mut t = sh.tracker.lock().unwrap();
                t.reserve(rem.len())
            };
            if k == 0 {
                marker("WRITER_WAITING_FOR_CREDIT");
                let g = sh.term.lock().unwrap();
                if *g {
                    marker("PRODUCER_BROKEN");
                    return 3;
                }
                let (guard, _) = sh.cv.wait_timeout(g, Duration::from_secs(600)).unwrap();
                drop(guard);
                continue;
            }
            // DATA header then exactly k payload bytes on the payload pipe
            if send(&mut out, KIND_DATA, k).is_err() {
                marker("PRODUCER_MID_RECORD_FAILURE");
                return 4;
            }
            if out.write_all(&rem[..k]).is_err() {
                // mid-record failure: terminal, do NOT reuse reservation
                marker("PRODUCER_MID_RECORD_FAILURE");
                return 4;
            }
            sh.tracker.lock().unwrap().commit(k, k).unwrap();
            rem = &rem[k..];
            sent += k;
        }
    }
    send(&mut out, KIND_CLOSE, 0).expect("close");
    marker("PRODUCER_ORDERLY_CLOSED");
    0
}

/// Consumer role: reads DATA/CLOSE, verifies incrementally, returns batched
/// application-consumed credits. hold=1 stops consuming after the first
/// byte so the driver can prove the exact semantic capacity clamp.
fn consumer_role(cap: usize, mode: &str) -> i32 {
    let hold = mode == "hold";
    let _ = hold;
    // modes: normal | hold_unconsumed | close_early
    let hold_unconsumed = mode == "hold_unconsumed";
    let stdin = std::io::stdin();
    let mut r = stdin.lock();
    let out = std::io::stdout();
    let mut w = out.lock();
    let mut total = 0usize;
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    let mut pending = 0usize;
    let mut orderly = false;
    let mut peer_gone = false;
    let mut staged_unread = 0usize; // bounded by capacity (HOLD_UNCONSUMED)
    loop {
        match read_rec(&mut r, cap) {
            Ok(Some(Rec::Credit(_))) | Ok(Some(Rec::ConsumerClose)) => {}
            Ok(Some(Rec::Data(b))) => {
                for x in &b {
                    hash ^= *x as u64;
                    hash = hash.wrapping_mul(0x1000_0000_01b3);
                }
                total += b.len();
                if hold_unconsumed {
                    staged_unread += b.len(); // staged, NOT consumed
                    if staged_unread >= cap {
                        marker(&format!("CONSUMER_STAGED_CAPACITY bytes={staged_unread}"));
                        // stop reading kernel + return zero credits forever;
                        // producer must now clamp at semantic capacity.
                        let _ = r.read(&mut [0u8; 0]);
                        loop {
                            if r.fill_buf().map(|b| b.is_empty()).unwrap_or(true) {
                                break; // producer died / closed: EOF
                            }
                        }
                        peer_gone = !orderly;
                        break;
                    }
                } else {
                    pending += b.len();
                    if pending >= cap / 4 {
                        send(&mut w, KIND_CREDIT, pending).ok();
                        pending = 0;
                    }
                }
            }
            Ok(Some(Rec::Close)) => {
                orderly = true;
                break;
            }
            Ok(None) => {
                peer_gone = true;
                break;
            }
            Err(_) => break,
        }
    }
    marker(&format!(
        "CONSUMER_DONE total={total} hash={hash:x} orderly={orderly} peer_gone={peer_gone} peak_pending_credit={pending}"
    ));
    // Truncated/unannounced streams are failures, never clean finishes.
    if orderly && !peer_gone {
        0
    } else {
        5
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let code = match args.first().map(String::as_str) {
        Some("producer") => producer_role(
            args.get(1)
                .and_then(|v| v.parse::<usize>().ok())
                .unwrap_or(65536),
            args.get(2)
                .and_then(|v| v.parse::<usize>().ok())
                .unwrap_or(32768),
        ),
        Some("consumer") => consumer_role(
            args.get(1)
                .and_then(|v| v.parse::<usize>().ok())
                .unwrap_or(65536),
            args.get(2).map(String::as_str).unwrap_or("normal"),
        ),
        _ => {
            eprintln!("usage: datapipe_peer producer|consumer <cap> ...");
            2
        }
    };
    std::process::exit(code);
}
