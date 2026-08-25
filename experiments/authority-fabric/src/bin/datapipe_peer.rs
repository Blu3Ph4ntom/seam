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

fn trace(s: &str) {
    if std::env::var_os("SEAM_PIPE_TRACE").is_some() {
        marker(&format!("TRC {s}"));
    }
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
    let n = r.read_line(&mut line)?;
    trace(&format!("rec hdr bytes={n} line={:?}", line.trim_end()));
    if n == 0 {
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
            trace(&format!("rec body want={len}"));
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

struct State {
    tracker: CreditTracker,
    /// Credits received but not yet applied; drained by the writer thread
    /// only after its own commits so forgery detection sees an exact
    /// `outstanding`.
    pending: usize,
    term: bool,
}

struct Shared {
    /// Single state mutex: the writer waits on THIS guard, and every
    /// predicate mutation (credits, termination) happens under it before
    /// notify — no lost-wakeup window can exist.
    st: Mutex<State>,
    /// Set once the CLOSE record has been physically written: control-channel
    /// EOF afterwards is expected teardown, not peer death.
    close_sent: Mutex<bool>,
    cv: Condvar,
}

/// Producer role: writes irregular DATA chunks gated by credit reservation;
/// a control-reader thread consumes CREDIT/CONSUMER_CLOSE and wakes waits.
fn producer_role(cap: usize, total: usize) -> i32 {
    let sh = Arc::new(Shared {
        st: Mutex::new(State {
            tracker: CreditTracker::new(cap).expect("capacity"),
            pending: 0,
            term: false,
        }),
        close_sent: Mutex::new(false),
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
                        trace(&format!("prod credit k={k}"));
                        sh.st.lock().unwrap().pending += k;
                        sh.cv.notify_all();
                    }
                    Ok(Some(Rec::ConsumerClose)) => {
                        marker("PRODUCER_SAW_CONSUMER_CLOSE");
                        sh.st.lock().unwrap().term = true;
                        sh.cv.notify_all();
                        return;
                    }
                    outcome => {
                        // Transport EOF/error without CONSUMER_CLOSE. If we
                        // already sent CLOSE this is the peer's orderly exit;
                        // otherwise it is genuine PeerGone.
                        if *sh.close_sent.lock().unwrap() {
                            marker("PRODUCER_CONTROL_EOF_AFTER_CLOSE");
                        } else {
                            let _ = outcome;
                            marker("PRODUCER_PEER_GONE");
                            sh.st.lock().unwrap().term = true;
                            sh.cv.notify_all();
                        }
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
    // Chunk-size schedule advances per CHUNK (not per sent byte): indexing
    // by `sent % len` self-traps when two adjacent sizes sum to the period
    // (7+3==10) and degrades the stream to an endless 7/3 alternation.
    let mut chunk_idx = 0usize;
    let mut seed = 0x1234_5678_9abc_def0u64;
    let mut chunk = vec![0u8; 65535];
    while sent < total {
        let n = sizes[chunk_idx % sizes.len()].min(total - sent);
        chunk_idx += 1;
        fill(&mut chunk[..n], seed);
        seed ^= seed << 1;

        // reservation-safe blocking write: drain/reserve/wait all under the
        // single state mutex the control reader mutates through.
        let mut rem = &chunk[..n];
        while !rem.is_empty() {
            let k = {
                let mut s = sh.st.lock().unwrap();
                loop {
                    // Apply arrived credits only here, after our own commits:
                    // outstanding is exact, so forgery detection is sound.
                    let got = std::mem::take(&mut s.pending);
                    if got > 0 {
                        if s.tracker.return_credit(got).is_err() {
                            marker("PRODUCER_FORGED_CREDIT");
                            return 3;
                        }
                        continue;
                    }
                    let k = s.tracker.reserve(rem.len());
                    if k > 0 {
                        break k;
                    }
                    if s.term {
                        marker("PRODUCER_BROKEN");
                        return 3;
                    }
                    marker("WRITER_WAITING_FOR_CREDIT");
                    let (guard, _) = sh.cv.wait_timeout(s, Duration::from_secs(600)).unwrap();
                    s = guard;
                }
            };
            // DATA header then exactly k payload bytes on the payload pipe.
            // StdoutLock is a LineWriter: binary bodies contain 0x0A bytes
            // and would leave their post-newline tail buffered while
            // write_all still reports success — an explicit flush makes the
            // physical-write accounting match the credit reservation.
            if send(&mut out, KIND_DATA, k).is_err() {
                marker("PRODUCER_MID_RECORD_FAILURE");
                return 4;
            }
            if out.write_all(&rem[..k]).is_err() || out.flush().is_err() {
                // mid-record failure: terminal, do NOT reuse reservation
                marker("PRODUCER_MID_RECORD_FAILURE");
                return 4;
            }
            sh.st.lock().unwrap().tracker.commit(k, k).unwrap();
            rem = &rem[k..];
            sent += k;
            // Deterministic abrupt-death barrier for harness scenarios:
            // die mid-stream WITHOUT CLOSE after N physical bytes.
            if let Some(n) = std::env::var("SEAM_CRASH_AFTER_BYTES")
                .ok()
                .and_then(|v| v.parse::<usize>().ok())
            {
                if sent >= n {
                    marker("PRODUCER_SELF_CRASH");
                    std::process::exit(101);
                }
            }
        }
    }
    send(&mut out, KIND_CLOSE, 0).expect("close");
    *sh.close_sent.lock().unwrap() = true;
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
    // close_early: after the first DATA record, deliver one credit batch and
    // issue CONSUMER_CLOSE — a deliberate consumer-initiated orderly break.
    let close_early = mode == "close_early";
    let stdin = std::io::stdin();
    let mut r = stdin.lock();
    let out = std::io::stdout();
    let mut w = out.lock();
    let mut total = 0usize;
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    let mut pending = 0usize;
    let mut orderly = false;
    let mut peer_gone = false;
    let mut closed_early = false;
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
                        while let Ok(b) = r.fill_buf() {
                            if b.is_empty() {
                                break; // EOF: producer gone/closed
                            }
                            // Data may sit unconsumed while we hold
                            // capacity; wait for writer death without
                            // consuming. 1ms keeps this off the CPU.
                            std::thread::sleep(Duration::from_millis(1));
                        }
                        peer_gone = !orderly;
                        break;
                    }
                } else {
                    pending += b.len();
                    trace(&format!("cons rec len={} total={total}", b.len()));
                    if pending >= cap / 4 {
                        trace(&format!("cons credit send pending={pending}"));
                        send(&mut w, KIND_CREDIT, pending).ok();
                        pending = 0;
                    }
                    if close_early {
                        marker("CONSUMER_CLOSE_EARLY");
                        send(&mut w, KIND_CONSUMER_CLOSE, 0).ok();
                        closed_early = true;
                        break;
                    }
                }
            }
            Ok(Some(Rec::Close)) => {
                // Deliver every owed credit before orderly completion so the
                // producer's accounting can reach zero; EPIPE here is benign
                // (producer may already be gone after CLOSE).
                if pending > 0 {
                    let _ = send(&mut w, KIND_CREDIT, pending);
                    pending = 0;
                }
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
        "CONSUMER_DONE total={total} hash={hash:x} orderly={orderly} peer_gone={peer_gone} closed_early={closed_early} peak_pending_credit={pending}"
    ));
    // Truncated/unannounced streams are failures, never clean finishes; a
    // deliberate consumer-initiated close IS a clean finish.
    let code = if (orderly && !peer_gone) || closed_early {
        0
    } else {
        5
    };
    eprintln!("CONSUMER_EXIT code={code} orderly={orderly} peer_gone={peer_gone}");
    code
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    eprintln!(
        "PEER_ENTRY pid={} role={:?} argc={} args={:?}",
        std::process::id(),
        args.first(),
        args.len(),
        &args[..args.len().min(4)]
    );
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
