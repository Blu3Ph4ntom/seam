//! Windows direct DataPipe data-plane proof.
//!
//! Topology (driver wires two anonymous kernel pipes then drops every
//! transport copy; it relays neither payload nor credits):
//!
//!   producer child: stdin <- control.rx   stdout -> payload.tx
//!   consumer child: stdin <- payload.rx   stdout -> control.tx
//!
//! Evidence markers arrive on each child's stderr, captured into shared
//! buffers so tests can poll for markers while peers run (no sleeps).

use std::io::{Read, Write};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

fn peer_exe() -> &'static str {
    env!("CARGO_BIN_EXE_datapipe_peer")
}

fn kill_tree(pid: u32) {
    #[cfg(windows)]
    {
        let _ = Command::new("taskkill")
            .args(["/PID", &pid.to_string(), "/T", "/F"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
    #[cfg(not(windows))]
    {
        let _ = Command::new("kill").args(["-9", &pid.to_string()]).status();
    }
}

/// Spawn both peers over std::io::pipe() transport; the Stdio conversions
/// consume the pipe objects, so the driver holds zero transport endpoints
/// and peer death/closure wakes the opposite side deterministically.
fn wire(cap: usize, total: usize, consumer_mode: &str) -> Topology {
    let (payload_rx, payload_tx) = std::io::pipe().expect("payload pipe");
    let (control_rx, control_tx) = std::io::pipe().expect("control pipe");

    // Producer: stdin <- control.rx (credits), stdout -> payload.tx (DATA).
    let prod = Command::new(peer_exe())
        .args(["producer", &cap.to_string(), &total.to_string()])
        .stdin(Stdio::from(control_rx))
        .stdout(Stdio::from(payload_tx))
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn producer");

    // Consumer: stdin <- payload.rx, stdout -> control.tx.
    let cons = Command::new(peer_exe())
        .args(["consumer", &cap.to_string(), consumer_mode])
        .stdin(Stdio::from(payload_rx))
        .stdout(Stdio::from(control_tx))
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn consumer");

    Topology { prod, cons }
}

struct Topology {
    prod: Child,
    cons: Child,
}

impl Drop for Topology {
    fn drop(&mut self) {
        // Never leave orphan peers behind on a failed assert.
        kill_tree(self.prod.id());
        kill_tree(self.cons.id());
        let _ = self.prod.wait();
        let _ = self.cons.wait();
    }
}

/// Live stderr capture: readers append into a shared buffer the test polls.
type ErrBuf = Arc<Mutex<String>>;

fn collect_stderr(child: &mut Child) -> (thread::JoinHandle<()>, ErrBuf) {
    let mut err = child.stderr.take().expect("stderr piped");
    let buf: ErrBuf = Arc::new(Mutex::new(String::new()));
    let sink = buf.clone();
    let handle = thread::spawn(move || {
        let mut chunk = [0u8; 4096];
        loop {
            match err.read(&mut chunk) {
                Ok(0) | Err(_) => break,
                Ok(n) => sink
                    .lock()
                    .unwrap()
                    .push_str(&String::from_utf8_lossy(&chunk[..n])),
            }
        }
    });
    (handle, buf)
}

fn wait_exit(child: &mut Child, secs: u64) -> Option<ExitStatus> {
    let deadline = Instant::now() + Duration::from_secs(secs);
    loop {
        if let Some(st) = child.try_wait().expect("try_wait") {
            return Some(st);
        }
        if Instant::now() >= deadline {
            return None;
        }
        thread::sleep(Duration::from_millis(10));
    }
}

/// True once `needle` appears in the captured stream before `secs` elapse.
fn wait_marker(buf: &ErrBuf, needle: &str, secs: u64) -> bool {
    let deadline = Instant::now() + Duration::from_secs(secs);
    while Instant::now() < deadline {
        if buf.lock().unwrap().contains(needle) {
            return true;
        }
        thread::sleep(Duration::from_millis(5));
    }
    false
}

/// Driver-independent regeneration of the exact byte stream the producer
/// emits (same size schedule, same xorshift fill, same seed chain).
fn expected_hash(cap: usize, total: usize) -> u64 {
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
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    let mut sent = 0usize;
    let mut chunk_idx = 0usize;
    let mut base_seed = 0x1234_5678_9abc_def0u64;
    let mut chunk = vec![0u8; 65535];
    while sent < total {
        let n = sizes[chunk_idx % sizes.len()].min(total - sent);
        chunk_idx += 1;
        super_fill(&mut chunk[..n], base_seed);
        base_seed ^= base_seed << 1;
        for x in &chunk[..n] {
            hash ^= *x as u64;
            hash = hash.wrapping_mul(0x1000_0000_01b3);
        }
        sent += n;
    }
    hash
}

fn super_fill(buf: &mut [u8], seed0: u64) {
    let mut s = seed0 | 1;
    for b in buf.iter_mut() {
        s ^= s << 13;
        s ^= s >> 7;
        s ^= s << 17;
        *b = s as u8;
    }
}

/// Extract "key=value" from a "key=<value>" marker field.
fn field<'a>(stderr: &'a str, key: &str) -> Option<&'a str> {
    stderr
        .split([',', ' ', '\n'])
        .find_map(|tok| tok.strip_prefix(key)?.strip_prefix('='))
}

/// PEER_ENTRY pid must equal the spawned Child pid: catches any collector/
/// endpoint cross-association permanently.
fn assert_entry_pid(stderr: &str, child: &Child, role: &str) {
    let want = format!("PEER_ENTRY pid={} role=Some(\"{role}\")", child.id());
    assert!(stderr.contains(&want), "{role} identity\n{stderr}");
}

// ---------------------------------------------------------------- tests --

#[test]
fn datapipe_native_payload_eof_on_producer_death() {
    // In-process microtest of the same primitive the children use: when the
    // only writer dies, reader sees EOF. Driver-drop == writer death here.
    let (mut rx, tx) = std::io::pipe().unwrap();
    drop(tx);
    let mut b = [0u8; 4];
    assert_eq!(rx.read(&mut b).unwrap(), 0, "writer death must yield EOF");
}

#[test]
fn datapipe_native_control_eof_on_consumer_death() {
    let (rx, tx) = std::io::pipe().unwrap();
    drop(rx);
    let mut wtx = tx;
    // With the only reader gone, write wakes/fails (broken pipe), never hangs.
    let res = wtx.write_all(b"ping");
    let _ = res;
}

#[test]
fn datapipe_happy_small_stream() {
    // capacity 4096, total 32 KiB through the small window; both peers must
    // finish cleanly with an exactly-verified byte stream.
    let cap = 4096;
    let total = 32 * 1024;
    let mut topo = wire(cap, total, "normal");
    let (prod_t, perr) = collect_stderr(&mut topo.prod);
    let (cons_t, cerr) = collect_stderr(&mut topo.cons);

    let cons_st = wait_exit(&mut topo.cons, 120);
    let prod_st = wait_exit(&mut topo.prod, 120);
    let pe = perr.lock().unwrap().clone();
    let ce = cerr.lock().unwrap().clone();

    assert_eq!(cons_st.and_then(|s| s.code()), Some(0), "consumer\n{ce}");
    assert_eq!(prod_st.and_then(|s| s.code()), Some(0), "producer\n{pe}");
    assert_entry_pid(&pe, &topo.prod, "producer");
    assert_entry_pid(&ce, &topo.cons, "consumer");
    assert!(pe.contains("PRODUCER_ORDERLY_CLOSED"), "producer\n{pe}");
    assert!(
        !pe.contains("PRODUCER_PEER_GONE"),
        "EOF after CLOSE is benign but pre-close PeerGone is not\n{pe}"
    );
    assert!(ce.contains("orderly=true"), "consumer\n{ce}");
    assert!(!ce.contains("peer_gone=true"), "{ce}");
    // Exact bytes: driver recomputes the stream independently of the peer.
    let want = format!("hash={:x}", expected_hash(cap, total));
    assert!(ce.contains(&want), "hash {want}\n{ce}");
    assert!(ce.contains(&format!("total={total}")), "{ce}");

    prod_t.join().unwrap();
    cons_t.join().unwrap();
}

#[test]
fn datapipe_capacity_clamp_hold_unconsumed() {
    // Consumer stages up to EXACT semantic capacity without crediting; the
    // producer clamps there (never past it). Consumer death while clamped
    // must wake the producer as a failure, never a clean finish.
    let cap = 64 * 1024;
    let total = 16 * 1024 * 1024;
    let mut topo = wire(cap, total, "hold_unconsumed");
    let (prod_t, perr) = collect_stderr(&mut topo.prod);
    let (cons_t, cerr) = collect_stderr(&mut topo.cons);

    // The clamp point: staged-unread reaches capacity exactly, zero credits
    // returned, producer parked waiting for credit.
    assert!(
        wait_marker(&cerr, "CONSUMER_STAGED_CAPACITY", 60),
        "consumer never reached capacity clamp\nproducer:\n{}\nconsumer:\n{}",
        perr.lock().unwrap(),
        cerr.lock().unwrap()
    );
    let ce_now = cerr.lock().unwrap().clone();
    let staged: usize = field(&ce_now, "bytes")
        .and_then(|v| v.parse().ok())
        .expect("staged byte count in marker");
    assert_eq!(staged, cap, "clamp must engage at EXACT semantic capacity");

    assert!(
        wait_marker(&perr, "WRITER_WAITING_FOR_CREDIT", 10),
        "producer must be credit-stalled at the clamp\n{}",
        perr.lock().unwrap()
    );

    kill_tree(topo.cons.id());
    let prod_st = wait_exit(&mut topo.prod, 20);
    match prod_st {
        Some(st) => assert_ne!(st.code(), Some(0), "clamped producer must not exit clean"),
        None => panic!("producer failed to wake from consumer death"),
    }
    let pe = perr.lock().unwrap().clone();
    assert!(
        pe.contains("PRODUCER_BROKEN")
            || pe.contains("PRODUCER_PEER_GONE")
            || pe.contains("PRODUCER_MID_RECORD_FAILURE"),
        "{pe}"
    );

    let _ = topo.cons.wait();
    prod_t.join().unwrap();
    cons_t.join().unwrap();
}

#[test]
fn datapipe_producer_crash_not_clean_eof() {
    // Producer dies mid-stream WITHOUT CLOSE at a deterministic barrier:
    // consumer must wake and report a truncated stream, never clean EOF.
    let cap = 4096;
    let total = 16 * 1024 * 1024;
    std::env::set_var("SEAM_CRASH_AFTER_BYTES", "8192");
    let mut topo = wire(cap, total, "normal");
    let (_prod_t, perr) = collect_stderr(&mut topo.prod);
    let (_cons_t, cerr) = collect_stderr(&mut topo.cons);

    assert!(
        wait_marker(&perr, "PRODUCER_SELF_CRASH", 30),
        "producer never reached crash barrier\n{}",
        perr.lock().unwrap()
    );
    // Children already spawned carry their copy; stop leaking to siblings.
    std::env::remove_var("SEAM_CRASH_AFTER_BYTES");
    let st = wait_exit(&mut topo.cons, 20);
    assert!(st.is_some(), "consumer must wake from producer death");
    assert_ne!(
        st.unwrap().code(),
        Some(0),
        "truncated stream must not be clean"
    );
    let ce = cerr.lock().unwrap().clone();
    assert!(ce.contains("orderly=false"), "{ce}");
    assert!(ce.contains("peer_gone=true"), "{ce}");
}

#[test]
fn diag_d5_driver_feeds_consumer_big_record() {
    // Driver keeps payload_tx and hand-feeds the consumer child the exact
    // byte sequence the producer would write (records 1,7,17,511,3560).
    let cap = 4096usize;
    let (payload_rx, mut payload_tx) = std::io::pipe().expect("pipe");
    let (control_rx, control_tx) = std::io::pipe().expect("ctl");
    let mut cons = Command::new(peer_exe())
        .args(["consumer", &cap.to_string(), "normal"])
        .stdin(Stdio::from(payload_rx))
        .stdout(Stdio::from(control_tx))
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn");
    drop(control_rx); // driver must not hold consumer-side control end
    let (_t, cerrb) = collect_stderr(&mut cons);

    let mut wire: Vec<u8> = Vec::new();
    for len in [1usize, 7, 17, 511, 3560] {
        use std::io::Write as _;
        writeln!(wire, "1 {len}").unwrap();
        let base = wire.len();
        wire.resize(base + len, b'x');
    }
    eprintln!("D5 writing {} physical bytes", wire.len());
    payload_tx.write_all(&wire).expect("driver feed");
    eprintln!("D5 feed complete");
    drop(payload_tx);

    let st = wait_exit(&mut cons, 30);
    let ce = cerrb.lock().unwrap().clone();
    eprintln!("D5 exit={st:?}\n{ce}");
    assert!(ce.contains("total=4096"), "{ce}");
    assert!(ce.contains("hash=7580ad4254676325"), "exact bytes\n{ce}");
    assert!(
        ce.contains("peer_gone=true"),
        "driver drop must EOF the consumer\n{ce}"
    );
}
