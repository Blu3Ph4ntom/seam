//! Isolated IPC benchmark (release only):
//!   CONTROL SYNC | COLD SHARED SETUP | WARM SHARED REUSE | COPY BASELINE
//! Two real OS processes (driver + peer) over stdio control channel.
//! Shared backing uses the real section/memfd path with an RO handle/fd
//! handed to the peer; copy baseline uses the same kernel pipe as transport.

use std::io::{BufRead, BufReader, Read, Write};
use std::process::{Child, Command, Stdio};
use std::time::Instant;

const SIZES: &[(&str, usize, usize)] = &[
    ("4KiB", 4 * 1024, 2000),
    ("64KiB", 64 * 1024, 1000),
    ("1MiB", 1024 * 1024, 400),
    ("4MiB", 4 * 1024 * 1024, 150),
    ("64MiB", 64 * 1024 * 1024, 40),
];

fn pct(v: &mut Vec<u128>, p: f64) -> u128 {
    v.sort();
    let i = (((v.len() as f64) * p).ceil() as usize).saturating_sub(1);
    v[i.min(v.len() - 1)]
}

#[allow(dead_code)]
fn table(name: &str, rows: &[(String, usize, u128, u128)], thr: bool) {
    println!("== {name} ==");
    for (sz, it, p50, p95) in rows {
        if thr {
            let mib = |_us: u128| -> String {
                // size known via label suffix lookup not needed; print us/s
                format!("{p50}us {p95}us")
            };
            let _ = mib;
            println!("{sz}\t{it}\t{p50}us\t{p95}us");
        } else {
            println!("{sz}\t{it}\t{p50}us\t{p95}us");
        }
    }
}

thread_local! {
    static PEER_PTR: std::cell::RefCell<Option<(*const u8, usize)>> =
        const { std::cell::RefCell::new(None) };
    static CUR_REGION: std::cell::RefCell<Option<authority_fabric::shared::SharedRegion>> =
        const { std::cell::RefCell::new(None) };
}

fn touch(buf: &[u8]) -> u64 {
    let mut acc = 0u64;
    for b in buf {
        acc = acc.wrapping_add(*b as u64).rotate_left(1);
    }
    std::hint::black_box(acc)
}

fn main() {
    match std::env::args().nth(1).as_deref() {
        Some("peer") => peer(),
        _ => driver(),
    }
}

// -------------------------------------------------------------- peer ----

fn peer() {
    let stdin = std::io::stdin();
    let mut r = BufReader::new(stdin.lock());
    let mut out = std::io::stdout();
    let mut line = String::new();
    let mut buf: Vec<u8> = Vec::new();
    loop {
        line.clear();
        if r.read_line(&mut line).unwrap_or(0) == 0 {
            return;
        }
        let p: Vec<&str> = line.trim().split_whitespace().collect();
        match p[0] {
            "SYNC" => {
                out.write_all(b"ACK\n").unwrap();
                out.flush().unwrap();
            }
            "MAPW" => {
                #[cfg(windows)]
                {
                    let hv: u64 = p[1].parse().unwrap();
                    let sz: usize = p[2].parse().unwrap();
                    let f = authority_fabric::shared::windows_handle_to_file(hv);
                    let v = authority_fabric::shared::map_read_only(&f, sz).unwrap();
                    let parts = v.raw_parts_pub();
                    std::mem::forget(v); // process-lifetime mapping
                    std::mem::forget(f); // section stays alive for the view
                    PEER_PTR.with(|c| *c.borrow_mut() = Some(parts));
                }
                #[cfg(not(windows))]
                {
                    let _ = (&p[1], &p[2]);
                }
                out.write_all(b"READY\n").unwrap();
                out.flush().unwrap();
            }
            "MAPU" => {
                #[cfg(unix)]
                {
                    let pid: u32 = p[1].parse().unwrap();
                    let fd: i32 = p[2].parse().unwrap();
                    let sz: usize = p[3].parse().unwrap();
                    let path = format!("/proc/{pid}/fd/{fd}");
                    let f = std::fs::OpenOptions::new().read(true).open(path).unwrap();
                    let v = authority_fabric::shared::map_read_only(&f, sz).unwrap();
                    let parts = v.raw_parts_pub();
                    std::mem::forget(v);
                    std::mem::forget(f);
                    PEER_PTR.with(|c| *c.borrow_mut() = Some(parts));
                }
                #[cfg(not(unix))]
                {
                    let _ = (&p[1], &p[2], &p[3]);
                }
                out.write_all(b"READY\n").unwrap();
                out.flush().unwrap();
            }
            "GO" => {
                let n: usize = p[1].parse().unwrap();
                PEER_PTR.with(|c| {
                    if let Some((ptr, len)) = *c.borrow() {
                        let s = unsafe { std::slice::from_raw_parts(ptr, len.min(n).max(n)) };
                        std::hint::black_box(touch(&s[..n]));
                    }
                });
                out.write_all(b"ACK\n").unwrap();
                out.flush().unwrap();
            }
            "COPY" => {
                let n: usize = p[1].parse().unwrap();
                buf.resize(n, 0);
                r.read_exact(&mut buf).unwrap();
                std::hint::black_box(touch(&buf));
                out.write_all(b"ACK\n").unwrap();
                out.flush().unwrap();
            }
            "QUIT" => return,
            _ => {}
        }
    }
}

// ------------------------------------------------------------ driver ----

struct Peer {
    w: std::process::ChildStdin,
    r: BufReader<std::process::ChildStdout>,
    child: Child,
}
impl Peer {
    fn line(&mut self, want: &str) {
        let mut l = String::new();
        self.r.read_line(&mut l).unwrap();
        assert_eq!(l.trim(), want);
    }
    fn ack(&mut self) {
        self.line("ACK");
    }
}

#[cfg(windows)]
fn establish(p: &mut Peer, size: usize) {
    use std::os::windows::io::AsRawHandle;
    use winapi::um::handleapi::DuplicateHandle;
    use winapi::um::processthreadsapi::GetCurrentProcess;
    use winapi::um::winnt::SECTION_MAP_READ;
    let reg =
        authority_fabric::shared::SharedRegion::create(size as u64, &big_limits()).expect("create");
    let src = reg.backing_ref().as_raw_handle() as *mut winapi::ctypes::c_void;
    let child_proc = p.child.as_raw_handle() as *mut winapi::ctypes::c_void;
    let mut out = std::ptr::null_mut();
    // SAFETY: duplicating our live section handle into the spawned child.
    let ok = unsafe {
        DuplicateHandle(
            GetCurrentProcess(),
            src,
            child_proc,
            &mut out,
            SECTION_MAP_READ,
            0,
            0,
        )
    };
    assert!(ok != 0, "dup into child failed");
    CUR_REGION.with(|c| *c.borrow_mut() = Some(reg));
    writeln!(p.w, "MAPW {} {size}", out as usize).unwrap();
    p.w.flush().unwrap();
    p.line("READY");
}

#[cfg(unix)]
fn establish(p: &mut Peer, size: usize) {
    let reg =
        authority_fabric::shared::SharedRegion::create(size as u64, &big_limits()).expect("create");
    let raw = reg.backing_ref().as_raw_fd();
    let pid = std::process::id();
    CUR_REGION.with(|c| *c.borrow_mut() = Some(reg));
    writeln!(p.w, "MAPU {pid} {raw} {size}").unwrap();
    p.w.flush().unwrap();
    p.line("READY");
}

fn release(_p: &mut Peer) {
    CUR_REGION.with(|c| *c.borrow_mut() = None); // drops backing+view session
}

fn warm_handoff(p: &mut Peer, size: usize, seed: u64) {
    CUR_REGION.with(|c| {
        if let Some(reg) = &mut *c.borrow_mut() {
            let mut v = reg.map_read_write().unwrap();
            let mut s = seed | 1;
            for b in v.as_mut_slice()[..size].iter_mut() {
                s ^= s << 13;
                s ^= s >> 7;
                s ^= s << 17;
                *b = s as u8;
            }
        }
    });
    writeln!(p.w, "GO {size}").unwrap();
    p.w.flush().unwrap();
    p.ack();
}

fn big_limits() -> authority_fabric::Limits {
    authority_fabric::Limits {
        max_region_size: u64::MAX,
        max_total_region_bytes: u64::MAX,
        ..Default::default()
    }
}

fn driver() {
    let mut c = Command::new(std::env::current_exe().unwrap())
        .arg("peer")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn peer");
    let w = c.stdin.take().unwrap();
    let r = c.stdout.take().unwrap();
    let mut p = Peer {
        w,
        r: BufReader::new(r),
        child: c,
    };

    let mut t = Vec::new();
    for _ in 0..5000 {
        let s = Instant::now();
        writeln!(p.w, "SYNC").unwrap();
        p.w.flush().unwrap();
        p.ack();
        t.push(s.elapsed().as_micros());
    }
    println!(
        "== CONTROL SYNC ONLY ==\ntoken\t5000\t{}us\t{}us",
        pct(&mut t, 0.5),
        pct(&mut t, 0.95)
    );

    let mut cold_all = Vec::new();
    let mut warm_all = Vec::new();
    for (name, size, iters) in SIZES.iter().copied() {
        establish(&mut p, size);
        warm_handoff(&mut p, size, seed_of(0)); // warmup
        release(&mut p);
        let mut cold = Vec::new();
        let mut warm = Vec::new();
        for i in 0..iters {
            let s = Instant::now();
            establish(&mut p, size);
            cold.push(s.elapsed().as_micros());
            let s2 = Instant::now();
            warm_handoff(&mut p, size, seed_of(i as u64 + 7));
            warm.push(s2.elapsed().as_micros());
            release(&mut p);
        }
        let mibs = |us: u128| -> u128 { (size as u128) * 1_000_000 / (us.max(1) * 1024 * 1024) };
        cold_all.push((
            format!("* {name}"),
            iters,
            percentile(&mut cold, 0.5),
            percentile(&mut cold, 0.95),
        ));
        let w50 = percentile(&mut warm.clone(), 0.5);
        let w95 = percentile(&mut warm, 0.95);
        warm_all.push((format!("* {name}"), iters, w50, w95));
        println!(
            "== WARM {name} effective one-way throughput MiB/s: p50={} p95={} ==",
            mibs(w50),
            mibs(w95)
        );
        let c50 = percentile(&mut cold.clone(), 0.5);
        let c95 = percentile(&mut cold, 0.95);
        cold_all.pop();
        cold_all.push((format!("* {name}"), iters, c50, c95));
    }
    println!("== COLD SHARED SETUP ==");
    for (sz, it, a, b) in &cold_all {
        println!("{sz}\t{it}\t{a}us\t{b}us");
    }
    println!("== WARM SHARED REUSE ==");
    for (sz, it, a, b) in &warm_all {
        println!("{sz}\t{it}\t{a}us\t{b}us");
    }

    let mut copy_all = Vec::new();
    for (name, size, iters) in SIZES.iter().copied() {
        let payload = vec![0xA5u8; size];
        let mut t = Vec::new();
        for i in 0..iters {
            let s = Instant::now();
            writeln!(p.w, "COPY {size}").unwrap();
            p.w.write_all(&payload).unwrap();
            p.w.flush().unwrap();
            p.ack();
            t.push(s.elapsed().as_micros());
            std::hint::black_box(payload[i % size]);
        }
        let mibs = |us: u128| -> u128 { (size as u128) * 1_000_000 / (us.max(1) * 1024 * 1024) };
        let a = percentile(&mut t.clone(), 0.5);
        let b = percentile(&mut t, 0.95);
        copy_all.push((format!("* {name}"), iters, a, b));
        println!(
            "== COPY {name} effective one-way throughput MiB/s: p50={} p95={} ==",
            mibs(a),
            mibs(b)
        );
    }
    println!("== COPY BASELINE ==");
    for (sz, it, a, b) in &copy_all {
        println!("{sz}\t{it}\t{a}us\t{b}us");
    }

    writeln!(p.w, "QUIT").unwrap();
    let _ = p.w.flush();
    let _ = p.child.wait();
}

fn percentile(v: &mut Vec<u128>, p: f64) -> u128 {
    v.sort_unstable();
    let i = (((v.len() as f64) * p).ceil() as usize).saturating_sub(1);
    v[i.min(v.len() - 1)]
}

fn seed_of(i: u64) -> u64 {
    i.wrapping_mul(0x9E37_79B9_7F4A_7C15) ^ 0xDEAD_BEEF
}
