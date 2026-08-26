//! Bootstrap helper probe — child side HELLO/WELCOME/ACK

use seam_core::limits::Limits;
use seam_platform::NativeLane;

#[cfg(unix)]
fn main() {
    let args: Vec<String> = std::env::args().collect();
    // Expect --bootstrap-fd 3 (Unix)
    let mut fd_val: Option<i32> = None;
    let mut i = 1;
    while i < args.len() {
        if args[i] == "--bootstrap-fd" && i + 1 < args.len() {
            fd_val = args[i + 1].parse().ok();
            i += 2;
        } else {
            i += 1;
        }
    }
    // Also handle generic lane_probe fd 3 already proven, but for bootstrap we use fd 3
    let fd = fd_val.unwrap_or(3);
    // Reconstruct NativeLane from fd
    let lane = unsafe { NativeLane::from_raw_fd(fd) };
    let limits = Limits::default();
    match seam_process::child_handshake(&lane, &limits) {
        Ok(peer) => {
            eprintln!("bootstrap child peer {}", peer);
            std::process::exit(0);
        }
        Err(e) => {
            eprintln!("bootstrap child failed: {e}");
            std::process::exit(10);
        }
    }
}

#[cfg(windows)]
fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mut addr: Option<String> = None;
    let mut i = 1;
    while i < args.len() {
        if args[i] == "--bootstrap-addr" && i + 1 < args.len() {
            addr = Some(args[i + 1].clone());
            i += 2;
        } else if args[i] == "--bootstrap-read" || args[i] == "--bootstrap-write" {
            // legacy pipe args — ignore for TCP bootstrap
            i += 2;
        } else {
            i += 1;
        }
    }
    let addr = addr.unwrap_or_else(|| {
        eprintln!("missing --bootstrap-addr");
        std::process::exit(2);
    });
    let stream = std::net::TcpStream::connect(&addr).unwrap_or_else(|e| {
        eprintln!("connect {addr} failed: {e}");
        std::process::exit(10);
    });
    stream.set_nodelay(true).ok();
    let lane = NativeLane::from_tcp(stream);
    let limits = Limits::default();
    match seam_process::child_handshake(&lane, &limits) {
        Ok(peer) => {
            eprintln!("bootstrap child peer {}", peer);
            std::process::exit(0);
        }
        Err(e) => {
            eprintln!("bootstrap child failed: {e}");
            std::process::exit(11);
        }
    }
}
