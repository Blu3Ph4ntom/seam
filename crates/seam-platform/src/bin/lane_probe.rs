//! Canonical helper for real cross-process lane proofs.
//! Role: lane-child — receives fd via private inherited NativeLane (fd 3),
//! validates stream continuity (PREFIX -> SUFFIX).

#[cfg(unix)]
fn main() {
    let role = std::env::args().nth(1).unwrap_or_default();
    if role == "lane-child" {
        lane_child();
    } else {
        eprintln!("usage: lane_probe lane-child (fd 3 is private lane)");
        std::process::exit(2);
    }
}

#[cfg(windows)]
fn main() {
    let mut args = std::env::args();
    let _bin = args.next();
    let role = args.next().unwrap_or_default();
    if role == "lane-child" {
        let addr = args.next().unwrap_or_default();
        if addr.is_empty() {
            eprintln!("lane-child needs addr");
            std::process::exit(2);
        }
        lane_child_windows(&addr);
    } else {
        eprintln!("usage: lane_probe lane-child <127.0.0.1:port>");
        std::process::exit(2);
    }
}

#[cfg(windows)]
fn lane_child_windows(addr: &str) {
    use std::io::{Read, Write};
    use std::net::TcpStream;
    let mut stream = TcpStream::connect(addr).unwrap_or_else(|e| {
        eprintln!("child connect failed {addr}: {e}");
        std::process::exit(10);
    });
    stream.set_nodelay(true).ok();
    // Simple lane continuity: parent sends PREFIX-, child echoes SUFFIX via same lane? Actually helper mirrors unix fd move test via lane bytes.
    // For Windows lane proof, just read 7, write 6 over the lane itself.
    let mut prefix = [0u8; 7];
    if let Err(e) = stream.read_exact(&mut prefix) {
        eprintln!("child read failed: {e}");
        std::process::exit(11);
    }
    if &prefix != b"PREFIX-" {
        eprintln!("prefix mismatch {:?}", prefix);
        std::process::exit(12);
    }
    if let Err(e) = stream.write_all(b"SUFFIX") {
        eprintln!("child write failed: {e}");
        std::process::exit(13);
    }
    std::process::exit(0);
}

#[cfg(unix)]
fn lane_child() {
    use std::io::{Read, Write};
    use std::os::unix::io::{FromRawFd, OwnedFd};
    use std::os::unix::net::UnixStream;

    // SAFETY: fd 3 is the private inherited lane endpoint, handed by parent
    // via dup2 in pre_exec. It is owned exactly once here.
    let lane_fd: OwnedFd = unsafe { OwnedFd::from_raw_fd(3) };
    // Wrap as UnixStream without extra dup.
    let lane_stream = unsafe { UnixStream::from_raw_fd(lane_fd.into_raw_fd()) };

    // Minimal NativeLane recv_fd reimplementation to avoid crate dep cycle
    // in helper binary (or use seam-platform directly). We use rustix recvmsg.
    let received = recv_fd_via(&lane_stream).unwrap_or_else(|e| {
        eprintln!("child recv_fd failed: {e}");
        std::process::exit(10);
    });

    let mut stream = unsafe { UnixStream::from_raw_fd(received.into_raw_fd()) };
    // Stream continuity: read PREFIX- (7 bytes) then write SUFFIX (6 bytes)
    let mut prefix = [0u8; 7];
    if let Err(e) = stream.read_exact(&mut prefix) {
        eprintln!("child read prefix failed: {e}");
        std::process::exit(11);
    }
    if &prefix != b"PREFIX-" {
        eprintln!("child prefix mismatch: {:?}", prefix);
        std::process::exit(12);
    }
    if let Err(e) = stream.write_all(b"SUFFIX") {
        eprintln!("child write suffix failed: {e}");
        std::process::exit(13);
    }
    drop(stream);
    std::process::exit(0);
}

#[cfg(unix)]
fn recv_fd_via(stream: &std::os::unix::net::UnixStream) -> std::io::Result<OwnedFd> {
    use rustix::net::{RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags};
    use std::os::unix::io::OwnedFd;
    let mut buf = [0u8; 1];
    let mut cmsg_space = [0u8; 128];
    let mut cmsg = RecvAncillaryBuffer::new(&mut cmsg_space);
    let mut iov = [std::io::IoSliceMut::new(&mut buf)];
    rustix::net::recvmsg(stream, &mut iov, &mut cmsg, RecvFlags::empty())
        .map_err(|e| std::io::Error::from_raw_os_error(e.raw_os_error()))?;
    for msg in cmsg.drain() {
        if let RecvAncillaryMessage::ScmRights(mut fds) = msg {
            if let Some(fd) = fds.next() {
                return Ok(fd);
            }
        }
    }
    Err(std::io::Error::other("no fd received in helper"))
}
