//! Unix FD passing via SCM_RIGHTS (rustix 0.38 ownership-aware APIs).

use std::fs::File;
use std::os::unix::io::{AsRawFd, FromRawFd};

use rustix::cmsg_space;
use rustix::fd::{AsFd, BorrowedFd, OwnedFd};
use rustix::net::{
    recvmsg, sendmsg, RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags,
    SendAncillaryBuffer, SendAncillaryMessage, SendFlags,
};

/// Host escrow holds the received descriptor as owned RAII state.
pub struct Escrowed(pub OwnedFd);

fn errno_to_io(e: rustix::io::Errno) -> std::io::Error {
    std::io::Error::from_raw_os_error(e.raw_os_error().unwrap_or(0))
}

/// Send one descriptor over the lane. The source File stays open; the kernel
/// installs a new descriptor referring to the same open file description in
/// the receiver.
pub fn send_fd(lane: &std::os::unix::net::UnixStream, file: &File) -> std::io::Result<()> {
    // SAFETY: borrowed view of a live descriptor owned by `file`; the borrow
    // does not outlive this call and `file` is never closed during sendmsg.
    let borrowed = unsafe { BorrowedFd::borrow_raw(file.as_raw_fd()) };
    let mut space = cmsg_space!(ScmRights(1));
    let mut ancillary = SendAncillaryBuffer::new(&mut space);
    let pushed = ancillary.push(SendAncillaryMessage::ScmRights(&[borrowed]));
    debug_assert!(pushed);
    let payload = [b'x'];
    let iov = [std::io::IoSlice::new(&payload)];
    sendmsg(lane.as_fd(), &iov, &mut ancillary, SendFlags::empty()).map_err(errno_to_io)?;
    Ok(())
}

/// Receive exactly one descriptor from the lane. Any unexpected ancillary
/// data is closed immediately (RAII drop of OwnedFd) and reported as error.
pub fn recv_fd(lane: &std::os::unix::net::UnixStream) -> std::io::Result<Escrowed> {
    let mut space = cmsg_space!(ScmRights(2));
    let mut ancillary = RecvAncillaryBuffer::new(&mut space);
    let mut buf = [0u8; 1];
    let mut iov = [std::io::IoSliceMut::new(&mut buf)];
    let msg = recvmsg(lane.as_fd(), &mut iov, &mut ancillary, RecvFlags::empty())
        .map_err(errno_to_io)?;
    if msg.bytes == 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "lane closed",
        ));
    }
    let mut found: Option<OwnedFd> = None;
    let mut extra: usize = 0;
    for cmsg in ancillary.drain() {
        if let RecvAncillaryMessage::ScmRights(fds) = cmsg {
            for fd in fds {
                if found.is_none() {
                    found = Some(fd);
                } else {
                    extra += 1; // OwnedFd dropped here => descriptor closed
                }
            }
        }
    }
    match (found, extra) {
        (Some(fd), 0) => Ok(Escrowed(fd)),
        (Some(_), n) => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("expected 1 descriptor, got {}", n + 1),
        )),
        (None, _) => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "no SCM_RIGHTS in message",
        )),
    }
}

/// Wrap an escrowed descriptor into an application-facing File.
pub fn escrow_to_file(escrow: Escrowed) -> File {
    // SAFETY: we own exactly one OwnedFd and hand its descriptor to exactly
    // one File; no second Rust owner is ever created from this raw value.
    let raw = escrow.0.into_raw_fd();
    unsafe { File::from_raw_fd(raw) }
}

/// Unit-provable kernel transfer: roundtrip one real descriptor through a
/// real socketpair using SCM_RIGHTS (no path reopen anywhere).
#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::io::AsRawFd;
    use std::os::unix::net::UnixStream;

    #[test]
    fn scm_rights_roundtrip_transfers_real_descriptor() {
        let (a, b) = UnixStream::pair().unwrap();
        // Source file with known content, opened for read.
        let mut src = tempfile_bytes(b"SEAM_SCM_NONCE");
        let raw_before = src.as_raw_fd();
        send_fd(&a, &src).unwrap();
        let Escrowed(fd) = recv_fd(&b).unwrap();
        // The received descriptor is a NEW descriptor number referring to the
        // same open file description; it must differ numerically in general,
        // but the contract we assert is content identity through the object.
        let file = File::from(fd);
        assert_ne!(
            raw_before,
            file.as_raw_fd(),
            "kernel must install a distinct descriptor in receiver"
        );
        let mut got = Vec::new();
        let mut f = file;
        use std::io::Read;
        f.seek(std::io::SeekFrom::Start(0)).unwrap();
        f.read_to_end(&mut got).unwrap();
        assert_eq!(got, b"SEAM_SCM_NONCE");
        // Zero descriptors expected afterwards: both sides consumed.
        let _ = a.into_raw_fd();
        let _ = src;
    }

    fn tempfile_bytes(content: &[u8]) -> File {
        use std::io::Write;
        let mut p = std::env::temp_dir();
        p.push(format!("seam-scm-{}", std::process::id()));
        let mut f = File::create(&p).unwrap();
        f.write_all(content).unwrap();
        f.flush().unwrap();
        drop(std::fs::remove_file(p));
        f.seek(std::io::SeekFrom::Start(0)).unwrap();
        f
    }

    /// Malformed case: zero descriptors must fail closed.
    #[test]
    fn missing_descriptor_fails_closed() {
        let (a, b) = UnixStream::pair().unwrap();
        use std::io::Write as _;
        a.write_all(&[b'y']).unwrap();
        // Plain byte, no ancillary: recv_fd must error, nothing leaks.
        let r = recv_fd(&b);
        assert!(r.is_err());
    }
}
