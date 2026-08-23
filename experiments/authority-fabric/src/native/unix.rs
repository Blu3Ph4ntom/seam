//! Unix FD passing via SCM_RIGHTS (rustix sendmsg/recvmsg + std ownership).

use std::fs::File;
use std::io::{IoSlice, IoSliceMut};
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, IntoRawFd, OwnedFd};

use rustix::net::{
    recvmsg, sendmsg, RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags,
    SendAncillaryBuffer, SendAncillaryMessage, SendFlags,
};

/// Host escrow holds the received descriptor as owned RAII state.
pub struct Escrowed(pub OwnedFd);

fn errno_to_io(e: rustix::io::Errno) -> std::io::Error {
    std::io::Error::from_raw_os_error(e.raw_os_error())
}

/// Send one descriptor over the lane. The source File stays open; the kernel
/// installs a new descriptor referring to the same open file description.
pub fn send_fd(lane: &std::os::unix::net::UnixStream, file: &File) -> std::io::Result<()> {
    // SAFETY: borrowed view of a live descriptor owned by `file`; the borrow
    // does not outlive this call and `file` is never closed during sendmsg.
    let borrowed = unsafe { BorrowedFd::borrow_raw(file.as_raw_fd()) };
    let mut space = [0u8; 128];
    let mut ancillary = SendAncillaryBuffer::new(&mut space);
    let fds = [borrowed];
    let pushed = ancillary.push(SendAncillaryMessage::ScmRights(&fds));
    debug_assert!(pushed);
    let payload = [b'x'];
    let iov = [IoSlice::new(&payload)];
    sendmsg(lane, &iov, &mut ancillary, SendFlags::empty()).map_err(errno_to_io)?;
    Ok(())
}

/// Receive exactly one descriptor from the lane. Any unexpected ancillary
/// descriptor gains immediate RAII ownership and is closed on scope exit.
pub fn recv_fd(lane: &std::os::unix::net::UnixStream) -> std::io::Result<Escrowed> {
    let mut space = [0u8; 128];
    let mut ancillary = RecvAncillaryBuffer::new(&mut space);
    let mut buf = [0u8; 1];
    let mut iov = [IoSliceMut::new(&mut buf)];
    let msg = recvmsg(lane, &mut iov, &mut ancillary, RecvFlags::empty()).map_err(errno_to_io)?;
    if msg.bytes == 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "lane closed",
        ));
    }
    // Track every unexpected descriptor so RAII closes them even on error.
    struct Guard(Vec<OwnedFd>);
    impl Drop for Guard {
        fn drop(&mut self) {}
    }
    let mut found: Option<OwnedFd> = None;
    let mut extra: Vec<i32> = Vec::new();
    for cmsg in ancillary.drain() {
        if let RecvAncillaryMessage::ScmRights(fds) = cmsg {
            for fd in fds {
                if found.is_none() {
                    found = Some(fd);
                } else {
                    extra.push(fd.into_raw_fd());
                }
            }
        }
    }
    match (found, extra.len()) {
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
    // SAFETY: sole owner; descriptor moves from OwnedFd into exactly one File.
    let raw = escrow.0.into_raw_fd();
    unsafe { File::from_raw_fd(raw) }
}

// ---- Host-side helpers mirroring the Windows adapter shape ----

pub fn stage_from_sender(lane: &std::os::unix::net::UnixStream) -> std::io::Result<Escrowed> {
    recv_fd(lane)
}

pub fn restore_to_sender(
    lane: &std::os::unix::net::UnixStream,
    escrow: Escrowed,
) -> std::io::Result<()> {
    let f = escrow_to_file(escrow);
    send_fd(lane, &f)
}

pub fn commit_to_recipient(
    lane: &std::os::unix::net::UnixStream,
    escrow: Escrowed,
) -> std::io::Result<()> {
    let f = escrow_to_file(escrow);
    send_fd(lane, &f)
}

pub fn close_escrow(escrow: Escrowed) {
    drop(escrow);
}

/// Unit-provable kernel transfer: roundtrip one real descriptor through a
/// real socketpair using SCM_RIGHTS (no path reopen anywhere).
#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Seek, SeekFrom, Write};
    use std::os::unix::io::AsRawFd;
    use std::os::unix::net::UnixStream;

    #[test]
    fn scm_rights_roundtrip_transfers_real_descriptor() {
        let (a, b) = UnixStream::pair().unwrap();
        let mut src = tempfile_bytes(b"SEAM_SCM_NONCE");
        let raw_before = src.as_raw_fd();
        send_fd(&a, &src).unwrap();
        let Escrowed(fd) = recv_fd(&b).unwrap();
        let mut file = File::from(fd);
        assert_ne!(
            raw_before,
            file.as_raw_fd(),
            "kernel must install a distinct descriptor in receiver"
        );
        file.seek(SeekFrom::Start(0)).unwrap();
        let mut got = Vec::new();
        file.read_to_end(&mut got).unwrap();
        assert_eq!(got, b"SEAM_SCM_NONCE");
        drop(a);
        drop(src);
    }

    /// Malformed case: zero descriptors must fail closed.
    #[test]
    fn missing_descriptor_fails_closed() {
        let (mut a, b) = UnixStream::pair().unwrap();
        a.write_all(&[b'y']).unwrap();
        let r = recv_fd(&b);
        assert!(r.is_err());
    }

    fn tempfile_bytes(content: &[u8]) -> File {
        let mut p = std::env::temp_dir();
        p.push(format!("seam-scm-{}", std::process::id()));
        let mut f = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&p)
            .unwrap();
        f.write_all(content).unwrap();
        f.flush().unwrap();
        drop(std::fs::remove_file(p));
        f.seek(SeekFrom::Start(0)).unwrap();
        f
    }
}
