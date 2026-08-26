//! Platform lane abstraction — private bootstrap/control channel.

#[cfg(unix)]
pub mod unix_lane {
    use std::os::unix::io::{AsRawFd, OwnedFd};
    use std::os::unix::net::UnixStream;

    pub struct NativeLane {
        inner: UnixStream,
    }

    impl NativeLane {
        pub fn pair() -> std::io::Result<(Self, Self)> {
            let (a, b) = UnixStream::pair()?;
            // Ensure CLOEXEC so child inheritance is explicit.
            // SAFETY: just-created fds, no other threads racing.
            Ok((Self { inner: a }, Self { inner: b }))
        }

        pub fn send(&self, buf: &[u8]) -> std::io::Result<()> {
            use std::io::Write;
            (&self.inner).write_all(buf)
        }

        pub fn recv(&self, buf: &mut [u8]) -> std::io::Result<usize> {
            use std::io::Read;
            (&self.inner).read(buf)
        }

        pub fn as_raw_fd(&self) -> std::os::unix::io::RawFd {
            self.inner.as_raw_fd()
        }

        /// Send a single fd via SCM_RIGHTS (blocking).
        pub fn send_fd(&self, fd: OwnedFd) -> std::io::Result<()> {
            super::unix::send_fd(&self.inner, fd)
        }

        /// Receive a single fd via SCM_RIGHTS.
        pub fn recv_fd(&self) -> std::io::Result<OwnedFd> {
            super::unix::recv_fd(&self.inner)
        }
    }
}

#[cfg(windows)]
pub mod windows_lane {
    // Minimal stub — real implementation uses DuplicateHandle + named pipe
    // with explicit inheritance restriction (see experiments/authority-fabric
    // src/native/windows.rs for proven pattern). Stub keeps crate buildable
    // on Windows without pulling full winapi surface into this skeleton.

    pub struct NativeLane {
        _private: (),
    }

    impl NativeLane {
        pub fn pair() -> std::io::Result<(Self, Self)> {
            // Production will create an anonymous pipe pair with
            // SECURITY_ATTRIBUTES bInheritHandle=FALSE then duplicate
            // explicitly to child. Stub returns not-implemented until
            // Milestone B detailed port.
            Err(std::io::Error::other(
                "windows lane — port from experiments/native/windows.rs in Milestone B",
            ))
        }
    }
}

// Re-export per platform
#[cfg(unix)]
pub use unix_lane::NativeLane;
#[cfg(windows)]
pub use windows_lane::NativeLane;

/// Shared helpers for SCM_RIGHTS (unix only, isolated unsafe).
#[cfg(unix)]
mod unix {
    use rustix::net::{
        RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, SendAncillaryBuffer,
        SendAncillaryMessage, SendFlags,
    };
    use std::os::unix::io::OwnedFd;
    use std::os::unix::net::UnixStream;

    pub fn send_fd(stream: &UnixStream, fd: OwnedFd) -> std::io::Result<()> {
        use std::os::fd::{AsRawFd, BorrowedFd};
        let borrowed = unsafe { BorrowedFd::borrow_raw(fd.as_raw_fd()) };
        let fds = [borrowed];
        let mut cmsg_space = [0u8; rustix::cmsg_space!(ScmRights(1))];
        let mut cmsg = SendAncillaryBuffer::new(&mut cmsg_space);
        cmsg.push(SendAncillaryMessage::ScmRights(&fds));
        let iov = [std::io::IoSlice::new(&[0u8])];
        let res = rustix::net::sendmsg(stream, &iov, &mut cmsg, SendFlags::empty())
            .map(|_| ())
            .map_err(|e| std::io::Error::from_raw_os_error(e.raw_os_error()));
        // Ownership transfer: sender's original fd is now logically moved;
        // dropping `fd` closes the sender's copy (kernel retains dup for receiver).
        drop(fd);
        res
    }

    pub fn recv_fd(stream: &UnixStream) -> std::io::Result<OwnedFd> {
        let mut buf = [0u8; 1];
        let mut cmsg_space = [0u8; rustix::cmsg_space!(ScmRights(1))];
        let mut cmsg = RecvAncillaryBuffer::new(&mut cmsg_space);
        let mut iov = [std::io::IoSliceMut::new(&mut buf)];
        let _n = rustix::net::recvmsg(stream, &mut iov, &mut cmsg, RecvFlags::empty())
            .map_err(|e| std::io::Error::from_raw_os_error(e.raw_os_error()))?;
        for msg in cmsg.drain() {
            if let RecvAncillaryMessage::ScmRights(mut fds) = msg {
                if let Some(fd) = fds.next() {
                    return Ok(fd);
                }
            }
        }
        Err(std::io::Error::other("no fd received"))
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::NativeLane;
    use std::os::unix::io::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd};
    use std::os::unix::net::UnixStream;

    #[test]
    fn lane_moves_fd_still_functional() {
        // Linchpin for DataPipe: any fd sent via SCM_RIGHTS remains
        // functional in the recipient. Pipe continuity (prefix||suffix)
        // follows because the fd refers to the same kernel object.
        let (lane_a, lane_b) = NativeLane::pair().unwrap();
        let (payload_a, payload_b) = UnixStream::pair().unwrap();
        // Move ownership of payload_b into the lane (into_raw_fd gives
        // ownership to the new OwnedFd; no double-close)
        let fd_to_send: OwnedFd = unsafe { OwnedFd::from_raw_fd(payload_b.into_raw_fd()) };
        lane_a.send_fd(fd_to_send).unwrap();
        let received: OwnedFd = lane_b.recv_fd().unwrap();
        assert!(received.as_raw_fd() >= 0);
        // Verify the peer end still works by writing through the moved fd
        // and reading on the retained peer (UnixStream pair is bidirectional).
        let mut moved_stream = unsafe { UnixStream::from_raw_fd(received.into_raw_fd()) };
        let mut peer = payload_a;
        use std::io::{Read, Write};
        moved_stream.write_all(b"ping").unwrap();
        let mut buf = [0u8; 4];
        peer.set_read_timeout(Some(std::time::Duration::from_secs(1)))
            .ok();
        peer.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"ping");
    }
}
