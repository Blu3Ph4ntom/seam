//! Platform lane abstraction — private bootstrap/control channel.

#[cfg(unix)]
pub mod unix_lane {
    use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd};
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
            crate::unix::send_fd(&self.inner, fd)
        }

        /// Receive a single fd via SCM_RIGHTS.
        pub fn recv_fd(&self) -> std::io::Result<OwnedFd> {
            crate::unix::recv_fd(&self.inner)
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
        RecvAncillaryBuffer, RecvAncillaryMessage, SendAncillaryBuffer, SendAncillaryMessage,
    };
    use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd};
    use std::os::unix::net::UnixStream;

    pub fn send_fd(stream: &UnixStream, fd: OwnedFd) -> std::io::Result<()> {
        let mut cmsg_space = [0u8; rustix::cmsg_space!(ScmRights(1))];
        let mut cmsg = SendAncillaryBuffer::new(&mut cmsg_space);
        cmsg.push(SendAncillaryMessage::ScmRights(&[fd]));
        // Send a single dummy byte with the cmsg.
        let iov = [std::io::IoSlice::new(&[0u8])];
        rustix::net::sendmsg(stream.as_raw_fd(), &iov, &mut cmsg, Default::default())
            .map(|_| ())
            .map_err(|e| std::io::Error::from_raw_os_error(e.raw_os_error()))
    }

    pub fn recv_fd(stream: &UnixStream) -> std::io::Result<OwnedFd> {
        let mut buf = [0u8; 1];
        let mut cmsg_space = [0u8; rustix::cmsg_space!(ScmRights(1))];
        let mut cmsg = RecvAncillaryBuffer::new(&mut cmsg_space);
        let mut iov = [std::io::IoSliceMut::new(&mut buf)];
        let _n = rustix::net::recvmsg(stream.as_raw_fd(), &mut iov, &mut cmsg, Default::default())
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
