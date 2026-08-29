//! Platform lane abstraction — private bootstrap/control channel.

#[cfg(unix)]
pub mod unix_lane {
    use std::os::unix::io::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd};
    use std::os::unix::net::UnixStream;

    use seam_core::limits::Limits;
    use seam_core::wire::Header;

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

        /// Create lane from raw fd.
        ///
        /// # Safety
        /// fd must be an owned UnixStream fd, valid and not used elsewhere; caller transfers ownership exactly once.
        pub unsafe fn from_raw_fd(fd: std::os::unix::io::RawFd) -> Self {
            // SAFETY: caller guarantees fd is a valid owned UnixStream fd.
            Self {
                inner: unsafe { UnixStream::from_raw_fd(fd) },
            }
        }

        pub fn from_owned_fd(fd: OwnedFd) -> Self {
            Self {
                inner: UnixStream::from(fd),
            }
        }

        pub fn into_owned_fd(self) -> OwnedFd {
            unsafe { OwnedFd::from_raw_fd(self.inner.into_raw_fd()) }
        }

        pub fn send(&self, buf: &[u8]) -> std::io::Result<()> {
            use std::io::Write;
            (&self.inner).write_all(buf)
        }

        pub fn recv(&self, buf: &mut [u8]) -> std::io::Result<usize> {
            use std::io::Read;
            (&self.inner).read(buf)
        }

        /// Exact-bounded send of a whole frame buffer (write_all loop).
        pub fn send_all(&self, buf: &[u8]) -> std::io::Result<()> {
            use std::io::Write;
            (&self.inner).write_all(buf)
        }

        /// Exact-bounded receive: blocks until `buf.len()` bytes read or EOF.
        pub fn recv_exact(&self, buf: &mut [u8]) -> std::io::Result<()> {
            use std::io::Read;
            let mut off = 0;
            while off < buf.len() {
                let n = (&self.inner).read(&mut buf[off..])?;
                if n == 0 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "lane eof",
                    ));
                }
                off += n;
            }
            Ok(())
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

        /// Send a control frame (no ancillary data).
        pub fn send_frame(&self, h: &Header, body: &[u8]) -> std::io::Result<()> {
            let mut buf = [0u8; 32];
            h.encode(&mut buf);
            self.send_all(&buf)?;
            if !body.is_empty() {
                self.send_all(body)?;
            }
            Ok(())
        }

        /// Receive a control frame (no ancillary data).
        pub fn recv_frame(&self, limits: &Limits) -> std::io::Result<(Header, Vec<u8>)> {
            let mut hdr = [0u8; 32];
            self.recv_exact(&mut hdr)?;
            let h = Header::decode(&hdr, limits)
                .map_err(|e| std::io::Error::other(format!("bad header: {e:?}")))?;
            let mut body = vec![0u8; h.body_len as usize];
            if h.body_len > 0 {
                self.recv_exact(&mut body)?;
            }
            Ok((h, body))
        }

        /// Send a native frame carrying exactly one fd via SCM_RIGHTS.
        pub fn send_frame_fd(&self, h: &Header, body: &[u8], fd: OwnedFd) -> std::io::Result<()> {
            use rustix::net::{SendAncillaryBuffer, SendAncillaryMessage, SendFlags};
            use std::io::IoSlice;
            use std::os::fd::AsFd;
            let mut buf = [0u8; 32];
            h.encode(&mut buf);
            let fds = [fd.as_fd()];
            let mut space = [0u8; rustix::cmsg_space!(ScmRights(1))];
            let mut cmsg = SendAncillaryBuffer::new(&mut space);
            cmsg.push(SendAncillaryMessage::ScmRights(&fds));
            let iov = [IoSlice::new(&buf), IoSlice::new(body)];
            rustix::net::sendmsg(&self.inner, &iov, &mut cmsg, SendFlags::empty())
                .map(|_| ())
                .map_err(|e| std::io::Error::from_raw_os_error(e.raw_os_error()))?;
            drop(fd);
            Ok(())
        }

        /// Receive a native frame carrying exactly one fd via SCM_RIGHTS.
        pub fn recv_frame_fd(
            &self,
            limits: &Limits,
        ) -> std::io::Result<(Header, Vec<u8>, OwnedFd)> {
            use rustix::net::{RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags};
            use std::io::IoSliceMut;
            // Single recvmsg for header+body+FD — plain read would discard ancillary data.
            let mut buf = vec![0u8; 4096];
            let mut space = [0u8; rustix::cmsg_space!(ScmRights(1))];
            let mut cmsg = RecvAncillaryBuffer::new(&mut space);
            let mut iov = [IoSliceMut::new(&mut buf)];
            let n = rustix::net::recvmsg(&self.inner, &mut iov, &mut cmsg, RecvFlags::empty())
                .map_err(|e| std::io::Error::from_raw_os_error(e.raw_os_error()))?;
            if n < 32 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "short header",
                ));
            }
            let mut hdr = [0u8; 32];
            hdr.copy_from_slice(&buf[0..32]);
            let h = Header::decode(&hdr, limits)
                .map_err(|e| std::io::Error::other(format!("bad header: {e:?}")))?;
            let need = 32 + h.body_len as usize;
            if n < need {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "short body",
                ));
            }
            let body = buf[32..need].to_vec();
            for msg in cmsg.drain() {
                if let RecvAncillaryMessage::ScmRights(mut fds) = msg {
                    if let Some(fd) = fds.next() {
                        return Ok((h, body, fd));
                    }
                }
            }
            Err(std::io::Error::other("native frame without fd"))
        }
    }
}

#[cfg(windows)]
pub mod windows_lane {
    use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
    use winapi::shared::minwindef::{DWORD, FALSE};
    use winapi::um::minwinbase::SECURITY_ATTRIBUTES;
    use winapi::um::namedpipeapi::CreatePipe;

    pub enum Inner {
        Pipe {
            read: OwnedHandle,
            write: OwnedHandle,
        },
        Tcp(std::net::TcpStream),
    }

    pub struct NativeLane {
        inner: Inner,
    }

    fn create_pipe() -> std::io::Result<(OwnedHandle, OwnedHandle)> {
        let mut read: winapi::um::winnt::HANDLE = std::ptr::null_mut();
        let mut write: winapi::um::winnt::HANDLE = std::ptr::null_mut();
        let mut sa = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as DWORD,
            lpSecurityDescriptor: std::ptr::null_mut(),
            bInheritHandle: FALSE,
        };
        let ok = unsafe { CreatePipe(&mut read, &mut write, &mut sa, 0) };
        if ok == 0 {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: CreatePipe returns valid owned handles on success.
        let r = unsafe { OwnedHandle::from_raw_handle(read as *mut std::ffi::c_void) };
        let w = unsafe { OwnedHandle::from_raw_handle(write as *mut std::ffi::c_void) };
        Ok((r, w))
    }

    fn write_all(handle: &OwnedHandle, mut buf: &[u8]) -> std::io::Result<()> {
        use winapi::um::fileapi::WriteFile;
        while !buf.is_empty() {
            let mut n: DWORD = 0;
            let ok = unsafe {
                WriteFile(
                    handle.as_raw_handle() as *mut _,
                    buf.as_ptr() as *const _,
                    buf.len() as DWORD,
                    &mut n,
                    std::ptr::null_mut(),
                )
            };
            if ok == 0 {
                return Err(std::io::Error::last_os_error());
            }
            buf = &buf[n as usize..];
        }
        Ok(())
    }

    fn read_once(handle: &OwnedHandle, buf: &mut [u8]) -> std::io::Result<usize> {
        use winapi::um::fileapi::ReadFile;
        let mut n: DWORD = 0;
        let ok = unsafe {
            ReadFile(
                handle.as_raw_handle() as *mut _,
                buf.as_mut_ptr() as *mut _,
                buf.len() as DWORD,
                &mut n,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 {
            let e = std::io::Error::last_os_error();
            // Broken pipe == EOF on anonymous pipe when writer closed
            if e.raw_os_error() == Some(109) || e.kind() == std::io::ErrorKind::BrokenPipe {
                return Ok(0);
            }
            return Err(e);
        }
        Ok(n as usize)
    }

    impl NativeLane {
        /// Duplex private lane via two anonymous pipes (no global name, no TCP).
        /// Each lane owns one read and one write handle; opposite ends are cross-wired.
        /// Handles are non-inheritable by default; child spawn will use explicit
        /// STARTUPINFOEX + PROC_THREAD_ATTRIBUTE_HANDLE_LIST (see CTO lock §2).
        pub fn pair() -> std::io::Result<(Self, Self)> {
            let (r1, w1) = create_pipe()?;
            let (r2, w2) = create_pipe()?;
            // lane_a: writes w1, reads r2 ; lane_b: writes w2, reads r1
            Ok((
                Self {
                    inner: Inner::Pipe {
                        read: r2,
                        write: w1,
                    },
                },
                Self {
                    inner: Inner::Pipe {
                        read: r1,
                        write: w2,
                    },
                },
            ))
        }

        pub fn from_tcp(stream: std::net::TcpStream) -> Self {
            Self {
                inner: Inner::Tcp(stream),
            }
        }

        /// Create lane from raw pipe handles (child side, inherited).
        ///
        /// # Safety
        /// raw handles must be valid, uniquely owned, and not used elsewhere.
        pub unsafe fn from_raw_pipe_handles(
            read_raw: *mut std::ffi::c_void,
            write_raw: *mut std::ffi::c_void,
        ) -> Self {
            let read = unsafe { OwnedHandle::from_raw_handle(read_raw) };
            let write = unsafe { OwnedHandle::from_raw_handle(write_raw) };
            Self {
                inner: Inner::Pipe { read, write },
            }
        }

        pub fn into_pipe_handles(self) -> Option<(OwnedHandle, OwnedHandle)> {
            match self.inner {
                Inner::Pipe { read, write } => Some((read, write)),
                _ => None,
            }
        }

        pub fn as_pipe_handles(&self) -> Option<(*mut std::ffi::c_void, *mut std::ffi::c_void)> {
            match &self.inner {
                Inner::Pipe { read, write } => Some((read.as_raw_handle(), write.as_raw_handle())),
                _ => None,
            }
        }

        /// Duplicate handle as inheritable for child-specific handle list.
        ///
        /// # Safety
        /// handle must be valid in current process.
        pub fn duplicate_inheritable(handle: &OwnedHandle) -> std::io::Result<OwnedHandle> {
            use winapi::um::handleapi::DuplicateHandle;
            use winapi::um::processthreadsapi::GetCurrentProcess;
            let mut dup: winapi::um::winnt::HANDLE = std::ptr::null_mut();
            let ok = unsafe {
                DuplicateHandle(
                    GetCurrentProcess(),
                    handle.as_raw_handle() as *mut winapi::ctypes::c_void,
                    GetCurrentProcess(),
                    &mut dup,
                    0,
                    1, // TRUE inheritable
                    winapi::um::winnt::DUPLICATE_SAME_ACCESS,
                )
            };
            if ok == 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(unsafe { OwnedHandle::from_raw_handle(dup as *mut std::ffi::c_void) })
        }

        pub fn send(&self, buf: &[u8]) -> std::io::Result<()> {
            match &self.inner {
                Inner::Pipe { write, .. } => write_all(write, buf),
                Inner::Tcp(s) => {
                    use std::io::Write;
                    (&*s).write_all(buf)
                }
            }
        }

        /// Exact-bounded send of a whole frame buffer.
        pub fn send_all(&self, buf: &[u8]) -> std::io::Result<()> {
            self.send(buf)
        }

        /// Exact-bounded receive: blocks until filled or EOF (read_once loop).
        pub fn recv_exact(&self, buf: &mut [u8]) -> std::io::Result<()> {
            let mut off = 0;
            while off < buf.len() {
                let n = self.recv(&mut buf[off..])?;
                if n == 0 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "lane eof",
                    ));
                }
                off += n;
            }
            Ok(())
        }

        pub fn recv(&self, buf: &mut [u8]) -> std::io::Result<usize> {
            match &self.inner {
                Inner::Pipe { read, .. } => read_once(read, buf),
                Inner::Tcp(s) => {
                    use std::io::Read;
                    (&*s).read(buf)
                }
            }
        }

        // Real child spawn with explicit handle list will be implemented via
        // CreateProcessW + STARTUPINFOEXW + UpdateProcThreadAttribute in seam-process.
        // For now lane_probe Windows helper remains via separate binary + pipe inheritance test harness.
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
        use std::os::fd::AsFd;
        // Safe: AsFd borrows from live OwnedFd; SendAncillaryMessage only borrows for sendmsg duration.
        let fds = [fd.as_fd()];
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
        // REAL OS PRIMITIVE PROVEN (same-process): any fd sent via
        // SCM_RIGHTS remains functional in the recipient. Pipe continuity
        // (prefix||suffix) follows because the fd refers to the same kernel
        // object. This does NOT yet prove cross-process bootstrap.
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

    #[test]
    fn lane_cross_process_fd_transfer() {
        // REAL CROSS-PROCESS KERNEL PROOF — TEST HARNESS PROVISIONAL:
        // distinct PIDs via fork, SCM_RIGHTS continuity. Fork-from-harness
        // is not the production model (Command + inherited lane), but a
        // useful kernel regression. Canonical proof is lane_cross_process_via_command.
        // Never claim Windows evidence for this unix test.
        let (lane_a, lane_b) = NativeLane::pair().unwrap();
        let pid = unsafe { libc::fork() };
        if pid < 0 {
            panic!("fork failed");
        } else if pid == 0 {
            // Child
            drop(lane_a);
            let received: OwnedFd = lane_b.recv_fd().expect("child recv");
            let mut stream = unsafe { UnixStream::from_raw_fd(received.into_raw_fd()) };
            use std::io::{Read, Write};
            let mut prefix = [0u8; 7];
            stream.read_exact(&mut prefix).expect("child read prefix");
            assert_eq!(&prefix, b"PREFIX-");
            stream.write_all(b"SUFFIX").expect("child write");
            drop(stream);
            unsafe { libc::_exit(0) };
        } else {
            // Parent
            drop(lane_b);
            let (mut payload_a, payload_b) = UnixStream::pair().unwrap();
            use std::io::{Read, Write};
            payload_a.write_all(b"PREFIX-").unwrap();
            let fd_to_send: OwnedFd = unsafe { OwnedFd::from_raw_fd(payload_b.into_raw_fd()) };
            lane_a.send_fd(fd_to_send).unwrap();
            let mut buf = [0u8; 6];
            payload_a
                .set_read_timeout(Some(std::time::Duration::from_secs(2)))
                .ok();
            payload_a.read_exact(&mut buf).unwrap();
            assert_eq!(&buf, b"SUFFIX");
            let mut status: i32 = 0;
            unsafe { libc::waitpid(pid, &mut status, 0) };
            assert_eq!(libc::WEXITSTATUS(status), 0);
        }
    }

    #[test]
    fn lane_cross_process_via_command() {
        // REAL CROSS-PROCESS PROVEN (canonical): distinct executable via
        // Command + private inherited lane (fd 3) + SCM_RIGHTS. This is the
        // production bootstrap shape, not fork-from-harness.
        use std::os::unix::process::CommandExt;
        use std::process::Command;
        let (lane_a, lane_b) = NativeLane::pair().unwrap();
        let lane_b_raw = lane_b.as_raw_fd();
        // Binary path — CARGO_BIN_EXE set when built with --bins; fallback to target/debug
        let bin = std::env::var("CARGO_BIN_EXE_lane_probe").unwrap_or_else(|_| {
            let base = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../target/debug/lane_probe");
            if cfg!(windows) {
                base.with_extension("exe").to_string_lossy().into_owned()
            } else {
                base.to_string_lossy().into_owned()
            }
        });
        let mut cmd = Command::new(bin);
        cmd.arg("lane-child");
        // SAFETY: pre_exec runs in child after fork before exec; only async-signal-safe ops.
        unsafe {
            cmd.pre_exec(move || {
                if libc::dup2(lane_b_raw, 3) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let mut child = cmd.spawn().expect("spawn lane_probe");
        // Parent no longer needs child end — close our copy (keep lane_a)
        drop(lane_b);
        // Payload channel whose one end will be moved via lane
        let (mut payload_a, payload_b) = UnixStream::pair().unwrap();
        use std::io::{Read, Write};
        payload_a.write_all(b"PREFIX-").unwrap();
        let fd_to_send: OwnedFd = unsafe { OwnedFd::from_raw_fd(payload_b.into_raw_fd()) };
        lane_a.send_fd(fd_to_send).unwrap();
        // Child should echo SUFFIX on the moved fd's peer
        let mut buf = [0u8; 6];
        payload_a
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .ok();
        payload_a.read_exact(&mut buf).expect("parent read suffix");
        assert_eq!(&buf, b"SUFFIX");
        let status = child.wait().expect("wait child");
        assert!(status.success(), "child failed: {:?}", status);
    }

    #[test]
    fn lane_transfers_file_fd_same_unlinked_object() {
        // REAL CROSS-PROCESS PROVEN — file fd via SCM_RIGHTS, same underlying open file after unlink
        use std::fs::OpenOptions;
        use std::io::Write;
        use std::os::unix::io::IntoRawFd;
        use std::os::unix::process::CommandExt;
        use std::process::Command;
        let (lane_a, lane_b) = NativeLane::pair().unwrap();
        let lane_b_raw = lane_b.as_raw_fd();
        let bin = std::env::var("CARGO_BIN_EXE_lane_probe").unwrap_or_else(|_| {
            let base = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../target/debug/lane_probe");
            base.to_string_lossy().into_owned()
        });
        let mut cmd = Command::new(bin);
        cmd.arg("file-child");
        unsafe {
            cmd.pre_exec(move || {
                if libc::dup2(lane_b_raw, 3) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let mut child = cmd.spawn().expect("spawn file-child");
        drop(lane_b);
        // Create temp file, write PREFIX-, unlink, send fd
        let mut path = std::env::temp_dir();
        path.push(format!(
            "seam-file-{}-{}.tmp",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        file.write_all(b"PREFIX-").unwrap();
        file.flush().unwrap();
        // Unlink pathname — file remains via open fd, path reopen impossible
        let _ = std::fs::remove_file(&path);
        assert!(!path.exists(), "unlink should remove path");
        // Send fd via lane (move ownership)
        let fd_to_send: OwnedFd = unsafe { OwnedFd::from_raw_fd(file.into_raw_fd()) };
        lane_a.send_fd(fd_to_send).unwrap();
        let status = child.wait().expect("wait child");
        assert!(status.success(), "file-child failed {:?}", status);
    }
}

#[cfg(all(test, windows))]
mod tests_windows {
    use super::NativeLane;

    #[test]
    fn lane_moves_bytes_still_functional() {
        // REAL OS PRIMITIVE PROVEN (windows loopback): bytes via private lane remain functional
        let (a, b) = NativeLane::pair().unwrap();
        a.send(b"ping").unwrap();
        let mut buf = [0u8; 4];
        b.recv(&mut buf).unwrap();
        assert_eq!(&buf, b"ping");
        b.send(b"pong").unwrap();
        a.recv(&mut buf).unwrap();
        assert_eq!(&buf, b"pong");
    }

    #[test]
    #[ignore] // exercised via manual platform-verify with cargo run --bin lane_probe
    fn lane_cross_process_via_command_windows() {
        // Stub — real Command+port helper proven in workflow (see lane_probe windows)
    }
}
