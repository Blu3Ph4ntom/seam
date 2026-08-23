//! Unix FD passing via SCM_RIGHTS (rustix sendmsg/recvmsg + std ownership),
//! plus a tiny framed lane protocol so every descriptor travels with its
//! transaction identity (kind, tid, rid) in the same sendmsg.

use std::fs::File;
use std::io::{IoSlice, IoSliceMut};
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, IntoRawFd, OwnedFd};

use rustix::net::{
    recvmsg, sendmsg, RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, SendAncillaryBuffer,
    SendAncillaryMessage, SendFlags,
};

use crate::id::{EpId, TransferId};
use crate::native::ResourceId;

/// Host escrow holds the received descriptor as owned RAII state.
pub struct Escrowed(pub OwnedFd);

/// Lane message kinds.
pub const LANE_KIND_DELIVER: u8 = 1; // Host -> recipient (commit delivery)
pub const LANE_KIND_RESTORE: u8 = 2; // Host -> sender (abort restoration)
pub const LANE_KIND_STAGE: u8 = 3; // sender -> Host (staging)

#[derive(Debug)]
pub struct LaneMsg {
    pub kind: u8,
    pub tid: TransferId,
    pub rid: ResourceId,
    /// Present for STAGE/DELIVER/RESTORE; None only in malformed frames.
    pub fd: Option<OwnedFd>,
}

const HDR: usize = 1 + 16 + 16;

fn errno_to_io(e: rustix::io::Errno) -> std::io::Error {
    std::io::Error::from_raw_os_error(e.raw_os_error())
}

/// Send one descriptor with its correlation header over the lane.
/// The source File stays open; the kernel installs a new descriptor in the
/// receiver referring to the same open file description.
pub fn send_lane_msg(
    lane: &std::os::unix::net::UnixStream,
    kind: u8,
    tid: TransferId,
    rid: ResourceId,
    file: &File,
) -> std::io::Result<()> {
    // SAFETY: borrowed view of a live descriptor owned by `file`; borrow does
    // not outlive this call and `file` is never closed during sendmsg.
    let borrowed = unsafe { BorrowedFd::borrow_raw(file.as_raw_fd()) };
    let mut space = [0u8; 128];
    let mut ancillary = SendAncillaryBuffer::new(&mut space);
    let fds = [borrowed];
    let pushed = ancillary.push(SendAncillaryMessage::ScmRights(&fds));
    debug_assert!(pushed);
    let mut body = Vec::with_capacity(HDR + 1);
    body.push(kind);
    body.extend_from_slice(&tid.0);
    body.extend_from_slice(&rid.0);
    body.push(b'x'); // payload byte so MSG_TRUNC-free recv
    let iov = [IoSlice::new(&body)];
    sendmsg(lane, &iov, &mut ancillary, SendFlags::empty()).map_err(errno_to_io)?;
    Ok(())
}

/// Receive exactly one framed descriptor message.
/// Every unexpected ancillary descriptor gains immediate RAII ownership and
/// is closed on scope exit (no naked-FD window, hostile-extra safe).
pub fn recv_lane_msg(lane: &std::os::unix::net::UnixStream) -> std::io::Result<LaneMsg> {
    let mut space = [0u8; 128]; // room for several hostile descriptors
    let mut ancillary = RecvAncillaryBuffer::new(&mut space);
    let mut buf = [0u8; HDR + 1];
    let mut iov = [IoSliceMut::new(&mut buf)];
    let msg = recvmsg(lane, &mut iov, &mut ancillary, RecvFlags::empty()).map_err(errno_to_io)?;
    if msg.bytes < HDR as usize {
        // EOF or truncated: any received-but-unmatched descriptors drop here.
        for c in ancillary.drain() {
            if let RecvAncillaryMessage::ScmRights(fds) = c {
                for _fd in fds {} // OwnedFd Drop closes
            }
        }
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
                    extra += 1; // dropped => descriptor closed immediately
                }
            }
        }
    }
    if extra != 0 || found.is_none() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "expected exactly 1 descriptor, got {}",
                extra + usize::from(found.is_some())
            ),
        ));
    }
    let mut t = [0u8; 16];
    t.copy_from_slice(&buf[1..17]);
    let mut r = [0u8; 16];
    r.copy_from_slice(&buf[17..33]);
    Ok(LaneMsg {
        kind: buf[0],
        tid: TransferId(t),
        rid: ResourceId(r),
        fd: found,
    })
}

// ---- Back-compat single-fd wrappers used by host staging glue ----

pub fn send_fd(lane: &std::os::unix::net::UnixStream, file: &File) -> std::io::Result<()> {
    send_lane_msg(
        lane,
        LANE_KIND_STAGE,
        TransferId([0; 16]),
        ResourceId([0; 16]),
        file,
    )
}

pub fn recv_fd(lane: &std::os::unix::net::UnixStream) -> std::io::Result<Escrowed> {
    let m = recv_lane_msg(lane)?;
    m.fd.map(Escrowed).ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, "no SCM_RIGHTS in message")
    })
}

/// Wrap an escrowed descriptor into an application-facing File.
pub fn escrow_to_file(escrow: Escrowed) -> File {
    // SAFETY: sole owner; descriptor moves from OwnedFd into exactly one File.
    let raw = escrow.0.into_raw_fd();
    unsafe { File::from_raw_fd(raw) }
}

// ---- Host-side helpers mirroring the Windows adapter shape ----

pub fn stage_from_sender(lane: &std::os::unix::net::UnixStream) -> std::io::Result<LaneMsg> {
    let m = recv_lane_msg(lane)?;
    if m.kind != LANE_KIND_STAGE {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "unexpected lane kind",
        ));
    }
    Ok(m)
}

pub fn deliver_to_recipient(
    lane: &std::os::unix::net::UnixStream,
    tid: TransferId,
    rid: ResourceId,
    escrow: Escrowed,
) -> std::io::Result<()> {
    let f = escrow_to_file(escrow);
    send_lane_msg(lane, LANE_KIND_DELIVER, tid, rid, &f)
}

pub fn restore_to_sender(
    lane: &std::os::unix::net::UnixStream,
    tid: TransferId,
    rid: ResourceId,
    escrow: Escrowed,
) -> std::io::Result<()> {
    let f = escrow_to_file(escrow);
    send_lane_msg(lane, LANE_KIND_RESTORE, tid, rid, &f)
}

pub fn close_escrow(escrow: Escrowed) {
    drop(escrow);
}

/// Helper used by EpId-free contexts to build zero ids for plain fd probes.
pub fn zero_ep() -> EpId {
    EpId([0; 16])
}

/// Unit-provable kernel transfer: roundtrip one real framed descriptor
/// through a real socketpair using SCM_RIGHTS (no path reopen anywhere).
#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Seek, SeekFrom, Write};
    use std::os::unix::io::AsRawFd;
    use std::os::unix::net::UnixStream;

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

    #[test]
    fn scm_rights_roundtrip_transfers_real_descriptor() {
        let (a, b) = UnixStream::pair().unwrap();
        let mut src = tempfile_bytes(b"SEAM_SCM_NONCE");
        let raw_before = src.as_raw_fd();
        let tid = TransferId([7; 16]);
        let rid = ResourceId([9; 16]);
        send_lane_msg(&a, LANE_KIND_STAGE, tid, rid, &src).unwrap();
        let m = recv_lane_msg(&b).unwrap();
        assert_eq!(m.kind, LANE_KIND_STAGE);
        assert_eq!(m.tid, tid);
        assert_eq!(m.rid, rid);
        let mut file = File::from(m.fd.unwrap());
        assert_ne!(
            raw_before,
            file.as_raw_fd(),
            "kernel must install a distinct descriptor in receiver"
        );
        file.seek(SeekFrom::Start(0)).unwrap();
        let mut got = Vec::new();
        file.read_to_end(&mut got).unwrap();
        assert_eq!(got, b"SEAM_SCM_NONCE");
    }

    /// Malformed case: zero descriptors must fail closed.
    #[test]
    fn missing_descriptor_fails_closed() {
        let (mut a, b) = UnixStream::pair().unwrap();
        a.write_all(&vec![0u8; HDR]).unwrap(); // header only, no cmsg
        assert!(recv_lane_msg(&b).is_err());
    }
}
