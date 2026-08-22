//! Unix FD passing via SCM_RIGHTS over UnixStream.

use std::fs::File;
use std::os::unix::io::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd};

use rustix::cmsg_space;
use rustix::net::{RecvAncillaryBuffer, RecvAncillaryMessage, SendAncillaryBuffer, SendAncillaryMessage};

use super::ResourceId;

/// Host escrow holds the received OwnedFd.
pub struct Escrowed(pub OwnedFd);

/// Send a File's FD over the resource lane socket.
/// The File is borrowed; the sender must close its own copy only after Host confirms.
pub fn send_fd(lane: &std::os::unix::net::UnixStream, file: &File) -> std::io::Result<()> {
    let fd = file.as_raw_fd();
    // SAFETY: BorrowedFd is valid for the duration of this call
    let borrowed = unsafe { BorrowedFd::borrow_raw(fd) };
    let mut cmsg_space = cmsg_space!(ScmRights(1));
    let mut ancillary = SendAncillaryBuffer::new(&mut cmsg_space);
    ancillary.push(SendAncillaryMessage::ScmRights(&[borrowed]));
    // Use rustix's sendmsg with one dummy byte
    let stream = rustix::net::Socket::from_raw_fd(lane.as_raw_fd());
    // We must not close the raw fd; we borrowed it
    let iov = [std::io::IoSlice::new(b"x")];
    rustix::net::sendmsg(&stream, &iov, &mut ancillary, rustix::net::SendFlags::empty())?;
    std::mem::forget(stream);
    Ok(())
}

/// Receive one FD from the lane. Returns Escrowed.
pub fn recv_fd(lane: &std::os::unix::net::UnixStream) -> std::io::Result<Escrowed> {
    let mut cmsg_space = cmsg_space!(ScmRights(1));
    let mut ancillary = RecvAncillaryBuffer::new(&mut cmsg_space);
    let mut buf = [0u8; 1];
    let mut iov = [std::io::IoSliceMut::new(&mut buf)];
    let stream = rustix::net::Socket::from_raw_fd(lane.as_raw_fd());
    let msg = rustix::net::recvmsg(&stream, &mut iov, &mut ancillary, rustix::net::RecvFlags::empty())?;
    std::mem::forget(stream);
    if msg.bytes == 0 {
        return Err(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "no fd"));
    }
    for cmsg in ancillary.drain() {
        if let RecvAncillaryMessage::ScmRights(mut fds) = cmsg {
            if let Some(fd) = fds.next() {
                // fd is OwnedFd already
                return Ok(Escrowed(fd));
            }
        }
    }
    Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "no SCM_RIGHTS"))
}

/// Host stages from sender: recv FD from sender lane and return Escrowed.
pub fn stage_from_sender(lane: &std::os::unix::net::UnixStream) -> std::io::Result<Escrowed> {
    recv_fd(lane)
}

/// Host restores to sender: send escrow FD back to sender lane.
pub fn restore_to_sender(lane: &std::os::unix::net::UnixStream, escrow: Escrowed) -> std::io::Result<()> {
    // Convert OwnedFd to File for sending
    let file = File::from(escrow.0);
    send_fd(lane, &file)?;
    // File's OwnedFd is consumed by send (dup), original File drops and closes its copy
    // The sent FD is a dup; Host's escrow is now gone (moved into File)
    Ok(())
}

/// Host commits to recipient: send escrow FD to recipient lane.
pub fn commit_to_recipient(lane: &std::os::unix::net::UnixStream, escrow: Escrowed) -> std::io::Result<()> {
    let file = File::from(escrow.0);
    send_fd(lane, &file)?;
    Ok(())
}

pub fn close_escrow(escrow: Escrowed) {
    drop(escrow);
}

/// Helper to materialize Escrowed into File for recipient
pub fn escrow_to_file(escrow: Escrowed) -> File {
    File::from(escrow.0)
}

/// Materialize received FD on peer side into NativeFile
pub fn recv_to_file(lane: &std::os::unix::net::UnixStream, _rid: ResourceId) -> std::io::Result<File> {
    let esc = recv_fd(lane)?;
    Ok(File::from(esc.0))
}
