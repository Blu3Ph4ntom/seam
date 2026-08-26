//! Bootstrap HELLO/WELCOME/ACK over private NativeLane.
//! Production wire header 32B LE per CTO 1G. Possession of lane = authority.

use seam_core::ids::PeerId;
use seam_core::limits::Limits;
use seam_core::wire::{Header, Kind, CURRENT_MAJOR, CURRENT_MINOR, MAGIC};
use seam_platform::NativeLane;

fn write_frame(lane: &NativeLane, header: &Header, body: &[u8]) -> std::io::Result<()> {
    let mut hdr = [0u8; 32];
    header.encode(&mut hdr);
    lane.send(&hdr)?;
    if !body.is_empty() {
        lane.send(body)?;
    }
    Ok(())
}

fn read_frame(lane: &NativeLane, limits: &Limits) -> std::io::Result<(Header, Vec<u8>)> {
    let mut hdr = [0u8; 32];
    let mut off = 0;
    while off < 32 {
        let n = lane.recv(&mut hdr[off..])?;
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "lane EOF reading header",
            ));
        }
        off += n;
    }
    let h = Header::decode(&hdr, limits)
        .map_err(|e| std::io::Error::other(format!("header decode: {e:?}")))?;
    let mut body = vec![0u8; h.body_len as usize];
    let mut off = 0;
    while off < body.len() {
        let n = lane.recv(&mut body[off..])?;
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "lane EOF reading body",
            ));
        }
        off += n;
    }
    Ok((h, body))
}

/// Parent side: wait HELLO, validate major, allocate PeerId, send WELCOME, wait ACK.
pub fn parent_handshake(lane: &NativeLane, limits: &Limits) -> std::io::Result<PeerId> {
    let (h, body) = read_frame(lane, limits)?;
    if h.kind != Kind::Control {
        return Err(std::io::Error::other("expected Control HELLO"));
    }
    if body.len() < 4 {
        return Err(std::io::Error::other("HELLO too short"));
    }
    let major = body[0];
    let minor = body[1];
    if major != CURRENT_MAJOR {
        return Err(std::io::Error::other(format!("unsupported major {major}")));
    }
    let _ = minor;
    // Allocate PeerId
    let pid = PeerId::fresh();
    // WELCOME: body = peer id 16 bytes
    let wh = Header {
        magic: MAGIC,
        major: CURRENT_MAJOR,
        minor: CURRENT_MINOR,
        kind: Kind::Control,
        flags: 1, // WELCOME
        body_len: 16,
        request_id: 1,
        channel_id: 0,
        attachment_count: 0,
        reserved: 0,
    };
    write_frame(lane, &wh, pid.as_bytes())?;
    // Wait ACK
    let (ah, abody) = read_frame(lane, limits)?;
    if ah.kind != Kind::Control || ah.flags != 2 || abody.len() != 16 {
        return Err(std::io::Error::other("expected ACK"));
    }
    if abody != pid.as_bytes() {
        return Err(std::io::Error::other("ACK peer mismatch"));
    }
    Ok(pid)
}

/// Child side: send HELLO, wait WELCOME, send ACK.
pub fn child_handshake(lane: &NativeLane, limits: &Limits) -> std::io::Result<PeerId> {
    let hello = Header {
        magic: MAGIC,
        major: CURRENT_MAJOR,
        minor: CURRENT_MINOR,
        kind: Kind::Control,
        flags: 0, // HELLO
        body_len: 4,
        request_id: 0,
        channel_id: 0,
        attachment_count: 0,
        reserved: 0,
    };
    let body = [CURRENT_MAJOR, CURRENT_MINOR, 0, 0];
    write_frame(lane, &hello, &body)?;
    let (wh, wbody) = read_frame(lane, limits)?;
    if wh.kind != Kind::Control || wh.flags != 1 || wbody.len() != 16 {
        return Err(std::io::Error::other("expected WELCOME"));
    }
    let pid = PeerId::from_bytes(wbody.try_into().unwrap());
    let ack = Header {
        magic: MAGIC,
        major: CURRENT_MAJOR,
        minor: CURRENT_MINOR,
        kind: Kind::Control,
        flags: 2,
        body_len: 16,
        request_id: 2,
        channel_id: 0,
        attachment_count: 0,
        reserved: 0,
    };
    write_frame(lane, &ack, pid.as_bytes())?;
    Ok(pid)
}

#[cfg(unix)]
pub mod unix_spawn {
    use super::*;
    use seam_platform::NativeLane;
    use std::os::unix::process::CommandExt;
    use std::process::{Child, Command};

    pub struct BootstrappedChild {
        pub child: Child,
        pub lane: NativeLane,
        pub peer: PeerId,
    }

    pub fn spawn_bootstrap(bin: &str, extra_args: &[&str]) -> std::io::Result<BootstrappedChild> {
        let (parent_lane, child_lane) = NativeLane::pair()?;
        let child_fd = child_lane.as_raw_fd();
        // Need to keep child_lane alive until spawn; we will dup2 in pre_exec
        // Use into_raw_fd to avoid double close? Keep child_lane as owned but dup.
        // We leak child_lane's fd number via raw value; parent keeps parent_lane.
        // child_lane will be closed in parent after spawn (drop).
        let mut cmd = Command::new(bin);
        for a in extra_args {
            cmd.arg(a);
        }
        cmd.arg("--bootstrap-fd");
        cmd.arg("3");
        // SAFETY: pre_exec dup2 is async-signal-safe
        unsafe {
            cmd.pre_exec(move || {
                if libc::dup2(child_fd, 3) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let mut child = cmd.spawn()?;
        // parent no longer needs child_lane copy
        drop(child_lane);
        // Handshake
        let limits = Limits::default();
        let peer = parent_handshake(&parent_lane, &limits)?;
        Ok(BootstrappedChild {
            child,
            lane: parent_lane,
            peer,
        })
    }
}

#[cfg(windows)]
pub mod windows_spawn {
    use super::*;
    use seam_platform::NativeLane;
    use std::net::TcpListener;
    use std::process::{Child, Command};

    pub struct BootstrappedChild {
        pub child: Child,
        pub lane: NativeLane,
        pub peer: PeerId,
    }

    pub fn spawn_bootstrap(bin: &str, extra_args: &[&str]) -> std::io::Result<BootstrappedChild> {
        // Temporary TCP rendezvous for bootstrap (private ephemeral port, no global service).
        // Pipe-based explicit handle list (STARTUPINFOEX) will replace this next.
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let addr = listener.local_addr()?.to_string();
        let mut cmd = Command::new(bin);
        for a in extra_args {
            cmd.arg(a);
        }
        cmd.arg("--bootstrap-addr");
        cmd.arg(&addr);
        let child = cmd.spawn()?;
        let (stream, _) = listener.accept()?;
        stream.set_nodelay(true).ok();
        let lane = NativeLane::from_tcp(stream);
        let limits = Limits::default();
        let peer = parent_handshake(&lane, &limits)?;
        Ok(BootstrappedChild { child, lane, peer })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    #[test]
    fn bootstrap_unix_valid() {
        let bin = std::env::var("CARGO_BIN_EXE_bootstrap_probe").unwrap_or_else(|_| {
            let base = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../target/debug/bootstrap_probe");
            base.to_string_lossy().into_owned()
        });
        let bc = unix_spawn::spawn_bootstrap(&bin, &[]).expect("spawn");
        assert_ne!(bc.peer, PeerId::from_bytes([0; 16]));
        let mut child = bc.child;
        let status = child.wait().expect("wait");
        assert!(status.success(), "child failed {:?}", status);
    }
    #[cfg(windows)]
    #[test]
    fn bootstrap_windows_valid() {
        let bin = std::env::var("CARGO_BIN_EXE_bootstrap_probe").unwrap_or_else(|_| {
            let base = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../target/debug/bootstrap_probe.exe");
            base.to_string_lossy().into_owned()
        });
        let bc = windows_spawn::spawn_bootstrap(&bin, &[]).expect("spawn");
        assert_ne!(bc.peer, PeerId::from_bytes([0; 16]));
        let mut child = bc.child;
        let status = child.wait().expect("wait");
        assert!(status.success(), "child failed {:?}", status);
    }
}
