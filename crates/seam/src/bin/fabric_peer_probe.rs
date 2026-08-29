//! fabric_peer_probe — holder/recipient child for Fabric runtime E2E.
//! Inherits two private lanes: fd 3 = CONTROL, fd 4 = NATIVE (Unix SCM_RIGHTS).
//! Unix-only logic; on other platforms the binary is a no-op.

#[cfg(unix)]
mod imp {
    use std::fs::File;
    use std::io::{Read, Seek, SeekFrom, Write};
    use std::os::unix::io::{FromRawFd, IntoRawFd, OwnedFd, RawFd};
    use std::process::exit;

    use seam_core::ids::{PeerId, ResourceId, TransferId};
    use seam_core::limits::Limits;
    use seam_core::wire::{Header, Kind, CURRENT_MAJOR, CURRENT_MINOR, MAGIC};

    use seam_platform::NativeLane;

    fn header(kind: Kind, body_len: u32) -> Header {
        Header {
            magic: MAGIC,
            major: CURRENT_MAJOR,
            minor: CURRENT_MINOR,
            kind,
            flags: 0,
            body_len,
            request_id: 0,
            channel_id: 0,
            attachment_count: 0,
            reserved: 0,
        }
    }

    fn parse16(s: &str) -> [u8; 16] {
        let s = s.trim();
        assert_eq!(s.len(), 32, "expected 32 hex chars");
        let mut out = [0u8; 16];
        for i in 0..16 {
            out[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).expect("hex");
        }
        out
    }

    /// Read PREFIX-, append SUFFIX, read PREFIX-SUFFIX, verify equality.
    fn verify_file(mut file: File) {
        file.seek(SeekFrom::Start(0)).unwrap();
        let mut prefix = [0u8; 7];
        file.read_exact(&mut prefix).unwrap();
        assert_eq!(&prefix, b"PREFIX-", "expected PREFIX-");
        file.seek(SeekFrom::End(0)).unwrap();
        file.write_all(b"SUFFIX").unwrap();
        file.flush().unwrap();
        file.seek(SeekFrom::Start(0)).unwrap();
        let mut all = Vec::new();
        file.read_to_end(&mut all).unwrap();
        assert_eq!(all, b"PREFIX-SUFFIX", "expected PREFIX-SUFFIX");
    }

    pub fn run() {
        let args: Vec<String> = std::env::args().collect();
        let get = |name: &str| -> String {
            let pos = args.iter().position(|a| a == name).expect("arg");
            args[pos + 1].clone()
        };
        let role = get("--role");
        let mode = get("--mode");
        let tid = TransferId(parse16(&get("--transfer-id")));
        let rid = ResourceId(parse16(&get("--resource-id")));
        let _peer = PeerId(parse16(&get("--peer-id")));
        let control_fd: RawFd = get("--fd-control").parse().unwrap();
        let native_fd: RawFd = get("--fd-native").parse().unwrap();

        // SAFETY: these fds are inherited private lanes owned by this process.
        let control = unsafe { NativeLane::from_raw_fd(control_fd) };
        let native = unsafe { NativeLane::from_raw_fd(native_fd) };

        if role == "holder" {
            // Create temp unlinked file with PREFIX-, wrapping with the passed ResourceId
            // so it matches the Fabric's pre-registered authority.
            let mut path = std::env::temp_dir();
            path.push(format!(
                "seam-native-{}-{}.tmp",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            let mut file = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .open(&path)
                .unwrap();
            file.write_all(b"PREFIX-").unwrap();
            file.flush().unwrap();
            let _ = std::fs::remove_file(&path); // unlink; fd keeps the open file

            // OFFER (control)
            let mut body = [0u8; 36];
            body[0..16].copy_from_slice(&tid.0);
            body[16..18].copy_from_slice(&0u16.to_le_bytes());
            body[18] = 2;
            body[19] = 1;
            body[20..36].copy_from_slice(&rid.0);
            control.send_frame(&header(Kind::Offer, 36), &body).unwrap();
            // NATIVE_ESCROW (native lane, SCM_RIGHTS of the file fd)
            let fd = file.into_raw_fd();
            let owned = unsafe { OwnedFd::from_raw_fd(fd) };
            let mut env = [0u8; 36];
            if mode == "wrong-envelope" {
                // Wrong TransferId in envelope
                let mut wrong = tid.0;
                wrong[0] ^= 0xFF;
                env[0..16].copy_from_slice(&wrong);
            } else {
                env[0..16].copy_from_slice(&tid.0);
            }
            env[16..18].copy_from_slice(&0u16.to_le_bytes());
            env[18] = 2;
            env[19] = 1;
            env[20..36].copy_from_slice(&rid.0);
            if mode == "wrong-index" {
                env[16..18].copy_from_slice(&1u16.to_le_bytes());
            }
            native
                .send_frame_fd(&header(Kind::NativeEscrow, 36), &env, owned)
                .unwrap();
            // ESCROW_ACQUIRED (not for wrong-envelope — Fabric will reject and close)
            if mode == "wrong-envelope" || mode == "wrong-index" {
                std::thread::sleep(std::time::Duration::from_millis(200));
                exit(0);
            }
            let (k, _) = control.recv_frame(&Limits::default()).unwrap();
            assert_eq!(k.kind, Kind::EscrowAcquired, "expected ESCROW_ACQUIRED");
            if mode == "duplicate" {
                // Send a second (duplicate) NativeEscrow with a fresh fd; Fabric
                // must close the late descriptor without breaking the transfer.
                let mut dup = std::env::temp_dir();
                dup.push(format!(
                    "seam-dup-{}-{}.tmp",
                    std::process::id(),
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_nanos()
                ));
                let mut f = std::fs::OpenOptions::new()
                    .read(true)
                    .write(true)
                    .create_new(true)
                    .open(&dup)
                    .unwrap();
                f.write_all(b"DUP-").unwrap();
                f.flush().unwrap();
                let _ = std::fs::remove_file(&dup);
                let dup_fd = unsafe { OwnedFd::from_raw_fd(f.into_raw_fd()) };
                let _ = native.send_frame_fd(&header(Kind::NativeEscrow, 36), &env, dup_fd);
                std::thread::sleep(std::time::Duration::from_millis(200));
                exit(0);
            }
            if mode == "success" {
                exit(0);
            } else if mode == "abort" {
                // ABORT: wait RESTORE (native lane, SCM_RIGHTS back)
                let (k2, _b, fd2) = native.recv_frame_fd(&Limits::default()).unwrap();
                assert_eq!(k2.kind, Kind::Restore, "expected RESTORE");
                let file = unsafe { File::from_raw_fd(fd2.into_raw_fd()) };
                verify_file(file);
                control
                    .send_frame(&header(Kind::RestoreAck, 16), &tid.0)
                    .unwrap();
                exit(0);
            }
        } else {
            // recipient
            control
                .send_frame(&header(Kind::Accept, 16), &tid.0)
                .unwrap();
            let (k, _b, fd) = native.recv_frame_fd(&Limits::default()).unwrap();
            assert_eq!(k.kind, Kind::NativeDeliver, "expected NATIVE_DELIVER");
            control
                .send_frame(&header(Kind::NativeStaged, 16), &tid.0)
                .unwrap();
            let (k2, _) = control.recv_frame(&Limits::default()).unwrap();
            if k2.kind == Kind::Commit {
                let file = unsafe { File::from_raw_fd(fd.into_raw_fd()) };
                verify_file(file);
                exit(0);
            } else {
                drop(fd);
                exit(0);
            }
        }
    }
}

fn main() {
    #[cfg(unix)]
    imp::run();
}
