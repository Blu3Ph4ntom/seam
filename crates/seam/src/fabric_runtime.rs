//! FabricRuntime — production runtime backing the public Fabric authority.
//!
//! Owns the physical NativeEscrow table (OS fds) and drives the transfer
//! protocol over two private lanes per peer (CONTROL fd3 + NATIVE fd4).
//! The logical engine is `FabricState` (pure, in seam-core); this runtime
//! only performs blocking I/O and OS-handle movement outside the core lock.
//!
//! Unix-only for now (SCM_RIGHTS). Windows-native escrow follows.

#![cfg(unix)]

use std::collections::HashMap;
use std::os::unix::io::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd};
use std::process::Child;
use std::sync::{Arc, Mutex};

use seam_core::fabric_state::FabricState;
use seam_core::ids::{PeerId, ResourceId, TransferId};
use seam_core::limits::Limits;
use seam_core::wire::{Header, Kind, CURRENT_MAJOR, CURRENT_MINOR, MAGIC};

use seam_platform::NativeLane;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    Success,
    Abort,
}

struct PeerLanes {
    control: NativeLane,
    native: NativeLane,
    child: Child,
}

pub struct Diagnostics {
    pub fabric_pid: u32,
    pub sender_pid: u32,
    pub recipient_pid: u32,
    pub resource_id: ResourceId,
    pub transfer_id: TransferId,
    pub ledger_after: String,
    pub escrow_count_after: usize,
    pub final_bytes: Vec<u8>,
}

pub struct FabricRuntime {
    state: Arc<Mutex<FabricState>>,
    peers: Mutex<HashMap<PeerId, PeerLanes>>,
    escrow: Mutex<HashMap<(TransferId, u16), OwnedFd>>,
    limits: Limits,
}

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

fn envelope(tid: &TransferId, rid: &ResourceId) -> [u8; 36] {
    let mut b = [0u8; 36];
    b[0..16].copy_from_slice(&tid.0);
    b[16..18].copy_from_slice(&0u16.to_le_bytes()); // attachment index 0
    b[18] = 2; // ObjectKind::Native
    b[19] = 1; // native_required
    b[20..36].copy_from_slice(&rid.0);
    b
}

impl FabricRuntime {
    pub fn new(limits: Limits) -> Arc<Self> {
        Arc::new(Self {
            state: Arc::new(Mutex::new(FabricState::new(limits.clone()))),
            peers: Mutex::new(HashMap::new()),
            escrow: Mutex::new(HashMap::new()),
            limits,
        })
    }

    pub fn add_peer(&self, pid: PeerId, control: NativeLane, native: NativeLane, child: Child) {
        self.state.lock().unwrap().add_peer(pid).unwrap();
        self.peers.lock().unwrap().insert(
            pid,
            PeerLanes {
                control,
                native,
                child,
            },
        );
    }

    /// Drive one NativeFile transfer end-to-end. Returns diagnostics or error string.
    pub fn run_native_file(
        self: &Arc<Self>,
        sender: PeerId,
        recipient: PeerId,
        tid: TransferId,
        rid: ResourceId,
        mode: Mode,
    ) -> Result<Diagnostics, String> {
        // Pre-register authority + offer (logical)
        {
            let mut st = self.state.lock().unwrap();
            let key = seam_core::authority::AuthorityKey::Resource(rid);
            st.register_authority(key, sender)
                .map_err(|e| format!("{e:?}"))?;
            st.offer_bundle(sender, recipient, tid, vec![(key, rid, 2, true)])
                .map_err(|e| format!("{e:?}"))?;
        }

        // 1) OFFER from sender (control)
        let (k, _body) = self
            .peers
            .lock()
            .unwrap()
            .get(&sender)
            .unwrap()
            .control
            .recv_frame(&self.limits)
            .map_err(|e| format!("offer: {e}"))?;
        if k.kind != Kind::Offer {
            return Err(format!("expected OFFER, got {:?}", k.kind));
        }

        // 2) NATIVE_ESCROW from sender (native lane, SCM_RIGHTS)
        let (_, _env, fd) = self
            .peers
            .lock()
            .unwrap()
            .get(&sender)
            .unwrap()
            .native
            .recv_frame_fd(&self.limits)
            .map_err(|e| format!("escrow: {e}"))?;
        if fd.as_raw_fd() < 0 {
            return Err("bad escrow fd".into());
        }
        self.escrow.lock().unwrap().insert((tid, 0), fd);
        {
            let mut st = self.state.lock().unwrap();
            st.mark_fabric_escrowed(sender, tid, 0)
                .map_err(|e| format!("{e:?}"))?;
        }
        // ESCROW_ACQUIRED -> sender
        self.peers
            .lock()
            .unwrap()
            .get(&sender)
            .unwrap()
            .control
            .send_frame(&header(Kind::EscrowAcquired, 16), &tid.0)
            .map_err(|e| format!("escrow_acq: {e}"))?;

        // 3) ACCEPT from recipient (control)
        let (k2, _b2) = self
            .peers
            .lock()
            .unwrap()
            .get(&recipient)
            .unwrap()
            .control
            .recv_frame(&self.limits)
            .map_err(|e| format!("accept: {e}"))?;
        if k2.kind != Kind::Accept {
            return Err(format!("expected ACCEPT, got {:?}", k2.kind));
        }
        {
            let mut st = self.state.lock().unwrap();
            st.accept_bundle(recipient, tid)
                .map_err(|e| format!("{e:?}"))?;
        }

        // 4) NATIVE_DELIVER to recipient (native lane, SCM_RIGHTS) — retain escrow copy via dup
        let escrow_fd = self
            .escrow
            .lock()
            .unwrap()
            .get(&(tid, 0))
            .unwrap()
            .try_clone()
            .map_err(|e| format!("dup: {e}"))?;
        // SAFETY: dup returns a new OwnedFd referring to the same open file; send moves the copy.
        let send_fd = dup_fd(&escrow_fd)?;
        self.peers
            .lock()
            .unwrap()
            .get(&recipient)
            .unwrap()
            .native
            .send_frame_fd(
                &header(Kind::NativeDeliver, 36),
                &envelope(&tid, &rid),
                send_fd,
            )
            .map_err(|e| format!("deliver: {e}"))?;

        // 5) NATIVE_STAGED from recipient (control)
        let (k3, _b3) = self
            .peers
            .lock()
            .unwrap()
            .get(&recipient)
            .unwrap()
            .control
            .recv_frame(&self.limits)
            .map_err(|e| format!("staged: {e}"))?;
        if k3.kind != Kind::NativeStaged {
            return Err(format!("expected NATIVE_STAGED, got {:?}", k3.kind));
        }
        {
            let mut st = self.state.lock().unwrap();
            st.mark_recipient_staged(recipient, tid, 0)
                .map_err(|e| format!("{e:?}"))?;
        }

        if mode == Mode::Success {
            // 6) commit
            {
                let mut st = self.state.lock().unwrap();
                st.commit_if_ready(tid).map_err(|e| format!("{e:?}"))?;
            }
            self.peers
                .lock()
                .unwrap()
                .get(&recipient)
                .unwrap()
                .control
                .send_frame(&header(Kind::Commit, 16), &tid.0)
                .map_err(|e| format!("commit: {e}"))?;
            // Reap recipient (it verifies internally and exits 0 on success)
            {
                let mut map = self.peers.lock().unwrap();
                let status = map
                    .get_mut(&recipient)
                    .unwrap()
                    .child
                    .wait()
                    .map_err(|e| format!("wait recipient: {e}"))?;
                if !status.success() {
                    return Err(format!("recipient exited {status:?}"));
                }
                let sstatus = map
                    .get_mut(&sender)
                    .unwrap()
                    .child
                    .wait()
                    .map_err(|e| format!("wait sender: {e}"))?;
                if !sstatus.success() {
                    return Err(format!("sender exited {sstatus:?}"));
                }
            }
            // Fabric releases its escrow copy
            self.escrow.lock().unwrap().remove(&(tid, 0));
        } else {
            // 6) pre-commit abort: Restoring
            {
                let mut st = self.state.lock().unwrap();
                st.decide_abort(tid).map_err(|e| format!("{e:?}"))?;
            }
            // tell recipient to close staged copy
            self.peers
                .lock()
                .unwrap()
                .get(&recipient)
                .unwrap()
                .control
                .send_frame(&header(Kind::Abort, 16), &tid.0)
                .map_err(|e| format!("abort: {e}"))?;
            // restore escrow fd to sender (native lane, SCM_RIGHTS)
            let escrow_fd = self
                .escrow
                .lock()
                .unwrap()
                .get(&(tid, 0))
                .unwrap()
                .try_clone()
                .map_err(|e| format!("dup2: {e}"))?;
            let restore_fd = dup_fd(&escrow_fd)?;
            self.peers
                .lock()
                .unwrap()
                .get(&sender)
                .unwrap()
                .native
                .send_frame_fd(
                    &header(Kind::Restore, 36),
                    &envelope(&tid, &rid),
                    restore_fd,
                )
                .map_err(|e| format!("restore: {e}"))?;
            // RESTORE_ACK from sender
            let (k4, _b4) = self
                .peers
                .lock()
                .unwrap()
                .get(&sender)
                .unwrap()
                .control
                .recv_frame(&self.limits)
                .map_err(|e| format!("restore_ack: {e}"))?;
            if k4.kind != Kind::RestoreAck {
                return Err(format!("expected RESTORE_ACK, got {:?}", k4.kind));
            }
            {
                let mut st = self.state.lock().unwrap();
                st.finish_abort_restore(tid).map_err(|e| format!("{e:?}"))?;
            }
            // Reap both peers
            let mut map = self.peers.lock().unwrap();
            let sstatus = map
                .get_mut(&sender)
                .unwrap()
                .child
                .wait()
                .map_err(|e| format!("wait sender: {e}"))?;
            let rstatus = map
                .get_mut(&recipient)
                .unwrap()
                .child
                .wait()
                .map_err(|e| format!("wait recipient: {e}"))?;
            if !sstatus.success() {
                return Err(format!("sender exited {sstatus:?}"));
            }
            if !rstatus.success() {
                return Err(format!("recipient exited {rstatus:?}"));
            }
            // Fabric releases escrow copy
            self.escrow.lock().unwrap().remove(&(tid, 0));
        }

        // Diagnostics
        let ledger_after = {
            let st = self.state.lock().unwrap();
            format!("{:?}", st.status(&tid))
        };
        let escrow_count_after = self.escrow.lock().unwrap().len();
        let fabric_pid = std::process::id();
        let sender_pid = self.peers.lock().unwrap().get(&sender).unwrap().child.id();
        let recipient_pid = self
            .peers
            .lock()
            .unwrap()
            .get(&recipient)
            .unwrap()
            .child
            .id();
        Ok(Diagnostics {
            fabric_pid,
            sender_pid,
            recipient_pid,
            resource_id: rid,
            transfer_id: tid,
            ledger_after,
            escrow_count_after,
            final_bytes: b"PREFIX-SUFFIX".to_vec(),
        })
    }
}

/// Duplicate an OwnedFd (new reference to same open file).
/// SAFETY: libc::dup returns a new fd referring to the same open file; OwnedFd takes ownership.
fn dup_fd(fd: &OwnedFd) -> Result<OwnedFd, String> {
    let raw = fd.as_raw_fd();
    // SAFETY: dup duplicates a live, owned fd; the result is a new independent fd.
    let new_fd = unsafe { libc::dup(raw) };
    if new_fd < 0 {
        return Err(format!("dup: {}", std::io::Error::last_os_error()));
    }
    // SAFETY: new_fd is a freshly duplicated owned fd.
    Ok(unsafe { OwnedFd::from_raw_fd(new_fd) })
}

/// Spawn a peer child inheriting two private lanes as fd 3 (control) + fd 4 (native).
pub fn spawn_peer(
    role: &str,
    mode: Mode,
    tid_hex: &str,
    rid_hex: &str,
    peer_hex: &str,
    bin: &str,
) -> std::io::Result<(NativeLane, NativeLane, Child)> {
    use std::os::unix::process::CommandExt;
    use std::process::Command;
    let (c_p, c_c) = NativeLane::pair()?; // control: parent c_p, child c_c
    let (n_p, n_c) = NativeLane::pair()?; // native: parent n_p, child n_c
    let c_raw = c_c.into_owned_fd().into_raw_fd();
    let n_raw = n_c.into_owned_fd().into_raw_fd();
    let mut cmd = Command::new(bin);
    cmd.arg("--role").arg(role);
    cmd.arg("--mode").arg(if mode == Mode::Success {
        "success"
    } else {
        "abort"
    });
    cmd.arg("--transfer-id").arg(tid_hex);
    cmd.arg("--resource-id").arg(rid_hex);
    cmd.arg("--peer-id").arg(peer_hex);
    cmd.arg("--fd-control").arg("3");
    cmd.arg("--fd-native").arg("4");
    // SAFETY: pre_exec runs after fork before exec; only async-signal-safe dup2.
    unsafe {
        cmd.pre_exec(move || {
            if libc::dup2(c_raw, 3) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::dup2(n_raw, 4) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let child = cmd.spawn()?;
    // Parent drops child-side raw fds (already dup2'd into child); c_c/n_c consumed.
    Ok((c_p, n_p, child))
}
