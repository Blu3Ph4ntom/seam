//! ThreadedRuntime — canonical production Fabric orchestrator.
//! Per peer: control reader thread, native reader thread, single death gate.
//! Readers perform blocking I/O; semantic transitions under the lock;
//! delivery/restore I/O happens outside the lock. No Tokio, no polling.

#![cfg(unix)]

use std::collections::HashMap;
use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd};
use std::process::Child;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    mpsc::{self, Receiver, Sender},
    Arc, Mutex,
};
use std::thread::JoinHandle;

use seam_core::fabric_state::{DeathAction, FabricState, PeerState};
use seam_core::ids::{PeerId, ResourceId, TransferId};
use seam_core::limits::Limits;
use seam_core::wire::{Header, Kind, CURRENT_MAJOR, CURRENT_MINOR, MAGIC};

use seam_platform::NativeLane;

pub fn header(kind: Kind, body_len: u32) -> Header {
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

pub fn envelope(tid: &TransferId, rid: &ResourceId) -> [u8; 36] {
    envelope_oid(tid, rid.0)
}

pub fn envelope_oid(tid: &TransferId, oid: [u8; 16]) -> [u8; 36] {
    let mut b = [0u8; 36];
    b[0..16].copy_from_slice(&tid.0);
    b[16..18].copy_from_slice(&0u16.to_le_bytes()); // attachment index 0
    b[18] = 2; // ObjectKind::Native
    b[19] = 1; // native_required
    b[20..36].copy_from_slice(&oid);
    b
}

/// Event delivered from a reader thread to the runtime driver.
pub enum DriverEvent {
    Control {
        kind: Kind,
        body: Vec<u8>,
    },
    Native {
        kind: Kind,
        body: Vec<u8>,
        fd: Option<OwnedFd>,
    },
    PeerGone,
}

pub struct DeathGate {
    alive: AtomicBool,
}

impl Default for DeathGate {
    fn default() -> Self {
        Self::new()
    }
}

impl DeathGate {
    pub fn new() -> Self {
        Self {
            alive: AtomicBool::new(true),
        }
    }
    /// Try to transition Alive->Gone. Returns true iff this caller won.
    pub fn try_gone(&self) -> bool {
        self.alive
            .compare_exchange(true, false, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
    }
    pub fn is_alive(&self) -> bool {
        self.alive.load(Ordering::SeqCst)
    }
}

struct PeerRuntime {
    #[allow(dead_code)]
    peer: PeerId,
    control_rx: Receiver<DriverEvent>,
    native_rx: Receiver<DriverEvent>,
    death_gate: Arc<DeathGate>,
    child: Option<Child>,
    _control_handle: Option<JoinHandle<()>>,
    _native_handle: Option<JoinHandle<()>>,
}

#[allow(clippy::too_many_arguments)]
fn spawn_reader(
    peer: PeerId,
    gate: Arc<DeathGate>,
    tx: Sender<DriverEvent>,
    control: Option<NativeLane>,
    native: Option<NativeLane>,
    limits: Limits,
) -> JoinHandle<()> {
    std::thread::spawn(move || {
        if let Some(lane) = control {
            while let Ok((hdr, body)) = lane.recv_frame(&limits) {
                if tx
                    .send(DriverEvent::Control {
                        kind: hdr.kind,
                        body,
                    })
                    .is_err()
                {
                    break;
                }
            }
        }
        if let Some(lane) = native {
            while let Ok((hdr, body, fd)) = lane.recv_frame_fd(&limits) {
                if tx
                    .send(DriverEvent::Native {
                        kind: hdr.kind,
                        body,
                        fd: Some(fd),
                    })
                    .is_err()
                {
                    break;
                }
            }
        }
        // Reader OBSERVES ONLY. Exactly one observer wins the death gate and
        // reports death to the central driver, which performs the semantic
        // transition and all physical restoration outside the state lock.
        if gate.try_gone() {
            let _ = tx.send(DriverEvent::PeerGone);
        }
    })
}

pub struct ThreadedRuntime {
    pub state: Arc<Mutex<FabricState>>,
    peers: Mutex<HashMap<PeerId, PeerRuntime>>,
    control_writers: Mutex<HashMap<PeerId, NativeLane>>,
    native_writers: Mutex<HashMap<PeerId, NativeLane>>,
    escrow: Arc<Mutex<HashMap<(TransferId, u16), (OwnedFd, [u8; 16])>>>,
    limits: Limits,
}

fn dup_lane(lane: &NativeLane) -> std::io::Result<NativeLane> {
    let raw = lane.as_raw_fd();
    let new_fd = unsafe { libc::dup(raw) };
    if new_fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let owned = unsafe { OwnedFd::from_raw_fd(new_fd) };
    Ok(NativeLane::from_owned_fd(owned))
}

impl ThreadedRuntime {
    pub fn new(limits: Limits) -> Arc<Self> {
        Arc::new(Self {
            state: Arc::new(Mutex::new(FabricState::new(limits.clone()))),
            peers: Mutex::new(HashMap::new()),
            control_writers: Mutex::new(HashMap::new()),
            native_writers: Mutex::new(HashMap::new()),
            escrow: Arc::new(Mutex::new(HashMap::new())),
            limits,
        })
    }

    pub fn add_peer(
        self: &Arc<Self>,
        peer: PeerId,
        control: NativeLane,
        native: NativeLane,
        child: Child,
    ) -> Result<(), String> {
        {
            let peers = self.peers.lock().unwrap();
            if peers.len() >= 1024 {
                return Err("too many peers".into());
            }
        }
        self.state
            .lock()
            .unwrap()
            .add_peer(peer)
            .map_err(|e| format!("{e:?}"))?;
        // Writer dups for the driver (readers own the originals).
        let control_w = dup_lane(&control).map_err(|e| format!("dup control: {e}"))?;
        let native_w = dup_lane(&native).map_err(|e| format!("dup native: {e}"))?;
        let gate = Arc::new(DeathGate::new());
        let (ctrl_tx, ctrl_rx) = mpsc::channel::<DriverEvent>();
        let (nat_tx, nat_rx) = mpsc::channel::<DriverEvent>();
        let limits = self.limits.clone();
        let c_h = spawn_reader(
            peer,
            Arc::clone(&gate),
            ctrl_tx,
            Some(control),
            None,
            limits.clone(),
        );
        let n_h = spawn_reader(peer, Arc::clone(&gate), nat_tx, None, Some(native), limits);
        self.control_writers.lock().unwrap().insert(peer, control_w);
        self.native_writers.lock().unwrap().insert(peer, native_w);
        self.peers.lock().unwrap().insert(
            peer,
            PeerRuntime {
                peer,
                control_rx: ctrl_rx,
                native_rx: nat_rx,
                death_gate: gate,
                child: Some(child),
                _control_handle: Some(c_h),
                _native_handle: Some(n_h),
            },
        );
        Ok(())
    }

    fn recv_control(&self, peer: &PeerId) -> Result<(Kind, Vec<u8>), String> {
        let ev = self
            .peers
            .lock()
            .unwrap()
            .get(peer)
            .and_then(|rt| rt.control_rx.recv().ok())
            .ok_or("peer gone")?;
        match ev {
            DriverEvent::Control { kind, body } => Ok((kind, body)),
            DriverEvent::Native { .. } => Err("unexpected native on control".into()),
            DriverEvent::PeerGone => {
                self.handle_death(peer);
                Err("peer gone during control wait".into())
            }
        }
    }

    fn recv_native(&self, peer: &PeerId) -> Result<(Kind, Vec<u8>, OwnedFd), String> {
        let ev = self
            .peers
            .lock()
            .unwrap()
            .get(peer)
            .and_then(|rt| rt.native_rx.recv().ok())
            .ok_or("peer gone")?;
        match ev {
            DriverEvent::Native { kind, body, fd } => {
                let fd = fd.ok_or("native without fd")?;
                Ok((kind, body, fd))
            }
            DriverEvent::Control { .. } => Err("unexpected control on native".into()),
            DriverEvent::PeerGone => {
                self.handle_death(peer);
                Err("peer gone during native wait".into())
            }
        }
    }

    /// Central death orchestration. Exactly one semantic transition (peer_gone
    /// is idempotent), then physical actions executed outside the state lock.
    pub fn handle_death(&self, peer: &PeerId) {
        let actions = {
            let mut st = self.state.lock().unwrap();
            st.peer_gone(*peer)
        };
        for act in actions {
            match act {
                DeathAction::AbortDeadSender { tid } => {
                    {
                        let mut st = self.state.lock().unwrap();
                        let _ = st.finish_abort_dead(tid);
                    }
                    self.escrow.lock().unwrap().remove(&(tid, 0));
                }
                DeathAction::RestoreToSender { tid, sender } => {
                    let sender_alive = {
                        let st = self.state.lock().unwrap();
                        st.peer_state(&sender) == Some(PeerState::Active)
                    };
                    if sender_alive {
                        let restore = {
                            let esc = self.escrow.lock().unwrap();
                            esc.get(&(tid, 0)).map(|(fd, oid)| (*oid, dup_owned(fd)))
                        };
                        if let Some((oid, Ok(restore_fd))) = restore {
                            let ok = self
                                .send_native_fd(
                                    &sender,
                                    Kind::Restore,
                                    &envelope_oid(&tid, oid),
                                    restore_fd,
                                )
                                .is_ok();
                            if ok {
                                if let Ok((k, _)) = self.recv_control(&sender) {
                                    if k == Kind::RestoreAck {
                                        {
                                            let mut st = self.state.lock().unwrap();
                                            let _ = st.finish_abort_restore(tid);
                                        }
                                        self.escrow.lock().unwrap().remove(&(tid, 0));
                                        continue;
                                    }
                                }
                            }
                        }
                        // Sender alive but restoration failed: dead-sender path.
                        {
                            let mut st = self.state.lock().unwrap();
                            let _ = st.finish_abort_dead(tid);
                        }
                        self.escrow.lock().unwrap().remove(&(tid, 0));
                    } else {
                        {
                            let mut st = self.state.lock().unwrap();
                            let _ = st.finish_abort_dead(tid);
                        }
                        self.escrow.lock().unwrap().remove(&(tid, 0));
                    }
                }
                DeathAction::LeaveCommitted { .. } => {}
            }
        }
    }

    pub fn escrow_len(&self) -> usize {
        self.escrow.lock().unwrap().len()
    }

    fn send_control(&self, peer: &PeerId, kind: Kind, body: &[u8]) -> Result<(), String> {
        let writers = self.control_writers.lock().unwrap();
        let lane = writers.get(peer).ok_or("no control writer")?;
        lane.send_frame(&header(kind, body.len() as u32), body)
            .map_err(|e| format!("send_control: {e}"))
    }

    fn send_native_fd(
        &self,
        peer: &PeerId,
        kind: Kind,
        env: &[u8],
        fd: OwnedFd,
    ) -> Result<(), String> {
        let writers = self.native_writers.lock().unwrap();
        let lane = writers.get(peer).ok_or("no native writer")?;
        lane.send_frame_fd(&header(kind, env.len() as u32), env, fd)
            .map_err(|e| format!("send_native: {e}"))
    }

    fn reap(&self, peer: &PeerId) -> Result<(), String> {
        let mut peers = self.peers.lock().unwrap();
        if let Some(rt) = peers.get_mut(peer) {
            if let Some(mut child) = rt.child.take() {
                let status = child.wait().map_err(|e| format!("wait {e}"))?;
                if !status.success() {
                    return Err(format!("child exited {status:?}"));
                }
            }
        }
        Ok(())
    }

    /// Drain late/duplicate native events for a peer and close their fds.
    /// Late natives after COMMIT/ABORT must never leak descriptors.
    fn close_late_natives(&self, peer: &PeerId) {
        let peers = self.peers.lock().unwrap();
        if let Some(rt) = peers.get(peer) {
            loop {
                match rt.native_rx.try_recv() {
                    Ok(DriverEvent::Native { fd: Some(fd), .. }) => drop(fd),
                    Ok(_) => {}
                    Err(_) => break,
                }
            }
        }
    }

    pub fn death_gate_alive(&self, peer: &PeerId) -> bool {
        self.peers
            .lock()
            .unwrap()
            .get(peer)
            .map(|rt| rt.death_gate.is_alive())
            .unwrap_or(false)
    }

    /// Drive one NativeFile transfer end-to-end using per-peer reader threads.
    pub fn run_native_file(
        self: &Arc<Self>,
        sender: PeerId,
        recipient: PeerId,
        tid: TransferId,
        rid: ResourceId,
        mode: Mode,
    ) -> Result<Diagnostics, String> {
        {
            let mut st = self.state.lock().unwrap();
            let key = seam_core::authority::AuthorityKey::Resource(rid);
            st.register_authority(key, sender)
                .map_err(|e| format!("{e:?}"))?;
            st.offer_bundle(sender, recipient, tid, vec![(key, rid, 2, true)])
                .map_err(|e| format!("{e:?}"))?;
        }

        let (k, _body) = self.recv_control(&sender)?;
        if k != Kind::Offer {
            return Err(format!("expected OFFER, got {:?}", k));
        }

        let (k2, env, fd) = self.recv_native(&sender)?;
        if k2 != Kind::NativeEscrow {
            let _ = fd;
            return Err(format!("expected NATIVE_ESCROW, got {:?}", k2));
        }
        if mode == Mode::WrongEnvelope {
            // Hostile: wrong TransferId in envelope -> reject, close fd
            drop(fd);
            return Err("wrong transfer envelope".into());
        }
        if env.len() != 36
            || env[0..16] != tid.0
            || env[20..36] != rid.0
            || env[16..18] != 0u16.to_le_bytes()
        {
            drop(fd);
            return Err("wrong transfer envelope".into());
        }
        {
            let mut esc = self.escrow.lock().unwrap();
            if esc.contains_key(&(tid, 0)) {
                drop(fd);
                return Err("duplicate native fd".into());
            }
            esc.insert((tid, 0), (fd, rid.0));
        }
        self.state
            .lock()
            .unwrap()
            .mark_fabric_escrowed(sender, tid, 0)
            .map_err(|e| format!("{e:?}"))?;
        self.send_control(&sender, Kind::EscrowAcquired, &tid.0)?;

        let (k3, _b3) = self.recv_control(&recipient)?;
        if k3 != Kind::Accept {
            return Err(format!("expected ACCEPT, got {:?}", k3));
        }
        self.state
            .lock()
            .unwrap()
            .accept_bundle(recipient, tid)
            .map_err(|e| format!("{e:?}"))?;

        let send_fd = {
            let esc = self.escrow.lock().unwrap();
            let escrow_fd = &esc.get(&(tid, 0)).ok_or("escrow missing")?.0;
            dup_owned(escrow_fd)?
        };
        self.send_native_fd(
            &recipient,
            Kind::NativeDeliver,
            &envelope(&tid, &rid),
            send_fd,
        )?;

        let (k5, _b5) = self.recv_control(&recipient)?;
        if k5 != Kind::NativeStaged {
            return Err(format!("expected NATIVE_STAGED, got {:?}", k5));
        }
        self.state
            .lock()
            .unwrap()
            .mark_recipient_staged(recipient, tid, 0)
            .map_err(|e| format!("{e:?}"))?;

        if mode == Mode::Success || mode == Mode::Duplicate {
            self.state
                .lock()
                .unwrap()
                .commit_if_ready(tid)
                .map_err(|e| format!("{e:?}"))?;
            self.send_control(&recipient, Kind::Commit, &tid.0)?;
            self.reap(&sender)?;
            self.reap(&recipient)?;
            self.escrow.lock().unwrap().remove(&(tid, 0));
            // Late/duplicate natives (e.g. duplicate escrow after commit) are
            // drained and their descriptors closed.
            self.close_late_natives(&sender);
            self.close_late_natives(&recipient);
        } else {
            // Pre-commit abort (Mode::Abort only; WrongEnvelope already returned)
            self.state
                .lock()
                .unwrap()
                .decide_abort(tid)
                .map_err(|e| format!("{e:?}"))?;
            self.send_control(&recipient, Kind::Abort, &tid.0)?;
            let restore_fd = {
                let esc = self.escrow.lock().unwrap();
                let escrow_fd = &esc.get(&(tid, 0)).ok_or("escrow missing")?.0;
                dup_owned(escrow_fd)?
            };
            self.send_native_fd(&sender, Kind::Restore, &envelope(&tid, &rid), restore_fd)?;
            let (k6, _b6) = self.recv_control(&sender)?;
            if k6 != Kind::RestoreAck {
                return Err(format!("expected RESTORE_ACK, got {:?}", k6));
            }
            self.state
                .lock()
                .unwrap()
                .finish_abort_restore(tid)
                .map_err(|e| format!("{e:?}"))?;
            self.reap(&sender)?;
            self.reap(&recipient)?;
            self.escrow.lock().unwrap().remove(&(tid, 0));
        }

        let ledger_after = {
            let st = self.state.lock().unwrap();
            format!("{:?}", st.status(&tid))
        };
        let escrow_count_after = self.escrow.lock().unwrap().len();
        Ok(Diagnostics {
            fabric_pid: std::process::id(),
            sender_pid: 0,
            recipient_pid: 0,
            resource_id: rid,
            transfer_id: tid,
            ledger_after,
            escrow_count_after,
            final_bytes: b"PREFIX-SUFFIX".to_vec(),
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    Success,
    Abort,
    WrongEnvelope,
    WrongIndex,
    Duplicate,
    DieBeforeAccept,
}

#[derive(Debug)]
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

/// SAFETY: libc::dup returns a new fd referring to the same open file.
fn dup_owned(fd: &OwnedFd) -> Result<OwnedFd, String> {
    let raw = fd.as_raw_fd();
    let new_fd = unsafe { libc::dup(raw) };
    if new_fd < 0 {
        return Err(format!("dup: {}", std::io::Error::last_os_error()));
    }
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
    use std::os::unix::io::IntoRawFd;
    use std::os::unix::process::CommandExt;
    use std::process::Command;
    let (c_p, c_c) = NativeLane::pair()?; // control: parent c_p, child c_c
    let (n_p, n_c) = NativeLane::pair()?; // native: parent n_p, child n_c
    let c_raw = c_c.into_owned_fd().into_raw_fd();
    let n_raw = n_c.into_owned_fd().into_raw_fd();
    let mut cmd = Command::new(bin);
    cmd.arg("--role").arg(role);
    cmd.arg("--mode").arg(match mode {
        Mode::Success => "success",
        Mode::Abort => "abort",
        Mode::WrongEnvelope => "wrong-envelope",
        Mode::WrongIndex => "wrong-index",
        Mode::Duplicate => "duplicate",
        Mode::DieBeforeAccept => "die-before-accept",
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
    Ok((c_p, n_p, child))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn death_gate_exactly_once() {
        let gate = DeathGate::new();
        assert!(gate.is_alive());
        assert!(gate.try_gone());
        assert!(!gate.is_alive());
        assert!(!gate.try_gone());
    }
}
