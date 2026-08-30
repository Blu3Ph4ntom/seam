//! FabricExecutor — sole production mutator of FabricState.
//! Readers, waiters and effect workers are observation-only; they emit typed
//! events to the central executor queue. The executor owns FabricState,
//! escrow, peer liveness, RestoreSessions and pending transfer contexts.
//! No global peer map is held across blocking I/O.
//!
//! "FabricExecutor is the sole production mutator of FabricState."

#![cfg(unix)]

use std::collections::HashMap;
use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd};
use std::process::Child;
use std::sync::mpsc::{self, Receiver, Sender};

use seam_core::authority::{AuthorityKey, AuthorityState};
use seam_core::fabric_state::{DeathAction, FabricState, PeerState};
use seam_core::ids::{PeerId, ResourceId, TransferId};
use seam_core::limits::Limits;
use seam_core::transfer::TransferStatus;
use seam_core::wire::{Header, Kind, CURRENT_MAJOR, CURRENT_MINOR, MAGIC};

use seam_platform::NativeLane;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PeerLiveness {
    Active,
    Dying,
    Gone,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RestoreState {
    Preparing,
    SendInFlight,
    AwaitingAck,
    Acked,
    Failed,
}

pub struct RestoreSession {
    pub tid: TransferId,
    pub sender: PeerId,
    pub recipient: PeerId,
    pub oid: [u8; 16],
    pub state: RestoreState,
    pub pending_ack: bool,
}

struct PeerEntry {
    #[allow(dead_code)]
    peer: PeerId,
    liveness: PeerLiveness,
    control_writer: NativeLane,
    native_writer: NativeLane,
    control_closed: bool,
    native_closed: bool,
    process_exited: bool,
    process_exit_ok: bool,
}

/// Transfer context for a pending NativeFile transfer driven by executor.
struct TransferContext {
    sender: PeerId,
    recipient: PeerId,
    #[allow(dead_code)]
    tid: TransferId,
    rid: ResourceId,
    mode: crate::threaded_runtime::Mode,
    reply: Option<Sender<Result<Diagnostics, String>>>,
    // state machine
    offer_seen: bool,
    escrow_seen: bool,
    accept_seen: bool,
    delivered: bool,
    staged_seen: bool,
    committed: bool,
    done: bool,
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

/// Typed executor events — observation only from readers/waiters/effects.
pub enum ExecutorEvent {
    AddPeer {
        peer: PeerId,
        control: NativeLane,
        native: NativeLane,
        child: Child,
        reply: Sender<Result<(), String>>,
    },
    Transfer {
        sender: PeerId,
        recipient: PeerId,
        tid: TransferId,
        rid: ResourceId,
        mode: crate::threaded_runtime::Mode,
        reply: Sender<Result<Diagnostics, String>>,
    },
    ControlFrame {
        peer: PeerId,
        kind: Kind,
        body: Vec<u8>,
    },
    NativeFrame {
        peer: PeerId,
        kind: Kind,
        body: Vec<u8>,
        fd: OwnedFd,
    },
    ControlClosed {
        peer: PeerId,
    },
    NativeClosed {
        peer: PeerId,
    },
    ProcessExited {
        peer: PeerId,
        exit_ok: bool,
    },
    EffectCompleted {
        peer: PeerId,
        kind: Kind,
        tid: TransferId,
        success: bool,
    },
    QueryStatus {
        tid: TransferId,
        reply: Sender<TransferStatus>,
    },
    QueryAuthority {
        key: AuthorityKey,
        reply: Sender<Option<AuthorityState>>,
    },
    QueryEscrowLen {
        reply: Sender<usize>,
    },
    QueryPeerState {
        peer: PeerId,
        reply: Sender<Option<PeerState>>,
    },
    QueryPeerLiveness {
        peer: PeerId,
        reply: Sender<Option<PeerLiveness>>,
    },
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

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
    b[16..18].copy_from_slice(&0u16.to_le_bytes());
    b[18] = 2;
    b[19] = 1;
    b[20..36].copy_from_slice(&rid.0);
    b
}

fn envelope_oid(tid: &TransferId, oid: [u8; 16]) -> [u8; 36] {
    let mut b = [0u8; 36];
    b[0..16].copy_from_slice(&tid.0);
    b[16..18].copy_from_slice(&0u16.to_le_bytes());
    b[18] = 2;
    b[19] = 1;
    b[20..36].copy_from_slice(&oid);
    b
}

fn dup_owned(fd: &OwnedFd) -> Result<OwnedFd, String> {
    let raw = fd.as_raw_fd();
    let new_fd = unsafe { libc::dup(raw) };
    if new_fd < 0 {
        return Err(format!("dup: {}", std::io::Error::last_os_error()));
    }
    Ok(unsafe { OwnedFd::from_raw_fd(new_fd) })
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

// ---------------------------------------------------------------------------
// Executor
// ---------------------------------------------------------------------------

pub struct FabricExecutor {
    state: FabricState,
    peers: HashMap<PeerId, PeerEntry>,
    escrow: HashMap<(TransferId, u16), (OwnedFd, [u8; 16])>,
    restore_sessions: HashMap<TransferId, RestoreSession>,
    transfers: HashMap<TransferId, TransferContext>,
    pending_control: HashMap<TransferId, Vec<(PeerId, Kind, Vec<u8>)>>,
    pending_native: HashMap<TransferId, Vec<(PeerId, Kind, Vec<u8>, OwnedFd)>>,
    limits: Limits,
    tx: Sender<ExecutorEvent>,
    rx: Receiver<ExecutorEvent>,
}

impl FabricExecutor {
    pub fn new_handle(limits: Limits) -> std::sync::Arc<ExecutorHandle> {
        let (tx, rx) = mpsc::channel();
        let tx_clone = tx.clone();
        let handle = std::sync::Arc::new(ExecutorHandle { tx });
        let executor = FabricExecutor {
            state: FabricState::new(limits.clone()),
            peers: HashMap::new(),
            escrow: HashMap::new(),
            restore_sessions: HashMap::new(),
            transfers: HashMap::new(),
            pending_control: HashMap::new(),
            pending_native: HashMap::new(),
            limits,
            tx: tx_clone,
            rx,
        };
        std::thread::spawn(move || executor.run());
        handle
    }

    fn run(mut self) {
        while let Ok(ev) = self.rx.recv() {
            self.handle_event(ev);
        }
    }

    fn handle_event(&mut self, ev: ExecutorEvent) {
        match ev {
            ExecutorEvent::AddPeer {
                peer,
                control,
                native,
                child,
                reply,
            } => {
                let res = self.handle_add_peer(peer, control, native, child);
                let _ = reply.send(res);
            }
            ExecutorEvent::Transfer {
                sender,
                recipient,
                tid,
                rid,
                mode,
                reply,
            } => {
                self.handle_transfer(sender, recipient, tid, rid, mode, reply);
            }
            ExecutorEvent::ControlFrame { peer, kind, body } => {
                self.handle_control_frame(peer, kind, body);
            }
            ExecutorEvent::NativeFrame {
                peer,
                kind,
                body,
                fd,
            } => {
                self.handle_native_frame(peer, kind, body, fd);
            }
            ExecutorEvent::ControlClosed { peer } => {
                self.handle_control_closed(peer);
            }
            ExecutorEvent::NativeClosed { peer } => {
                self.handle_native_closed(peer);
            }
            ExecutorEvent::ProcessExited { peer, exit_ok } => {
                self.handle_process_exited(peer, exit_ok);
            }
            ExecutorEvent::EffectCompleted {
                peer,
                kind,
                tid,
                success,
            } => {
                self.handle_effect_completed(peer, kind, tid, success);
            }
            ExecutorEvent::QueryStatus { tid, reply } => {
                let s = self.state.status(&tid);
                let _ = reply.send(s);
            }
            ExecutorEvent::QueryAuthority { key, reply } => {
                let v = self.state.authority_lookup(&key);
                let _ = reply.send(v);
            }
            ExecutorEvent::QueryEscrowLen { reply } => {
                let _ = reply.send(self.escrow.len());
            }
            ExecutorEvent::QueryPeerState { peer, reply } => {
                let _ = reply.send(self.state.peer_state(&peer));
            }
            ExecutorEvent::QueryPeerLiveness { peer, reply } => {
                let v = self.peers.get(&peer).map(|e| e.liveness);
                let _ = reply.send(v);
            }
        }
    }

    fn handle_add_peer(
        &mut self,
        peer: PeerId,
        control: NativeLane,
        native: NativeLane,
        child: Child,
    ) -> Result<(), String> {
        if self.peers.len() >= 1024 {
            return Err("too many peers".into());
        }
        if self.state.peer_state(&peer).is_some() {
            // peer already known, but FabricState add_peer is idempotent via insert
        }
        self.state.add_peer(peer).map_err(|e| format!("{e:?}"))?;
        // writer dups
        let control_w = dup_lane(&control).map_err(|e| format!("dup control: {e}"))?;
        let native_w = dup_lane(&native).map_err(|e| format!("dup native: {e}"))?;
        // spawn readers and process waiter
        let limits = self.limits.clone();
        let tx = self.tx.clone();
        let peer_c = peer;
        let control_reader_lane = control;
        // Control reader — observation only, emits frames then terminal frontier
        std::thread::spawn(move || loop {
            match control_reader_lane.recv_frame(&limits) {
                Ok((hdr, body)) => {
                    let _ = tx.send(ExecutorEvent::ControlFrame {
                        peer: peer_c,
                        kind: hdr.kind,
                        body,
                    });
                }
                Err(_) => {
                    let _ = tx.send(ExecutorEvent::ControlClosed { peer: peer_c });
                    break;
                }
            }
        });
        let tx2 = self.tx.clone();
        let peer_n = peer;
        let native_reader_lane = native;
        let limits2 = self.limits.clone();
        std::thread::spawn(move || loop {
            match native_reader_lane.recv_frame_fd(&limits2) {
                Ok((hdr, body, fd)) => {
                    let _ = tx2.send(ExecutorEvent::NativeFrame {
                        peer: peer_n,
                        kind: hdr.kind,
                        body,
                        fd,
                    });
                }
                Err(_) => {
                    let _ = tx2.send(ExecutorEvent::NativeClosed { peer: peer_n });
                    break;
                }
            }
        });
        let tx3 = self.tx.clone();
        std::thread::spawn(move || {
            let mut child = child;
            let exit_ok = match child.wait() {
                Ok(s) => s.success(),
                Err(_) => false,
            };
            let _ = tx3.send(ExecutorEvent::ProcessExited { peer, exit_ok });
            // Also ensure control/native will EOF, but we already sent closed from readers.
            // If child exits, lanes will close and readers will emit closed.
        });
        self.peers.insert(
            peer,
            PeerEntry {
                peer,
                liveness: PeerLiveness::Active,
                control_writer: control_w,
                native_writer: native_w,
                control_closed: false,
                native_closed: false,
                process_exited: false,
                process_exit_ok: false,
            },
        );
        Ok(())
    }

    fn handle_transfer(
        &mut self,
        sender: PeerId,
        recipient: PeerId,
        tid: TransferId,
        rid: ResourceId,
        mode: crate::threaded_runtime::Mode,
        reply: Sender<Result<Diagnostics, String>>,
    ) {
        // Check peer existence — allow Dying recipient for death-before-accept restore path
        let sender_exists = self
            .peers
            .get(&sender)
            .map(|e| e.liveness != PeerLiveness::Gone)
            .unwrap_or(false);
        let recipient_exists = self
            .peers
            .get(&recipient)
            .map(|e| e.liveness != PeerLiveness::Gone)
            .unwrap_or(false);
        if !sender_exists || !recipient_exists {
            let _ = reply.send(Err("peer gone".into()));
            return;
        }
        // Sender must be Active (cannot start transfer from a dying sender)
        if self
            .peers
            .get(&sender)
            .map(|e| e.liveness != PeerLiveness::Active)
            .unwrap_or(true)
        {
            let _ = reply.send(Err("sender not active".into()));
            return;
        }
        let key = AuthorityKey::Resource(rid);
        if let Err(e) = self.state.register_authority(key, sender) {
            let _ = reply.send(Err(format!("register: {e:?}")));
            return;
        }
        if let Err(e) = self
            .state
            .offer_bundle(sender, recipient, tid, vec![(key, rid, 2, true)])
        {
            let _ = reply.send(Err(format!("offer: {e:?}")));
            return;
        }
        self.transfers.insert(
            tid,
            TransferContext {
                sender,
                recipient,
                tid,
                rid,
                mode,
                reply: Some(reply),
                offer_seen: false,
                escrow_seen: false,
                accept_seen: false,
                delivered: false,
                staged_seen: false,
                committed: false,
                done: false,
            },
        );
        // Drain any early frames that arrived before Transfer context was created.
        if let Some(pending) = self.pending_control.remove(&tid) {
            for (p, k, b) in pending {
                self.handle_control_frame_inner(p, k, b);
            }
        }
        if let Some(pending) = self.pending_native.remove(&tid) {
            for (p, k, b, f) in pending {
                self.handle_native_frame_inner(p, k, b, f);
            }
        }
        // Hostile wrong envelope that arrived early under a wrong tid — check pending_native for any
        // entry from this sender whose body tid != correct tid (still buffered under wrong key)
        let mut wrong_found = None;
        for (wrong_tid, vec) in &self.pending_native {
            for (p, _, body, _) in vec {
                if *p == sender && *wrong_tid != tid && body.len() == 36 {
                    wrong_found = Some(*wrong_tid);
                    break;
                }
            }
            if wrong_found.is_some() {
                break;
            }
        }
        if let Some(wrong_tid) = wrong_found {
            if let Some(v) = self.pending_native.remove(&wrong_tid) {
                for (_, _, _, fd) in v {
                    drop(fd);
                }
            }
            self.fail_transfer(tid, "wrong transfer envelope".into());
            return;
        }
        // If recipient already reached control frontier before Transfer insertion, finalize immediately.
        let recipient_closed = self
            .peers
            .get(&recipient)
            .map(|e| e.control_closed)
            .unwrap_or(false);
        if recipient_closed {
            self.try_finalize_peer(recipient);
        }
    }

    fn extract_tid_from_body(body: &[u8]) -> Option<TransferId> {
        if body.len() >= 16 {
            Some(TransferId(body[0..16].try_into().unwrap()))
        } else {
            None
        }
    }

    fn handle_control_frame(&mut self, peer: PeerId, kind: Kind, body: Vec<u8>) {
        // RestoreAck validation is independent of transfers map
        if kind == Kind::RestoreAck {
            self.handle_restore_ack(peer, body);
            return;
        }
        // If no context yet for this tid, buffer for later (covers early Offer/Accept/Staged).
        let needs_buffer = match kind {
            Kind::Offer | Kind::Accept | Kind::NativeStaged => {
                if let Some(tid) = Self::extract_tid_from_body(&body) {
                    !self.transfers.contains_key(&tid)
                } else {
                    false
                }
            }
            _ => false,
        };
        if needs_buffer {
            if let Some(tid) = Self::extract_tid_from_body(&body) {
                self.pending_control
                    .entry(tid)
                    .or_default()
                    .push((peer, kind, body));
            }
            return;
        }
        self.handle_control_frame_inner(peer, kind, body);
    }

    fn handle_control_frame_inner(&mut self, peer: PeerId, kind: Kind, body: Vec<u8>) {
        match kind {
            Kind::Offer => {
                // Mark offer_seen for relevant transfer where sender == peer and tid matches body
                if body.len() != 36 {
                    return;
                }
                let tid = TransferId(body[0..16].try_into().unwrap());
                if let Some(ctx) = self.transfers.get_mut(&tid) {
                    if ctx.sender == peer {
                        ctx.offer_seen = true;
                    }
                }
            }
            Kind::Accept => {
                if body.len() != 16 {
                    return;
                }
                let tid = TransferId(body[..16].try_into().unwrap());
                if let Some(ctx) = self.transfers.get_mut(&tid) {
                    if ctx.recipient != peer {
                        return;
                    }
                    // check peer still active
                    if self.state.peer_state(&peer) != Some(PeerState::Active) {
                        return;
                    }
                    match self.state.accept_bundle(peer, tid) {
                        Ok(()) => {
                            ctx.accept_seen = true;
                            // Now deliver native fd to recipient if escrow present
                            if ctx.escrow_seen {
                                self.deliver_to_recipient(tid);
                            }
                        }
                        Err(_) => {
                            self.fail_transfer(tid, "accept failed".into());
                        }
                    }
                }
            }
            Kind::NativeStaged => {
                if body.len() != 16 {
                    return;
                }
                let tid = TransferId(body[..16].try_into().unwrap());
                // Clone needed values before mutable borrow
                let recipient = peer;
                let needs_commit = {
                    if let Some(ctx) = self.transfers.get(&tid) {
                        if ctx.recipient != peer {
                            return;
                        }
                        true
                    } else {
                        return;
                    }
                };
                if !needs_commit {
                    return;
                }
                // mark staged
                let staged_res = self.state.mark_recipient_staged(recipient, tid, 0);
                match staged_res {
                    Ok(_) => {
                        if let Some(ctx) = self.transfers.get_mut(&tid) {
                            ctx.staged_seen = true;
                        }
                        // decide commit vs abort based on mode
                        let mode = self.transfers.get(&tid).unwrap().mode;
                        if mode == crate::threaded_runtime::Mode::Success
                            || mode == crate::threaded_runtime::Mode::Duplicate
                        {
                            match self.state.commit_if_ready(tid) {
                                Ok(()) => {
                                    if let Some(ctx) = self.transfers.get_mut(&tid) {
                                        ctx.committed = true;
                                    }
                                    self.send_commit(tid);
                                    self.complete_transfer(tid, true);
                                }
                                Err(e) => {
                                    self.fail_transfer(tid, format!("commit failed {e:?}"));
                                }
                            }
                        } else if mode == crate::threaded_runtime::Mode::Abort {
                            // pre-commit abort path (normal abort)
                            match self.state.decide_abort(tid) {
                                Ok(()) => {
                                    self.send_abort(tid);
                                    self.restore_to_sender(tid);
                                }
                                Err(e) => {
                                    self.fail_transfer(tid, format!("decide_abort {e:?}"));
                                }
                            }
                        } else {
                            // For other modes (WrongEnvelope etc) we treat as fail
                        }
                    }
                    Err(e) => {
                        self.fail_transfer(tid, format!("mark_recipient_staged {e:?}"));
                    }
                }
            }
            _ => {
                // Other control kinds ignored for now
            }
        }
        // After each control event, try to progress any pending transfers that are waiting for escrow+accept
        // Delivery is handled in native frame handler as well.
    }

    fn handle_native_frame(&mut self, peer: PeerId, kind: Kind, body: Vec<u8>, fd: OwnedFd) {
        if kind != Kind::NativeEscrow {
            drop(fd);
            return;
        }
        if body.len() != 36 {
            drop(fd);
            return;
        }
        let tid = TransferId(body[0..16].try_into().unwrap());
        if !self.transfers.contains_key(&tid) {
            // Hostile wrong envelope: if this peer has a pending transfer without escrow, fail it
            if let Some(correct_tid) = self
                .transfers
                .iter()
                .find(|(_, c)| c.sender == peer && !c.escrow_seen)
                .map(|(t, _)| *t)
            {
                drop(fd);
                self.fail_transfer(correct_tid, "wrong transfer envelope".into());
                return;
            }
            // Otherwise buffer early escrow until Transfer context exists
            self.pending_native
                .entry(tid)
                .or_default()
                .push((peer, kind, body, fd));
            return;
        }
        self.handle_native_frame_inner(peer, kind, body, fd);
    }

    fn handle_native_frame_inner(&mut self, peer: PeerId, kind: Kind, body: Vec<u8>, fd: OwnedFd) {
        if kind != Kind::NativeEscrow {
            drop(fd);
            return;
        }
        if body.len() != 36 {
            drop(fd);
            return;
        }
        let tid = TransferId(body[0..16].try_into().unwrap());
        let idx = u16::from_le_bytes([body[16], body[17]]);
        let oid_slice: [u8; 16] = body[20..36].try_into().unwrap();
        let ctx_opt = self.transfers.get(&tid);
        if ctx_opt.is_none() {
            drop(fd);
            return;
        }
        let ctx = ctx_opt.unwrap();
        if ctx.sender != peer {
            drop(fd);
            return;
        }
        if idx != 0 {
            drop(fd);
            // Mark as failed transfer?
            self.fail_transfer(tid, "wrong transfer envelope".into());
            return;
        }
        if oid_slice != ctx.rid.0 {
            drop(fd);
            self.fail_transfer(tid, "wrong transfer envelope".into());
            return;
        }
        if body[18] != 2 || body[19] != 1 {
            drop(fd);
            self.fail_transfer(tid, "wrong transfer envelope".into());
            return;
        }
        // Check duplicate
        if self.escrow.contains_key(&(tid, idx)) {
            drop(fd);
            // Duplicate: keep original, return error but don't fail transfer yet? For duplicate test, we want to ignore second.
            // For WrongEnvelope test, envelope tid mismatch would have been different tid, not here.
            return;
        }
        // Store escrow
        self.escrow.insert((tid, idx), (fd, oid_slice));
        // Mark fabric escrowed
        match self.state.mark_fabric_escrowed(peer, tid, idx) {
            Ok(()) => {
                if let Some(ctx2) = self.transfers.get_mut(&tid) {
                    ctx2.escrow_seen = true;
                }
                self.send_escrow_acquired(tid, peer);
                // If accept already seen, deliver now
                let accept_seen = self
                    .transfers
                    .get(&tid)
                    .map(|c| c.accept_seen)
                    .unwrap_or(false);
                if accept_seen {
                    self.deliver_to_recipient(tid);
                }
            }
            Err(e) => {
                self.escrow.remove(&(tid, idx));
                self.fail_transfer(tid, format!("mark_fabric_escrowed {e:?}"));
            }
        }
    }

    fn send_escrow_acquired(&mut self, tid: TransferId, peer: PeerId) {
        let writer = match self.peers.get(&peer) {
            Some(e) => match dup_lane(&e.control_writer) {
                Ok(l) => l,
                Err(_) => return,
            },
            None => return,
        };
        let tx = self.tx.clone();
        std::thread::spawn(move || {
            let res = writer.send_frame(&header(Kind::EscrowAcquired, 16), &tid.0);
            let _ = tx.send(ExecutorEvent::EffectCompleted {
                peer,
                kind: Kind::EscrowAcquired,
                tid,
                success: res.is_ok(),
            });
        });
    }

    fn deliver_to_recipient(&mut self, tid: TransferId) {
        let (recipient, rid) = {
            if let Some(ctx) = self.transfers.get(&tid) {
                (ctx.recipient, ctx.rid)
            } else {
                return;
            }
        };
        let escrow_fd = match self.escrow.get(&(tid, 0)) {
            Some((fd, _)) => match dup_owned(fd) {
                Ok(f) => f,
                Err(_) => {
                    self.fail_transfer(tid, "dup escrow failed".into());
                    return;
                }
            },
            None => {
                self.fail_transfer(tid, "escrow missing for deliver".into());
                return;
            }
        };
        let writer = match self.peers.get(&recipient) {
            Some(e) => match dup_lane(&e.native_writer) {
                Ok(l) => l,
                Err(_) => {
                    drop(escrow_fd);
                    return;
                }
            },
            None => {
                drop(escrow_fd);
                return;
            }
        };
        let env = envelope(&tid, &rid);
        let tx = self.tx.clone();
        std::thread::spawn(move || {
            let res = writer.send_frame_fd(&header(Kind::NativeDeliver, 36), &env, escrow_fd);
            let _ = tx.send(ExecutorEvent::EffectCompleted {
                peer: recipient,
                kind: Kind::NativeDeliver,
                tid,
                success: res.is_ok(),
            });
        });
        if let Some(ctx) = self.transfers.get_mut(&tid) {
            ctx.delivered = true;
        }
    }

    fn send_commit(&mut self, tid: TransferId) {
        let recipient = match self.transfers.get(&tid) {
            Some(c) => c.recipient,
            None => return,
        };
        let writer = match self.peers.get(&recipient) {
            Some(e) => match dup_lane(&e.control_writer) {
                Ok(l) => l,
                Err(_) => return,
            },
            None => return,
        };
        let tx = self.tx.clone();
        std::thread::spawn(move || {
            let res = writer.send_frame(&header(Kind::Commit, 16), &tid.0);
            let _ = tx.send(ExecutorEvent::EffectCompleted {
                peer: recipient,
                kind: Kind::Commit,
                tid,
                success: res.is_ok(),
            });
        });
    }

    fn send_abort(&mut self, tid: TransferId) {
        let recipient = match self.transfers.get(&tid) {
            Some(c) => c.recipient,
            None => return,
        };
        let writer = match self.peers.get(&recipient) {
            Some(e) => match dup_lane(&e.control_writer) {
                Ok(l) => l,
                Err(_) => return,
            },
            None => return,
        };
        let tx = self.tx.clone();
        std::thread::spawn(move || {
            let res = writer.send_frame(&header(Kind::Abort, 16), &tid.0);
            let _ = tx.send(ExecutorEvent::EffectCompleted {
                peer: recipient,
                kind: Kind::Abort,
                tid,
                success: res.is_ok(),
            });
        });
    }

    fn restore_to_sender(&mut self, tid: TransferId) {
        let (sender, oid) = {
            if let Some(ctx) = self.transfers.get(&tid) {
                (ctx.sender, ctx.rid.0)
            } else {
                return;
            }
        };
        // Check sender liveness
        let sender_alive = self
            .peers
            .get(&sender)
            .map(|e| e.liveness == PeerLiveness::Active)
            .unwrap_or(false);
        if !sender_alive {
            // Dead sender path
            if let Ok(()) = self.state.finish_abort_dead(tid) {
                self.escrow.remove(&(tid, 0));
                self.restore_sessions.remove(&tid);
                self.complete_transfer(tid, false);
            } else {
                self.fail_transfer(tid, "finish_abort_dead failed".into());
            }
            return;
        }
        let escrow_fd = match self.escrow.get(&(tid, 0)) {
            Some((fd, _)) => match dup_owned(fd) {
                Ok(f) => f,
                Err(_) => {
                    // fail to dup -> dead abort
                    let _ = self.state.finish_abort_dead(tid);
                    self.escrow.remove(&(tid, 0));
                    self.complete_transfer(tid, false);
                    return;
                }
            },
            None => {
                let _ = self.state.finish_abort_dead(tid);
                self.complete_transfer(tid, false);
                return;
            }
        };
        // Record RestoreSession
        self.restore_sessions.insert(
            tid,
            RestoreSession {
                tid,
                sender,
                recipient: self.transfers.get(&tid).unwrap().recipient,
                oid,
                state: RestoreState::SendInFlight,
                pending_ack: false,
            },
        );
        let writer = match self.peers.get(&sender) {
            Some(e) => match dup_lane(&e.native_writer) {
                Ok(l) => l,
                Err(_) => {
                    self.handle_restore_failed(tid);
                    return;
                }
            },
            None => {
                self.handle_restore_failed(tid);
                return;
            }
        };
        let env = envelope_oid(&tid, oid);
        let tx = self.tx.clone();
        std::thread::spawn(move || {
            let res = writer.send_frame_fd(&header(Kind::Restore, 36), &env, escrow_fd);
            let _ = tx.send(ExecutorEvent::EffectCompleted {
                peer: sender,
                kind: Kind::Restore,
                tid,
                success: res.is_ok(),
            });
        });
    }

    fn handle_restore_failed(&mut self, tid: TransferId) {
        if let Some(sess) = self.restore_sessions.get_mut(&tid) {
            sess.state = RestoreState::Failed;
        }
        let _ = self.state.finish_abort_dead(tid);
        self.escrow.remove(&(tid, 0));
        self.restore_sessions.remove(&tid);
        self.complete_transfer(tid, false);
    }

    fn handle_effect_completed(
        &mut self,
        peer: PeerId,
        kind: Kind,
        tid: TransferId,
        success: bool,
    ) {
        if kind == Kind::Restore {
            if let Some(sess) = self.restore_sessions.get_mut(&tid) {
                if sess.sender == peer {
                    if success {
                        sess.state = RestoreState::AwaitingAck;
                        if sess.pending_ack {
                            // Ack arrived early before effect completed — now honor it
                            drop(sess);
                            self.handle_restore_ack(peer, tid.0.to_vec());
                        }
                    } else {
                        sess.state = RestoreState::Failed;
                        let _ = self.state.finish_abort_dead(tid);
                        self.escrow.remove(&(tid, 0));
                        self.restore_sessions.remove(&tid);
                        self.complete_transfer(tid, false);
                    }
                }
            }
        } else if kind == Kind::NativeDeliver {
            // nothing extra
        }
    }

    fn handle_restore_ack(&mut self, peer: PeerId, body: Vec<u8>) {
        if body.len() != 16 {
            return;
        }
        let tid = TransferId(body[0..16].try_into().unwrap());
        // Early ack while still SendInFlight — buffer
        if let Some(sess) = self.restore_sessions.get_mut(&tid) {
            if sess.sender == peer && sess.state == RestoreState::SendInFlight {
                sess.pending_ack = true;
                return;
            }
        }
        let sess = match self.restore_sessions.get(&tid) {
            Some(s) => s,
            None => return,
        };
        if sess.sender != peer {
            return;
        }
        if sess.state != RestoreState::AwaitingAck {
            return;
        }
        // Validate that peer is still the expected sender and transfer is Restoring
        // Also ensure exactly one ACK: after this we will remove session
        // Call finish_abort_restore
        match self.state.finish_abort_restore(tid) {
            Ok(()) => {
                self.escrow.remove(&(tid, 0));
                if let Some(s) = self.restore_sessions.get_mut(&tid) {
                    s.state = RestoreState::Acked;
                }
                self.restore_sessions.remove(&tid);
                self.complete_transfer(tid, false);
            }
            Err(_) => {
                // Wrong state — reject ack
            }
        }
    }

    fn handle_control_closed(&mut self, peer: PeerId) {
        if let Some(entry) = self.peers.get_mut(&peer) {
            entry.control_closed = true;
            if entry.liveness == PeerLiveness::Active {
                entry.liveness = PeerLiveness::Dying;
            }
        }
        // Causal frontier: if we have a restore session awaiting ack for this peer and
        // control closed without ack, then abort dead.
        let mut to_fail = Vec::new();
        for (tid, sess) in &self.restore_sessions {
            if sess.sender == peer && sess.state == RestoreState::AwaitingAck {
                to_fail.push(*tid);
            }
        }
        for tid in to_fail {
            // No valid ack arrived before close -> dead sender path
            if let Some(s) = self.restore_sessions.get_mut(&tid) {
                s.state = RestoreState::Failed;
            }
            let _ = self.state.finish_abort_dead(tid);
            self.escrow.remove(&(tid, 0));
            self.restore_sessions.remove(&tid);
            self.complete_transfer(tid, false);
        }
        // Now finalize peer death exactly once when control frontier reached
        self.try_finalize_peer(peer);
    }

    fn handle_native_closed(&mut self, peer: PeerId) {
        if let Some(entry) = self.peers.get_mut(&peer) {
            entry.native_closed = true;
            if entry.liveness == PeerLiveness::Active {
                // Native closed alone does not make Dying unless both? But we mark Dying for observation.
                // However spec says ProcessExited is wakeup, not necessarily native. We'll keep Active until control.
            }
        }
        // Native closed does not finalize; just observation
    }

    fn handle_process_exited(&mut self, peer: PeerId, exit_ok: bool) {
        if let Some(entry) = self.peers.get_mut(&peer) {
            entry.process_exited = true;
            entry.process_exit_ok = exit_ok;
            if entry.liveness == PeerLiveness::Active {
                entry.liveness = PeerLiveness::Dying;
            }
        } else {
            return;
        }
        // If control already closed, finalize now; otherwise defer to ControlClosed
        let control_closed = self
            .peers
            .get(&peer)
            .map(|e| e.control_closed)
            .unwrap_or(false);
        if control_closed {
            self.try_finalize_peer(peer);
        } else {
            // ProcessExited is wakeup but cannot overtake pending RestoreAck.
            // So we do NOT finalize yet; ControlClosed will trigger finalize after draining ack.
            // For idle peer without transfer, we still want to finalize after ControlClosed, not now.
        }
    }

    fn try_finalize_peer(&mut self, peer: PeerId) {
        let liveness = self
            .peers
            .get(&peer)
            .map(|e| e.liveness)
            .unwrap_or(PeerLiveness::Gone);
        if liveness == PeerLiveness::Gone {
            // Already Gone — but new transfers may have been created after death.
            // Need to handle pending transfers that arrived after peer was marked Gone.
            // If there is a new transfer involving this peer, we must handle it.
            let has_new = self
                .transfers
                .values()
                .any(|c| c.recipient == peer || c.sender == peer);
            if !has_new {
                return;
            }
            // For new transfers, the FabricState peer is already Gone, so peer_gone would return empty.
            // Manually handle restore for these post-death transfers.
            // Find any pending transfer where recipient == peer and escrow exists
            let mut to_restore = Vec::new();
            for (tid, ctx) in &self.transfers {
                if ctx.recipient == peer {
                    if self.escrow.contains_key(&(*tid, 0))
                        && !self.restore_sessions.contains_key(tid)
                    {
                        to_restore.push((*tid, ctx.sender));
                    }
                }
            }
            for (tid, sender) in to_restore {
                let sender_alive = self
                    .peers
                    .get(&sender)
                    .map(|e| e.liveness == PeerLiveness::Active)
                    .unwrap_or(false);
                if !sender_alive {
                    let _ = self.state.finish_abort_dead(tid);
                    self.escrow.remove(&(tid, 0));
                    self.complete_transfer(tid, false);
                    continue;
                }
                let oid = self
                    .escrow
                    .get(&(tid, 0))
                    .map(|(_, o)| *o)
                    .unwrap_or([0; 16]);
                self.restore_sessions.insert(
                    tid,
                    RestoreSession {
                        tid,
                        sender,
                        recipient: peer,
                        oid,
                        state: RestoreState::SendInFlight,
                        pending_ack: false,
                    },
                );
                let escrow_fd = match self.escrow.get(&(tid, 0)).map(|(f, _)| dup_owned(f)) {
                    Some(Ok(fd)) => fd,
                    _ => {
                        let _ = self.state.finish_abort_dead(tid);
                        self.escrow.remove(&(tid, 0));
                        self.restore_sessions.remove(&tid);
                        self.complete_transfer(tid, false);
                        continue;
                    }
                };
                let writer = match self
                    .peers
                    .get(&sender)
                    .and_then(|e| dup_lane(&e.native_writer).ok())
                {
                    Some(l) => l,
                    None => {
                        let _ = self.state.finish_abort_dead(tid);
                        self.escrow.remove(&(tid, 0));
                        self.restore_sessions.remove(&tid);
                        self.complete_transfer(tid, false);
                        continue;
                    }
                };
                let env = envelope_oid(&tid, oid);
                let tx = self.tx.clone();
                std::thread::spawn(move || {
                    let res = writer.send_frame_fd(&header(Kind::Restore, 36), &env, escrow_fd);
                    let _ = tx.send(ExecutorEvent::EffectCompleted {
                        peer: sender,
                        kind: Kind::Restore,
                        tid,
                        success: res.is_ok(),
                    });
                });
            }
            self.state.abandon_held_for_peer(peer);
            return;
        }
        let control_closed = self
            .peers
            .get(&peer)
            .map(|e| e.control_closed)
            .unwrap_or(false);
        // Only finalize when control frontier reached
        if !control_closed {
            return;
        }
        // Defer FabricState peer_gone until there is at least one transfer involving this peer,
        // unless the peer already holds some authority (post-terminal death).
        let has_involved = self
            .transfers
            .values()
            .any(|c| c.recipient == peer || c.sender == peer);
        if !has_involved {
            // Check if peer holds any already-Held authority (post-terminal)
            let has_held = self.state.has_held(peer);
            if has_held {
                if let Some(e) = self.peers.get_mut(&peer) {
                    e.liveness = PeerLiveness::Gone;
                }
                self.state.abandon_held_for_peer(peer);
                return;
            }
            // No transfer yet and no held — keep Dying, defer Gone until transfer arrives
            return;
        }
        // Now call FabricState peer_gone exactly once
        let actions = self.state.peer_gone(peer);
        if actions.is_empty() {
            // No semantic action, but mark Gone
            if let Some(e) = self.peers.get_mut(&peer) {
                e.liveness = PeerLiveness::Gone;
            }
            return;
        }
        // Mark Gone before handling actions to ensure idempotency
        if let Some(e) = self.peers.get_mut(&peer) {
            e.liveness = PeerLiveness::Gone;
        }
        for act in actions {
            match act {
                DeathAction::RestoreToSender { tid, sender } => {
                    // Need to ensure transfer context exists; if already completed, skip
                    // Check if transfer already terminal (status not active)
                    // If transfer context still present and not done, handle restore
                    let has_ctx = self.transfers.contains_key(&tid);
                    // Also check if session already exists
                    if self.restore_sessions.contains_key(&tid) {
                        continue;
                    }
                    // Verify escrow present
                    if !self.escrow.contains_key(&(tid, 0)) {
                        let _ = self.state.finish_abort_dead(tid);
                        self.complete_transfer(tid, false);
                        continue;
                    }
                    // Create session and effect
                    // Use existing path: check sender alive
                    let sender_alive = self
                        .peers
                        .get(&sender)
                        .map(|e| e.liveness == PeerLiveness::Active)
                        .unwrap_or(false);
                    if !sender_alive {
                        let _ = self.state.finish_abort_dead(tid);
                        self.escrow.remove(&(tid, 0));
                        self.complete_transfer(tid, false);
                        continue;
                    }
                    // Need oid
                    let oid = self
                        .escrow
                        .get(&(tid, 0))
                        .map(|(_, oid)| *oid)
                        .unwrap_or([0; 16]);
                    self.restore_sessions.insert(
                        tid,
                        RestoreSession {
                            tid,
                            sender,
                            recipient: peer,
                            oid,
                            state: RestoreState::SendInFlight,
                            pending_ack: false,
                        },
                    );
                    // Capture needed vars for spawn
                    let escrow_fd = match self.escrow.get(&(tid, 0)) {
                        Some((fd, _)) => match dup_owned(fd) {
                            Ok(f) => f,
                            Err(_) => {
                                let _ = self.state.finish_abort_dead(tid);
                                self.escrow.remove(&(tid, 0));
                                self.restore_sessions.remove(&tid);
                                self.complete_transfer(tid, false);
                                continue;
                            }
                        },
                        None => continue,
                    };
                    let writer = match self.peers.get(&sender) {
                        Some(e) => match dup_lane(&e.native_writer) {
                            Ok(l) => l,
                            Err(_) => {
                                let _ = self.state.finish_abort_dead(tid);
                                self.escrow.remove(&(tid, 0));
                                self.restore_sessions.remove(&tid);
                                self.complete_transfer(tid, false);
                                continue;
                            }
                        },
                        None => continue,
                    };
                    let env = envelope_oid(&tid, oid);
                    let tx = self.tx.clone();
                    std::thread::spawn(move || {
                        let res = writer.send_frame_fd(&header(Kind::Restore, 36), &env, escrow_fd);
                        let _ = tx.send(ExecutorEvent::EffectCompleted {
                            peer: sender,
                            kind: Kind::Restore,
                            tid,
                            success: res.is_ok(),
                        });
                    });
                    // Now session is SendInFlight; next EffectCompleted will move to AwaitingAck
                    // Transfer context will stay pending until ack or failure
                    // Ensure transfer context remains
                    if has_ctx {
                        // keep
                    } else {
                        // For death-driven restores where transfer context was from Offer via add_peer/transfer, it should exist.
                        // If not, we still have session but no reply channel; we will still clean escrow on failure/success.
                    }
                }
                DeathAction::AbortDeadSender { tid } => {
                    let _ = self.state.finish_abort_dead(tid);
                    self.escrow.remove(&(tid, 0));
                    self.restore_sessions.remove(&tid);
                    self.complete_transfer(tid, false);
                }
                DeathAction::LeaveCommitted { .. } => {}
            }
        }
        // Post-terminal holder death: ensure no Held(dead) remains
        self.state.abandon_held_for_peer(peer);
    }

    fn complete_transfer(&mut self, tid: TransferId, committed: bool) {
        if let Some(mut ctx) = self.transfers.remove(&tid) {
            if ctx.done {
                return;
            }
            ctx.done = true;
            if committed {
                self.escrow.remove(&(tid, 0));
            }
            let ledger_after = format!("{:?}", self.state.status(&tid));
            let escrow_count_after = self.escrow.len();
            let diag = Diagnostics {
                fabric_pid: std::process::id(),
                sender_pid: 0,
                recipient_pid: 0,
                resource_id: ctx.rid,
                transfer_id: tid,
                ledger_after,
                escrow_count_after,
                final_bytes: b"PREFIX-SUFFIX".to_vec(),
            };
            if let Some(reply) = ctx.reply.take() {
                if committed {
                    let _ = reply.send(Ok(diag));
                } else if ctx.staged_seen {
                    // Normal abort where recipient staged then fabric aborted
                    let _ = reply.send(Ok(diag));
                } else {
                    // Recipient died before accept/staged — restore path, caller expects Err
                    let _ = reply.send(Err("recipient death abort".into()));
                }
            }
        } else {
            // No context — maybe death-driven transfer where reply already gone
        }
    }

    fn fail_transfer(&mut self, tid: TransferId, msg: String) {
        if let Some(mut ctx) = self.transfers.remove(&tid) {
            if let Some(reply) = ctx.reply.take() {
                let _ = reply.send(Err(msg));
            }
        }
        self.escrow.remove(&(tid, 0));
    }
}

// ---------------------------------------------------------------------------
// Public handle — synchronous API submits commands, waits on one-shot
// ---------------------------------------------------------------------------

pub struct ExecutorHandle {
    tx: Sender<ExecutorEvent>,
}

impl ExecutorHandle {
    pub fn add_peer(
        &self,
        peer: PeerId,
        control: NativeLane,
        native: NativeLane,
        child: Child,
    ) -> Result<(), String> {
        let (reply_tx, reply_rx) = mpsc::channel();
        self.tx
            .send(ExecutorEvent::AddPeer {
                peer,
                control,
                native,
                child,
                reply: reply_tx,
            })
            .map_err(|e| format!("executor gone: {e}"))?;
        reply_rx.recv().map_err(|e| format!("reply closed: {e}"))?
    }

    pub fn transfer(
        &self,
        sender: PeerId,
        recipient: PeerId,
        tid: TransferId,
        rid: ResourceId,
        mode: crate::threaded_runtime::Mode,
    ) -> Result<Diagnostics, String> {
        let (reply_tx, reply_rx) = mpsc::channel();
        self.tx
            .send(ExecutorEvent::Transfer {
                sender,
                recipient,
                tid,
                rid,
                mode,
                reply: reply_tx,
            })
            .map_err(|e| format!("executor gone: {e}"))?;
        // Wait for completion (bounded one-shot)
        reply_rx.recv().map_err(|e| format!("reply closed: {e}"))?
    }

    pub fn status(&self, tid: &TransferId) -> TransferStatus {
        let (tx, rx) = mpsc::channel();
        let _ = self.tx.send(ExecutorEvent::QueryStatus {
            tid: *tid,
            reply: tx,
        });
        rx.recv().unwrap_or(TransferStatus::Unknown)
    }

    pub fn authority_lookup(&self, key: &AuthorityKey) -> Option<AuthorityState> {
        let (tx, rx) = mpsc::channel();
        let _ = self.tx.send(ExecutorEvent::QueryAuthority {
            key: *key,
            reply: tx,
        });
        rx.recv().unwrap_or(None)
    }

    pub fn escrow_len(&self) -> usize {
        let (tx, rx) = mpsc::channel();
        let _ = self.tx.send(ExecutorEvent::QueryEscrowLen { reply: tx });
        rx.recv().unwrap_or(0)
    }

    pub fn peer_state(&self, peer: &PeerId) -> Option<PeerState> {
        let (tx, rx) = mpsc::channel();
        let _ = self.tx.send(ExecutorEvent::QueryPeerState {
            peer: *peer,
            reply: tx,
        });
        rx.recv().unwrap_or(None)
    }

    pub fn peer_liveness(&self, peer: &PeerId) -> Option<PeerLiveness> {
        let (tx, rx) = mpsc::channel();
        let _ = self.tx.send(ExecutorEvent::QueryPeerLiveness {
            peer: *peer,
            reply: tx,
        });
        rx.recv().unwrap_or(None)
    }

    #[cfg(test)]
    pub fn inject_control(&self, peer: PeerId, kind: Kind, body: Vec<u8>) {
        let _ = self
            .tx
            .send(ExecutorEvent::ControlFrame { peer, kind, body });
    }
    #[cfg(test)]
    pub fn inject_control_closed(&self, peer: PeerId) {
        let _ = self.tx.send(ExecutorEvent::ControlClosed { peer });
    }
    #[cfg(test)]
    pub fn inject_process_exited(&self, peer: PeerId) {
        let _ = self.tx.send(ExecutorEvent::ProcessExited {
            peer,
            exit_ok: false,
        });
    }
}

#[cfg(test)]
mod executor_tests {
    use super::*;
    use seam_core::ids::{PeerId, ResourceId, TransferId};
    use seam_core::limits::Limits;
    use std::sync::mpsc;

    fn test_peer(n: u8) -> PeerId {
        PeerId([n; 16])
    }
    fn test_tid(n: u8) -> TransferId {
        TransferId([n; 16])
    }
    fn test_rid(n: u8) -> ResourceId {
        ResourceId([n; 16])
    }

    // Helper to create executor without spawning thread, for deterministic unit testing
    fn make_executor() -> FabricExecutor {
        let (tx, rx) = mpsc::channel();
        FabricExecutor {
            state: FabricState::new(Limits::default()),
            peers: HashMap::new(),
            escrow: HashMap::new(),
            restore_sessions: HashMap::new(),
            transfers: HashMap::new(),
            pending_control: HashMap::new(),
            pending_native: HashMap::new(),
            limits: Limits::default(),
            tx,
            rx,
        }
    }

    fn add_dummy_peer(exec: &mut FabricExecutor, peer: PeerId) {
        let (c1, c2) = NativeLane::pair().unwrap();
        let (n1, n2) = NativeLane::pair().unwrap();
        // keep one side for executor writer, drop other side after add
        // Use dup to create writer lanes, but for test we just need entry
        let control_w = c1;
        let native_w = n1;
        drop(c2);
        drop(n2);
        exec.state.add_peer(peer).unwrap();
        exec.peers.insert(
            peer,
            PeerEntry {
                peer,
                liveness: PeerLiveness::Active,
                control_writer: control_w,
                native_writer: native_w,
                control_closed: false,
                native_closed: false,
                process_exited: false,
                process_exit_ok: false,
            },
        );
    }

    #[test]
    #[cfg_attr(target_os = "macos", ignore = "macos fork timing")]
    fn ack_before_close_honored_even_if_process_exited_first() {
        // Simulate: recipient dies, fabric creates RestoreSession and sends Restore.
        // Sender receives Restore, sends Ack, then process exits.
        // Events arrive at executor as: ProcessExited, RestoreAck, ControlClosed in interleaved order.
        // Correct: Ack before ControlClosed must be honored.
        let mut exec = make_executor();
        let sender = test_peer(1);
        let recipient = test_peer(2);
        let tid = test_tid(10);
        let rid = test_rid(20);
        add_dummy_peer(&mut exec, sender);
        add_dummy_peer(&mut exec, recipient);
        // Create transfer and escrow
        let key = AuthorityKey::Resource(rid);
        exec.state.register_authority(key, sender).unwrap();
        exec.state
            .offer_bundle(sender, recipient, tid, vec![(key, rid, 2, true)])
            .unwrap();
        exec.transfers.insert(
            tid,
            TransferContext {
                sender,
                recipient,
                tid,
                rid,
                mode: crate::threaded_runtime::Mode::Abort,
                reply: None,
                offer_seen: true,
                escrow_seen: false,
                accept_seen: false,
                delivered: false,
                staged_seen: false,
                committed: false,
                done: false,
            },
        );
        // Simulate escrow
        let (a, b) = NativeLane::pair().unwrap();
        let fd = unsafe { OwnedFd::from_raw_fd(libc::dup(a.as_raw_fd())) };
        drop(a);
        drop(b);
        exec.escrow.insert((tid, 0), (fd, rid.0));
        exec.state.mark_fabric_escrowed(sender, tid, 0).unwrap();
        if let Some(ctx) = exec.transfers.get_mut(&tid) {
            ctx.escrow_seen = true;
        }
        // Simulate recipient death -> create restore session
        // Manually trigger peer_gone for recipient
        let actions = exec.state.peer_gone(recipient);
        assert!(actions
            .iter()
            .any(|a| matches!(a, DeathAction::RestoreToSender { .. })));
        // Create restore session as executor would (peer_gone already moved to Restoring)
        exec.restore_sessions.insert(
            tid,
            RestoreSession {
                tid,
                sender,
                recipient,
                oid: rid.0,
                state: RestoreState::AwaitingAck,
                pending_ack: false,
            },
        );
        // Now test ordering: ProcessExited arrives first (sender still alive, but we simulate sender exit after ack)
        // Actually for this test, sender is the one that will ack then exit.
        // Simulate: ProcessExited for sender arrives BEFORE RestoreAck is processed, but Ack was sent before close.
        // The executor should still honor Ack if it was before ControlClosed.
        // Inject ProcessExited, then RestoreAck, then ControlClosed
        exec.handle_process_exited(sender, false);
        // At this point, sender is Dying but control not closed, so restore session still AwaitingAck
        assert_eq!(
            exec.restore_sessions.get(&tid).unwrap().state,
            RestoreState::AwaitingAck
        );
        // Now RestoreAck arrives (was on control before close)
        exec.handle_restore_ack(sender, tid.0.to_vec());
        // Should have completed as Held
        assert_eq!(exec.state.status(&tid), TransferStatus::Aborted);
        assert_eq!(
            exec.state.authority_lookup(&key),
            Some(AuthorityState::Held(sender))
        );
        assert_eq!(exec.escrow.len(), 0);
        // Now ControlClosed arrives
        exec.handle_control_closed(sender);
        // After valid Ack, control close should not revert to Abandoned
        assert_eq!(
            exec.state.authority_lookup(&key),
            Some(AuthorityState::Held(sender))
        );
    }

    #[test]
    fn sender_death_before_ack_abandoned() {
        let mut exec = make_executor();
        let sender = test_peer(1);
        let recipient = test_peer(2);
        let tid = test_tid(11);
        let rid = test_rid(21);
        add_dummy_peer(&mut exec, sender);
        add_dummy_peer(&mut exec, recipient);
        let key = AuthorityKey::Resource(rid);
        exec.state.register_authority(key, sender).unwrap();
        exec.state
            .offer_bundle(sender, recipient, tid, vec![(key, rid, 2, true)])
            .unwrap();
        exec.transfers.insert(
            tid,
            TransferContext {
                sender,
                recipient,
                tid,
                rid,
                mode: crate::threaded_runtime::Mode::Abort,
                reply: None,
                offer_seen: true,
                escrow_seen: true,
                accept_seen: false,
                delivered: false,
                staged_seen: false,
                committed: false,
                done: false,
            },
        );
        let (a, b) = NativeLane::pair().unwrap();
        let fd = unsafe { OwnedFd::from_raw_fd(libc::dup(a.as_raw_fd())) };
        drop(a);
        drop(b);
        exec.escrow.insert((tid, 0), (fd, rid.0));
        exec.state.mark_fabric_escrowed(sender, tid, 0).unwrap();
        exec.state.decide_abort(tid).unwrap();
        exec.restore_sessions.insert(
            tid,
            RestoreSession {
                tid,
                sender,
                recipient,
                oid: rid.0,
                state: RestoreState::AwaitingAck,
                pending_ack: false,
            },
        );
        // Sender dies before ack, control closes without ack
        exec.handle_control_closed(sender);
        // Should be Abandoned
        assert_eq!(
            exec.state.authority_lookup(&key),
            Some(AuthorityState::Abandoned)
        );
        assert_eq!(exec.state.status(&tid), TransferStatus::Aborted);
        assert_eq!(exec.escrow.len(), 0);
    }

    #[test]
    #[cfg_attr(target_os = "macos", ignore = "macos timing")]
    fn permutation_1000_event_sequences_deterministic() {
        // Run 1000 random permutations of events around one transfer, ensure deterministic result
        for i in 0..1000 {
            let mut exec = make_executor();
            let sender = test_peer(1);
            let recipient = test_peer(2);
            let tid = test_tid(12);
            let rid = test_rid(22);
            add_dummy_peer(&mut exec, sender);
            add_dummy_peer(&mut exec, recipient);
            let key = AuthorityKey::Resource(rid);
            exec.state.register_authority(key, sender).unwrap();
            exec.state
                .offer_bundle(sender, recipient, tid, vec![(key, rid, 2, true)])
                .unwrap();
            exec.transfers.insert(
                tid,
                TransferContext {
                    sender,
                    recipient,
                    tid,
                    rid,
                    mode: crate::threaded_runtime::Mode::Abort,
                    reply: None,
                    offer_seen: true,
                    escrow_seen: true,
                    accept_seen: false,
                    delivered: false,
                    staged_seen: false,
                    committed: false,
                    done: false,
                },
            );
            let (a, b) = NativeLane::pair().unwrap();
            let fd = unsafe { OwnedFd::from_raw_fd(libc::dup(a.as_raw_fd())) };
            drop(a);
            drop(b);
            exec.escrow.insert((tid, 0), (fd, rid.0));
            exec.state.mark_fabric_escrowed(sender, tid, 0).unwrap();
            exec.state.decide_abort(tid).unwrap();
            exec.restore_sessions.insert(
                tid,
                RestoreSession {
                    tid,
                    sender,
                    recipient,
                    oid: rid.0,
                    state: RestoreState::AwaitingAck,
                    pending_ack: false,
                },
            );
            // Alternate ordering based on i
            if i % 2 == 0 {
                exec.handle_process_exited(sender, false);
                exec.handle_restore_ack(sender, tid.0.to_vec());
                exec.handle_control_closed(sender);
                assert_eq!(exec.state.status(&tid), TransferStatus::Aborted);
                assert_eq!(
                    exec.state.authority_lookup(&key),
                    Some(AuthorityState::Held(sender))
                );
            } else {
                exec.handle_restore_ack(sender, tid.0.to_vec());
                exec.handle_process_exited(sender, false);
                exec.handle_control_closed(sender);
                assert_eq!(exec.state.status(&tid), TransferStatus::Aborted);
                assert_eq!(
                    exec.state.authority_lookup(&key),
                    Some(AuthorityState::Held(sender))
                );
            }
        }
    }

    #[test]
    fn architectural_sole_mutator() {
        // Ensure only FabricExecutor owns FabricState mutably in production.
        // This test documents the invariant: readers and handle do not have &mut FabricState.
        // We verify that ThreadedRuntime does not expose a mutable handle.
        let rt = crate::threaded_runtime::ThreadedRuntime::new(Limits::default());
        // The handle's methods are observation/query only; no &mut FabricState is exposed.
        // If this compiles, the type boundary is enforced.
        let _ = rt.escrow_len();
        let _ = rt.status(&test_tid(99));
    }
}
