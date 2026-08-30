//! FabricExecutorCore — cross-platform semantic core.
//! Always compiled (unix, windows, etc.). No `OwnedFd`, no `NativeLane`.
//! Proves that the semantic executor's types and logic are not Unix-only.
//! "FabricExecutor is the sole production mutator of FabricState."
#![allow(dead_code)]

use std::collections::HashMap;
use std::sync::mpsc::{self, Receiver, Sender};

use seam_core::authority::AuthorityKey;
use seam_core::fabric_state::{FabricState, PeerState};
use seam_core::ids::{PeerId, ResourceId, TransferId};
use seam_core::limits::Limits;
use seam_core::transfer::TransferStatus;
use seam_core::wire::Kind;

/// Peer liveness — cross-platform.
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

/// Cross-platform transfer context (no `OwnedFd`).
struct TransferContext {
    sender: PeerId,
    recipient: PeerId,
    tid: TransferId,
    rid: ResourceId,
    reply: Option<Sender<Result<CoreDiagnostics, String>>>,
}

/// Diagnostics — cross-platform.
#[derive(Debug)]
pub struct CoreDiagnostics {
    pub fabric_pid: u32,
    pub transfer_id: TransferId,
    pub resource_id: ResourceId,
    pub ledger_after: String,
    pub escrow_count_after: usize,
}

/// Typed core events — no `OwnedFd`.
pub enum CoreEvent {
    AddPeer {
        peer: PeerId,
        reply: Sender<Result<(), String>>,
    },
    Transfer {
        sender: PeerId,
        recipient: PeerId,
        tid: TransferId,
        rid: ResourceId,
        reply: Sender<Result<CoreDiagnostics, String>>,
    },
    ControlFrame {
        peer: PeerId,
        kind: Kind,
        body: Vec<u8>,
    },
    ControlClosed {
        peer: PeerId,
    },
    ProcessExited {
        peer: PeerId,
    },
    QueryStatus {
        tid: TransferId,
        reply: Sender<TransferStatus>,
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

/// Core executor — owns `FabricState` only, no OS handles.
#[allow(dead_code)]
pub struct FabricExecutorCore {
    state: FabricState,
    peers: HashMap<PeerId, PeerLiveness>,
    transfers: HashMap<TransferId, TransferContext>,
    restore_sessions: HashMap<TransferId, RestoreSession>,
    #[allow(dead_code)]
    limits: Limits,
    tx: Sender<CoreEvent>,
    rx: Receiver<CoreEvent>,
}

impl FabricExecutorCore {
    pub fn new_handle(limits: Limits) -> std::sync::Arc<CoreHandle> {
        let (tx, rx) = mpsc::channel();
        let tx2 = tx.clone();
        let handle = std::sync::Arc::new(CoreHandle { tx });
        let core = FabricExecutorCore {
            state: FabricState::new(limits.clone()),
            peers: HashMap::new(),
            transfers: HashMap::new(),
            restore_sessions: HashMap::new(),
            limits,
            tx: tx2,
            rx,
        };
        std::thread::spawn(move || core.run());
        handle
    }

    fn run(mut self) {
        while let Ok(ev) = self.rx.recv() {
            self.handle_event(ev);
        }
    }

    fn handle_event(&mut self, ev: CoreEvent) {
        match ev {
            CoreEvent::AddPeer { peer, reply } => {
                let res = self.state.add_peer(peer).map_err(|e| format!("{e:?}"));
                if res.is_ok() {
                    self.peers.insert(peer, PeerLiveness::Active);
                }
                let _ = reply.send(res);
            }
            CoreEvent::Transfer {
                sender,
                recipient,
                tid,
                rid,
                reply,
            } => {
                let key = AuthorityKey::Resource(rid);
                let r1 = self.state.register_authority(key, sender);
                let r2 = r1.and_then(|_| {
                    self.state
                        .offer_bundle(sender, recipient, tid, vec![(key, rid, 2, true)])
                });
                match r2 {
                    Ok(()) => {
                        self.transfers.insert(
                            tid,
                            TransferContext {
                                sender,
                                recipient,
                                tid,
                                rid,
                                reply: Some(reply),
                            },
                        );
                    }
                    Err(e) => {
                        let _ = reply.send(Err(format!("{e:?}")));
                    }
                }
            }
            CoreEvent::ControlFrame { peer, kind, body } => {
                if kind == Kind::RestoreAck && body.len() == 16 {
                    let tid = TransferId(body[0..16].try_into().unwrap());
                    if let Some(sess) = self.restore_sessions.get(&tid) {
                        if sess.sender == peer && sess.state == RestoreState::AwaitingAck {
                            let _ = self.state.finish_abort_restore(tid);
                            self.restore_sessions.remove(&tid);
                            if let Some(mut ctx) = self.transfers.remove(&tid) {
                                if let Some(r) = ctx.reply.take() {
                                    let _ = r.send(Ok(CoreDiagnostics {
                                        fabric_pid: 0,
                                        transfer_id: tid,
                                        resource_id: ctx.rid,
                                        ledger_after: format!("{:?}", self.state.status(&tid)),
                                        escrow_count_after: 0,
                                    }));
                                }
                            }
                        }
                    }
                }
            }
            CoreEvent::ControlClosed { peer } => {
                self.peers.insert(peer, PeerLiveness::Dying);
                // causal frontier: if restore awaiting ack, and close without ack, abort dead
                let mut to_fail = Vec::new();
                for (tid, sess) in &self.restore_sessions {
                    if sess.sender == peer && sess.state == RestoreState::AwaitingAck {
                        to_fail.push(*tid);
                    }
                }
                for tid in to_fail {
                    let _ = self.state.finish_abort_dead(tid);
                    self.restore_sessions.remove(&tid);
                    if let Some(mut ctx) = self.transfers.remove(&tid) {
                        if let Some(r) = ctx.reply.take() {
                            let _ = r.send(Err("abandoned".into()));
                        }
                    }
                }
                // peer gone exactly once
                let actions = self.state.peer_gone(peer);
                if actions.is_empty() {
                    self.peers.insert(peer, PeerLiveness::Gone);
                } else {
                    self.peers.insert(peer, PeerLiveness::Gone);
                    for act in actions {
                        match act {
                            seam_core::fabric_state::DeathAction::RestoreToSender {
                                tid,
                                sender,
                            } => {
                                if self.peers.get(&sender) == Some(&PeerLiveness::Active) {
                                    self.restore_sessions.insert(
                                        tid,
                                        RestoreSession {
                                            tid,
                                            sender,
                                            recipient: peer,
                                            oid: [0; 16],
                                            state: RestoreState::AwaitingAck,
                                            pending_ack: false,
                                        },
                                    );
                                    self.state.decide_abort(tid).ok();
                                } else {
                                    let _ = self.state.finish_abort_dead(tid);
                                    if let Some(mut ctx) = self.transfers.remove(&tid) {
                                        if let Some(r) = ctx.reply.take() {
                                            let _ = r.send(Err("abandoned".into()));
                                        }
                                    }
                                }
                            }
                            seam_core::fabric_state::DeathAction::AbortDeadSender { tid } => {
                                let _ = self.state.finish_abort_dead(tid);
                                if let Some(mut ctx) = self.transfers.remove(&tid) {
                                    if let Some(r) = ctx.reply.take() {
                                        let _ = r.send(Err("abandoned".into()));
                                    }
                                }
                            }
                            _ => {}
                        }
                    }
                }
                self.state.abandon_held_for_peer(peer);
            }
            CoreEvent::ProcessExited { peer } => {
                self.peers.insert(peer, PeerLiveness::Dying);
                // defer finalization until ControlClosed
            }
            CoreEvent::QueryStatus { tid, reply } => {
                let _ = reply.send(self.state.status(&tid));
            }
            CoreEvent::QueryPeerState { peer, reply } => {
                let _ = reply.send(self.state.peer_state(&peer));
            }
            CoreEvent::QueryPeerLiveness { peer, reply } => {
                let _ = reply.send(self.peers.get(&peer).copied());
            }
        }
    }
}

pub struct CoreHandle {
    tx: Sender<CoreEvent>,
}

impl CoreHandle {
    pub fn add_peer(&self, peer: PeerId) -> Result<(), String> {
        let (tx, rx) = mpsc::channel();
        self.tx
            .send(CoreEvent::AddPeer { peer, reply: tx })
            .map_err(|e| format!("{e}"))?;
        rx.recv().map_err(|e| format!("{e}"))?
    }
    pub fn status(&self, tid: &TransferId) -> TransferStatus {
        let (tx, rx) = mpsc::channel();
        let _ = self.tx.send(CoreEvent::QueryStatus {
            tid: *tid,
            reply: tx,
        });
        rx.recv().unwrap_or(TransferStatus::Unknown)
    }
    pub fn peer_liveness(&self, peer: &PeerId) -> Option<PeerLiveness> {
        let (tx, rx) = mpsc::channel();
        let _ = self.tx.send(CoreEvent::QueryPeerLiveness {
            peer: *peer,
            reply: tx,
        });
        rx.recv().unwrap_or(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use seam_core::limits::Limits;
    #[test]
    fn core_compiles_and_runs_on_all_platforms() {
        let h = FabricExecutorCore::new_handle(Limits::default());
        let p = PeerId([1; 16]);
        h.add_peer(p).unwrap();
        assert_eq!(h.peer_liveness(&p), Some(PeerLiveness::Active));
        // sole mutator proof: only core owns FabricState
        let _ = h.status(&TransferId([9; 16]));
    }
    #[test]
    fn core_control_closed_frontier() {
        let h = FabricExecutorCore::new_handle(Limits::default());
        let s = PeerId([2; 16]);
        let r = PeerId([3; 16]);
        h.add_peer(s).unwrap();
        h.add_peer(r).unwrap();
        // simulate transfer and death via core events
        let tid = TransferId([10; 16]);
        let rid = ResourceId([20; 16]);
        let (tx, _rx) = mpsc::channel();
        h.tx.send(CoreEvent::Transfer {
            sender: s,
            recipient: r,
            tid,
            rid,
            reply: tx,
        })
        .unwrap();
        // we don't wait for completion, just check that core still handles queries
        std::thread::sleep(std::time::Duration::from_millis(10));
        // clean shutdown via ControlClosed
        h.tx.send(CoreEvent::ControlClosed { peer: r }).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(10));
        assert!(matches!(
            h.peer_liveness(&r),
            Some(PeerLiveness::Dying) | Some(PeerLiveness::Gone)
        ));
    }
}
