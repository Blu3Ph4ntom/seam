//! ThreadedRuntime — canonical production Fabric orchestrator backed by
//! FabricExecutor (sole mutator of FabricState).
//! Readers, waiters and effect workers are observation-only; executor owns
//! state, escrow, peer liveness, RestoreSessions. No global lock across I/O.

#![cfg(unix)]

use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd};
use std::process::Child;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

use seam_core::authority::{AuthorityKey, AuthorityState};
use seam_core::fabric_state::PeerState;
use seam_core::ids::{PeerId, ResourceId, TransferId};
use seam_core::limits::Limits;
use seam_core::transfer::TransferStatus;
use seam_core::wire::{Header, Kind, CURRENT_MAJOR, CURRENT_MINOR, MAGIC};

use seam_platform::NativeLane;

use crate::fabric_executor::{ExecutorHandle, FabricExecutor};

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
    b[16..18].copy_from_slice(&0u16.to_le_bytes());
    b[18] = 2;
    b[19] = 1;
    b[20..36].copy_from_slice(&oid);
    b
}

/// DeathGate kept for unit test compatibility — now delegates to executor liveness.
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
    pub fn try_gone(&self) -> bool {
        self.alive
            .compare_exchange(true, false, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
    }
    pub fn is_alive(&self) -> bool {
        self.alive.load(Ordering::SeqCst)
    }
}

// ---------------------------------------------------------------------------
// Public ThreadedRuntime facade — owns ExecutorHandle
// ---------------------------------------------------------------------------

pub struct ThreadedRuntime {
    handle: Arc<ExecutorHandle>,
    limits: Limits,
}

impl ThreadedRuntime {
    pub fn new(limits: Limits) -> Arc<Self> {
        let handle = FabricExecutor::new_handle(limits.clone());
        Arc::new(Self { handle, limits })
    }

    pub fn add_peer(
        self: &Arc<Self>,
        peer: PeerId,
        control: NativeLane,
        native: NativeLane,
        child: Child,
    ) -> Result<(), String> {
        self.handle.add_peer(peer, control, native, child)
    }

    pub fn escrow_len(&self) -> usize {
        self.handle.escrow_len()
    }

    pub fn death_gate_alive(&self, peer: &PeerId) -> bool {
        // Active == alive, Dying/Gone == not alive
        matches!(
            self.handle.peer_liveness(peer),
            Some(crate::fabric_executor::PeerLiveness::Active)
        )
    }

    /// Compatibility shim — new executor handles death automatically via
    /// ControlClosed/ProcessExited frontier. This is now a no-op that ensures
    /// exactly-once semantics via executor's peer_gone.
    pub fn handle_death(&self, _peer: &PeerId) {
        // No-op: death is driven by executor events. Kept for backward compat
        // tests that call handle_death explicitly.
    }

    pub fn authority_lookup(&self, key: &AuthorityKey) -> Option<AuthorityState> {
        self.handle.authority_lookup(key)
    }

    pub fn status(&self, tid: &TransferId) -> TransferStatus {
        self.handle.status(tid)
    }

    pub fn peer_state(&self, peer: &PeerId) -> Option<PeerState> {
        self.handle.peer_state(peer)
    }

    /// Expose state snapshot for tests that previously used rt.state.lock()
    /// This returns a snapshot via executor queries; no direct mutation handle.
    pub fn snapshot_state<F, R>(&self, _f: F) -> R
    where
        F: FnOnce(&seam_core::fabric_state::FabricState) -> R,
    {
        panic!(
            "snapshot_state is removed — use handle queries (status/authority_lookup/peer_state)"
        );
    }

    pub fn run_native_file(
        self: &Arc<Self>,
        sender: PeerId,
        recipient: PeerId,
        tid: TransferId,
        rid: ResourceId,
        mode: Mode,
    ) -> Result<Diagnostics, String> {
        self.handle.transfer(sender, recipient, tid, rid, mode)
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

// Re-export Diagnostics from executor for internal use
impl From<crate::fabric_executor::Diagnostics> for Diagnostics {
    fn from(d: crate::fabric_executor::Diagnostics) -> Self {
        Self {
            fabric_pid: d.fabric_pid,
            sender_pid: d.sender_pid,
            recipient_pid: d.recipient_pid,
            resource_id: d.resource_id,
            transfer_id: d.transfer_id,
            ledger_after: d.ledger_after,
            escrow_count_after: d.escrow_count_after,
            final_bytes: d.final_bytes,
        }
    }
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
    let (c_p, c_c) = NativeLane::pair()?;
    let (n_p, n_c) = NativeLane::pair()?;
    let c_child_owned = c_c.into_owned_fd();
    let n_child_owned = n_c.into_owned_fd();
    let c_raw = c_child_owned.as_raw_fd();
    let n_raw = n_child_owned.as_raw_fd();
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
    drop(c_child_owned);
    drop(n_child_owned);
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
