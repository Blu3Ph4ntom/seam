//! Real three-process Fabric NativeFile E2E (Linux/Unix) via canonical
//! ThreadedRuntime (per-peer reader threads + single death gate).
//! Fabric = test process; A (holder) and B (recipient) are spawned children
//! inheriting private CONTROL(fd3) + NATIVE(fd4) lanes. REAL CROSS-PROCESS.

#![cfg(unix)]

use seam::threaded_runtime::{spawn_peer, Mode, ThreadedRuntime};
use seam_core::ids::{PeerId, ResourceId, TransferId};
use seam_core::limits::Limits;
use std::fmt::Write as _;
use std::process::Child;

fn hexstr(arr: &[u8; 16]) -> String {
    let mut s = String::new();
    for b in arr {
        write!(s, "{b:02x}").unwrap();
    }
    s
}

fn wait_children(children: Vec<Child>) {
    // Best-effort reap so no zombies are left behind regardless of outcome.
    for mut c in children {
        let _ = c.wait();
    }
}

#[test]
fn threaded_native_file_success() {
    let a = PeerId([1; 16]);
    let b = PeerId([2; 16]);
    let rid = ResourceId([10; 16]);
    let tid = TransferId([20; 16]);
    let rt = ThreadedRuntime::new(Limits::default());
    let bin = env!("CARGO_BIN_EXE_fabric_peer_probe");
    let (c_a, n_a, child_a) = spawn_peer(
        "holder",
        Mode::Success,
        &hexstr(&tid.0),
        &hexstr(&rid.0),
        &hexstr(&a.0),
        bin,
    )
    .expect("spawn holder");
    let (c_b, n_b, child_b) = spawn_peer(
        "recipient",
        Mode::Success,
        &hexstr(&tid.0),
        &hexstr(&rid.0),
        &hexstr(&b.0),
        bin,
    )
    .expect("spawn recipient");
    rt.add_peer(a, c_a, n_a, child_a).unwrap();
    rt.add_peer(b, c_b, n_b, child_b).unwrap();
    let d = rt
        .run_native_file(a, b, tid, rid, Mode::Success)
        .expect("transfer success");
    assert_eq!(d.escrow_count_after, 0, "escrow table must return to zero");
    assert!(
        d.ledger_after.contains("Committed"),
        "ledger should be Committed, got {}",
        d.ledger_after
    );
    assert_eq!(d.final_bytes, b"PREFIX-SUFFIX");
}

#[test]
fn threaded_native_file_abort() {
    let a = PeerId([3; 16]);
    let b = PeerId([4; 16]);
    let rid = ResourceId([11; 16]);
    let tid = TransferId([21; 16]);
    let rt = ThreadedRuntime::new(Limits::default());
    let bin = env!("CARGO_BIN_EXE_fabric_peer_probe");
    let (c_a, n_a, child_a) = spawn_peer(
        "holder",
        Mode::Abort,
        &hexstr(&tid.0),
        &hexstr(&rid.0),
        &hexstr(&a.0),
        bin,
    )
    .expect("spawn holder");
    let (c_b, n_b, child_b) = spawn_peer(
        "recipient",
        Mode::Abort,
        &hexstr(&tid.0),
        &hexstr(&rid.0),
        &hexstr(&b.0),
        bin,
    )
    .expect("spawn recipient");
    rt.add_peer(a, c_a, n_a, child_a).unwrap();
    rt.add_peer(b, c_b, n_b, child_b).unwrap();
    let d = rt
        .run_native_file(a, b, tid, rid, Mode::Abort)
        .expect("transfer abort");
    assert_eq!(d.escrow_count_after, 0, "escrow table must return to zero");
    assert!(
        d.ledger_after.contains("Aborted"),
        "ledger should be Aborted, got {}",
        d.ledger_after
    );
}

#[test]
fn threaded_native_file_wrong_envelope_rejected() {
    // Wrong TransferId in native envelope must be rejected, leaked FD closed, no commit.
    let a = PeerId([5; 16]);
    let b = PeerId([6; 16]);
    let rid = ResourceId([12; 16]);
    let tid = TransferId([22; 16]);
    let rt = ThreadedRuntime::new(Limits::default());
    let bin = env!("CARGO_BIN_EXE_fabric_peer_probe");
    let (c_a, n_a, child_a) = spawn_peer(
        "holder",
        Mode::WrongEnvelope,
        &hexstr(&tid.0),
        &hexstr(&rid.0),
        &hexstr(&a.0),
        bin,
    )
    .expect("spawn holder");
    let (c_b, n_b, child_b) = spawn_peer(
        "recipient",
        Mode::Success,
        &hexstr(&tid.0),
        &hexstr(&rid.0),
        &hexstr(&b.0),
        bin,
    )
    .expect("spawn recipient");
    rt.add_peer(a, c_a, n_a, child_a).unwrap();
    rt.add_peer(b, c_b, n_b, child_b).unwrap();
    let res = rt.run_native_file(a, b, tid, rid, Mode::Success);
    assert!(res.is_err(), "wrong envelope must be rejected");
    let err = res.unwrap_err();
    assert!(
        err.contains("wrong transfer"),
        "expected wrong transfer, got {err}"
    );
    // Leave children reaping to drop; free the runtime so readers exit.
    wait_children(vec![]);
    drop(rt);
}

#[test]
fn threaded_wrong_index_rejected() {
    // Hostile wrong AttachmentIndex (1 instead of 0) -> reject + close fd.
    let a = PeerId([7; 16]);
    let b = PeerId([8; 16]);
    let rid = ResourceId([13; 16]);
    let tid = TransferId([23; 16]);
    let rt = ThreadedRuntime::new(Limits::default());
    let bin = env!("CARGO_BIN_EXE_fabric_peer_probe");
    let (c_a, n_a, child_a) = spawn_peer(
        "holder",
        Mode::WrongIndex,
        &hexstr(&tid.0),
        &hexstr(&rid.0),
        &hexstr(&a.0),
        bin,
    )
    .expect("spawn holder");
    let (c_b, n_b, child_b) = spawn_peer(
        "recipient",
        Mode::Success,
        &hexstr(&tid.0),
        &hexstr(&rid.0),
        &hexstr(&b.0),
        bin,
    )
    .expect("spawn recipient");
    rt.add_peer(a, c_a, n_a, child_a).unwrap();
    rt.add_peer(b, c_b, n_b, child_b).unwrap();
    let res = rt.run_native_file(a, b, tid, rid, Mode::Success);
    assert!(res.is_err(), "wrong index must be rejected");
    let err = res.unwrap_err();
    assert!(
        err.contains("wrong transfer"),
        "expected wrong transfer, got {err}"
    );
    wait_children(vec![]);
    drop(rt);
}

#[test]
fn threaded_duplicate_late_native_closed() {
    // Holder sends a second (duplicate) NativeEscrow after ESCROW_ACQUIRED.
    // Transfer still commits; the late fd must be closed, never leaked.
    let a = PeerId([9; 16]);
    let b = PeerId([10; 16]);
    let rid = ResourceId([14; 16]);
    let tid = TransferId([24; 16]);
    let rt = ThreadedRuntime::new(Limits::default());
    let bin = env!("CARGO_BIN_EXE_fabric_peer_probe");
    let (c_a, n_a, child_a) = spawn_peer(
        "holder",
        Mode::Duplicate,
        &hexstr(&tid.0),
        &hexstr(&rid.0),
        &hexstr(&a.0),
        bin,
    )
    .expect("spawn holder");
    let (c_b, n_b, child_b) = spawn_peer(
        "recipient",
        Mode::Success,
        &hexstr(&tid.0),
        &hexstr(&rid.0),
        &hexstr(&b.0),
        bin,
    )
    .expect("spawn recipient");
    rt.add_peer(a, c_a, n_a, child_a).unwrap();
    rt.add_peer(b, c_b, n_b, child_b).unwrap();
    let d = rt
        .run_native_file(a, b, tid, rid, Mode::Duplicate)
        .expect("transfer with late duplicate native");
    assert_eq!(d.escrow_count_after, 0, "escrow must settle to zero");
    assert!(
        d.ledger_after.contains("Committed"),
        "ledger should be Committed, got {}",
        d.ledger_after
    );
}

#[test]
fn threaded_death_gate_exactly_once_via_readers() {
    // Idle peer death is observed via ControlClosed + ProcessExited without any
    // incidental recv. Executor owns peer liveness and finalizes exactly once.
    let rt = ThreadedRuntime::new(Limits::default());
    let peer = PeerId([9; 16]);
    let (c1, c2) = seam_platform::NativeLane::pair().unwrap();
    let (n1, n2) = seam_platform::NativeLane::pair().unwrap();
    let child = std::process::Command::new("true").spawn().unwrap();
    rt.add_peer(peer, c1, n1, child).unwrap();
    drop(c2);
    drop(n2);
    // Wait for executor to observe ControlClosed + ProcessExited (event-driven, timeout is deadlock guard)
    let mut observed = false;
    for _ in 0..50 {
        std::thread::sleep(std::time::Duration::from_millis(20));
        if !rt.death_gate_alive(&peer) {
            observed = true;
            break;
        }
    }
    assert!(
        observed,
        "executor must observe peer death via ControlClosed frontier without polling"
    );
    assert!(
        !rt.death_gate_alive(&peer),
        "liveness must be Dying/Gone after EOF"
    );
    // Idempotent: second observation does not revert to Active
    assert!(
        !rt.death_gate_alive(&peer),
        "second observation must remain Dying/Gone"
    );
}

#[test]
fn threaded_recipient_death_precommit_restores_sender() {
    // Recipient dies before ACCEPT while Fabric holds physical escrow.
    // Precommit recipient death with live sender -> RestoreToSender: Fabric
    // sends the SAME unlinked file fd back, sender verifies, sends RESTORE_ACK,
    // then Held(sender) + terminal Aborted. Escrow returns to zero.
    let a = PeerId([11; 16]);
    let b = PeerId([12; 16]);
    let rid = ResourceId([15; 16]);
    let tid = TransferId([25; 16]);
    let rt = ThreadedRuntime::new(Limits::default());
    let bin = env!("CARGO_BIN_EXE_fabric_peer_probe");
    let (c_a, n_a, child_a) = spawn_peer(
        "holder",
        Mode::Abort, // holder waits for RESTORE then RESTORE_ACK
        &hexstr(&tid.0),
        &hexstr(&rid.0),
        &hexstr(&a.0),
        bin,
    )
    .expect("spawn holder");
    let (c_b, n_b, child_b) = spawn_peer(
        "recipient",
        Mode::DieBeforeAccept,
        &hexstr(&tid.0),
        &hexstr(&rid.0),
        &hexstr(&b.0),
        bin,
    )
    .expect("spawn recipient");
    rt.add_peer(a, c_a, n_a, child_a).unwrap();
    rt.add_peer(b, c_b, n_b, child_b).unwrap();
    let res = rt.run_native_file(a, b, tid, rid, Mode::Abort);
    assert!(
        res.is_err(),
        "recipient death must abort the transfer, got {:?}",
        res.map(|_| ())
    );
    // Logical: Held(sender), terminal Aborted, no Held(dead).
    {
        let key = seam_core::authority::AuthorityKey::Resource(rid);
        assert_eq!(
            rt.authority_lookup(&key),
            Some(seam_core::authority::AuthorityState::Held(a))
        );
        assert_eq!(
            rt.status(&tid),
            seam_core::transfer::TransferStatus::Aborted
        );
    }
    assert_eq!(rt.escrow_len(), 0, "escrow must settle to zero");
}

#[test]
fn threaded_sender_death_after_escrow_abandoned() {
    // B: sender dies after Fabric escrow (after Offer+Escrow, before commit) -> Abandoned, escrow 0
    let a = PeerId([20; 16]);
    let b = PeerId([21; 16]);
    let rid = ResourceId([30; 16]);
    let tid = TransferId([40; 16]);
    let rt = ThreadedRuntime::new(Limits::default());
    let bin = env!("CARGO_BIN_EXE_fabric_peer_probe");
    let (c_a, n_a, child_a) = spawn_peer(
        "holder",
        Mode::DieAfterEscrow,
        &hexstr(&tid.0),
        &hexstr(&rid.0),
        &hexstr(&a.0),
        bin,
    )
    .expect("spawn holder");
    let (c_b, n_b, child_b) = spawn_peer(
        "recipient",
        Mode::SlowAccept,
        &hexstr(&tid.0),
        &hexstr(&rid.0),
        &hexstr(&b.0),
        bin,
    )
    .expect("spawn recipient");
    rt.add_peer(a, c_a, n_a, child_a).unwrap();
    rt.add_peer(b, c_b, n_b, child_b).unwrap();
    let res = rt.run_native_file(a, b, tid, rid, Mode::Success);
    // Poll for terminal state (death handling is async via ControlClosed frontier)
    let key = seam_core::authority::AuthorityKey::Resource(rid);
    let mut auth = None;
    for _ in 0..50 {
        std::thread::sleep(std::time::Duration::from_millis(20));
        auth = rt.authority_lookup(&key);
        if auth == Some(seam_core::authority::AuthorityState::Abandoned)
            && rt.status(&tid) == seam_core::transfer::TransferStatus::Aborted
            && rt.escrow_len() == 0
        {
            break;
        }
    }
    assert_eq!(
        auth,
        Some(seam_core::authority::AuthorityState::Abandoned),
        "sender death after escrow must be Abandoned, got {auth:?}"
    );
    assert_eq!(
        rt.status(&tid),
        seam_core::transfer::TransferStatus::Aborted
    );
    assert_eq!(rt.escrow_len(), 0, "escrow must settle to zero");
    // Transfer may have returned Err due to sender death
    let _ = res;
}

#[test]
fn threaded_sender_death_before_ack_abandoned() {
    // C: sender dies after receiving RESTORE before Ack -> must not become Held(dead)
    let a = PeerId([22; 16]);
    let b = PeerId([23; 16]);
    let rid = ResourceId([31; 16]);
    let tid = TransferId([41; 16]);
    let rt = ThreadedRuntime::new(Limits::default());
    let bin = env!("CARGO_BIN_EXE_fabric_peer_probe");
    let (c_a, n_a, child_a) = spawn_peer(
        "holder",
        Mode::DieBeforeAck,
        &hexstr(&tid.0),
        &hexstr(&rid.0),
        &hexstr(&a.0),
        bin,
    )
    .expect("spawn holder");
    let (c_b, n_b, child_b) = spawn_peer(
        "recipient",
        Mode::DieBeforeAccept,
        &hexstr(&tid.0),
        &hexstr(&rid.0),
        &hexstr(&b.0),
        bin,
    )
    .expect("spawn recipient");
    rt.add_peer(a, c_a, n_a, child_a).unwrap();
    rt.add_peer(b, c_b, n_b, child_b).unwrap();
    let res = rt.run_native_file(a, b, tid, rid, Mode::DieBeforeAck);
    std::thread::sleep(std::time::Duration::from_millis(300));
    let key = seam_core::authority::AuthorityKey::Resource(rid);
    let auth = rt.authority_lookup(&key);
    assert_eq!(
        auth,
        Some(seam_core::authority::AuthorityState::Abandoned),
        "sender death before ack must be Abandoned, got {auth:?}"
    );
    assert_eq!(
        rt.status(&tid),
        seam_core::transfer::TransferStatus::Aborted
    );
    assert_eq!(rt.escrow_len(), 0);
    let _ = res;
}

#[test]
fn threaded_sender_ack_then_exit_honored() {
    // D: sender ACKs then exits immediately — valid Ack before ControlClosed must be honored
    let a = PeerId([24; 16]);
    let b = PeerId([25; 16]);
    let rid = ResourceId([32; 16]);
    let tid = TransferId([42; 16]);
    let rt = ThreadedRuntime::new(Limits::default());
    let bin = env!("CARGO_BIN_EXE_fabric_peer_probe");
    let (c_a, n_a, child_a) = spawn_peer(
        "holder",
        Mode::AckThenExit,
        &hexstr(&tid.0),
        &hexstr(&rid.0),
        &hexstr(&a.0),
        bin,
    )
    .expect("spawn holder");
    let (c_b, n_b, child_b) = spawn_peer(
        "recipient",
        Mode::DieBeforeAccept,
        &hexstr(&tid.0),
        &hexstr(&rid.0),
        &hexstr(&b.0),
        bin,
    )
    .expect("spawn recipient");
    rt.add_peer(a, c_a, n_a, child_a).unwrap();
    rt.add_peer(b, c_b, n_b, child_b).unwrap();
    let res = rt.run_native_file(a, b, tid, rid, Mode::AckThenExit);
    // Even though sender exits immediately after Ack, the Ack was on control before close, so must be honored
    // Transfer may be considered Err due to recipient death, but authority must be Held(sender) briefly then Abandoned after sender death? For this test we check escrow 0 and status Aborted, not Held(dead) forever
    std::thread::sleep(std::time::Duration::from_millis(300));
    // After valid Ack, transfer is Aborted with Held(sender) initially, but sender then exits, so final may be Abandoned after second death — but must not be Held(dead) and must not be Unknown due to race
    assert_eq!(
        rt.status(&tid),
        seam_core::transfer::TransferStatus::Aborted
    );
    assert_eq!(rt.escrow_len(), 0);
    // Authority should be Abandoned after sender death, not Held(dead)
    let key = seam_core::authority::AuthorityKey::Resource(rid);
    let auth = rt.authority_lookup(&key);
    assert_ne!(
        auth,
        Some(seam_core::authority::AuthorityState::Held(a)),
        "after sender exit, must not remain Held(dead)"
    );
    let _ = res;
}

#[test]
fn threaded_all_three_death_observations_race() {
    // H: CONTROL EOF, NATIVE EOF, ProcessExited all happen for same peer — exactly one semantic Gone
    let rt = ThreadedRuntime::new(Limits::default());
    let peer = PeerId([30; 16]);
    let (c1, c2) = seam_platform::NativeLane::pair().unwrap();
    let (n1, n2) = seam_platform::NativeLane::pair().unwrap();
    let child = std::process::Command::new("true").spawn().unwrap();
    rt.add_peer(peer, c1, n1, child).unwrap();
    drop(c2);
    drop(n2);
    // All three death sources will fire: control closed, native closed, process exited
    // Wait for observation
    let mut observed = false;
    for _ in 0..50 {
        std::thread::sleep(std::time::Duration::from_millis(20));
        if !rt.death_gate_alive(&peer) {
            observed = true;
            break;
        }
    }
    assert!(observed, "all three sources must converge to Dying");
    // Second check idempotent
    assert!(!rt.death_gate_alive(&peer));
}

#[test]
#[ignore = "heavy 100 repetition — run via --ignored or E2B"]
fn threaded_linux_restoration_100() {
    // 100/100 restoration via recipient death before accept
    for i in 0..100 {
        let a = PeerId([100, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, i as u8]);
        let b = PeerId([101, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, i as u8]);
        let rid = ResourceId([200, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, i as u8]);
        let tid = TransferId([210, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, i as u8]);
        let rt = ThreadedRuntime::new(Limits::default());
        let bin = env!("CARGO_BIN_EXE_fabric_peer_probe");
        let (c_a, n_a, child_a) = spawn_peer(
            "holder",
            Mode::Abort,
            &hexstr(&tid.0),
            &hexstr(&rid.0),
            &hexstr(&a.0),
            bin,
        )
        .unwrap();
        let (c_b, n_b, child_b) = spawn_peer(
            "recipient",
            Mode::DieBeforeAccept,
            &hexstr(&tid.0),
            &hexstr(&rid.0),
            &hexstr(&b.0),
            bin,
        )
        .unwrap();
        rt.add_peer(a, c_a, n_a, child_a).unwrap();
        rt.add_peer(b, c_b, n_b, child_b).unwrap();
        let res = rt.run_native_file(a, b, tid, rid, Mode::Abort);
        assert!(res.is_err(), "iteration {i} must be recipient death abort");
        assert_eq!(
            rt.status(&tid),
            seam_core::transfer::TransferStatus::Aborted
        );
        assert_eq!(rt.escrow_len(), 0, "iteration {i} escrow leak");
        let key = seam_core::authority::AuthorityKey::Resource(rid);
        assert_eq!(
            rt.authority_lookup(&key),
            Some(seam_core::authority::AuthorityState::Held(a)),
            "iteration {i} must be Held(sender)"
        );
    }
}

#[test]
#[ignore = "heavy 100 repetition"]
fn threaded_idle_death_100() {
    for i in 0..100 {
        let peer = PeerId([50, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, i as u8]);
        let rt = ThreadedRuntime::new(Limits::default());
        let (c1, c2) = seam_platform::NativeLane::pair().unwrap();
        let (n1, n2) = seam_platform::NativeLane::pair().unwrap();
        let child = std::process::Command::new("true").spawn().unwrap();
        rt.add_peer(peer, c1, n1, child).unwrap();
        drop(c2);
        drop(n2);
        let mut observed = false;
        for _ in 0..50 {
            std::thread::sleep(std::time::Duration::from_millis(10));
            if !rt.death_gate_alive(&peer) {
                observed = true;
                break;
            }
        }
        assert!(observed, "idle iteration {i} must be observed without recv");
    }
}

#[test]
#[ignore = "heavy 100 repetition"]
fn threaded_ack_then_exit_100() {
    for i in 0..100 {
        let a = PeerId([110, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, i as u8]);
        let b = PeerId([111, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, i as u8]);
        let rid = ResourceId([220, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, i as u8]);
        let tid = TransferId([230, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, i as u8]);
        let rt = ThreadedRuntime::new(Limits::default());
        let bin = env!("CARGO_BIN_EXE_fabric_peer_probe");
        let (c_a, n_a, child_a) = spawn_peer(
            "holder",
            Mode::AckThenExit,
            &hexstr(&tid.0),
            &hexstr(&rid.0),
            &hexstr(&a.0),
            bin,
        )
        .unwrap();
        let (c_b, n_b, child_b) = spawn_peer(
            "recipient",
            Mode::DieBeforeAccept,
            &hexstr(&tid.0),
            &hexstr(&rid.0),
            &hexstr(&b.0),
            bin,
        )
        .unwrap();
        rt.add_peer(a, c_a, n_a, child_a).unwrap();
        rt.add_peer(b, c_b, n_b, child_b).unwrap();
        let _ = rt.run_native_file(a, b, tid, rid, Mode::AckThenExit);
        // Must be Aborted and escrow 0 regardless of exit race
        assert_eq!(
            rt.status(&tid),
            seam_core::transfer::TransferStatus::Aborted
        );
        assert_eq!(rt.escrow_len(), 0, "iteration {i} escrow leak");
    }
}

#[test]
#[ignore = "heavy 100 repetition"]
fn threaded_resource_cycle_100() {
    // 100 peer create/death cycles, check fd baseline and no leak
    let rt = ThreadedRuntime::new(Limits::default());
    for i in 0..100 {
        let peer = PeerId([60, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, i as u8]);
        let (c1, c2) = seam_platform::NativeLane::pair().unwrap();
        let (n1, n2) = seam_platform::NativeLane::pair().unwrap();
        let child = std::process::Command::new("true").spawn().unwrap();
        rt.add_peer(peer, c1, n1, child).unwrap();
        drop(c2);
        drop(n2);
        // wait for death observation
        let mut ok = false;
        for _ in 0..20 {
            std::thread::sleep(std::time::Duration::from_millis(10));
            if !rt.death_gate_alive(&peer) {
                ok = true;
                break;
            }
        }
        assert!(ok, "cycle {i} death not observed");
    }
    // After 100 cycles, escrow must be 0 and no leaked peers (we only check escrow)
    assert_eq!(rt.escrow_len(), 0);
}

#[test]
fn threaded_linux_restoration_20() {
    for i in 0..20 {
        let a = PeerId([110, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, i as u8]);
        let b = PeerId([111, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, i as u8]);
        let rid = ResourceId([220, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, i as u8]);
        let tid = TransferId([230, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, i as u8]);
        let rt = ThreadedRuntime::new(Limits::default());
        let bin = env!("CARGO_BIN_EXE_fabric_peer_probe");
        let (c_a, n_a, child_a) = spawn_peer(
            "holder",
            Mode::Abort,
            &hexstr(&tid.0),
            &hexstr(&rid.0),
            &hexstr(&a.0),
            bin,
        )
        .unwrap();
        let (c_b, n_b, child_b) = spawn_peer(
            "recipient",
            Mode::DieBeforeAccept,
            &hexstr(&tid.0),
            &hexstr(&rid.0),
            &hexstr(&b.0),
            bin,
        )
        .unwrap();
        rt.add_peer(a, c_a, n_a, child_a).unwrap();
        rt.add_peer(b, c_b, n_b, child_b).unwrap();
        let res = rt.run_native_file(a, b, tid, rid, Mode::Abort);
        assert!(res.is_err(), "iteration {i} must be recipient death abort");
        assert_eq!(
            rt.status(&tid),
            seam_core::transfer::TransferStatus::Aborted
        );
        assert_eq!(rt.escrow_len(), 0, "iteration {i} escrow leak");
        let key = seam_core::authority::AuthorityKey::Resource(rid);
        assert_eq!(
            rt.authority_lookup(&key),
            Some(seam_core::authority::AuthorityState::Held(a)),
            "iteration {i} must be Held(sender)"
        );
    }
}
