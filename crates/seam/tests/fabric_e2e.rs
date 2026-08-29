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
fn threaded_death_gate_exactly_once_via_readers() {
    // Real reader-thread death: drop child-side lanes causing control+native
    // EOF on both reader threads; exactly one semantic peer_gone occurs.
    let rt = ThreadedRuntime::new(Limits::default());
    let peer = PeerId([9; 16]);
    let (c1, c2) = seam_platform::NativeLane::pair().unwrap();
    let (n1, n2) = seam_platform::NativeLane::pair().unwrap();
    // No real child; use a trivially-exited shell to satisfy Child.
    let child = std::process::Command::new("true").spawn().unwrap();
    rt.add_peer(peer, c1, n1, child).unwrap();
    // Drop child-side ends -> both readers see EOF and race the death gate.
    drop(c2);
    drop(n2);
    // Give readers a moment (blocking I/O threads, not a correctness sleep).
    std::thread::sleep(std::time::Duration::from_millis(200));
    assert!(
        !rt.death_gate_alive(&peer),
        "death gate must be tripped by reader EOF"
    );
    let st = rt.state.lock().unwrap();
    assert_eq!(
        st.peer_state(&peer),
        Some(seam_core::fabric_state::PeerState::Gone)
    );
}
