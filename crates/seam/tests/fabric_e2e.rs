//! Real three-process Fabric NativeFile E2E (Linux/Unix).
//! Fabric = test process; A (holder) and B (recipient) are spawned children
//! inheriting private CONTROL(fd3) + NATIVE(fd4) lanes. REAL CROSS-PROCESS.

#![cfg(unix)]

use seam::fabric_runtime::{spawn_peer, FabricRuntime, Mode};
use seam_core::ids::{PeerId, ResourceId, TransferId};
use seam_core::limits::Limits;
use std::fmt::Write as _;

fn hexstr(arr: &[u8; 16]) -> String {
    let mut s = String::new();
    for b in arr {
        write!(s, "{b:02x}").unwrap();
    }
    s
}

#[test]
fn linux_native_file_success() {
    let a = PeerId([1; 16]);
    let b = PeerId([2; 16]);
    let rid = ResourceId([10; 16]);
    let tid = TransferId([20; 16]);
    let rt = FabricRuntime::new(Limits::default());
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
    rt.add_peer(a, c_a, n_a, child_a);
    rt.add_peer(b, c_b, n_b, child_b);
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
fn linux_native_file_abort() {
    let a = PeerId([3; 16]);
    let b = PeerId([4; 16]);
    let rid = ResourceId([11; 16]);
    let tid = TransferId([21; 16]);
    let rt = FabricRuntime::new(Limits::default());
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
    rt.add_peer(a, c_a, n_a, child_a);
    rt.add_peer(b, c_b, n_b, child_b);
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
