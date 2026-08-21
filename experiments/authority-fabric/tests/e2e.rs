//! Real-process end-to-end tests.
//!
//! Each case spawns the host binary, which in turn spawns client and service
//! processes. Parallel execution is a spawn storm plus timing-margin
//! interference; hold the file mutex AND prefer `--test-threads=1`.

use std::process::{Command, Output, Stdio};
use std::sync::{mpsc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

static E2E: Mutex<()> = Mutex::new(());

fn host_bin() -> &'static str {
    env!("CARGO_BIN_EXE_host")
}

fn kill_tree(pid: u32) {
    #[cfg(windows)]
    {
        let _ = Command::new("taskkill")
            .args(["/PID", &pid.to_string(), "/T", "/F"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
    #[cfg(not(windows))]
    {
        let _ = Command::new("kill")
            .args(["-9", &pid.to_string()])
            .status();
    }
}

fn run_host(args: &[&str], envs: &[(&str, &str)], timeout: Duration) -> Output {
    let _guard = E2E.lock().unwrap_or_else(|e| e.into_inner());
    let mut cmd = Command::new(host_bin());
    cmd.args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (k, v) in envs {
        cmd.env(k, v);
    }
    let child = cmd.spawn().unwrap_or_else(|e| panic!("spawn host: {e}"));
    let pid = child.id();
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let _ = tx.send(child.wait_with_output());
    });
    match rx.recv_timeout(timeout) {
        Ok(Ok(out)) => out,
        Ok(Err(e)) => panic!("host wait failed: {e}"),
        Err(_) => {
            kill_tree(pid);
            let _ = rx.recv_timeout(Duration::from_secs(5));
            panic!("host {:?} hung past {:?}", args, timeout);
        }
    }
}

fn stdout_str(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn stderr_str(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

fn assert_contains(hay: &str, needle: &str, label: &str) {
    assert!(
        hay.contains(needle),
        "{label} missing {needle:?}\n--- stdout+stderr ---\n{hay}"
    );
}

#[test]
fn demo_full() {
    let out = run_host(&["demo"], &[], Duration::from_secs(60));
    let combined = format!("{}\n{}", stdout_str(&out), stderr_str(&out));
    assert_eq!(out.status.code(), Some(0), "demo exit\n{combined}");
    assert_contains(&combined, "DEMO_OK", "demo");
    for m in [
        "HOST_STARTED",
        "HOST_PIDS",
        "SERVICE_BOOTSTRAPPED",
        "CLIENT_BOOTSTRAPPED",
        "ROOT_CAPABILITY_TRANSFERRED",
        "CLIENT_HAS_ROOT_CAPABILITY",
        "CLIENT_RECEIVED_NESTED_CAPABILITY",
        "CLIENT_NESTED_INVOCATION_SUCCEEDED",
        "KILLING_SERVICE",
        "PEER_FAILURE_OBSERVED_BY_FABRIC",
        "CLIENT_ROOT_FAILURE_OBSERVED",
        "CLIENT_NESTED_FAILURE_OBSERVED",
        "CLIENT_ACKNOWLEDGED_FAILURES",
        "CLEANUP_COMPLETED",
        "HOST_ACCOUNTING tag=final",
        "peers=0",
        "live_eps=0",
    ] {
        assert_contains(&combined, m, "demo marker");
    }
    // RUN 002 shutdown anomaly: ASCII on the protocol pipe must not appear
    // as an oversized frame after a successful demo.
    assert!(
        !combined.contains("HOST_QUARANTINED_PEER"),
        "clean demo shutdown quarantined a peer:\n{combined}"
    );
}

fn scenario(case: &str) {
    let out = run_host(&["scenario", case], &[], Duration::from_secs(45));
    let combined = format!("{}\n{}", stdout_str(&out), stderr_str(&out));
    assert_eq!(out.status.code(), Some(0), "scenario {case}\n{combined}");
    assert_contains(&combined, &format!("CASE_{case}_OK"), "scenario");
}

#[test]
fn scenario_a() {
    scenario("A");
}
#[test]
fn scenario_b() {
    scenario("B");
}
#[test]
fn scenario_c() {
    scenario("C");
}
#[test]
fn scenario_d() {
    scenario("D");
}
#[test]
fn scenario_e() {
    scenario("E");
}
#[test]
fn scenario_f() {
    scenario("F");
}
#[test]
fn scenario_g() {
    scenario("G");
}

#[test]
fn quarantine() {
    let out = run_host(&["quarantine"], &[], Duration::from_secs(20));
    let combined = format!("{}\n{}", stdout_str(&out), stderr_str(&out));
    assert_eq!(out.status.code(), Some(0), "quarantine\n{combined}");
    assert_contains(&combined, "HOST_QUARANTINED_PEER", "quarantine");
    assert_contains(&combined, "HOST_SURVIVED_QUARANTINE", "quarantine");
}

#[test]
fn host_death() {
    let _guard = E2E.lock().unwrap_or_else(|e| e.into_inner());
    let dir = std::env::temp_dir().join(format!(
        "seam-hostdie-{}",
        std::process::id()
    ));
    let _ = std::fs::create_dir_all(&dir);
    let mut cmd = Command::new(host_bin());
    cmd.arg("hostdie")
        .env("SEAM_MARKER_DIR", &dir)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let child = cmd.spawn().expect("spawn hostdie");
    let pid = child.id();
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let _ = tx.send(child.wait_with_output());
    });
    let out = match rx.recv_timeout(Duration::from_secs(20)) {
        Ok(Ok(o)) => o,
        Ok(Err(e)) => panic!("hostdie wait: {e}"),
        Err(_) => {
            kill_tree(pid);
            panic!("hostdie hung");
        }
    };
    assert_eq!(out.status.code(), Some(9), "hostdie must exit 9");

    let marker = dir.join("client_fabric_lost");
    let deadline = Instant::now() + Duration::from_secs(15);
    while Instant::now() < deadline {
        if marker.exists() {
            let _ = std::fs::remove_dir_all(&dir);
            return;
        }
        thread::sleep(Duration::from_millis(50));
    }
    let _ = std::fs::remove_dir_all(&dir);
    panic!("client_fabric_lost marker never appeared");
}

#[test]
fn scale_small() {
    let out = run_host(
        &["scale"],
        &[("SEAM_CHURN_N", "2000")],
        Duration::from_secs(180),
    );
    let combined = format!("{}\n{}", stdout_str(&out), stderr_str(&out));
    assert_eq!(out.status.code(), Some(0), "scale\n{combined}");
    assert_contains(&combined, "SCALE_OK n=2000", "scale");
    assert_contains(&combined, "live_eps=4", "scale final");
    assert_contains(&combined, "retired=4000", "scale final");
}
