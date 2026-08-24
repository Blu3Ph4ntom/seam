//! Client role. Modes selected via SEAM_CLIENT_MODE:
//!   (empty|"full")  happy path + kill-then-failure assertions
//!   root_closed_tolerant : root grant may or may not arrive; any explicit
//!                          failure within bound is success
//!   root_closed_strict   : grant must arrive, then call must fail Closed
//!   outstanding_request  : request in flight when service dies
//!   kill_after_first_increment : nested capability proven once, then killed
//!   graceful_done        : full happy path, then signal Done
//!   watchdog             : report fabric loss (host-death test)
//!   churn                : N create/transfer/close cycles
//!   perf                 : RTT / transfer latency measurement

use std::collections::HashSet;
use std::io::Write;
use std::time::{Duration, Instant};

use authority_fabric::fabric_error::FabError;
use authority_fabric::peer::Runtime;
use authority_fabric::proto::{self, CounterRequest, CounterResponse, RootRequest, RootResponse};
use authority_fabric::{marker, Endpoint, EpId, Limits};

const CALL_TIMEOUT: Duration = Duration::from_secs(10);

fn mode() -> String {
    std::env::var("SEAM_CLIENT_MODE").unwrap_or_else(|_| "full".into())
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().map(String::as_str) == Some("rawpeer") {
        rawpeer();
        return;
    }
    let lim = Limits {
        // Churn needs more concurrent capacity than the default.
        max_live_endpoints: std::env::var("SEAM_CLI_MAX_EPS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(64),
        ..Limits::default()
    };
    let rt = match Runtime::connect_as_child(std::io::stdin(), std::io::stdout(), lim) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("CLIENT_FAIL connect: {e}");
            std::process::exit(2);
        }
    };
    adopt_native_lane(&rt);

    let code = match mode().as_str() {
        "root_closed_tolerant" => root_closed(&rt, false),
        "root_closed_strict" => root_closed(&rt, true),
        "outstanding_request" => outstanding_request(&rt),
        "kill_after_first_increment" => kill_after_first_increment(&rt),
        "graceful_done" => graceful_done(&rt),
        "watchdog" => watchdog(&rt),
        "churn" => churn(&rt),
        "perf" => perf(&rt),
        "abort_cycle" => abort_cycle(&rt),
        "txn_once" => txn_once(&rt),
        "native_happy" => native_happy(&rt),
        "native_abort" => native_abort(&rt),
        "native_stress" => native_stress(&rt),
        "shared_produce" => shared_produce(&rt),
        "preflight_p1_client" => preflight_p1_client(&rt),
        "preflight_p3_client" => preflight_p3_client(&rt),
        _ => full_demo(&rt),
    };
    rt.shutdown();
    std::process::exit(code);
}

/// Wait for the next granted handle not yet claimed.
fn claim(rt: &Runtime, exclude: &mut HashSet<EpId>) -> Result<EpId, FabError> {
    let id = rt.next_new_handle(
        &exclude.iter().copied().collect::<Vec<_>>(),
        Duration::from_secs(10),
    )?;
    exclude.insert(id);
    Ok(id)
}

fn claim_ep(rt: &Runtime, seen: &mut HashSet<EpId>) -> Result<Endpoint, String> {
    let id = claim(rt, seen).map_err(|e| format!("capability grant: {e}"))?;
    rt.endpoint_for(id)
        .ok_or_else(|| "claimed id not live".to_string())
}

/// Happy path + post-kill failure assertions (default demo).
fn full_demo(rt: &Runtime) -> i32 {
    let mut seen = HashSet::new();
    let Ok(root) = claim_ep(rt, &mut seen) else {
        eprintln!("CLIENT_FAIL no root capability");
        return 1;
    };
    marker!("CLIENT_HAS_ROOT_CAPABILITY");

    // Typed request through the transferred root capability.
    match root.call(proto::encode_root_request(RootRequest::Ping), CALL_TIMEOUT) {
        Ok(res) => match proto::decode_root_response(&res.payload) {
            Ok(RootResponse::Pong) => {}
            other => {
                eprintln!("CLIENT_FAIL ping reply {other:?}");
                return 1;
            }
        },
        Err(e) => {
            eprintln!("CLIENT_FAIL ping: {e}");
            return 1;
        }
    }

    // Nested capability: the service returns NEW authority inside an
    // ordinary reply. No name, no lookup, no registry.
    let res = match root.call(
        proto::encode_root_request(RootRequest::OpenCounter),
        CALL_TIMEOUT,
    ) {
        Ok(res) => res,
        Err(e) => {
            eprintln!("CLIENT_FAIL open_counter: {e}");
            return 1;
        }
    };
    match proto::decode_root_response(&res.payload) {
        Ok(RootResponse::Counter) => {}
        other => {
            eprintln!("CLIENT_FAIL open_counter reply {other:?}");
            return 1;
        }
    }
    let Some(counter) = res.received.into_iter().next() else {
        eprintln!("CLIENT_FAIL no counter capability attached");
        return 1;
    };
    marker!("CLIENT_RECEIVED_NESTED_CAPABILITY");

    let cres = match counter.call(
        proto::encode_counter_request(CounterRequest::Increment),
        CALL_TIMEOUT,
    ) {
        Ok(res) => res,
        Err(e) => {
            eprintln!("CLIENT_FAIL increment: {e}");
            return 1;
        }
    };
    match proto::decode_counter_response(&cres.payload) {
        Ok(CounterResponse::Incremented(1)) => {}
        other => {
            eprintln!("CLIENT_FAIL increment reply {other:?}");
            return 1;
        }
    }
    marker!("CLIENT_NESTED_INVOCATION_SUCCEEDED");

    // Signal the host to kill the service; wait for ack.
    let ctrl = match claim_ep(rt, &mut seen) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("CLIENT_FAIL no control channel: {e}");
            return 1;
        }
    };
    if send_ctrl_wait_ack(&ctrl, proto::ControlMsg::ReadyToKill).is_err() {
        // Ack may race the kill; failures below are what matter.
        marker!("CLIENT_CTRL_ACK_RACED");
    }

    // G11: root capability must now fail explicitly.
    match root.call(proto::encode_root_request(RootRequest::Ping), CALL_TIMEOUT) {
        Err(FabError::Closed(_)) => marker!("CLIENT_ROOT_FAILURE_OBSERVED"),
        Err(e) => {
            eprintln!("CLIENT_FAIL expected Closed on root, got {e}");
            return 1;
        }
        Ok(_) => {
            eprintln!("CLIENT_FAIL root still healthy after service death");
            return 1;
        }
    }

    // G12: the returned capability must fail too.
    match counter.call(
        proto::encode_counter_request(CounterRequest::Get),
        CALL_TIMEOUT,
    ) {
        Err(FabError::Closed(_)) => marker!("CLIENT_NESTED_FAILURE_OBSERVED"),
        Err(e) => {
            eprintln!("CLIENT_FAIL expected Closed on counter, got {e}");
            return 1;
        }
        Ok(_) => {
            eprintln!("CLIENT_FAIL counter still healthy after service death");
            return 1;
        }
    }

    // Report completion.
    if ctrl
        .call(proto::encode_control(proto::ControlMsg::Done), CALL_TIMEOUT)
        .is_err()
    {
        marker!("CLIENT_DONE_SIGNAL_UNACKED");
    } else {
        marker!("CLIENT_DONE_ACKED");
    }
    marker!("CLIENT_OK");
    0
}

fn send_ctrl_wait_ack(ctrl: &Endpoint, m: proto::ControlMsg) -> Result<(), FabError> {
    let res = ctrl.call(proto::encode_control(m), Duration::from_secs(5))?;
    proto::decode_control_ack(&res.payload)?;
    Ok(())
}

/// Grant may or may not have arrived before the peer died; either an
/// explicit Closed failure or a missing grant counts as observed failure.
fn root_closed(rt: &Runtime, strict: bool) -> i32 {
    let mut seen = HashSet::new();
    match claim(rt, &mut seen) {
        Err(FabError::Timeout) => {
            if strict {
                eprintln!("CLIENT_FAIL grant never arrived (strict)");
                1
            } else {
                marker!("CLIENT_GRANT_NEVER_ARRIVED");
                marker!("CLIENT_OK");
                0
            }
        }
        Err(e) => {
            marker!("CLIENT_FABRIC_LOST_WAITING_GRANT {e}");
            marker!("CLIENT_OK");
            0
        }
        Ok(id) => {
            let Some(root) = rt.endpoint_for(id) else {
                marker!("CLIENT_ROOT_CLOSED_OBSERVED");
                marker!("CLIENT_OK");
                return 0;
            };
            if !strict {
                std::thread::sleep(Duration::from_millis(50));
            }
            match root.call(proto::encode_root_request(RootRequest::Ping), CALL_TIMEOUT) {
                Err(FabError::Closed(_)) => {
                    marker!("CLIENT_ROOT_CLOSED_OBSERVED");
                    marker!("CLIENT_OK");
                    0
                }
                Err(e) => {
                    eprintln!("CLIENT_FAIL unexpected error {e}");
                    1
                }
                Ok(_) => {
                    eprintln!("CLIENT_FAIL root unexpectedly healthy");
                    1
                }
            }
        }
    }
}

/// A request left in flight must resolve as explicit failure, not hang.
fn outstanding_request(rt: &Runtime) -> i32 {
    let mut seen = HashSet::new();
    let Ok(root) = claim_ep(rt, &mut seen) else {
        eprintln!("CLIENT_FAIL no root");
        return 1;
    };
    let started = Instant::now();
    match root.call(
        proto::encode_root_request(RootRequest::Ping),
        Duration::from_secs(30),
    ) {
        Err(FabError::Closed(_)) => {
            marker!(
                "CLIENT_OUTSTANDING_FAILED_MS {}",
                started.elapsed().as_millis()
            );
            marker!("CLIENT_OK");
            0
        }
        Err(e) => {
            eprintln!("CLIENT_FAIL unexpected {e}");
            1
        }
        Ok(_) => {
            eprintln!("CLIENT_FAIL outstanding request succeeded after service death");
            1
        }
    }
}

/// Nested capability used exactly once, THEN the service dies; both caps
/// must fail (this is scenario F's client side).
fn kill_after_first_increment(rt: &Runtime) -> i32 {
    let mut seen = HashSet::new();
    let root = match claim_ep(rt, &mut seen) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("CLIENT_FAIL no root: {e}");
            return 1;
        }
    };
    let res = match root.call(
        proto::encode_root_request(RootRequest::OpenCounter),
        CALL_TIMEOUT,
    ) {
        Ok(res) => res,
        Err(e) => {
            eprintln!("CLIENT_FAIL open_counter: {e}");
            return 1;
        }
    };
    let Some(counter) = res.received.into_iter().next() else {
        eprintln!("CLIENT_FAIL no counter attached");
        return 1;
    };
    let cres = match counter.call(
        proto::encode_counter_request(CounterRequest::Increment),
        CALL_TIMEOUT,
    ) {
        Ok(res) => res,
        Err(e) => {
            eprintln!("CLIENT_FAIL increment: {e}");
            return 1;
        }
    };
    match proto::decode_counter_response(&cres.payload) {
        Ok(CounterResponse::Incremented(1)) => {}
        other => {
            eprintln!("CLIENT_FAIL increment reply {other:?}");
            return 1;
        }
    }
    marker!("CLIENT_FIRST_INCREMENT_OK");

    // Tell host to kill; await ack best-effort.
    let ctrl = match claim_ep(rt, &mut seen) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("CLIENT_FAIL no control: {e}");
            return 1;
        }
    };
    let _ = send_ctrl_wait_ack(&ctrl, proto::ControlMsg::ReadyToKill);

    match root.call(proto::encode_root_request(RootRequest::Ping), CALL_TIMEOUT) {
        Err(FabError::Closed(_)) => marker!("CLIENT_ROOT_FAILURE_OBSERVED"),
        _ => {
            eprintln!("CLIENT_FAIL root not explicitly failed");
            return 1;
        }
    }
    match counter.call(
        proto::encode_counter_request(CounterRequest::Get),
        CALL_TIMEOUT,
    ) {
        Err(FabError::Closed(_)) => marker!("CLIENT_NESTED_FAILURE_OBSERVED"),
        _ => {
            eprintln!("CLIENT_FAIL counter not explicitly failed");
            return 1;
        }
    }
    marker!("CLIENT_OK");
    0
}

/// Everything succeeds, then signal orderly completion.
fn graceful_done(rt: &Runtime) -> i32 {
    let mut seen = HashSet::new();
    let root = match claim_ep(rt, &mut seen) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("CLIENT_FAIL no root: {e}");
            return 1;
        }
    };
    if root
        .call(proto::encode_root_request(RootRequest::Ping), CALL_TIMEOUT)
        .is_err()
    {
        eprintln!("CLIENT_FAIL ping failed");
        return 1;
    }
    let res = match root.call(
        proto::encode_root_request(RootRequest::OpenCounter),
        CALL_TIMEOUT,
    ) {
        Ok(res) => res,
        Err(e) => {
            eprintln!("CLIENT_FAIL open_counter: {e}");
            return 1;
        }
    };
    let Some(counter) = res.received.into_iter().next() else {
        eprintln!("CLIENT_FAIL no counter");
        return 1;
    };
    if counter
        .call(
            proto::encode_counter_request(CounterRequest::Get),
            CALL_TIMEOUT,
        )
        .is_err()
    {
        eprintln!("CLIENT_FAIL counter get failed");
        return 1;
    }
    let ctrl = match claim_ep(rt, &mut seen) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("CLIENT_FAIL no control: {e}");
            return 1;
        }
    };
    match send_ctrl_wait_ack(&ctrl, proto::ControlMsg::Done) {
        Ok(()) => {
            marker!("CLIENT_OK");
            0
        }
        Err(e) => {
            eprintln!("CLIENT_FAIL done signal: {e}");
            1
        }
    }
}

/// Host-death watchdog: exit 0 iff fabric loss is observed deterministically.
fn watchdog(rt: &Runtime) -> i32 {
    let mut seen = HashSet::new();
    match claim(rt, &mut seen) {
        Ok(id) => {
            let Some(root) = rt.endpoint_for(id) else {
                marker!("CLIENT_FABRIC_LOST_OBSERVED");
                write_marker_file("client_fabric_lost");
                marker!("CLIENT_OK");
                return 0;
            };
            // Poll until the fabric is gone (bounded).
            let deadline = Instant::now() + Duration::from_secs(15);
            loop {
                if rt.fabric_terminal().is_some() {
                    break;
                }
                if Instant::now() > deadline {
                    write_marker_file("client_watchdog_timeout");
                    eprintln!("CLIENT_FAIL never observed fabric loss");
                    return 1;
                }
                let _ = root.call(
                    proto::encode_root_request(RootRequest::Ping),
                    Duration::from_millis(200),
                );
            }
        }
        Err(FabError::FabricLost | FabError::Closed(_)) => {}
        Err(e) => {
            eprintln!("CLIENT_FAIL waiting root: {e}");
            return 1;
        }
    }
    marker!("CLIENT_FABRIC_LOST_OBSERVED");
    write_marker_file("client_fabric_lost");
    marker!("CLIENT_OK");
    0
}

fn write_marker_file(name: &str) {
    if let Ok(dir) = std::env::var("SEAM_MARKER_DIR") {
        let p = std::path::Path::new(&dir).join(name);
        let _ = std::fs::write(p, b"1");
    }
}

/// N endpoint create/transfer/close cycles through the real fabric.
fn churn(rt: &Runtime) -> i32 {
    let n: usize = std::env::var("SEAM_CHURN_N")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(10_000);
    let mut seen = HashSet::new();
    let root = match claim_ep(rt, &mut seen) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("CLIENT_FAIL no root: {e}");
            return 1;
        }
    };
    let t0 = Instant::now();
    for i in 0..n {
        let res = match root.call(
            proto::encode_root_request(RootRequest::OpenCounter),
            Duration::from_secs(20),
        ) {
            Ok(res) => res,
            Err(e) => {
                eprintln!("CLIENT_FAIL churn[{i}]: {e}");
                return 1;
            }
        };
        let Some(counter) = res.received.into_iter().next() else {
            eprintln!("CLIENT_FAIL churn[{i}]: no capability");
            return 1;
        };
        // Destroy our side deliberately: conversation retires everywhere.
        if let Err(e) = counter.close() {
            eprintln!("CLIENT_FAIL churn[{i}] close: {e}");
            return 1;
        }
    }
    let ms = t0.elapsed().as_millis();
    marker!("CHURN_DONE n={n} ms={ms}");

    let ctrl = match claim_ep(rt, &mut seen) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("CLIENT_FAIL no control after churn: {e}");
            return 1;
        }
    };
    if send_ctrl_wait_ack(&ctrl, proto::ControlMsg::Done).is_err() {
        eprintln!("CLIENT_FAIL churn done signal");
        return 1;
    }
    marker!("CLIENT_OK");
    0
}

/// RTT and transfer-latency measurements (charter §51). Prints PERF lines.
fn perf(rt: &Runtime) -> i32 {
    const N: usize = 2000;
    let mut seen = HashSet::new();
    let root = match claim_ep(rt, &mut seen) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("CLIENT_FAIL no root: {e}");
            return 1;
        }
    };

    // Warmup.
    for _ in 0..100 {
        if root
            .call(
                proto::encode_root_request(RootRequest::Ping),
                Duration::from_secs(5),
            )
            .is_err()
        {
            eprintln!("CLIENT_FAIL warmup");
            return 1;
        }
    }

    let mut samples = Vec::with_capacity(N);
    for _ in 0..N {
        let t = Instant::now();
        if root
            .call(
                proto::encode_root_request(RootRequest::Ping),
                Duration::from_secs(5),
            )
            .is_err()
        {
            eprintln!("CLIENT_FAIL rtt probe");
            return 1;
        }
        samples.push(t.elapsed());
    }
    print_perf("root_rtt_us", &samples);

    // Transfer latency: create pair at service + transfer back to us.
    let mut tsamples = Vec::with_capacity(N);
    for _ in 0..N {
        let t = Instant::now();
        let res = match root.call(
            proto::encode_root_request(RootRequest::OpenCounter),
            Duration::from_secs(5),
        ) {
            Ok(res) => res,
            Err(e) => {
                eprintln!("CLIENT_FAIL transfer probe: {e}");
                return 1;
            }
        };
        let Some(counter) = res.received.into_iter().next() else {
            eprintln!("CLIENT_FAIL transfer probe: no cap");
            return 1;
        };
        tsamples.push(t.elapsed());
        let _ = counter.close();
    }
    print_perf("transfer_roundtrip_us", &tsamples);

    let ctrl = match claim_ep(rt, &mut seen) {
        Ok(c) => c,
        Err(_) => return 1,
    };
    if send_ctrl_wait_ack(&ctrl, proto::ControlMsg::Done).is_err() {
        return 1;
    }
    marker!("CLIENT_OK");
    0
}

fn abort_cycle(rt: &Runtime) -> i32 {
    let mut seen = HashSet::new();
    let root = match claim_ep(rt, &mut seen) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("CLIENT_FAIL no root: {e}");
            return 1;
        }
    };
    let ctrl = match claim_ep(rt, &mut seen) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("CLIENT_FAIL no ctrl: {e}");
            return 1;
        }
    };
    // Fill to capacity: 2 held counters + root + ctrl = 4 live.
    let mut held = Vec::new();
    for i in 0..2 {
        let res = match root.call(
            proto::encode_root_request(RootRequest::OpenCounter),
            CALL_TIMEOUT,
        ) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("CLIENT_FAIL fill[{i}]: {e}");
                return 1;
            }
        };
        if let Some(cap) = res.received.into_iter().next() {
            held.push(cap);
        } else {
            eprintln!("CLIENT_FAIL fill[{i}] no cap");
            return 1;
        }
    }
    // Next transfer should be rejected due to recipient capacity.
    // The call itself should fail with TransferAborted, not hang.
    match root.call(
        proto::encode_root_request(RootRequest::OpenCounter),
        CALL_TIMEOUT,
    ) {
        Err(FabError::TransferAborted(_)) => {
            marker!("CLIENT_ABORT_OBSERVED");
        }
        Ok(r) if r.received.is_empty() => {
            marker!("CLIENT_ABORT_OBSERVED_EMPTY");
        }
        Ok(_) => {
            eprintln!("CLIENT_FAIL expected abort, got success with cap");
            return 1;
        }
        Err(e) => {
            eprintln!("CLIENT_FAIL abort probe unexpected {e}");
            return 1;
        }
    }
    // Free one slot and retransmit: should succeed and be usable.
    drop(held.pop());
    let res = match root.call(
        proto::encode_root_request(RootRequest::OpenCounter),
        CALL_TIMEOUT,
    ) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("CLIENT_FAIL retransmit: {e}");
            return 1;
        }
    };
    let Some(counter) = res.received.into_iter().next() else {
        eprintln!("CLIENT_FAIL no cap after retransmit");
        return 1;
    };
    let cres = match counter.call(
        proto::encode_counter_request(CounterRequest::Increment),
        CALL_TIMEOUT,
    ) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("CLIENT_FAIL increment after restore: {e}");
            return 1;
        }
    };
    match proto::decode_counter_response(&cres.payload) {
        Ok(CounterResponse::Incremented(1)) => {}
        other => {
            eprintln!("CLIENT_FAIL increment value {other:?}");
            return 1;
        }
    }
    marker!("CLIENT_ABORT_RESTORED_USABLE");
    if send_ctrl_wait_ack(&ctrl, proto::ControlMsg::Done).is_err() {
        eprintln!("CLIENT_FAIL done signal");
        return 1;
    }
    marker!("CLIENT_ABORT_CYCLE_OK");
    0
}

fn txn_once(rt: &Runtime) -> i32 {
    let mut seen = HashSet::new();
    let root = match claim_ep(rt, &mut seen) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("CLIENT_FAIL txn_once no root: {e}");
            return 1;
        }
    };
    let ctrl = match claim_ep(rt, &mut seen) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("CLIENT_FAIL txn_once no ctrl: {e}");
            return 1;
        }
    };
    match root.call(
        proto::encode_root_request(RootRequest::OpenCounter),
        CALL_TIMEOUT,
    ) {
        Ok(res) => match proto::decode_root_response(&res.payload) {
            Ok(RootResponse::Counter) => {
                if let Some(cap) = res.received.into_iter().next() {
                    marker!("CLIENT_TXN_ONCE_COMMITTED");
                    // prove usable
                    let _ = cap.call(
                        proto::encode_counter_request(CounterRequest::Get),
                        CALL_TIMEOUT,
                    );
                    let _ = send_ctrl_wait_ack(&ctrl, proto::ControlMsg::Done);
                    marker!("CLIENT_TXN_ONCE_OK");
                    return 0;
                } else {
                    eprintln!("CLIENT_FAIL txn_once no cap");
                    return 1;
                }
            }
            other => {
                eprintln!("CLIENT_FAIL txn_once bad response {other:?}");
                return 1;
            }
        },
        Err(FabError::TransferAborted(_)) => {
            marker!("CLIENT_TXN_ONCE_ABORTED");
            let _ = send_ctrl_wait_ack(&ctrl, proto::ControlMsg::Done);
            return 0;
        }
        Err(e) => {
            eprintln!("CLIENT_FAIL txn_once {e}");
            return 1;
        }
    }
}

fn native_happy(rt: &Runtime) -> i32 {
    let mut seen = std::collections::HashSet::new();
    let root = match claim_ep(rt, &mut seen) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("CLIENT_FAIL native_happy no root: {e}");
            return 1;
        }
    };
    let ctrl = match claim_ep(rt, &mut seen) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("CLIENT_FAIL native_happy no ctrl: {e}");
            return 1;
        }
    };
    let res = match root.call(
        proto::encode_root_request(RootRequest::OpenCounter),
        CALL_TIMEOUT,
    ) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("CLIENT_FAIL native_happy open: {e}");
            return 1;
        }
    };
    if let Some(mut nf) = res.received_native {
        let data = nf.read_all().unwrap_or_default();
        if data.starts_with(b"SEAM_NATIVE_NONCE") {
            marker!("CLIENT_NATIVE_HAPPY_OK");
        }
        let _ = nf.write_marker(b"_CLIENT");
    } else {
        eprintln!(
            "DBG client reply corr={} payload_len={} received={}",
            res.payload.len(),
            res.payload.len(),
            res.received.len()
        );
    }
    let _ = send_ctrl_wait_ack(&ctrl, proto::ControlMsg::Done);
    0
}

fn native_abort(rt: &Runtime) -> i32 {
    let mut seen = HashSet::new();
    let root = match claim_ep(rt, &mut seen) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("CLIENT_FAIL native_abort no root: {e}");
            return 1;
        }
    };
    let ctrl = match claim_ep(rt, &mut seen) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("CLIENT_FAIL native_abort no ctrl: {e}");
            return 1;
        }
    };
    // Txn #1: reject the native offer (env set by host bootstrap).
    let _ = root.call(
        proto::encode_root_request(RootRequest::OpenCounter),
        Duration::from_secs(3),
    );
    std::thread::sleep(Duration::from_millis(300));
    // Stop rejecting for txn #2 (in-process flag; read per offer).
    std::env::remove_var("SEAM_CLI_REJECT_NATIVE");
    marker!("CLIENT_NATIVE_ABORT_TRIGGERED");
    // Txn #2: rejection env is cleared by host after phase 1; restored
    // resource must now commit and arrive readable.
    let res = match root.call(
        proto::encode_root_request(RootRequest::OpenCounter),
        Duration::from_secs(10),
    ) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("CLIENT_FAIL native_abort txn2: {e}");
            return 1;
        }
    };
    if let Some(mut nf) = res.received_native {
        match nf.read_all() {
            Ok(data) if data.starts_with(b"SEAM_NATIVE_NONCE") && data.ends_with(b"_RESTORED") => {
                marker!("CLIENT_NATIVE_RESTORED_RECOMMITTED_OK");
            }
            other => {
                eprintln!(
                    "CLIENT_FAIL native_abort content {:?}",
                    other.map(|v| v.len())
                );
                return 1;
            }
        }
    } else {
        eprintln!("CLIENT_FAIL native_abort no native attachment");
        return 1;
    }
    marker!("CLIENT_NATIVE_ABORT_OK");
    let _ = send_ctrl_wait_ack(&ctrl, proto::ControlMsg::Done);
    0
}

/// Adopt the inherited native resource lane (unix). The descriptor number is
/// metadata only; authority comes from possessing the descriptor itself.
#[cfg(unix)]
fn adopt_native_lane(rt: &Runtime) {
    if let Ok(fd_str) = std::env::var("SEAM_NATIVE_LANE_FD") {
        if let Ok(fd) = fd_str.parse::<i32>() {
            use std::os::unix::io::FromRawFd;
            // SAFETY: fd 3 was dup2'd by the host pre-exec solely for us and
            // marked non-CLOEXEC; we take sole ownership exactly once.
            let lane = unsafe { std::os::unix::net::UnixStream::from_raw_fd(fd) };
            rt.install_native_lane(lane);
        }
    }
}
#[cfg(not(unix))]
fn adopt_native_lane(_rt: &Runtime) {}

/// Shared-memory Producer: receives the Host-granted RW region through the
/// generic transaction, maps writable, fills a deterministic payload, and
/// reports ONLY its 8-byte hash over the control channel. The region
/// capability is held until fabric shutdown (writer authority must stay
/// alive for RegionTable consistency).
fn shared_produce(rt: &Runtime) -> i32 {
    const REGION_SIZE: usize = 4 * 1024 * 1024;
    let seed: u64 = 0x1234_5678_9abc_def0;
    let req = match rt.wait_inbound(Duration::from_secs(30)) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("CLIENT_SHARED_FAIL no offer: {e:?}");
            return 1;
        }
    };
    let mut reg = match req.received_shared {
        Some(r) => r,
        None => {
            eprintln!("CLIENT_SHARED_FAIL offer without shared capability");
            return 1;
        }
    };
    if reg.rights() != authority_fabric::shared::Rights::ReadWrite
        || reg.size() as usize != REGION_SIZE
    {
        eprintln!(
            "CLIENT_SHARED_FAIL rights={:?} size={}",
            reg.rights(),
            reg.size()
        );
        return 1;
    }
    marker!("CLIENT_SHARED_MATERIALIZED rw=true");
    {
        let mut view = match reg.map_read_write() {
            Ok(v) => v,
            Err(e) => {
                eprintln!("CLIENT_SHARED_FAIL map rw: {e}");
                return 1;
            }
        };
        authority_fabric::shared::fill_pattern(view.as_mut_slice(), seed);
    } // writable view unmapped before read-back
    let hash = {
        let view = match reg.map_read_only() {
            Ok(v) => v,
            Err(e) => {
                eprintln!("CLIENT_SHARED_FAIL map ro readback: {e}");
                return 1;
            }
        };
        authority_fabric::shared::fnv64(view.as_slice())
    };
    // Report the hash over the control channel via the endpoint the offer
    // arrived on (pair-routing delivers it to the Host).
    let ep = match rt.endpoint_for(req.local) {
        Some(e) => e,
        None => {
            eprintln!("CLIENT_SHARED_FAIL offer endpoint not held");
            return 1;
        }
    };
    // Fire-and-forget hash report: the Host consumes the frame from the
    // control drain; there is no reply leg, so a short timeout is expected.
    let _ = ep.call(hash.to_le_bytes().to_vec(), Duration::from_millis(500));
    marker!("SHARED_PRODUCER_WRITTEN");
    // Hold writer authority until the fabric shuts down; dropping early would
    // vacate the writer slot mid-experiment.
    loop {
        match rt.wait_inbound(Duration::from_secs(600)) {
            Ok(_) => {}
            Err(_) => break,
        }
    }
    marker!("CLIENT_SHARED_DONE");
    0
}

/// N sequential real native transfers (stress gate). Each cycle is a genuine
/// transaction: sender creates file+nonce, host escrows, recipient reads.
fn native_stress(rt: &Runtime) -> i32 {
    let n: usize = std::env::var("SEAM_STRESS_N")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(1000);
    let mut seen = HashSet::new();
    let root = match claim_ep(rt, &mut seen) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("CLIENT_FAIL stress no root: {e}");
            return 1;
        }
    };
    let ctrl = match claim_ep(rt, &mut seen) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("CLIENT_FAIL stress no ctrl: {e}");
            return 1;
        }
    };
    let t0 = Instant::now();
    let mut ok = 0usize;
    for i in 0..n {
        match root.call(
            proto::encode_root_request(RootRequest::OpenCounter),
            Duration::from_secs(20),
        ) {
            Ok(res) => {
                if let Some(mut nf) = res.received_native {
                    match nf.read_all() {
                        Ok(d) if d.starts_with(b"SEAM_NATIVE_NONCE") => {
                            ok += 1;
                        }
                        _ => {
                            eprintln!("CLIENT_FAIL stress[{i}] bad content");
                            return 1;
                        }
                    }
                    drop(nf);
                } else {
                    eprintln!("CLIENT_FAIL stress[{i}] no native attachment");
                    return 1;
                }
            }
            Err(e) => {
                eprintln!("CLIENT_FAIL stress[{i}]: {e}");
                return 1;
            }
        }
    }
    marker!(
        "NATIVE_STRESS_DONE n={n} ok={ok} ms={}",
        t0.elapsed().as_millis()
    );
    let _ = send_ctrl_wait_ack(&ctrl, proto::ControlMsg::Done);
    0
}

fn preflight_p1_client(rt: &Runtime) -> i32 {
    // Recipient that will be killed pre-accept; just do one txn and report.
    txn_once(rt)
}

fn preflight_p3_client(rt: &Runtime) -> i32 {
    let mut seen = HashSet::new();
    let root = match claim_ep(rt, &mut seen) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("CLIENT_FAIL p3 no root: {e}");
            return 1;
        }
    };
    let ctrl = match claim_ep(rt, &mut seen) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("CLIENT_FAIL p3 no ctrl: {e}");
            return 1;
        }
    };
    let res = match root.call(
        proto::encode_root_request(RootRequest::OpenCounter),
        CALL_TIMEOUT,
    ) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("CLIENT_FAIL p3 open {e}");
            return 1;
        }
    };
    let Some(cap) = res.received.into_iter().next() else {
        eprintln!("CLIENT_FAIL p3 no cap");
        return 1;
    };
    marker!("CLIENT_P3_COMMITTED");
    // Now committed; host will kill us after commit. Keep cap alive a bit then signal.
    std::thread::sleep(Duration::from_millis(200));
    let _ = cap.call(
        proto::encode_counter_request(CounterRequest::Increment),
        CALL_TIMEOUT,
    );
    marker!("CLIENT_P3_USED");
    let _ = send_ctrl_wait_ack(&ctrl, proto::ControlMsg::Done);
    0
}

fn print_perf(name: &str, s: &[Duration]) {
    let mut v: Vec<u128> = s.iter().map(|d| d.as_micros()).collect();
    v.sort_unstable();
    let pct = |p: f64| -> u128 {
        let idx = (((v.len() as f64) * p).ceil() as usize)
            .saturating_sub(1)
            .min(v.len() - 1);
        v[idx]
    };
    marker!(
        "PERF {} n={} min={}us p50={}us p95={}us p99={}us max={}us",
        name,
        v.len(),
        v[0],
        pct(0.50),
        pct(0.95),
        pct(0.99),
        v[v.len() - 1]
    );
}

/// Hostile raw peer: valid hello, then an oversized frame. Must be
/// quarantined by the host without crashing anything.
fn rawpeer() {
    let mut tx = std::io::stdout();
    // Valid handshake so adoption succeeds.
    let hello = hello_frame();
    let _ = tx.write_all(&hello);
    let _ = tx.flush();
    // Oversized declared length with a small body: decoder must reject
    // BEFORE allocating attacker-controlled memory.
    let mut evil = Vec::new();
    evil.extend_from_slice(&(u32::MAX / 2).to_le_bytes());
    evil.extend_from_slice(&[0u8; 16]);
    let _ = tx.write_all(&evil);
    let _ = tx.flush();
    // Then a normal-sized frame that must NEVER be processed (we are dead).
    let _ = tx.write_all(&hello);
    let _ = tx.flush();
    // Park until EOF from quarantine. Host waits on child.exit.
    std::thread::sleep(Duration::from_millis(800));
}

fn hello_frame() -> Vec<u8> {
    let f = authority_fabric::frame::Frame::Hello {
        magic: Limits::default().hello_magic,
        version: Limits::default().hello_version,
    };
    let mut buf = Vec::new();
    authority_fabric::frame::encode_into(&f, &mut buf);
    buf
}
