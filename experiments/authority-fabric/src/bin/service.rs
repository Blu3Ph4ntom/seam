//! Service role. Implements the root interface and any number of counters
//! created through it. Modes via SEAM_SERVICE_MODE: "normal" | "hold".

use std::collections::HashMap;
use std::io::Write as _;
use std::time::Duration;

use authority_fabric::fabric_error::FabError;
use authority_fabric::id::EpId;
use authority_fabric::peer::{Endpoint, Inbound, Runtime, TransferOutcome};
use authority_fabric::marker;
use authority_fabric::native::NativeFile;
use authority_fabric::proto::{
    self, CounterRequest, RootRequest, RootResponse,
};
use authority_fabric::Limits;

fn main() {
    let lim = Limits {
        max_live_endpoints: 4096,
        ..Limits::default()
    };
    let rt = match Runtime::connect_as_child(std::io::stdin(), std::io::stdout(), lim) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("SERVICE_FAIL connect: {e}");
            std::process::exit(2);
        }
    };
    adopt_native_lane(&rt);
    let mode = std::env::var("SEAM_SERVICE_MODE").unwrap_or_else(|_| "normal".into());
    let slow_ms: u64 = std::env::var("SEAM_SLOW_REPLY_MS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);

    // The root capability arrives as a bootstrap grant before any traffic.
    let root_id: EpId = match rt.next_new_handle(&[], Duration::from_secs(10)) {
        Ok(id) => id,
        Err(e) => {
            eprintln!("SERVICE_FAIL no root grant: {e}");
            rt.shutdown();
            std::process::exit(1);
        }
    };

    let mut counters: HashMap<EpId, u64> = HashMap::new();
    // RAII: keep implementation-side handles alive; dropping them would Close.
    let mut held: Vec<Endpoint> = Vec::new();
        let mut restored_q: Vec<Endpoint> = Vec::new();
    let mut restored_q_native: Vec<NativeFile> = Vec::new();

    loop {
        let req: Inbound = match rt.wait_inbound(Duration::from_secs(600)) {
            Ok(r) => r,
            Err(FabError::Timeout) => continue,
            Err(_) => break, // fabric gone (orderly or death)
        };
        if mode == "hold" {
            continue;
        }
        if req.local == root_id {
            match proto::decode_root_request(&req.payload) {
                Ok(RootRequest::Ping) => {
                    if slow_ms > 0 {
                        std::thread::sleep(Duration::from_millis(slow_ms));
                    }
                    let _ = rt.reply(
                        &req,
                        proto::encode_root_response(RootResponse::Pong),
                        vec![],
                    );
                }
                Ok(RootRequest::OpenCounter) => {
                    if mode == "native" || !restored_q_native.is_empty() {
                        // Retransfer a restored native file first (proves the
                        // returned resource is usable and retransferrable);
                        // otherwise create a fresh one.
                        let nf = match restored_q_native.pop() {
                            Some(f) => f,
                            None => match NativeFile::new_temp(b"SEAM_NATIVE_NONCE") {
                                Ok(f) => f,
                                Err(e) => { eprintln!("SERVICE_FAIL native create: {e}"); continue; }
                            },
                        };
                        match rt.reply_with_native(&req, proto::encode_root_response(RootResponse::Counter), Some(nf)) {
                            Ok(TransferOutcome::Committed) => {}
                            Ok(TransferOutcome::NativeAborted(back)) => {
                                marker!("SVC_NATIVE_RESTORED n={}", back.len());
                                // Prove restoration: read nonce, append marker.
                                for mut f in back {
                                    if let Ok(data) = f.read_all() {
                                        if data.starts_with(b"SEAM_NATIVE_NONCE") {
                                            marker!("SVC_NATIVE_NONCE_READBACK_OK");
                                        }
                                    }
                                    let _ = f.write_marker(b"_RESTORED");
                                    restored_q_native.push(f);
                                }
                            }
                            Ok(_) => {}
                            Err(e) => eprintln!("SERVICE_FAIL native reply: {e}"),
                        }
                        continue;
                    }
                    // Prefer re-transferring a previously aborted capability
                    // before creating a new one: proves restored authority is
                    // the same logical capability and is retransferrable.
                    let attempt = if let Some(cap) = restored_q.pop() {
                        rt.reply(
                            &req,
                            proto::encode_root_response(RootResponse::Counter),
                            vec![cap],
                        )
                    } else {
                        match rt.create_endpoint(Duration::from_secs(5)) {
                            Ok((imp, transferable)) => {
                                counters.insert(imp.id(), 0);
                                held.push(imp);
                                rt.reply(
                                    &req,
                                    proto::encode_root_response(RootResponse::Counter),
                                    vec![transferable],
                                )
                            }
                            Err(e) => {
                                eprintln!("SERVICE_FAIL create_endpoint: {e}");
                                continue;
                            }
                        }
                    };
                    match attempt {
                        Ok(TransferOutcome::Committed) => {}
                        Ok(TransferOutcome::NativeAborted(back)) => {
                            marker!("SVC_NATIVE_RESTORED n={}", back.len());
                            restored_q_native.extend(back);
                        }
                        Ok(TransferOutcome::Aborted(back)) => {
                            marker!("SVC_AUTHORITY_RESTORED n={}", back.len());
                            // Keep restored handles alive for re-transfer.
                            // Drop-after-abort case: handled via env hook below.
                            if std::env::var("SEAM_SVC_DROP_RESTORED")
                                .map(|v| v == "1")
                                .unwrap_or(false)
                            {
                                drop(back);
                            } else {
                                restored_q.extend(back);
                            }
                        }
                        Ok(TransferOutcome::AuthorityLost(c)) => {
                            eprintln!("SERVICE_FAIL authority lost: {c:?}");
                        }
                        Err(e) => {
                            eprintln!("SERVICE_FAIL transfer error: {e}");
                        }
                    }
                }
                Err(e) => {
                    eprintln!("SERVICE_FAIL bad root request: {e}");
                }
            }
        } else if counters.contains_key(&req.local) {
            match proto::decode_counter_request(&req.payload) {
                Ok(CounterRequest::Increment) => {
                    let n = counters.entry(req.local).or_insert(0);
                    *n += 1;
                    let _ = rt.reply(
                        &req,
                        proto::encode_counter_response(proto::CounterResponse::Incremented(*n)),
                        vec![],
                    );
                }
                Ok(CounterRequest::Get) => {
                    let n = counters.get(&req.local).copied().unwrap_or(0);
                    let _ = rt.reply(
                        &req,
                        proto::encode_counter_response(proto::CounterResponse::Value(n)),
                        vec![],
                    );
                }
                Err(e) => {
                    eprintln!("SERVICE_FAIL bad counter request: {e}");
                }
            }
        } else {
            eprintln!("SERVICE_FAIL message for unknown endpoint {:?}", req.local);
        }
    }
    rt.shutdown();
    std::process::exit(0);
}

/// Adopt the inherited native resource lane (unix).
#[cfg(unix)]
fn adopt_native_lane(rt: &Runtime) {
    eprintln!(
        "SVC_DEBUG lane_env={:?} fd3={}",
        std::env::var("SEAM_NATIVE_LANE_FD"),
        std::fs::metadata("/proc/self/fd/3").is_ok()
    );
    if let Ok(fd_str) = std::env::var("SEAM_NATIVE_LANE_FD") {
        if let Ok(fd) = fd_str.parse::<i32>() {
            use std::os::unix::io::FromRawFd;
            // SAFETY: fd 3 dup2'd by host pre-exec solely for us; sole owner.
            let lane = unsafe { std::os::unix::net::UnixStream::from_raw_fd(fd) };
            rt.install_native_lane(lane);
            eprintln!("SVC_DEBUG lane_installed");
        }
    }
}
#[cfg(not(unix))]
fn adopt_native_lane(_rt: &Runtime) {}