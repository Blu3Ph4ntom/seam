//! Service role. Implements the root interface and any number of counters
//! created through it. Modes via SEAM_SERVICE_MODE: "normal" | "hold".

use std::collections::HashMap;
use std::time::Duration;

use authority_fabric::fabric_error::FabError;
use authority_fabric::id::EpId;
use authority_fabric::peer::{Endpoint, Inbound, Runtime};
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
                    match rt.create_endpoint(Duration::from_secs(5)) {
                        Ok((imp, transferable)) => {
                            counters.insert(imp.id(), 0);
                            // Transfer invocation authority inside an
                            // ordinary reply. No registry involved.
                            let _ = rt.reply(
                                &req,
                                proto::encode_root_response(RootResponse::Counter),
                                vec![transferable],
                            );
                            held.push(imp);
                        }
                        Err(e) => {
                            eprintln!("SERVICE_FAIL create_endpoint: {e}");
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
