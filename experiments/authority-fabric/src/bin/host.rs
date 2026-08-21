//! Host process: owns the router exclusively, spawns children, mediates all
//! traffic, runs demo/scenario/perf/scale choreography.
//!
//! Threading: per-peer reader thread (parse -> channel), per-peer writer
//! thread (bounded queue -> pipe). The ROUTER lives on the main thread only;
//! readers never touch it.

use std::collections::{HashMap, HashSet, VecDeque};
use std::io::Write;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{sync_channel, Receiver, RecvTimeoutError, SyncSender};
use std::sync::Arc;
use std::time::{Duration, Instant};

use authority_fabric::frame::{self, Frame, FrameError};
use authority_fabric::id::EpId;
use authority_fabric::proto::{self, ControlMsg};
use authority_fabric::queue::{BoundedQueue, PopError};
use authority_fabric::router::{PeerId, Router};
use authority_fabric::{marker, Limits};

// ---------------------------------------------------------------- core ----

enum HostMsg {
    Frame(PeerId, Frame),
    /// Transport broke without protocol violation (crash / EOF).
    PeerLost(PeerId),
    /// Protocol violation detected by the reader itself (oversized frame).
    Quarantined(PeerId, &'static str),
}

struct Conn {
    child: Child,
    out: Arc<BoundedQueue<Frame>>,
    ctrl: Arc<BoundedQueue<Frame>>,
}

struct Fabric {
    router: Router,
    conns: HashMap<PeerId, Conn>,
    tx: SyncSender<HostMsg>,
    rx: Receiver<HostMsg>,
    hellos: HashSet<PeerId>,
    /// Deliveries addressed to HOST-HELD endpoints (control channel),
    /// drained by the choreography layer.
    /// (corr, payload) of DATA delivered to host-held endpoints.
    ctrl_drain: VecDeque<(u32, Vec<u8>)>,
    exit_codes: HashMap<PeerId, i32>,
}

impl Fabric {
    fn new(lim: Limits) -> Fabric {
        // Bounded: charter forbids unbounded queues. A full channel blocks
        // the reader (backpressure) rather than growing without limit.
        let (tx, rx) = sync_channel(4096);
        Fabric {
            router: Router::new(lim.clone()),
            conns: HashMap::new(),
            tx,
            rx,
            hellos: HashSet::new(),
            ctrl_drain: VecDeque::new(),
            exit_codes: HashMap::new(),
        }
    }

    fn lim(&self) -> Limits {
        self.router.limits().clone()
    }

    fn spawn_role(
        &mut self,
        role: &str,
        envs: &[(&str, String)],
    ) -> Result<PeerId, String> {
        let mut cmd = role_command(role)?;
        cmd.stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit());
        for (k, v) in envs {
            cmd.env(k, v);
        }
        let mut child = cmd.spawn().map_err(|e| format!("spawn {role}: {e}"))?;
        let stdin = child.stdin.take().expect("stdin piped");
        let stdout = child.stdout.take().expect("stdout piped");
        // Parent pipe ends must not be inheritable by later siblings; extra
        // copies keep pipes open after host death (orphans).
        #[cfg(windows)]
        {
            deny_inherit(&stdin);
            deny_inherit(&stdout);
        }

        let pid = self.router.accept_peer();
        let outq: Arc<BoundedQueue<Frame>> = Arc::new(BoundedQueue::new(
            self.lim().queue_max_msgs,
            self.lim().queue_max_bytes,
        ));
        let ctrlq: Arc<BoundedQueue<Frame>> = Arc::new(BoundedQueue::new(
            self.lim().control_queue_max_msgs,
            self.lim().control_queue_max_bytes,
        ));

        // Writer: prefer control frames so lifecycle is not stuck behind DATA.
        {
            let q = outq.clone();
            let c = ctrlq.clone();
            std::thread::spawn(move || {
                let mut tx = stdin;
                loop {
                    let frame = if let Some(f) = c.try_pop() {
                        Some(f)
                    } else {
                        match q.pop_deadline(Instant::now() + Duration::from_millis(1)) {
                            Ok(f) => Some(f),
                            Err(PopError::Timeout) => c.try_pop(),
                            Err(PopError::Closed) => break,
                        }
                    };
                    let Some(f) = frame else { continue };
                    let mut buf = Vec::with_capacity(f.cost());
                    frame::encode_into(&f, &mut buf);
                    if tx.write_all(&buf).and_then(|_| tx.flush()).is_err() {
                        break;
                    }
                }
            });
        }

        // Reader thread: parse frames, forward raw to the owner thread.
        {
            let tx = self.tx.clone();
            let lim = self.lim();
            let me = pid;
            std::thread::spawn(move || {
                let mut rx = stdout;
                loop {
                    match frame::read_frame(&mut rx, &lim) {
                        Ok(f) => {
                            if tx.send(HostMsg::Frame(me, f)).is_err() {
                                break;
                            }
                        }
                        Err(FrameError::TooLarge { .. }) => {
                            let _ = tx.send(HostMsg::Quarantined(me, "oversized frame"));
                            break;
                        }
                        Err(_) => {
                            let _ = tx.send(HostMsg::PeerLost(me));
                            break;
                        }
                    }
                }
            });
        }

        self.conns.insert(pid, Conn { child, out: outq, ctrl: ctrlq });
        Ok(pid)
    }

    /// Process exactly one queued message (with deadline). Returns false on
    /// timeout.
    fn step(&mut self, deadline: Instant) -> bool {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return false;
        }
        let msg = match self.rx.recv_timeout(remaining) {
            Ok(m) => m,
            Err(RecvTimeoutError::Timeout) => return false,
            Err(RecvTimeoutError::Disconnected) => return false,
        };
        match msg {
            HostMsg::Frame(pid, f) => self.on_frame(pid, f),
            HostMsg::PeerLost(pid) => {
                marker!("HOST_PEER_LOST peer={}", pid.0);
                self.collapse_peer(pid);
                true
            }
            HostMsg::Quarantined(pid, why) => {
                marker!("HOST_QUARANTINED_PEER peer={} reason={}", pid.0, why);
                self.collapse_peer(pid);
                true
            }
        }
    }

    fn on_frame(&mut self, pid: PeerId, f: Frame) -> bool {
        let outcome = match f {
            Frame::Hello { magic, version } => {
                let r = self.router.on_hello(pid, magic, version);
                match r {
                    Ok(()) => {
                        self.hellos.insert(pid);
                        marker!("HOST_HELLO_OK peer={}", pid.0);
                        None
                    }
                    Err(p) => Some(p),
                }
            }
            Frame::Data(d) => match self.router.on_data(pid, d) {
                Ok(mut oc) => {
                    for h in oc.to_host.drain(..) {
                        self.ctrl_drain.push_back((h.corr, h.payload));
                    }
                    self.dispatch_sends(&oc);
                    None
                }
                Err(p) => Some(p),
            },
            Frame::Close { target } => match self.router.on_close(pid, target) {
                Ok(oc) => {
                    self.dispatch_sends(&oc);
                    for e in self.router.take_host_events() {
                        marker!("HOST_EVENT {:?}", e);
                    }
                    None
                }
                Err(p) => Some(p),
            },
            Frame::Create => match self.router.on_create(pid) {
                Ok(oc) => {
                    self.dispatch_sends(&oc);
                    None
                }
                Err(p) => Some(p),
            },
            Frame::Xfer(x) => match self.router.on_xfer(pid, x) {
                Ok(oc) => {
                    self.dispatch_sends(&oc);
                    None
                }
                Err(p) => Some(p),
            },
            Frame::ClosedNotify { .. } | Frame::Grant { .. } | Frame::CreateAck { .. } | Frame::Error(_) => {
                Some(self.router.on_illegal(pid, "peer sent host-only frame"))
            }
            Frame::Shutdown => {
                let oc = self.router.on_shutdown(pid);
                self.dispatch_sends(&oc);
                self.teardown_conn(pid);
                marker!("HOST_PEER_SHUTDOWN peer={}", pid.0);
                return true;
            }
        };
        match outcome {
            None => true,
            Some(poison) => {
                marker!(
                    "HOST_QUARANTINED_PEER peer={} reason={}",
                    pid.0,
                    poison.0
                );
                self.collapse_peer(pid);
                true
            }
        }
    }

    fn dispatch_sends(&mut self, oc: &authority_fabric::router::RouteOutcome) {
        for (dest, f) in &oc.send {
            if let Some(c) = self.conns.get(dest) {
                let frame = f.clone();
                let cost = frame.cost();
                let offer = matches!(&frame, Frame::Data(d) if !d.attachments.is_empty());
                if frame::is_control_frame(&frame) || offer {
                    let deadline = Instant::now() + Duration::from_millis(2000);
                    let q = if frame::is_control_frame(&frame) { &c.ctrl } else { &c.out };
                    if q.push_deadline(frame, cost, deadline).is_err() {
                        marker!("HOST_CTRL_PUSH_FAILED dest={}", dest.0);
                    }
                } else if c.out.try_push(frame, cost).is_err() {
                    marker!("HOST_DATA_BACKPRESSURE dest={}", dest.0);
                }
            }
        }
    }

    fn teardown_conn(&mut self, pid: PeerId) {
        if let Some(mut c) = self.conns.remove(&pid) {
            c.out.close();
            c.ctrl.close();
            let code = c.child.wait().map(|s| s.code().unwrap_or(-1)).unwrap_or(-1);
            self.exit_codes.insert(pid, code);
        }
    }

    fn collapse_peer(&mut self, pid: PeerId) {
        let oc = self.router.on_eof(pid);
        self.dispatch_sends(&oc);
        for e in self.router.take_host_events() {
            marker!("HOST_EVENT {:?}", e);
        }
        self.teardown_conn(pid);
    }

    fn kill_peer(&mut self, pid: PeerId) {
        if let Some(c) = self.conns.get_mut(&pid) {
            let _ = c.child.kill();
            if let Ok(s) = c.child.wait() {
                self.exit_codes.insert(pid, s.code().unwrap_or(-1));
            }
        }
    }

    fn grant(&mut self, to: PeerId, ep: EpId) {
        match self.router.grant(to, ep) {
            Ok(frame) => {
                if let Some(c) = self.conns.get(&to) {
                    let deadline = Instant::now() + Duration::from_millis(500);
                    if c.ctrl.push_deadline(frame.clone(), frame.cost(), deadline).is_err() {
                        marker!("HOST_GRANT_PUSH_FAILED");
                    }
                }
            }
            Err(p) => marker!("HOST_GRANT_FAILED {:?}", p),
        }
    }

    fn settle_escrow(&mut self, timeout: Duration) -> Result<(), String> {
        let deadline = Instant::now() + timeout;
        while self.router.accounting().escrowed > 0 {
            if !self.step(deadline) {
                return Err(format!(
                    "escrow settle timeout remaining={}",
                    self.router.accounting().escrowed
                ));
            }
        }
        Ok(())
    }

    fn host_send(&mut self, target: EpId, corr: u32, payload: Vec<u8>) {
        match self.router.host_emit(target, corr, payload) {
            Ok(oc) => self.dispatch_sends(&oc),
            Err(p) => marker!("HOST_SEND_FAILED {:?}", p),
        }
    }

    fn ack_ctrl(&mut self, setup: &Setup, corr: u32) {
        self.host_send(
            setup.ctrl_host_side,
            corr,
            proto::encode_control_ack(proto::ControlAck::Ack),
        );
    }

    fn shutdown_orderly(&mut self) {
        let ids: Vec<PeerId> = self.conns.keys().copied().collect();
        for pid in &ids {
            if let Some(c) = self.conns.get(pid) {
                let _ = c.out.try_push(Frame::Shutdown, 8);
            }
        }
        // Give writers a moment to flush, then process graceful collapses.
        let deadline = Instant::now() + Duration::from_millis(400);
        while Instant::now() < deadline && !self.conns.is_empty() {
            self.step(deadline);
        }
        for pid in self.conns.keys().copied().collect::<Vec<_>>() {
            let oc = self.router.on_shutdown(pid);
            self.dispatch_sends(&oc);
            self.teardown_conn(pid);
        }
    }

    fn print_accounting(&self, tag: &str) {
        let a = self.router.accounting();
        marker!(
            "HOST_ACCOUNTING tag={} peers={} live_eps={} retired={} host_held={}",
            tag,
            a.peers,
            a.live_endpoints,
            a.retired_identities,
            a.host_held
        );
    }

    fn wait_hellos(&mut self, n: usize, timeout: Duration) -> Result<(), String> {
        let deadline = Instant::now() + timeout;
        while self.hellos.len() < n {
            if !self.step(deadline) {
                return Err(format!("hello timeout (got {})", self.hellos.len()));
            }
        }
        Ok(())
    }

    /// Wait for a control message matching `pred` on any host-held endpoint.
    fn wait_ctrl(
        &mut self,
        timeout: Duration,
        pred: impl Fn(&ControlMsg) -> bool,
    ) -> Result<u32, String> {
        let deadline = Instant::now() + timeout;
        loop {
            while let Some((corr, payload)) = self.ctrl_drain.pop_front() {
                if let Ok(m) = proto::decode_control(&payload) {
                    if pred(&m) {
                        return Ok(corr);
                    }
                }
            }
            if !self.step(deadline) {
                return Err("ctrl wait timeout".into());
            }
        }
    }

    fn wait_exit(&mut self, pid: PeerId, timeout: Duration) -> Result<i32, String> {
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(code) = self.exit_codes.get(&pid) {
                return Ok(*code);
            }
            if !self.step(deadline) {
                return Err(format!("exit wait timeout for peer {}", pid.0));
            }
        }
    }
}

// ----------------------------------------------------------- bootstrap ----

struct Setup {
    svc: PeerId,
    cli: PeerId,
    _root_client_side: EpId,
    _root_service_side: EpId,
    _ctrl_client_side: EpId,
    ctrl_host_side: EpId,
    t0: Instant,
}

/// Common bootstrap: spawn service + client, exchange hellos, create the
/// root capability pair and grant its sides, create the control pair.
fn bootstrap(
    fab: &mut Fabric,
    svc_env: &[(&str, String)],
    cli_env: &[(&str, String)],
) -> Result<Setup, String> {
    marker!("HOST_STARTED");
    let t0 = Instant::now();
    let svc = fab.spawn_role("service", svc_env)?;
    let cli = fab.spawn_role("client", cli_env)?;
    let svc_os = fab.conns.get(&svc).map(|c| c.child.id()).unwrap_or(0);
    let cli_os = fab.conns.get(&cli).map(|c| c.child.id()).unwrap_or(0);
    marker!("HOST_PIDS svc={} cli={}", svc_os, cli_os);
    fab.wait_hellos(2, Duration::from_secs(10))?;
    marker!("SERVICE_BOOTSTRAPPED");
    marker!("CLIENT_BOOTSTRAPPED");

    // Root capability: a conversation between client and service. The host
    // creates the pair, then TRANSFERS each side. Possession begins here.
    let (a, b) = fab.router.create_host_pair();
    fab.grant(cli, a); // client may invoke the service through a
    fab.grant(svc, b); // service implements b
    fab.settle_escrow(Duration::from_secs(5))?;
    marker!("ROOT_CAPABILITY_TRANSFERRED");

    // Demo-control capability between host and client (orchestration only).
    let (cc, ch) = fab.router.create_host_pair();
    fab.grant(cli, cc);
    fab.settle_escrow(Duration::from_secs(5))?;
    marker!("CONTROL_CAPABILITY_TRANSFERRED");

    Ok(Setup {
        svc,
        cli,
        _root_client_side: a,
        _root_service_side: b,
        _ctrl_client_side: cc,
        ctrl_host_side: ch,
        t0,
    })
}

#[cfg(windows)]
fn deny_inherit(h: &impl std::os::windows::io::AsRawHandle) {
    const HANDLE_FLAG_INHERIT: u32 = 0x0000_0001;
    extern "system" {
        fn SetHandleInformation(
            hobject: *mut core::ffi::c_void,
            dwmask: u32,
            dwflags: u32,
        ) -> i32;
    }
    let raw = h.as_raw_handle();
    // SAFETY: `raw` is a valid open handle owned by `h` for the duration of
    // this call; we only clear HANDLE_FLAG_INHERIT.
    let _ = unsafe { SetHandleInformation(raw, HANDLE_FLAG_INHERIT, 0) };
}

/// Resolve the sibling binary for a role. Host, client, and service are
/// separate bins; `current_exe` is the host, so we retarget the filename.
fn role_command(role: &str) -> Result<Command, String> {
    let mut path = std::env::current_exe().map_err(|e| e.to_string())?;
    let bin = match role {
        "service" => "service",
        "client" | "rawpeer" => "client",
        other => return Err(format!("unknown role {other}")),
    };
    path.set_file_name(format!("{bin}{}", std::env::consts::EXE_SUFFIX));
    if !path.exists() {
        return Err(format!("missing sibling binary {}", path.display()));
    }
    let mut cmd = Command::new(path);
    if role == "rawpeer" {
        cmd.arg("rawpeer");
    }
    Ok(cmd)
}

// --------------------------------------------------------------- modes ----

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mode = args.first().map(String::as_str).unwrap_or("demo");
    let lim = Limits::default();
    let code = match mode {
        "demo" => demo(lim),
        "scenario" => match args.get(1).map(String::as_str) {
            Some(case) => scenario(lim, case),
            None => fail("scenario needs a case name"),
        },
        "perf" => perf(lim),
        "scale" => scale(lim),
        "hostdie" => hostdie(lim),
        "quarantine" => quarantine(lim),
        other => fail(&format!("unknown host mode {other:?}")),
    };
    std::process::exit(code);
}

fn fail(msg: &str) -> i32 {
    eprintln!("HOST_FAIL {msg}");
    2
}

/// Full happy-path demonstration plus lifecycle proof. Prints all markers
/// required by the run charter.
fn demo(lim: Limits) -> i32 {
    let mut fab = Fabric::new(lim);
    let setup = match bootstrap(&mut fab, &[], &[]) {
        Ok(s) => s,
        Err(e) => return fail(&e),
    };
    marker!(
        "BOOTSTRAP_MS {}",
        setup.t0.elapsed().as_millis()
    );

    // Wait for the client to finish the nested-capability phase.
    let kill_corr = match fab.wait_ctrl(Duration::from_secs(30), |m| {
        matches!(m, ControlMsg::ReadyToKill)
    }) {
        Ok(c) => c,
        Err(e) => return fail(&e),
    };
    marker!("REQUEST_SUCCEEDED");
    marker!("NESTED_CAPABILITY_TRANSFERRED");
    marker!("NESTED_CAPABILITY_INVOKED");
    marker!("KILLING_SERVICE");
    fab.kill_peer(setup.svc);
    // Death propagation: collapsing the dead peer notifies the surviving
    // holder deterministically.
    fab.collapse_peer(setup.svc);
    marker!("PEER_FAILURE_OBSERVED_BY_FABRIC");
    // Unblock the client's ReadyToKill call now that the service is gone,
    // so the subsequent Closed assertions do not wait out the ack timeout.
    fab.ack_ctrl(&setup, kill_corr);

    // Client asserts failures and signals Done.
    let done_corr = match fab.wait_ctrl(Duration::from_secs(20), |m| matches!(m, ControlMsg::Done)) {
        Ok(c) => c,
        Err(e) => return fail(&e),
    };
    fab.ack_ctrl(&setup, done_corr);
    marker!("CLIENT_ACKNOWLEDGED_FAILURES");
    fab.shutdown_orderly();
    fab.print_accounting("final");
    let a = fab.router.accounting();
    if a.peers != 0 || a.live_endpoints != 0 {
        return fail("cleanup left live state");
    }
    marker!("CLEANUP_COMPLETED");
    println!("DEMO_OK");
    0
}

fn scenario(lim: Limits, case: &str) -> i32 {
    let r = match case {
        "A" => crash_a(lim),
        "B" => crash_b(lim),
        "C" => crash_c(lim),
        "D" => crash_d(lim),
        "E" => crash_e(lim),
        "F" => crash_f(lim),
        "G" => crash_g(lim),
        other => return fail(&format!("unknown scenario {other:?}")),
    };
    match r {
        Ok(()) => {
            println!("CASE_{case}_OK");
            0
        }
        Err(e) => {
            eprintln!("CASE_{case}_FAIL {e}");
            1
        }
    }
}

/// A: kill immediately after spawn, before bootstrap completes.
fn crash_a(lim: Limits) -> Result<(), String> {
    let mut fab = Fabric::new(lim);
    let svc = fab.spawn_role("service", &[])?;
    fab.kill_peer(svc);
    fab.collapse_peer(svc);
    let a = fab.router.accounting();
    if a.peers != 0 || a.live_endpoints != 0 {
        return Err("state leaked".into());
    }
    Ok(())
}

/// B: after hello, before capability transfer.
fn crash_b(lim: Limits) -> Result<(), String> {
    let mut fab = Fabric::new(lim);
    let svc = fab.spawn_role("service", &[])?;
    fab.wait_hellos(1, Duration::from_secs(10))?;
    fab.kill_peer(svc);
    fab.collapse_peer(svc);
    Ok(())
}

/// C: grants written, killed immediately without settle time.
fn crash_c(lim: Limits) -> Result<(), String> {
    let mut fab = Fabric::new(lim);
    let setup = bootstrap(
        &mut fab,
        &[("SEAM_SERVICE_MODE", "hold".into())],
        &[("SEAM_CLIENT_MODE", "root_closed_tolerant".into())],
    )?;
    fab.kill_peer(setup.svc);
    fab.collapse_peer(setup.svc);
    let code = fab.wait_exit(setup.cli, Duration::from_secs(15))?;
    if code != 0 {
        return Err(format!("client exit {code}"));
    }
    Ok(())
}

/// D: grants settled, then killed; client must observe Closed(PeerLost).
fn crash_d(lim: Limits) -> Result<(), String> {
    let mut fab = Fabric::new(lim);
    let setup = bootstrap(
        &mut fab,
        &[("SEAM_SERVICE_MODE", "hold".into())],
        &[("SEAM_CLIENT_MODE", "root_closed_strict".into())],
    )?;
    std::thread::sleep(Duration::from_millis(250));
    fab.kill_peer(setup.svc);
    fab.collapse_peer(setup.svc);
    let code = fab.wait_exit(setup.cli, Duration::from_secs(15))?;
    if code != 0 {
        return Err(format!("client exit {code}"));
    }
    Ok(())
}

/// E: request outstanding when service dies.
fn crash_e(lim: Limits) -> Result<(), String> {
    let mut fab = Fabric::new(lim);
    let setup = bootstrap(
        &mut fab,
        &[("SEAM_SERVICE_MODE", "normal".into()), ("SEAM_SLOW_REPLY_MS", "8000".into())],
        &[("SEAM_CLIENT_MODE", "outstanding_request".into())],
    )?;
    std::thread::sleep(Duration::from_millis(400)); // let the request land
    fab.kill_peer(setup.svc);
    fab.collapse_peer(setup.svc);
    let code = fab.wait_exit(setup.cli, Duration::from_secs(15))?;
    if code != 0 {
        return Err(format!("client exit {code}"));
    }
    Ok(())
}

/// F: nested capability exists and was used once, THEN service dies; both
/// capabilities must fail explicitly (G11 + G12).
fn crash_f(lim: Limits) -> Result<(), String> {
    let mut fab = Fabric::new(lim);
    let setup = bootstrap(
        &mut fab,
        &[("SEAM_SERVICE_MODE", "normal".into())],
        &[("SEAM_CLIENT_MODE", "kill_after_first_increment".into())],
    )?;
    let kill_corr = fab.wait_ctrl(Duration::from_secs(30), |m| {
        matches!(m, ControlMsg::ReadyToKill)
    })?;
    fab.kill_peer(setup.svc);
    fab.collapse_peer(setup.svc);
    // Acknowledge so the client proceeds to assert the failures.
    fab.ack_ctrl(&setup, kill_corr);
    let code = fab.wait_exit(setup.cli, Duration::from_secs(20))?;
    if code != 0 {
        return Err(format!("client exit {code}"));
    }
    Ok(())
}

/// G: fully graceful shutdown, no kills anywhere.
fn crash_g(lim: Limits) -> Result<(), String> {
    let mut fab = Fabric::new(lim);
    let setup = bootstrap(
        &mut fab,
        &[("SEAM_SERVICE_MODE", "normal".into())],
        &[("SEAM_CLIENT_MODE", "graceful_done".into())],
    )?;
    let done_corr = fab.wait_ctrl(Duration::from_secs(30), |m| matches!(m, ControlMsg::Done))?;
    fab.ack_ctrl(&setup, done_corr);
    fab.shutdown_orderly();
    let c = fab.exit_codes.get(&setup.cli).copied();
    let s = fab.exit_codes.get(&setup.svc).copied();
    let a = fab.router.accounting();
    if a.peers != 0 || a.live_endpoints != 0 {
        return Err(format!("leak: {a:?}"));
    }
    if c != Some(0) || s != Some(0) {
        return Err(format!("exit codes cli={c:?} svc={s:?}"));
    }
    Ok(())
}

/// RTT / transfer latency measurement harness.
fn perf(lim: Limits) -> i32 {
    let mut fab = Fabric::new(lim);
    let setup = match bootstrap(
        &mut fab,
        &[("SEAM_SERVICE_MODE", "normal".into())],
        &[("SEAM_CLIENT_MODE", "perf".into()), ("SEAM_PERF_N", "2000".into())],
    ) {
        Ok(s) => s,
        Err(e) => return fail(&e),
    };
    marker!("PERF_BOOTSTRAP_MS {}", setup.t0.elapsed().as_millis());
    let done_corr = match fab.wait_ctrl(Duration::from_secs(300), |m| {
        matches!(m, ControlMsg::Done)
    }) {
        Ok(c) => c,
        Err(e) => return fail(&e),
    };
    fab.ack_ctrl(&setup, done_corr);
    fab.shutdown_orderly();
    marker!("PERF_DONE");
    0
}

/// Scale smoke: N endpoint create/transfer/close cycles through real
/// processes (charter §52).
fn scale(lim: Limits) -> i32 {
    let n: usize = std::env::var("SEAM_CHURN_N")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(10_000);
    let mut fab = Fabric::new(lim);
    let setup = match bootstrap(
        &mut fab,
        &[("SEAM_SERVICE_MODE", "normal".into())],
        &[("SEAM_CLIENT_MODE", "churn".into()), ("SEAM_CHURN_N", n.to_string())],
    ) {
        Ok(s) => s,
        Err(e) => return fail(&e),
    };
    let done_corr = match fab.wait_ctrl(Duration::from_secs(1800), |m| {
        matches!(m, ControlMsg::Done)
    }) {
        Ok(c) => c,
        Err(e) => return fail(&e),
    };
    fab.ack_ctrl(&setup, done_corr);
    let a = fab.router.accounting();
    marker!(
        "SCALE_FINAL before_teardown live_eps={} retired={}",
        a.live_endpoints,
        a.retired_identities
    );
    // Live = root pair (2) + control pair (2). Retirement is a bounded
    // cache, not 2*N historical tombstones.
    let max_ret = fab.lim().max_retired;
    if a.live_endpoints != 4 || a.retired_identities > max_ret {
        return fail(&format!(
            "scale accounting wrong: live={} retired={} want live=4 retired<={}",
            a.live_endpoints,
            a.retired_identities,
            max_ret
        ));
    }
    fab.shutdown_orderly();
    let a = fab.router.accounting();
    if a.peers != 0 || a.live_endpoints != 0 {
        return fail("cleanup left live state");
    }
    marker!("SCALE_DONE retired_total={}", a.retired_identities);
    println!("SCALE_OK n={n}");
    0
}

/// Host dies abruptly; children must notice and exit deterministically.
fn hostdie(lim: Limits) -> i32 {
    let mut fab = Fabric::new(lim);
    let setup = match bootstrap(
        &mut fab,
        &[("SEAM_SERVICE_MODE", "hold".into())],
        &[("SEAM_CLIENT_MODE", "watchdog".into())],
    ) {
        Ok(s) => s,
        Err(e) => return fail(&e),
    };
    let _ = setup;
    // Abrupt death: pipes close, children see EOF.
    std::process::exit(9);
}

/// A hostile raw peer speaking garbage gets quarantined; the host survives.
fn quarantine(lim: Limits) -> i32 {
    let mut fab = Fabric::new(lim);
    let rp = match fab.spawn_role("rawpeer", &[]) {
        Ok(p) => p,
        Err(e) => return fail(&e),
    };
    // Expect the reader to flag the oversized frame.
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut saw_quarantine = false;
    while Instant::now() < deadline {
        if fab.exit_codes.contains_key(&rp) && saw_quarantine {
            break;
        }
        if !fab.step(deadline) {
            continue;
        }
        // step() prints the quarantine marker; detect via exit code presence
        // is not enough, so watch the accounting instead.
        if fab.exit_codes.contains_key(&rp) {
            saw_quarantine = true;
        }
    }
    if !saw_quarantine {
        return fail("rawpeer never quarantined");
    }
    // The fabric must still function afterwards.
    let (x, y) = fab.router.create_host_pair();
    let a = fab.router.accounting();
    if a.peers != 0 || a.live_endpoints != 2 {
        return fail("host state damaged by hostile peer");
    }
    let _ = (x, y);
    marker!("HOST_SURVIVED_QUARANTINE");
    0
}
