//! In-process longevity: 1M create/grant/close cycles and a 100k drop storm.

use authority_fabric::frame::{Frame, XferMsg};
use authority_fabric::router::Router;
use authority_fabric::Limits;
use std::time::Instant;

fn hello(r: &mut Router, p: authority_fabric::PeerId) {
    r.on_hello(p, Limits::default().hello_magic, Limits::default().hello_version)
        .unwrap();
}

fn grant_commit(r: &mut Router, to: authority_fabric::PeerId, ep: authority_fabric::EpId) {
    let f = r.grant(to, ep).unwrap();
    let tid = match f {
        Frame::Grant { tid, .. } => tid,
        _ => panic!("grant"),
    };
    r.on_xfer(to, XferMsg::Accept { tid }).unwrap();
}

#[test]
fn million_lifecycle_churn() {
    let n = 1_000_000usize;
    let mut r = Router::new(Limits {
        max_retired: 4096,
        max_live_endpoints: 16,
        ..Limits::default()
    });
    let a = r.accept_peer();
    hello(&mut r, a);
    let t0 = Instant::now();
    for _ in 0..n {
        let (x, y) = r.create_host_pair();
        grant_commit(&mut r, a, x);
        r.on_close(a, x).unwrap();
        let _ = y;
        assert!(r.authority_mass_ok());
    }
    let a = r.accounting();
    assert_eq!(a.pending_transfers, 0);
    assert!(a.retired_identities <= 4096, "retired {}", a.retired_identities);
    assert_eq!(a.escrowed, 0);
    eprintln!(
        "CHURN_1M n={n} ms={} live={} retired={} pending={} collisions={}",
        t0.elapsed().as_millis(),
        a.live_endpoints,
        a.retired_identities,
        a.pending_transfers,
        r.collisions()
    );
}

#[test]
fn drop_storm_100k() {
    let mut r = Router::new(Limits {
        max_retired: 4096,
        max_live_endpoints: 8,
        ..Limits::default()
    });
    let a = r.accept_peer();
    hello(&mut r, a);
    for _ in 0..100_000 {
        let (x, _) = r.create_host_pair();
        grant_commit(&mut r, a, x);
        r.on_close(a, x).unwrap();
    }
    let a = r.accounting();
    assert_eq!(a.pending_transfers, 0);
    assert!(a.retired_identities <= 4096);
    assert!(r.authority_mass_ok());
}
