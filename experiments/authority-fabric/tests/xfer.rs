//! Transfer crash matrix T1–T9 (router-level) plus replay / lost-ack.

use authority_fabric::frame::{Attachment, DataInner, Frame, XferMsg, XFER_ST_COMMITTED};
use authority_fabric::id::{EpId, TransferId};
use authority_fabric::router::{Holder, Router};
use authority_fabric::Limits;

fn hello(r: &mut Router, p: authority_fabric::PeerId) {
    r.on_hello(p, Limits::default().hello_magic, Limits::default().hello_version)
        .unwrap();
}

fn primed() -> (Router, authority_fabric::PeerId, authority_fabric::PeerId, EpId, EpId) {
    let mut r = Router::new(Limits::default());
    let a = r.accept_peer();
    let b = r.accept_peer();
    hello(&mut r, a);
    hello(&mut r, b);
    let (x, y) = r.create_host_pair();
    commit_grant(&mut r, a, x);
    commit_grant(&mut r, b, y);
    (r, a, b, x, y)
}

fn commit_grant(r: &mut Router, to: authority_fabric::PeerId, ep: EpId) {
    let f = r.grant(to, ep).unwrap();
    let tid = match f {
        Frame::Grant { tid, .. } => tid,
        _ => panic!("grant"),
    };
    r.on_xfer(to, XferMsg::Accept { tid }).unwrap();
}

fn att(id: EpId, partner: EpId) -> Attachment {
    Attachment { tid: TransferId(id.0), id, partner }
}

fn data(target: EpId, atts: Vec<Attachment>) -> DataInner {
    DataInner { target, corr: 1, attachments: atts, payload: b"x".to_vec() }
}

#[test]
fn t2_sender_dies_after_prepare_aborts() {
    let (mut r, a, b, x, _) = primed();
    let oc = r.on_create(a).unwrap();
    let (imp, tra) = match oc.send[0].1 {
        Frame::CreateAck { impl_ep, transferable_ep } => (impl_ep, transferable_ep),
        _ => panic!(),
    };
    r.on_data(a, data(x, vec![att(tra, imp)])).unwrap();
    assert!(matches!(r.holder_of(tra), Some(Holder::Escrow(_))));
    r.on_eof(a);
    assert!(r.holder_of(tra).is_none());
    assert!(r.authority_mass_ok());
    let _ = (b, imp);
}

#[test]
fn t3_recipient_dies_before_accept_restores() {
    let (mut r, a, b, x, _) = primed();
    let oc = r.on_create(a).unwrap();
    let (imp, tra) = match oc.send[0].1 {
        Frame::CreateAck { impl_ep, transferable_ep } => (impl_ep, transferable_ep),
        _ => panic!(),
    };
    r.on_data(a, data(x, vec![att(tra, imp)])).unwrap();
    r.on_eof(b);
    assert_eq!(r.holder_of(tra), Some(Holder::Peer(a)));
    assert!(r.authority_mass_ok());
}

#[test]
fn t6_commit_then_recipient_death_does_not_restore() {
    let (mut r, a, b, x, _) = primed();
    let oc = r.on_create(a).unwrap();
    let (imp, tra) = match oc.send[0].1 {
        Frame::CreateAck { impl_ep, transferable_ep } => (impl_ep, transferable_ep),
        _ => panic!(),
    };
    r.on_data(a, data(x, vec![att(tra, imp)])).unwrap();
    let tid = match r.holder_of(tra) {
        Some(Holder::Escrow(t)) => t,
        _ => panic!(),
    };
    r.on_xfer(b, XferMsg::Accept { tid }).unwrap();
    assert_eq!(r.holder_of(tra), Some(Holder::Peer(b)));
    r.on_eof(b);
    assert!(r.holder_of(tra).is_none());
    assert_ne!(r.holder_of(tra), Some(Holder::Peer(a)));
}

#[test]
fn t8_lost_committed_ack_status_is_committed() {
    let (mut r, a, b, x, _) = primed();
    r.inject.drop_committed = true;
    let oc = r.on_create(a).unwrap();
    let (imp, tra) = match oc.send[0].1 {
        Frame::CreateAck { impl_ep, transferable_ep } => (impl_ep, transferable_ep),
        _ => panic!(),
    };
    r.on_data(a, data(x, vec![att(tra, imp)])).unwrap();
    let tid = match r.holder_of(tra) {
        Some(Holder::Escrow(t)) => t,
        _ => panic!(),
    };
    let oc = r.on_xfer(b, XferMsg::Accept { tid }).unwrap();
    assert!(!oc.send.iter().any(|(_, f)| matches!(f, Frame::Xfer(XferMsg::Committed { .. }))));
    assert_eq!(r.xfer_status(tid), XFER_ST_COMMITTED);
    assert_eq!(r.holder_of(tra), Some(Holder::Peer(b)));
    let st = r.on_xfer(a, XferMsg::Status { tid }).unwrap();
    assert!(st.send.iter().any(|(_, f)| matches!(
        f,
        Frame::Xfer(XferMsg::StatusAck { status: XFER_ST_COMMITTED, .. })
    )));
}

#[test]
fn replay_accept_is_idempotent() {
    let (mut r, a, b, x, _) = primed();
    let oc = r.on_create(a).unwrap();
    let (imp, tra) = match oc.send[0].1 {
        Frame::CreateAck { impl_ep, transferable_ep } => (impl_ep, transferable_ep),
        _ => panic!(),
    };
    r.on_data(a, data(x, vec![att(tra, imp)])).unwrap();
    let tid = match r.holder_of(tra) {
        Some(Holder::Escrow(t)) => t,
        _ => panic!(),
    };
    r.on_xfer(b, XferMsg::Accept { tid }).unwrap();
    r.on_xfer(b, XferMsg::Accept { tid }).unwrap();
    assert_eq!(r.holder_of(tra), Some(Holder::Peer(b)));
    assert!(r.authority_mass_ok());
}

#[test]
fn ancient_replay_after_tombstone_eviction() {
    let mut r = Router::new(Limits {
        max_retired: 4,
        ..Limits::default()
    });
    let a = r.accept_peer();
    hello(&mut r, a);
    let (old, _) = r.create_host_pair();
    commit_grant(&mut r, a, old);
    r.on_close(a, old).unwrap();
    assert!(r.is_retired(old));
    for _ in 0..8 {
        let (x, y) = r.create_host_pair();
        commit_grant(&mut r, a, x);
        r.on_close(a, x).unwrap();
        let _ = y;
    }
    // Evicted tombstone becomes unknown, still fail-closed.
    let err = r.on_data(a, data(old, vec![])).unwrap_err();
    assert_eq!(err.0, "unknown endpoint identity");
    assert!(r.holder_of(old).is_none());
}

#[test]
fn property_random_events_conserve_mass() {
    let mut r = Router::new(Limits::default());
    let a = r.accept_peer();
    let b = r.accept_peer();
    hello(&mut r, a);
    hello(&mut r, b);
    for i in 0..200 {
        let (x, y) = r.create_host_pair();
        commit_grant(&mut r, a, x);
        commit_grant(&mut r, b, y);
        match i % 4 {
            0 => {
                let _ = r.on_close(a, x);
            }
            1 => {
                let _ = r.on_data(a, data(x, vec![]));
            }
            2 => {
                let _ = r.on_close(b, y);
            }
            _ => {
                let _ = r.on_close(a, x);
                let _ = r.on_close(b, y);
            }
        }
        assert!(r.authority_mass_ok(), "mass broken at i={i}");
    }
}
