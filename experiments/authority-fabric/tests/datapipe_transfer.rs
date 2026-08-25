//! DataPipe endpoint transfer semantics over the semantic core.
//!
//! Producer and Consumer authorities MOVE between owners (threads here
//! stand in for peers; the authority object is identical). The stream must
//! continue exactly: prefix || suffix || EOF on the same PipeId, credit /
//! unread-position state carried inside the moved endpoint, abort restores,
//! and the Host-side PipeTable joins commits order-independently with no
//! duplicate mint.

use std::thread;

use authority_fabric::data_pipe::registry::{PipeRole, PipeTable};
use authority_fabric::data_pipe::Producer;
use authority_fabric::id::TransferId;
use authority_fabric::router::PeerId;

fn tid(n: u8) -> TransferId {
    TransferId([n; 16])
}

#[test]
fn producer_transfer_stream_continues_prefix_then_suffix() {
    let (mut p, mut c) = Producer::new(4096).unwrap();
    let id = p.id();
    let cap = p.capacity();

    // A writes a prefix, then transfers the Producer away.
    p.write(b"PREFIX-").unwrap();
    let mut c2 = thread::spawn(move || {
        // Recipient B continues the SAME stream and closes orderly.
        p.write(b"SUFFIX").unwrap();
        p.close_write();
        p.id()
    })
    .join()
    .unwrap();
    assert_eq!(id, c2);
    c2 = id;

    // C observes prefix || suffix || EOF, nothing replayed or lost.
    let mut got = Vec::new();
    loop {
        let mut buf = [0u8; 64];
        let n = c.read(&mut buf).unwrap();
        if n == 0 {
            break;
        }
        got.extend_from_slice(&buf[..n]);
    }
    assert_eq!(got, b"PREFIX-SUFFIX");
    assert_eq!(cap, 4096);
}

#[test]
fn consumer_transfer_resumes_at_exact_unread_position() {
    let (mut p, mut c) = Producer::new(1024).unwrap();
    p.write(b"0123456789").unwrap();

    // A consumes a partial prefix, then moves the Consumer mid-stream.
    let mut head = [0u8; 4];
    c.read(&mut head).unwrap();
    assert_eq!(&head, b"0123");

    thread::spawn(move || {
        // Producer keeps writing while ownership is in flight; buffered
        // bytes belong to the pipe, not to any holder snapshot.
        p.write(b"ABCDEF").unwrap();
        p.close_write();
    })
    .join()
    .unwrap();

    let rest = thread::spawn(move || {
        // B resumes at the exact unread next byte: no replay of "0123".
        let mut out = Vec::new();
        loop {
            let mut buf = [0u8; 8];
            let n = c.read(&mut buf).unwrap();
            if n == 0 {
                break;
            }
            out.extend_from_slice(&buf[..n]);
        }
        out
    })
    .join()
    .unwrap();
    assert_eq!(rest, b"456789ABCDEF");
}

#[test]
fn registry_abort_restores_and_sender_continues() {
    let mut table = PipeTable::new();
    let (mut p, mut c) = Producer::new(512).unwrap();
    let pid = p.id();
    table.create(pid, 512, PeerId(1), PeerId(2)).unwrap();

    p.write(b"before-").unwrap();

    // Escrow A->B, then the recipient fails pre-commit: abort restores A.
    table
        .offer_transfer(&pid, PipeRole::Producer, tid(1), PeerId(1), PeerId(3))
        .unwrap();
    assert_eq!(table.producer_holder(&pid), None);
    table
        .abort_transfer(PipeRole::Producer, tid(1), PeerId(1))
        .unwrap();
    assert_eq!(table.producer_holder(&pid), Some(PeerId(1)));

    // Restored A continues the same stream unchanged, then closes orderly.
    p.write(b"after").unwrap();
    p.close_write();

    let mut got = Vec::new();
    loop {
        let mut buf = [0u8; 32];
        let n = c.read(&mut buf).unwrap();
        if n == 0 {
            break;
        }
        got.extend_from_slice(&buf[..n]);
    }
    assert_eq!(got, b"before-after");
}

#[test]
fn registry_commit_join_is_order_independent_single_mint() {
    let mut table = PipeTable::new();
    let pid = authority_fabric::data_pipe::PipeId([9u8; 16]);
    table.create(pid, 64, PeerId(1), PeerId(2)).unwrap();
    table
        .offer_transfer(&pid, PipeRole::Consumer, tid(3), PeerId(2), PeerId(5))
        .unwrap();
    table
        .offer_transfer(&pid, PipeRole::Producer, tid(4), PeerId(1), PeerId(4))
        .unwrap();
    // Reverse-order commit of both arcs mints each authority exactly once.
    table.commit_transfer(PipeRole::Consumer, tid(3)).unwrap();
    table.commit_transfer(PipeRole::Producer, tid(4)).unwrap();
    assert_eq!(
        (table.producer_holder(&pid), table.consumer_holder(&pid)),
        (Some(PeerId(4)), Some(PeerId(5)))
    );
}

#[test]
fn registry_10k_churn_bounded() {
    // 10,000 full create -> offer -> commit -> retire arcs. Table size,
    // retirement ledger, and authority count must stay bounded throughout;
    // no state may grow with cycle count.
    let mut table = PipeTable::new();
    for i in 0..10_000u32 {
        let mut b = [0u8; 16];
        b[..4].copy_from_slice(&i.to_be_bytes());
        let pid = authority_fabric::data_pipe::PipeId(b);
        table.create(pid, 64, PeerId(1), PeerId(2)).unwrap();
        assert_eq!(table.live(), 1);
        table
            .offer_transfer(
                &pid,
                PipeRole::Producer,
                tid((i % 251) as u8 + 1),
                PeerId(1),
                PeerId(7),
            )
            .unwrap();
        assert_eq!(table.producer_holder(&pid), None);
        assert_eq!(
            table.commit_transfer(PipeRole::Producer, tid((i % 251) as u8 + 1)),
            Ok(pid)
        );
        assert_eq!(table.producer_holder(&pid), Some(PeerId(7)));
        table.retire(&pid, PeerId(7)).unwrap();
        assert_eq!(table.live(), 0);
        assert!(table.retired_len() <= authority_fabric::data_pipe::PIPE_RETIRE_CAP);
    }
}
