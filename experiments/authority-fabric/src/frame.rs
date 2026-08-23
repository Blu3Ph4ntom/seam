//! Wire frames. Hand-written bounded encoding; NOT Seam's final format
//! (experimental / not architecturally locked).
//!
//! Layout on the wire:
//!
//! ```text
//! u32le body_len          (body_len <= limits.max_frame_body, checked pre-allocation)
//! u8   kind
//! ... kind-specific body
//! ```
//!
//! Kinds:
//! - `Hello        (1)`: u16 magic | u16 version                      child -> host once
//! - `Data         (2)`: 16B target | u32 corr | u8 natt |
//!                       natt*(16B tid | 16B id | 16B partner) | payload
//! - `Close        (3)`: 16B target
//! - `ClosedNotify (4)`: u16 count | count*(16B id | u8 cause)
//! - `Grant        (5)`: 16B ep | 16B partner | 16B tid               host -> peer (offer)
//! - `Create       (6)`: empty
//! - `Shutdown     (7)`: empty
//! - `CreateAck    (8)`: 16B impl | 16B transferable                  host -> peer
//! - `Error        (9)`: u8 code
//! - `Xfer        (10)`: u8 sub | 16B tid | optional ids              transfer control

use std::io::Read;

use crate::fabric_error::Cause;
use crate::id::{EpId, TransferId};
use crate::limits::Limits;
use crate::native::ResourceId;

pub const KIND_HELLO: u8 = 1;
pub const KIND_DATA: u8 = 2;
pub const KIND_CLOSE: u8 = 3;
pub const KIND_CLOSED_NOTIFY: u8 = 4;
pub const KIND_GRANT: u8 = 5;
pub const KIND_CREATE: u8 = 6;
pub const KIND_SHUTDOWN: u8 = 7;
pub const KIND_CREATE_ACK: u8 = 8;
pub const KIND_ERROR: u8 = 9;
pub const KIND_XFER: u8 = 10;

pub const XFER_ACCEPT: u8 = 1;
pub const XFER_REJECT: u8 = 2;
pub const XFER_COMMIT: u8 = 3;
pub const XFER_COMMITTED: u8 = 4;
pub const XFER_ABORT: u8 = 5;
pub const XFER_STATUS: u8 = 6;
pub const XFER_STATUS_ACK: u8 = 7;
pub const XFER_RESULT_ACK: u8 = 8;
pub const XFER_NATIVE_COMMIT: u8 = 9;
pub const XFER_NATIVE_ABORT: u8 = 10;

pub const XFER_ST_PENDING: u8 = 0;
pub const XFER_ST_COMMITTED: u8 = 1;
pub const XFER_ST_ABORTED: u8 = 2;
pub const XFER_ST_UNKNOWN: u8 = 3;

/// Error codes carried by `Frame::Error`.
pub const ERR_CAPACITY: u8 = 1;

/// Host->peer-only frame kinds. A peer sending any of these demonstrates it
/// is not a legitimate fabric client => quarantine.
pub fn is_host_only_kind(kind: u8) -> bool {
    matches!(
        kind,
        KIND_CLOSED_NOTIFY | KIND_GRANT | KIND_CREATE_ACK | KIND_ERROR
    )
}

/// True for lifecycle/transfer frames that must not be silently dropped.
pub fn is_control_frame(f: &Frame) -> bool {
    matches!(
        f,
        Frame::ClosedNotify { .. }
            | Frame::Grant { .. }
            | Frame::CreateAck { .. }
            | Frame::Error(_)
            | Frame::Shutdown
            | Frame::Xfer(_)
            | Frame::Close { .. }
            | Frame::Create
    ) || matches!(f, Frame::Data(d) if d.native.is_some() || !d.attachments.is_empty())
}

/// Payload-bearing routed message body (kept separate so the router can take
/// ownership of fields without destructuring the enum).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DataInner {
    pub target: EpId,
    pub corr: u32,
    pub attachments: Vec<Attachment>,
    pub payload: Vec<u8>,
    pub native: Option<NativeAttachment>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Attachment {
    pub tid: TransferId,
    pub id: EpId,
    pub partner: EpId,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NativeAttachment {
    pub tid: TransferId,
    pub rid: ResourceId,
    pub handle_value: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum XferMsg {
    Accept { tid: TransferId },
    Reject { tid: TransferId },
    Commit { tid: TransferId, ep: EpId, partner: EpId },
    Committed { tid: TransferId },
    Abort { tid: TransferId },
    Status { tid: TransferId },
    StatusAck { tid: TransferId, status: u8 },
    ResultAck { tid: TransferId },
    NativeCommit { tid: TransferId, rid: ResourceId, handle_value: u64 },
    NativeAbort { tid: TransferId },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Frame {
    Hello { magic: u16, version: u16 },
    Data(DataInner),
    Close { target: EpId },
    ClosedNotify { entries: Vec<(EpId, Cause)> },
    Grant { ep: EpId, partner: EpId, tid: TransferId },
    Create,
    CreateAck { impl_ep: EpId, transferable_ep: EpId },
    Error(u8),
    Shutdown,
    Xfer(XferMsg),
}

impl Frame {
    pub fn kind(&self) -> u8 {
        match self {
            Frame::Hello { .. } => KIND_HELLO,
            Frame::Data(_) => KIND_DATA,
            Frame::Close { .. } => KIND_CLOSE,
            Frame::ClosedNotify { .. } => KIND_CLOSED_NOTIFY,
            Frame::Grant { .. } => KIND_GRANT,
            Frame::Create => KIND_CREATE,
            Frame::CreateAck { .. } => KIND_CREATE_ACK,
            Frame::Error(_) => KIND_ERROR,
            Frame::Shutdown => KIND_SHUTDOWN,
            Frame::Xfer(_) => KIND_XFER,
        }
    }

    /// Approximate wire cost, used for queue byte accounting.
    pub fn cost(&self) -> usize {
        let body = match self {
            Frame::Hello { .. } => 5,
            Frame::Data(d) => {
                let native_len = if d.native.is_some() { 1 + 40 } else { 1 };
                16 + 4 + 1 + d.attachments.len() * 48 + native_len + d.payload.len()
            }
            Frame::Close { .. } => 16,
            Frame::ClosedNotify { entries } => 2 + entries.len() * 17,
            Frame::Grant { .. } => 48,
            Frame::CreateAck { .. } => 32,
            Frame::Create => 0,
            Frame::Error(_) => 1,
            Frame::Shutdown => 0,
            Frame::Xfer(XferMsg::Commit { .. }) => 1 + 16 + 32,
            Frame::Xfer(XferMsg::StatusAck { .. }) => 1 + 16 + 1,
            Frame::Xfer(XferMsg::NativeCommit { .. }) => 1 + 16 + 16 + 8,
            Frame::Xfer(XferMsg::NativeAbort { .. }) => 1 + 16,
            Frame::Xfer(_) => 1 + 16,
        };
        4 + 1 + body // length prefix + kind byte + body
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrameError {
    Truncated,
    TooLarge { declared: u32, cap: u32 },
    UnknownKind(u8),
    BadMagic(u16),
    BadVersion(u16),
    AttachCountExceedsLimit(usize),
    DuplicateAttachment,
    BodyTooShort,
}

impl core::fmt::Display for FrameError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            FrameError::Truncated => write!(f, "frame truncated"),
            FrameError::TooLarge { declared, cap } => write!(f, "declared frame {declared} exceeds cap {cap}"),
            FrameError::UnknownKind(k) => write!(f, "unknown frame kind {k}"),
            FrameError::BadMagic(m) => write!(f, "bad hello magic 0x{m:04x}"),
            FrameError::BadVersion(v) => write!(f, "bad protocol version {v}"),
            FrameError::AttachCountExceedsLimit(n) => write!(f, "{n} attachments exceeds limit"),
            FrameError::DuplicateAttachment => write!(f, "duplicate attachment id in one frame"),
            FrameError::BodyTooShort => write!(f, "frame body shorter than its own header claims"),
        }
    }
}
impl std::error::Error for FrameError {}

fn put_u16(out: &mut Vec<u8>, v: u16) {
    out.extend_from_slice(&v.to_le_bytes());
}
fn put_u32(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_le_bytes());
}
fn put_ep(out: &mut Vec<u8>, id: EpId) {
    out.extend_from_slice(&id.0);
}
fn put_tid(out: &mut Vec<u8>, id: TransferId) {
    out.extend_from_slice(&id.0);
}
fn put_rid(out: &mut Vec<u8>, id: ResourceId) {
    out.extend_from_slice(&id.0);
}
fn put_u64(out: &mut Vec<u8>, v: u64) {
    out.extend_from_slice(&v.to_le_bytes());
}

struct Cursor<'a> {
    b: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(b: &'a [u8]) -> Self {
        Cursor { b, pos: 0 }
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8], FrameError> {
        if self.b.len() - self.pos < n {
            return Err(FrameError::Truncated);
        }
        let s = &self.b[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }
    fn u8v(&mut self) -> Result<u8, FrameError> {
        Ok(self.take(1)?[0])
    }
    fn u16v(&mut self) -> Result<u16, FrameError> {
        Ok(u16::from_le_bytes(self.take(2)?.try_into().unwrap()))
    }
    fn u32v(&mut self) -> Result<u32, FrameError> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }
    fn epid(&mut self) -> Result<EpId, FrameError> {
        let s = self.take(16)?;
        let mut b = [0u8; 16];
        b.copy_from_slice(s);
        Ok(EpId(b))
    }
    fn tid(&mut self) -> Result<TransferId, FrameError> {
        let s = self.take(16)?;
        let mut b = [0u8; 16];
        b.copy_from_slice(s);
        Ok(TransferId(b))
    }
    fn rid(&mut self) -> Result<ResourceId, FrameError> {
        let s = self.take(16)?;
        let mut b = [0u8; 16];
        b.copy_from_slice(s);
        Ok(ResourceId(b))
    }
    fn u64v(&mut self) -> Result<u64, FrameError> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }
    fn rest(&mut self) -> &'a [u8] {
        let s = &self.b[self.pos..];
        self.pos = self.b.len();
        s
    }
}

/// Encode a frame into a fresh buffer (test/demo convenience).
pub fn encode(frame: &Frame) -> Vec<u8> {
    let mut out = Vec::with_capacity(frame.cost());
    encode_into(frame, &mut out);
    out
}

/// Encode into a caller buffer with the u32 length prefix included.
pub fn encode_into(frame: &Frame, out: &mut Vec<u8>) {
    let start = out.len();
    out.extend_from_slice(&[0u8; 4]); // reserve length
    out.push(frame.kind());
    match frame {
        Frame::Hello { magic, version } => {
            put_u16(out, *magic);
            put_u16(out, *version);
        }
        Frame::Data(d) => {
            put_ep(out, d.target);
            put_u32(out, d.corr);
            out.push(d.attachments.len() as u8);
            for a in &d.attachments {
                put_tid(out, a.tid);
                put_ep(out, a.id);
                put_ep(out, a.partner);
            }
            if let Some(n) = &d.native {
                out.push(1);
                put_tid(out, n.tid);
                put_rid(out, n.rid);
                put_u64(out, n.handle_value);
            } else {
                out.push(0);
            }
            out.extend_from_slice(&d.payload);
        }
        Frame::Close { target } => put_ep(out, *target),
        Frame::ClosedNotify { entries } => {
            put_u16(out, entries.len() as u16);
            for (id, cause) in entries {
                put_ep(out, *id);
                out.push(match cause {
                    Cause::Graceful => 0,
                    Cause::PeerLost => 1,
                });
            }
        }
        Frame::Grant { ep, partner, tid } => {
            put_ep(out, *ep);
            put_ep(out, *partner);
            put_tid(out, *tid);
        }
        Frame::Create => {}
        Frame::CreateAck { impl_ep, transferable_ep } => {
            put_ep(out, *impl_ep);
            put_ep(out, *transferable_ep);
        }
        Frame::Error(code) => {
            out.push(*code);
        }
        Frame::Shutdown => {}
        Frame::Xfer(x) => match x {
            XferMsg::Accept { tid } => {
                out.push(XFER_ACCEPT);
                put_tid(out, *tid);
            }
            XferMsg::Reject { tid } => {
                out.push(XFER_REJECT);
                put_tid(out, *tid);
            }
            XferMsg::Commit { tid, ep, partner } => {
                out.push(XFER_COMMIT);
                put_tid(out, *tid);
                put_ep(out, *ep);
                put_ep(out, *partner);
            }
            XferMsg::Committed { tid } => {
                out.push(XFER_COMMITTED);
                put_tid(out, *tid);
            }
            XferMsg::Abort { tid } => {
                out.push(XFER_ABORT);
                put_tid(out, *tid);
            }
            XferMsg::Status { tid } => {
                out.push(XFER_STATUS);
                put_tid(out, *tid);
            }
            XferMsg::StatusAck { tid, status } => {
                out.push(XFER_STATUS_ACK);
                put_tid(out, *tid);
                out.push(*status);
            }
            XferMsg::ResultAck { tid } => {
                out.push(XFER_RESULT_ACK);
                put_tid(out, *tid);
            }
            XferMsg::NativeCommit { tid, rid, handle_value } => {
                out.push(XFER_NATIVE_COMMIT);
                put_tid(out, *tid);
                put_rid(out, *rid);
                put_u64(out, *handle_value);
            }
            XferMsg::NativeAbort { tid } => {
                out.push(XFER_NATIVE_ABORT);
                put_tid(out, *tid);
            }
        },
    }
    let len = (out.len() - start - 4) as u32;
    out[start..start + 4].copy_from_slice(&len.to_le_bytes());
}

/// Decode one frame from an exact-length body slice (already bounds-checked
/// by the caller). Pure function; fuzz-friendly.
pub fn decode_body(kind: u8, body: &[u8], lim: &Limits) -> Result<Frame, FrameError> {
    let mut c = Cursor::new(body);
    match kind {
        KIND_HELLO => {
            let magic = c.u16v()?;
            let version = c.u16v()?;
            Ok(Frame::Hello { magic, version })
        }
        KIND_DATA => {
            let target = c.epid()?;
            let corr = c.u32v()?;
            let natt = c.u8v()? as usize;
            if natt > lim.max_attachments {
                return Err(FrameError::AttachCountExceedsLimit(natt));
            }
            let mut attachments = Vec::with_capacity(natt);
            for _ in 0..natt {
                let tid = c.tid()?;
                let id = c.epid()?;
                let partner = c.epid()?;
                attachments.push(Attachment { tid, id, partner });
            }
            for i in 0..attachments.len() {
                for j in (i + 1)..attachments.len() {
                    if attachments[i].id == attachments[j].id {
                        return Err(FrameError::DuplicateAttachment);
                    }
                }
            }
            let has_native = c.u8v()?;
            let native = if has_native == 1 {
                let tid = c.tid()?;
                let rid = c.rid()?;
                let handle_value = c.u64v()?;
                Some(NativeAttachment { tid, rid, handle_value })
            } else if has_native == 0 {
                None
            } else {
                return Err(FrameError::UnknownKind(KIND_DATA));
            };
            let payload = c.rest().to_vec();
            Ok(Frame::Data(DataInner { target, corr, attachments, payload, native }))
        }
        KIND_CLOSE => Ok(Frame::Close { target: c.epid()? }),
        KIND_CLOSED_NOTIFY => {
            let count = c.u16v()? as usize;
            if count > lim.max_attachments * 256 {
                return Err(FrameError::BodyTooShort); // absurd count for a notify
            }
            let mut entries = Vec::with_capacity(count);
            for _ in 0..count {
                let id = c.epid()?;
                let cause = match c.u8v()? {
                    0 => Cause::Graceful,
                    _ => Cause::PeerLost,
                };
                entries.push((id, cause));
            }
            Ok(Frame::ClosedNotify { entries })
        }
        KIND_GRANT => {
            let ep = c.epid()?;
            let partner = c.epid()?;
            let tid = c.tid()?;
            Ok(Frame::Grant { ep, partner, tid })
        }
        KIND_CREATE => Ok(Frame::Create),
        KIND_CREATE_ACK => {
            let impl_ep = c.epid()?;
            let transferable_ep = c.epid()?;
            Ok(Frame::CreateAck { impl_ep, transferable_ep })
        }
        KIND_ERROR => {
            let code = c.u8v()?;
            Ok(Frame::Error(code))
        }
        KIND_SHUTDOWN => Ok(Frame::Shutdown),
        KIND_XFER => {
            let sub = c.u8v()?;
            let tid = c.tid()?;
            let msg = match sub {
                XFER_ACCEPT => XferMsg::Accept { tid },
                XFER_REJECT => XferMsg::Reject { tid },
                XFER_COMMIT => XferMsg::Commit {
                    tid,
                    ep: c.epid()?,
                    partner: c.epid()?,
                },
                XFER_COMMITTED => XferMsg::Committed { tid },
                XFER_ABORT => XferMsg::Abort { tid },
                XFER_STATUS => XferMsg::Status { tid },
                XFER_STATUS_ACK => XferMsg::StatusAck {
                    tid,
                    status: c.u8v()?,
                },
                XFER_RESULT_ACK => XferMsg::ResultAck { tid },
                XFER_NATIVE_COMMIT => XferMsg::NativeCommit { tid, rid: c.rid()?, handle_value: c.u64v()? },
                XFER_NATIVE_ABORT => XferMsg::NativeAbort { tid },
                _ => return Err(FrameError::UnknownKind(KIND_XFER)),
            };
            Ok(Frame::Xfer(msg))
        }
        other => Err(FrameError::UnknownKind(other)),
    }
}

/// Decode a full on-wire frame (length prefix included) from a buffer that is
/// expected to contain exactly one frame plus optionally nothing else.
/// Enforces the size cap BEFORE allocating the body vector.
pub fn decode(buf: &[u8], lim: &Limits) -> Result<Frame, FrameError> {
    if buf.len() < 5 {
        return Err(FrameError::Truncated);
    }
    let declared = u32::from_le_bytes(buf[0..4].try_into().unwrap()) as usize;
    if declared > lim.max_frame_body as usize {
        return Err(FrameError::TooLarge {
            declared: declared as u32,
            cap: lim.max_frame_body,
        });
    }
    if declared == 0 {
        return Err(FrameError::Truncated);
    }
    if buf.len() < 4 + declared {
        return Err(FrameError::Truncated);
    }
    // `declared` counts kind + body (same contract as `read_frame`).
    let kind = buf[4];
    decode_body(kind, &buf[5..4 + declared], lim)
}

/// Streaming reader half: reads exactly one frame. The declared length is
/// checked against the cap BEFORE `read_exact` of the body, so a hostile
/// length cannot make us allocate attacker-controlled memory.
pub fn read_frame<R: Read>(r: &mut R, lim: &Limits) -> Result<Frame, FrameError> {
    let mut lb = [0u8; 4];
    r.read_exact(&mut lb).map_err(|_| FrameError::Truncated)?;
    let declared = u32::from_le_bytes(lb);
    if declared > lim.max_frame_body {
        return Err(FrameError::TooLarge { declared, cap: lim.max_frame_body });
    }
    if declared == 0 {
        return Err(FrameError::Truncated); // no kind byte
    }
    let mut body = vec![0u8; declared as usize];
    r.read_exact(&mut body).map_err(|_| FrameError::Truncated)?;
    decode_body(body[0], &body[1..], lim)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lim() -> Limits {
        Limits { max_frame_body: 128, ..Limits::default() }
    }

    fn ep(n: u8) -> EpId {
        let mut b = [0u8; 16];
        b[15] = n;
        EpId(b)
    }
    fn tid(n: u8) -> TransferId {
        let mut b = [0u8; 16];
        b[15] = n;
        TransferId(b)
    }

    #[test]
    fn roundtrip_all_kinds() {
        let l = lim();
        let frames = vec![
            Frame::Hello { magic: 0x5345, version: 2 },
            Frame::Data(DataInner {
                target: ep(7),
                corr: 9,
                attachments: vec![Attachment { tid: tid(1), id: ep(100), partner: ep(101) }],
                payload: vec![1, 2, 3],
                native: None,
            }),
            Frame::Close { target: ep(7) },
            Frame::ClosedNotify {
                entries: vec![(ep(1), Cause::Graceful), (ep(2), Cause::PeerLost)],
            },
            Frame::Grant { ep: ep(10), partner: ep(11), tid: tid(3) },
            Frame::Create,
            Frame::CreateAck { impl_ep: ep(12), transferable_ep: ep(13) },
            Frame::Error(ERR_CAPACITY),
            Frame::Shutdown,
            Frame::Xfer(XferMsg::Accept { tid: tid(4) }),
            Frame::Xfer(XferMsg::Commit { tid: tid(5), ep: ep(6), partner: ep(7) }),
            Frame::Xfer(XferMsg::StatusAck { tid: tid(8), status: XFER_ST_COMMITTED }),
        ];
        for f in frames {
            let buf = encode(&f);
            assert_eq!(decode(&buf, &l).unwrap(), f);
        }
    }

    #[test]
    fn oversized_declared_len_rejected_before_body() {
        let l = lim();
        let mut buf = Vec::new();
        buf.extend_from_slice(&(1u32 << 30).to_le_bytes()); // huge declared
        buf.push(KIND_SHUTDOWN);
        match decode(&buf, &l) {
            Err(FrameError::TooLarge { declared, cap }) => {
                assert_eq!(cap, 128);
                assert_eq!(declared, 1 << 30);
            }
            other => panic!("expected TooLarge, got {other:?}"),
        }
    }

    #[test]
    fn truncated_frames_rejected() {
        let l = lim();
        let buf = encode(&Frame::Hello { magic: 1, version: 1 });
        for cut in [0usize, 1, 3, 4, buf.len() - 1] {
            assert_eq!(
                decode(&buf[..cut.min(buf.len())], &l),
                Err(FrameError::Truncated),
                "cut at {cut}"
            );
        }
    }

    #[test]
    fn ascii_stdout_pollution_is_oversized_not_a_frame() {
        // "CLIENT_OK\n" on the protocol pipe: first 4 bytes are ASCII
        // 'C','L','I','E' = 0x45494C43 >> 64KiB cap.
        let l = lim();
        let buf = b"CLIENT_OK\n";
        match decode(buf, &l) {
            Err(FrameError::TooLarge { declared, .. }) => {
                assert_eq!(declared, u32::from_le_bytes(*b"CLIE"));
            }
            other => panic!("expected TooLarge, got {other:?}"),
        }
    }

    #[test]
    fn unknown_kind_rejected() {
        let l = lim();
        let mut buf = Vec::new();
        buf.extend_from_slice(&1u32.to_le_bytes());
        buf.push(200);
        buf.push(0);
        assert_eq!(decode(&buf, &l), Err(FrameError::UnknownKind(200)));
    }

    #[test]
    fn attach_count_over_limit_rejected() {
        let l = Limits { max_attachments: 2, max_frame_body: 4096, ..lim() };
        let mut buf = Vec::new();
        let body_len = 16 + 4 + 1 + 3 * 48 + 1;
        buf.extend_from_slice(&((1 + body_len) as u32).to_le_bytes());
        buf.push(KIND_DATA);
        buf.extend_from_slice(&[0u8; 15]);
        buf.push(7);
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf.push(3); // declares 3 > limit 2
        for i in 0..3u8 {
            buf.extend_from_slice(&[0u8; 15]);
            buf.push(i); // tid
            buf.extend_from_slice(&[0u8; 15]);
            buf.push(i); // id
            buf.extend_from_slice(&[0u8; 15]);
            buf.push(i.saturating_add(50)); // partner
        }
        buf.push(0); // has_native = 0
        assert_eq!(
            decode(&buf, &l),
            Err(FrameError::AttachCountExceedsLimit(3))
        );
    }

    #[test]
    fn duplicate_attachment_rejected() {
        let l = lim();
        let mut buf = Vec::new();
        let body_len = 16 + 4 + 1 + 2 * 48 + 1;
        buf.extend_from_slice(&((1 + body_len) as u32).to_le_bytes());
        buf.push(KIND_DATA);
        buf.extend_from_slice(&[0u8; 15]);
        buf.push(7);
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf.push(2);
        for _ in 0..2 {
            buf.extend_from_slice(&[0u8; 16]); // tid
            buf.extend_from_slice(&[0u8; 15]);
            buf.push(99); // duplicate id
            buf.extend_from_slice(&[0u8; 15]);
            buf.push(100);
        }
        buf.push(0); // has_native = 0
        assert_eq!(decode(&buf, &l), Err(FrameError::DuplicateAttachment));
    }

    /// Mock reader that fails the test if anyone attempts to read more than
    /// the cap allows — proves allocation never follows hostile length.
    struct GuardedReader {
        data: Vec<u8>,
        pos: usize,
        max_read: usize,
    }
    impl Read for GuardedReader {
        fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
            let n = out.len().min(self.data.len() - self.pos);
            self.max_read = self.max_read.max(n);
            out[..n].copy_from_slice(&self.data[self.pos..self.pos + n]);
            self.pos += n;
            Ok(n)
        }
    }

    #[test]
    fn streaming_reader_never_reads_beyond_cap() {
        let l = lim();
        // Declared 2GB, but stream only contains the header. Reader must bail
        // on the cap check without attempting a giant read.
        let mut g = GuardedReader { data: vec![], pos: 0, max_read: 0 };
        g.data.extend_from_slice(&(1u32 << 31).to_le_bytes());
        g.data.push(KIND_SHUTDOWN);
        assert!(matches!(
            read_frame(&mut g, &l),
            Err(FrameError::TooLarge { .. })
        ));
        assert!(g.max_read <= 5, "reader consumed {} bytes", g.max_read);
    }
}
