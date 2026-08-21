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
//! - `Data         (2)`: u64 target | u32 corr | u8 natt |
//!                       natt*(u64 id | u64 partner) | payload bytes  both directions
//! - `Close        (3)`: u64 target                                   peer -> host
//! - `ClosedNotify (4)`: u16 count | count*(u64 id | u8 cause)       host -> peer only
//! - `Grant        (5)`: u64 ep | u64 partner                         host -> peer only
//! - `Create       (6)`: u64 impl_ep | u64 transferable_ep            peer -> host only
//! - `Shutdown     (7)`: (empty)                                      either direction

use std::io::Read;

use crate::fabric_error::Cause;
use crate::id::EpId;
use crate::limits::Limits;

pub const KIND_HELLO: u8 = 1;
pub const KIND_DATA: u8 = 2;
pub const KIND_CLOSE: u8 = 3;
pub const KIND_CLOSED_NOTIFY: u8 = 4;
pub const KIND_GRANT: u8 = 5;
pub const KIND_CREATE: u8 = 6;
pub const KIND_SHUTDOWN: u8 = 7;
pub const KIND_CREATE_ACK: u8 = 8;
pub const KIND_ERROR: u8 = 9;

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

/// Payload-bearing routed message body (kept separate so the router can take
/// ownership of fields without destructuring the enum).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DataInner {
    pub target: EpId,
    pub corr: u32,
    pub attachments: Vec<Attachment>,
    pub payload: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Attachment {
    pub id: EpId,
    pub partner: EpId,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Frame {
    Hello { magic: u16, version: u16 },
    Data(DataInner),
    Close { target: EpId },
    ClosedNotify { entries: Vec<(EpId, Cause)> },
    Grant { ep: EpId, partner: EpId },
    Create,
    CreateAck { impl_ep: EpId, transferable_ep: EpId },
    Error(u8),
    Shutdown,
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
        }
    }

    /// Approximate wire cost, used for queue byte accounting.
    pub fn cost(&self) -> usize {
        let body = match self {
            Frame::Hello { .. } => 5,
            Frame::Data(d) => 8 + 4 + 1 + d.attachments.len() * 16 + d.payload.len(),
            Frame::Close { .. } => 8,
            Frame::ClosedNotify { entries } => 2 + entries.len() * 9,
            Frame::Grant { .. } | Frame::CreateAck { .. } => 16,
            Frame::Create => 0,
            Frame::Error(_) => 1,
            Frame::Shutdown => 0,
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
            put_u64(out, d.target.0);
            put_u32(out, d.corr);
            out.push(d.attachments.len() as u8);
            for a in &d.attachments {
                put_u64(out, a.id.0);
                put_u64(out, a.partner.0);
            }
            out.extend_from_slice(&d.payload);
        }
        Frame::Close { target } => put_u64(out, target.0),
        Frame::ClosedNotify { entries } => {
            put_u16(out, entries.len() as u16);
            for (id, cause) in entries {
                put_u64(out, id.0);
                out.push(match cause {
                    Cause::Graceful => 0,
                    Cause::PeerLost => 1,
                });
            }
        }
        Frame::Grant { ep, partner } => {
            put_u64(out, ep.0);
            put_u64(out, partner.0);
        }
        Frame::Create => {}
        Frame::CreateAck { impl_ep, transferable_ep } => {
            put_u64(out, impl_ep.0);
            put_u64(out, transferable_ep.0);
        }
        Frame::Error(code) => {
            out.push(*code);
        }
        Frame::Shutdown => {}
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
            let target = EpId(c.u64v()?);
            let corr = c.u32v()?;
            let natt = c.u8v()? as usize;
            if natt > lim.max_attachments {
                return Err(FrameError::AttachCountExceedsLimit(natt));
            }
            let mut attachments = Vec::with_capacity(natt);
            for _ in 0..natt {
                let id = EpId(c.u64v()?);
                let partner = EpId(c.u64v()?);
                attachments.push(Attachment { id, partner });
            }
            for i in 0..attachments.len() {
                for j in (i + 1)..attachments.len() {
                    if attachments[i].id == attachments[j].id {
                        return Err(FrameError::DuplicateAttachment);
                    }
                }
            }
            let payload = c.rest().to_vec();
            Ok(Frame::Data(DataInner { target, corr, attachments, payload }))
        }
        KIND_CLOSE => Ok(Frame::Close { target: EpId(c.u64v()?) }),
        KIND_CLOSED_NOTIFY => {
            let count = c.u16v()? as usize;
            if count > lim.max_attachments * 256 {
                return Err(FrameError::BodyTooShort); // absurd count for a notify
            }
            let mut entries = Vec::with_capacity(count);
            for _ in 0..count {
                let id = EpId(c.u64v()?);
                let cause = match c.u8v()? {
                    0 => Cause::Graceful,
                    _ => Cause::PeerLost,
                };
                entries.push((id, cause));
            }
            Ok(Frame::ClosedNotify { entries })
        }
        KIND_GRANT => {
            let ep = EpId(c.u64v()?);
            let partner = EpId(c.u64v()?);
            Ok(Frame::Grant { ep, partner })
        }
        KIND_CREATE => Ok(Frame::Create),
        KIND_CREATE_ACK => {
            let impl_ep = EpId(c.u64v()?);
            let transferable_ep = EpId(c.u64v()?);
            Ok(Frame::CreateAck { impl_ep, transferable_ep })
        }
        KIND_ERROR => {
            let code = c.u8v()?;
            Ok(Frame::Error(code))
        }
        KIND_SHUTDOWN => Ok(Frame::Shutdown),
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

    #[test]
    fn roundtrip_all_kinds() {
        let l = lim();
        let frames = vec![
            Frame::Hello { magic: 0x5345, version: 1 },
            Frame::Data(DataInner {
                target: EpId(7),
                corr: 9,
                attachments: vec![Attachment { id: EpId(100), partner: EpId(101) }],
                payload: vec![1, 2, 3],
            }),
            Frame::Close { target: EpId(7) },
            Frame::ClosedNotify {
                entries: vec![(EpId(1), Cause::Graceful), (EpId(2), Cause::PeerLost)],
            },
            Frame::Grant { ep: EpId(10), partner: EpId(11) },
            Frame::Create,
            Frame::CreateAck { impl_ep: EpId(12), transferable_ep: EpId(13) },
            Frame::Error(ERR_CAPACITY),
            Frame::Shutdown,
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
        let l = Limits { max_attachments: 2, ..lim() };
        let mut buf = Vec::new();
        let body_len = 8 + 4 + 1 + 3 * 16;
        buf.extend_from_slice(&((1 + body_len) as u32).to_le_bytes());
        buf.push(KIND_DATA);
        buf.extend_from_slice(&7u64.to_le_bytes());
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf.push(3); // declares 3 > limit 2
        for i in 0..3u64 {
            buf.extend_from_slice(&i.to_le_bytes());
            buf.extend_from_slice(&(i + 50).to_le_bytes());
        }
        assert_eq!(
            decode(&buf, &l),
            Err(FrameError::AttachCountExceedsLimit(3))
        );
    }

    #[test]
    fn duplicate_attachment_rejected() {
        let l = lim();
        let mut buf = Vec::new();
        let body_len = 8 + 4 + 1 + 2 * 16;
        buf.extend_from_slice(&((1 + body_len) as u32).to_le_bytes());
        buf.push(KIND_DATA);
        buf.extend_from_slice(&7u64.to_le_bytes());
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf.push(2);
        for _ in 0..2 {
            buf.extend_from_slice(&99u64.to_le_bytes());
            buf.extend_from_slice(&100u64.to_le_bytes());
        }
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
