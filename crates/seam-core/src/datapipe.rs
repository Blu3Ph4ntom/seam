//! DataPipe — binary record codec, no OS, no async.
//! Records: DATA, CREDIT, CLOSE, CONSUMER_CLOSE.
//! Wire: little-endian, fixed-width, no usize, deterministic.
//! Decoding distinguishes incomplete input (NeedMore) from protocol errors.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecordKind {
    Data = 1,
    Credit = 2,
    Close = 3,
    ConsumerClose = 4,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Record {
    Data(Vec<u8>),
    Credit(u32),
    Close,
    ConsumerClose,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Decoded {
    Complete { record: Record, consumed: usize },
    NeedMore,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CodecError {
    /// payload exceeds configured max
    PayloadTooLarge,
    /// payload longer than u32::MAX
    PayloadNarrowing,
    /// zero credit is invalid
    ZeroCredit,
    /// record kind unsupported
    UnknownKind(u8),
    /// header declares more bytes than data remaining (only when frames are
    /// being decoded from a buffer that must contain the whole record)
    Truncated,
    /// protocol-level malformed input
    Malformed(&'static str),
}

impl std::fmt::Display for CodecError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}
impl std::error::Error for CodecError {}

/// Encode a DATA record, bounded and fallible.
/// Rejects payload > max_data and payload > u32::MAX before allocating output.
pub fn encode_data(payload: &[u8], max_data: usize) -> Result<Vec<u8>, CodecError> {
    if payload.len() > max_data {
        return Err(CodecError::PayloadTooLarge);
    }
    if payload.len() > u32::MAX as usize {
        return Err(CodecError::PayloadNarrowing);
    }
    let mut v = Vec::with_capacity(5 + payload.len());
    v.push(RecordKind::Data as u8);
    v.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    v.extend_from_slice(payload);
    Ok(v)
}

/// Encode a CREDIT record. Zero credit is invalid.
pub fn encode_credit(delta: u32) -> Result<Vec<u8>, CodecError> {
    if delta == 0 {
        return Err(CodecError::ZeroCredit);
    }
    let mut v = Vec::with_capacity(5);
    v.push(RecordKind::Credit as u8);
    v.extend_from_slice(&delta.to_le_bytes());
    Ok(v)
}

pub fn encode_close() -> Vec<u8> {
    vec![RecordKind::Close as u8]
}

pub fn encode_consumer_close() -> Vec<u8> {
    vec![RecordKind::ConsumerClose as u8]
}

/// Canonical single-record parser.
/// Returns NeedMore when the buffer is a prefix of a valid record (normal
/// stream fragmentation), and Err only for genuine protocol violations.
/// First checks kind and bounded length BEFORE any allocation.
pub fn decode_one(buf: &[u8], max_data: usize) -> Result<Decoded, CodecError> {
    if buf.is_empty() {
        return Ok(Decoded::NeedMore);
    }
    match buf[0] {
        1 => {
            // DATA: kind(1) + len(4) + payload(len)
            if buf.len() < 5 {
                return Ok(Decoded::NeedMore);
            }
            let len = u32::from_le_bytes([buf[1], buf[2], buf[3], buf[4]]) as usize;
            if len > max_data {
                return Err(CodecError::PayloadTooLarge);
            }
            if buf.len() < 5 + len {
                return Ok(Decoded::NeedMore);
            }
            Ok(Decoded::Complete {
                record: Record::Data(buf[5..5 + len].to_vec()),
                consumed: 5 + len,
            })
        }
        2 => {
            if buf.len() < 5 {
                return Ok(Decoded::NeedMore);
            }
            let delta = u32::from_le_bytes([buf[1], buf[2], buf[3], buf[4]]);
            if delta == 0 {
                return Err(CodecError::ZeroCredit);
            }
            Ok(Decoded::Complete {
                record: Record::Credit(delta),
                consumed: 5,
            })
        }
        3 => Ok(Decoded::Complete {
            record: Record::Close,
            consumed: 1,
        }),
        4 => Ok(Decoded::Complete {
            record: Record::ConsumerClose,
            consumed: 1,
        }),
        k => Err(CodecError::UnknownKind(k)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn data_roundtrip() {
        let enc = encode_data(b"hello", 1024).unwrap();
        let (rec, n) = match decode_one(&enc, 1024).unwrap() {
            Decoded::Complete { record, consumed } => (record, consumed),
            Decoded::NeedMore => panic!("need more"),
        };
        assert_eq!(rec, Record::Data(b"hello".to_vec()));
        assert_eq!(n, enc.len());
    }

    #[test]
    fn data_too_large_rejected_before_alloc() {
        // encode gate
        assert_eq!(
            encode_data(&[0u8; 11], 10),
            Err(CodecError::PayloadTooLarge)
        );
        // decode gate: hostile declared length
        let mut enc = encode_data(b"x", 10).unwrap();
        enc[1..5].copy_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(decode_one(&enc, 10), Err(CodecError::PayloadTooLarge));
    }

    #[test]
    fn zero_credit_symmetric() {
        assert_eq!(encode_credit(0), Err(CodecError::ZeroCredit));
        let enc = vec![RecordKind::Credit as u8, 0, 0, 0, 0];
        assert_eq!(decode_one(&enc, 10), Err(CodecError::ZeroCredit));
    }

    #[test]
    fn fragmented_is_needmore_not_error() {
        let mut stream = Vec::new();
        stream.extend(encode_data(b"a", 10).unwrap());
        stream.extend(encode_credit(10).unwrap());
        stream.extend(encode_data(b"bc", 10).unwrap());
        stream.extend(encode_close());
        // Feed one byte at a time; pauses at NeedMore, never Err.
        let mut buf = Vec::new();
        let mut records = Vec::new();
        for &b in &stream {
            buf.push(b);
            while let Decoded::Complete { record, consumed } = decode_one(&buf, 10).unwrap() {
                records.push(record);
                buf.drain(..consumed);
                if buf.is_empty() {
                    break;
                }
            }
        }
        assert_eq!(
            records,
            vec![
                Record::Data(b"a".to_vec()),
                Record::Credit(10),
                Record::Data(b"bc".to_vec()),
                Record::Close
            ]
        );
        assert!(buf.is_empty());
    }

    #[test]
    fn partial_credit_and_back_to_back() {
        // 2/3/4-byte DATA header, partial CREDIT
        let stream = {
            let mut s = Vec::new();
            s.extend(encode_close());
            s.extend(encode_credit(7).unwrap());
            s
        };
        // Split: half of first record + one complete + half of next
        let mut buf = Vec::new();
        let mut records = Vec::new();
        for &b in &stream {
            buf.push(b);
            while let Decoded::Complete { record, consumed } = decode_one(&buf, 10).unwrap() {
                records.push(record);
                buf.drain(..consumed);
                if buf.is_empty() {
                    break;
                }
            }
        }
        assert_eq!(records, vec![Record::Close, Record::Credit(7)]);
    }

    #[test]
    fn empty_input_needmore() {
        assert_eq!(decode_one(&[], 10), Ok(Decoded::NeedMore));
    }

    #[test]
    fn unknown_kind_is_error() {
        assert_eq!(decode_one(&[99], 10), Err(CodecError::UnknownKind(99)));
    }

    #[test]
    fn close_and_consumer_close() {
        assert_eq!(
            decode_one(&encode_close(), 10).unwrap(),
            Decoded::Complete {
                record: Record::Close,
                consumed: 1
            }
        );
        assert_eq!(
            decode_one(&encode_consumer_close(), 10).unwrap(),
            Decoded::Complete {
                record: Record::ConsumerClose,
                consumed: 1
            }
        );
    }
}
