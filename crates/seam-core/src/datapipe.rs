//! DataPipe — binary record codec, no OS, no async.
//! Records: DATA, CREDIT, CLOSE, CONSUMER_CLOSE. Bounded, no Alloc before check.
//! Wire: little-endian, fixed width, no usize, deterministic.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
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
pub struct DataRecord {
    pub payload: Vec<u8>,
}

pub fn encode_data(payload: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(1 + 4 + payload.len());
    v.push(RecordKind::Data as u8);
    v.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    v.extend_from_slice(payload);
    v
}

pub fn encode_credit(delta: u32) -> Vec<u8> {
    let mut v = Vec::with_capacity(5);
    v.push(RecordKind::Credit as u8);
    v.extend_from_slice(&delta.to_le_bytes());
    v
}

pub fn encode_close() -> Vec<u8> {
    vec![RecordKind::Close as u8]
}

pub fn encode_consumer_close() -> Vec<u8> {
    vec![RecordKind::ConsumerClose as u8]
}

pub fn decode_data(buf: &[u8], max: usize) -> Result<(DataRecord, usize), &'static str> {
    if buf.is_empty() {
        return Err("empty");
    }
    if buf[0] != RecordKind::Data as u8 {
        return Err("not data");
    }
    if buf.len() < 5 {
        return Err("truncated header");
    }
    let len = u32::from_le_bytes([buf[1], buf[2], buf[3], buf[4]]) as usize;
    if len > max {
        return Err("too large");
    }
    if buf.len() < 5 + len {
        return Err("truncated body");
    }
    Ok((
        DataRecord {
            payload: buf[5..5 + len].to_vec(),
        },
        5 + len,
    ))
}

/// Decode next record from a byte stream, handling fragmentation and multiple records.
/// Returns (Record, consumed_bytes) or Err. Caller advances buf by consumed_bytes.
/// Unknown kind, truncated, oversized all Err before allocation.
/// No assumption one write == one read.
/// No unbounded allocation.
pub fn decode_next(buf: &[u8], max_data: usize) -> Result<(Record, usize), &'static str> {
    if buf.is_empty() {
        return Err("empty");
    }
    match buf[0] {
        1 => {
            if buf.len() < 5 {
                return Err("truncated header");
            }
            let len = u32::from_le_bytes([buf[1], buf[2], buf[3], buf[4]]) as usize;
            if len > max_data {
                return Err("too large");
            }
            if buf.len() < 5 + len {
                return Err("truncated body");
            }
            Ok((Record::Data(buf[5..5 + len].to_vec()), 5 + len))
        }
        2 => {
            if buf.len() < 5 {
                return Err("truncated header");
            }
            let delta = u32::from_le_bytes([buf[1], buf[2], buf[3], buf[4]]);
            if delta == 0 {
                return Err("zero credit");
            }
            Ok((Record::Credit(delta), 5))
        }
        3 => Ok((Record::Close, 1)),
        4 => Ok((Record::ConsumerClose, 1)),
        _ => Err("unknown kind"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn data_roundtrip() {
        let p = b"hello";
        let enc = encode_data(p);
        let (dec, n) = decode_data(&enc, 1024).unwrap();
        assert_eq!(dec.payload, p);
        assert_eq!(n, enc.len());
    }

    #[test]
    fn data_too_large_rejected_before_alloc() {
        let mut enc = encode_data(b"x");
        enc[1..5].copy_from_slice(&(1_000_000u32).to_le_bytes());
        assert_eq!(decode_data(&enc, 10), Err("too large"));
    }

    #[test]
    fn truncated_rejected() {
        let enc = encode_data(b"hello");
        assert_eq!(decode_data(&enc[..3], 1024), Err("truncated header"));
        assert_eq!(decode_data(&enc[..5], 1024), Err("truncated body"));
    }

    #[test]
    fn credit_roundtrip() {
        let enc = encode_credit(42);
        let (rec, n) = decode_next(&enc, 1024).unwrap();
        assert_eq!(rec, Record::Credit(42));
        assert_eq!(n, 5);
    }

    #[test]
    fn close_roundtrip() {
        assert_eq!(decode_next(&encode_close(), 1024).unwrap().0, Record::Close);
        assert_eq!(
            decode_next(&encode_consumer_close(), 1024).unwrap().0,
            Record::ConsumerClose
        );
    }

    #[test]
    fn fragmented_and_back_to_back() {
        let mut stream = Vec::new();
        stream.extend(encode_data(b"a"));
        stream.extend(encode_credit(10));
        stream.extend(encode_data(b"bc"));
        stream.extend(encode_close());
        // Fragmented reads: 1 byte at a time
        let mut buf = Vec::new();
        let mut pos = 0;
        let mut records = Vec::new();
        while pos < stream.len() {
            // Simulate fragmented delivery: add 1..3 bytes per iteration
            let chunk = std::cmp::min(1 + (pos % 3), stream.len() - pos);
            buf.extend_from_slice(&stream[pos..pos + chunk]);
            pos += chunk;
            loop {
                match decode_next(&buf, 1024) {
                    Ok((rec, consumed)) => {
                        records.push(rec);
                        buf.drain(..consumed);
                    }
                    Err(e) if e == "truncated header" || e == "truncated body" => break,
                    Err(e) => panic!("unexpected {e}"),
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
    }

    #[test]
    fn hostile_unknown_kind() {
        assert_eq!(decode_next(&[99], 1024), Err("unknown kind"));
    }

    #[test]
    fn hostile_oversized_before_alloc() {
        let mut enc = encode_data(b"x");
        enc[1..5].copy_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(decode_next(&enc, 10), Err("too large"));
    }
}
