//! DataPipe — binary record codec, no OS, no async.
//! Records: DATA, CREDIT, CLOSE, CONSUMER_CLOSE. Bounded, no Alloc before check.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum RecordKind {
    Data = 1,
    Credit = 2,
    Close = 3,
    ConsumerClose = 4,
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
    Ok((DataRecord { payload: buf[5..5 + len].to_vec() }, 5 + len))
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
        // Forge length 1M where max is 10
        enc[1..5].copy_from_slice(&(1_000_000u32).to_le_bytes());
        assert_eq!(decode_data(&enc, 10), Err("too large"));
    }

    #[test]
    fn truncated_rejected() {
        let enc = encode_data(b"hello");
        assert_eq!(decode_data(&enc[..3], 1024), Err("truncated header"));
        assert_eq!(decode_data(&enc[..5], 1024), Err("truncated body"));
    }
}
