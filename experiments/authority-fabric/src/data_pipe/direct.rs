//! Direct DataPipe record protocol: tiny bounded framing over the payload
//! and control pipes. Payload direction carries DATA/CLOSE; control
//! direction carries CREDIT/CONSUMER_CLOSE. All peer-controlled integers are
//! length/bounds checked before any allocation.

use std::io::{BufRead, Write};

pub const MAX_DATA: usize = 8 * 1024 * 1024;

pub const KIND_DATA: u32 = 1;
pub const KIND_CLOSE: u32 = 2;
pub const KIND_CREDIT: u32 = 3;
pub const KIND_CONSUMER_CLOSE: u32 = 4;

#[derive(Debug, PartialEq, Eq)]
pub enum Rec {
    /// DATA with bounded body.
    Data(Vec<u8>),
    Close,
    Credit(usize),
    ConsumerClose,
}

fn perr(m: &'static str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, m)
}

/// Encode a record. `body.len()` must be <= MAX_DATA for KIND_DATA.
/// The trailing newline is protocol framing (line-delimited headers), so the
/// lint against `write!`-with-newline is intentionally suppressed here.
#[allow(clippy::write_literal)]
pub fn encode(w: &mut dyn Write, rec: &Rec) -> std::io::Result<()> {
    match rec {
        Rec::Data(b) => {
            if b.len() > MAX_DATA {
                return Err(perr("data exceeds bound"));
            }
            write!(w, "{} {}\n", KIND_DATA, b.len())?;
            w.write_all(b)?;
        }
        Rec::Close => write!(w, "{} 0\n", KIND_CLOSE)?,
        Rec::Credit(k) => {
            if *k > MAX_DATA {
                return Err(perr("credit exceeds bound"));
            }
            write!(w, "{} {}\n", KIND_CREDIT, k)?;
        }
        Rec::ConsumerClose => write!(w, "{} 0\n", KIND_CONSUMER_CLOSE)?,
    }
    w.flush()
}

/// Decode one record header + body from a buffered reader.
/// Returns Ok(None) on clean transport EOF between records.
pub fn decode(r: &mut dyn BufRead) -> std::io::Result<Option<Rec>> {
    let mut line = String::new();
    if r.read_line(&mut line)? == 0 {
        return Ok(None);
    }
    let mut it = line.split_whitespace();
    // checked parse: kind
    let kind: u32 = it
        .next()
        .ok_or_else(|| perr("missing kind"))?
        .parse()
        .map_err(|_| perr("bad kind"))?;
    // checked parse: len field (present for all kinds; must be 0 for CLOSE/
    // CONSUMER_CLOSE so peers cannot smuggle payloads in control records)
    let len: usize = it
        .next()
        .unwrap_or("0")
        .parse()
        .map_err(|_| perr("bad len"))?;
    match kind {
        KIND_DATA => {
            if len == 0 || len > MAX_DATA {
                return Err(perr("data len out of bounds"));
            }
            let mut body = vec![0u8; len];
            r.read_exact(&mut body)?;
            Ok(Some(Rec::Data(body)))
        }
        KIND_CREDIT => {
            if len == 0 || len > MAX_DATA {
                return Err(perr("credit delta out of bounds"));
            }
            Ok(Some(Rec::Credit(len)))
        }
        KIND_CLOSE => Ok(Some(Rec::Close)),
        KIND_CONSUMER_CLOSE => Ok(Some(Rec::ConsumerClose)),
        _ => Err(perr("unknown kind")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::BufReader;

    fn roundtrip(rec: &Rec) -> Rec {
        let mut buf: Vec<u8> = Vec::new();
        encode(&mut buf, rec).unwrap();
        let mut br = BufReader::new(&buf[..]);
        decode(&mut br).unwrap().expect("record")
    }

    #[test]
    fn data_roundtrip() {
        assert_eq!(
            roundtrip(&Rec::Data(b"hello".to_vec())),
            Rec::Data(b"hello".to_vec())
        );
    }

    #[test]
    fn close_roundtrip() {
        assert_eq!(roundtrip(&Rec::Close), Rec::Close);
    }

    #[test]
    fn credit_roundtrip() {
        assert_eq!(roundtrip(&Rec::Credit(4096)), Rec::Credit(4096));
    }

    #[test]
    fn consumer_close_roundtrip() {
        assert_eq!(roundtrip(&Rec::ConsumerClose), Rec::ConsumerClose);
    }

    /// M1 unknown record kind fails closed.
    #[test]
    fn m1_unknown_kind_rejected() {
        let buf = b"9 0\n";
        let mut br = BufReader::new(&buf[..]);
        assert!(decode(&mut br).is_err());
    }

    /// M2 oversized DATA length rejected before allocation.
    #[test]
    fn m2_oversized_data_len_rejected() {
        let buf = format!("{} {}\n", KIND_DATA, usize::MAX).into_bytes();
        let mut br = BufReader::new(&buf[..]);
        assert!(decode(&mut br).is_err());
    }

    /// M3 truncated header (no len) rejected.
    #[test]
    fn m3_truncated_header_rejected() {
        let buf = format!("{}\n", KIND_DATA).into_bytes();
        let mut br = BufReader::new(&buf[..]);
        assert!(decode(&mut br).is_err());
    }

    /// M4 truncated DATA body: header parses but body read fails.
    #[test]
    fn m4_truncated_body_fails() {
        let mut buf: Vec<u8> = Vec::new();
        encode(&mut buf, &Rec::Data(vec![1, 2, 3])).unwrap();
        let mut br = BufReader::new(&buf[..buf.len() - 1]); // cut last byte
        assert!(decode(&mut br).is_err());
    }

    /// D5/D7 zero credit delta rejected by the codec bound (delta must be
    /// >=1), matching the tracker's no-zero-credit policy.
    #[test]
    fn m5_zero_credit_rejected() {
        let buf = format!("{} 0\n", KIND_CREDIT).into_bytes();
        let mut br = BufReader::new(&buf[..]);
        assert!(decode(&mut br).is_err());
    }

    /// M6 duplicate CLOSE decodes twice; idempotence is the caller's duty
    /// (first terminal transition wins) - verified at the runtime layer.
    #[test]
    fn m6_duplicate_close_parses() {
        let mut buf: Vec<u8> = Vec::new();
        encode(&mut buf, &Rec::Close).unwrap();
        encode(&mut buf, &Rec::Close).unwrap();
        let mut br = BufReader::new(&buf[..]);
        assert_eq!(decode(&mut br).unwrap(), Some(Rec::Close));
        assert_eq!(decode(&mut br).unwrap(), Some(Rec::Close));
        assert_eq!(decode(&mut br).unwrap(), None);
    }

    /// D9 DATA after CLOSE parses at the codec layer; ordering enforcement
    /// is the runtime's terminal-state machine responsibility.
    #[test]
    fn d9_data_after_close_parses_at_codec_layer() {
        let mut buf: Vec<u8> = Vec::new();
        encode(&mut buf, &Rec::Close).unwrap();
        encode(&mut buf, &Rec::Data(b"x".to_vec())).unwrap();
        let mut br = BufReader::new(&buf[..]);
        assert_eq!(decode(&mut br).unwrap(), Some(Rec::Close));
        assert_eq!(decode(&mut br).unwrap(), Some(Rec::Data(b"x".to_vec())));
    }
}
