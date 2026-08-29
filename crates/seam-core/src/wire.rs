//! Wire framing — exact 32-byte little-endian header per CTO 1G.
//! Never transmute. All integers LE. Reserved must be 0.

use crate::limits::Limits;

pub const MAGIC: u32 = 0x5345414D; // "SEAM" LE
pub const HEADER_SIZE: usize = 32;
pub const CURRENT_MAJOR: u8 = 1;
pub const CURRENT_MINOR: u8 = 0;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Kind {
    Control = 1,
    Data = 2,
    Request = 3,
    Reply = 4,
    OneWay = 5,
    // Transfer-protocol control messages (all on CONTROL lane unless noted)
    Register = 11,
    Offer = 12,
    Accept = 13,
    NativeEscrow = 14, // on NATIVE lane, carries SCM_RIGHTS
    EscrowAcquired = 15,
    NativeDeliver = 16, // on NATIVE lane, carries SCM_RIGHTS
    NativeStaged = 17,
    Commit = 18,
    Abort = 19,
    Restore = 20, // on NATIVE lane, carries SCM_RIGHTS back to sender
    RestoreAck = 21,
    Status = 22,
    ResultAck = 23,
}

impl TryFrom<u8> for Kind {
    type Error = WireError;
    fn try_from(v: u8) -> Result<Self, Self::Error> {
        match v {
            1 => Ok(Kind::Control),
            2 => Ok(Kind::Data),
            3 => Ok(Kind::Request),
            4 => Ok(Kind::Reply),
            5 => Ok(Kind::OneWay),
            11 => Ok(Kind::Register),
            12 => Ok(Kind::Offer),
            13 => Ok(Kind::Accept),
            14 => Ok(Kind::NativeEscrow),
            15 => Ok(Kind::EscrowAcquired),
            16 => Ok(Kind::NativeDeliver),
            17 => Ok(Kind::NativeStaged),
            18 => Ok(Kind::Commit),
            19 => Ok(Kind::Abort),
            20 => Ok(Kind::Restore),
            21 => Ok(Kind::RestoreAck),
            22 => Ok(Kind::Status),
            23 => Ok(Kind::ResultAck),
            _ => Err(WireError::UnknownKind(v)),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header {
    pub magic: u32,
    pub major: u8,
    pub minor: u8,
    pub kind: Kind,
    pub flags: u8,
    pub body_len: u32,
    pub request_id: u64,
    pub channel_id: u64,
    pub attachment_count: u16,
    pub reserved: u16,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WireError {
    TooShort,
    BadMagic(u32),
    UnsupportedMajor { got: u8, want: u8 },
    ReservedNonZero(u16),
    UnknownKind(u8),
    BodyTooLarge { got: u32, max: usize },
    TooManyAttachments { got: u16, max: usize },
}

impl std::fmt::Display for WireError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}
impl std::error::Error for WireError {}

impl Header {
    pub fn encode(&self, out: &mut [u8; 32]) {
        out[0..4].copy_from_slice(&self.magic.to_le_bytes());
        out[4] = self.major;
        out[5] = self.minor;
        out[6] = self.kind as u8;
        out[7] = self.flags;
        out[8..12].copy_from_slice(&self.body_len.to_le_bytes());
        out[12..20].copy_from_slice(&self.request_id.to_le_bytes());
        out[20..28].copy_from_slice(&self.channel_id.to_le_bytes());
        out[28..30].copy_from_slice(&self.attachment_count.to_le_bytes());
        out[30..32].copy_from_slice(&self.reserved.to_le_bytes());
    }

    pub fn decode(buf: &[u8; 32], limits: &Limits) -> Result<Self, WireError> {
        let magic = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
        if magic != MAGIC {
            return Err(WireError::BadMagic(magic));
        }
        let major = buf[4];
        if major != CURRENT_MAJOR {
            return Err(WireError::UnsupportedMajor {
                got: major,
                want: CURRENT_MAJOR,
            });
        }
        let minor = buf[5];
        let _ = minor; // additive compat: accept any minor for same major
        let kind = Kind::try_from(buf[6])?;
        let flags = buf[7];
        let body_len = u32::from_le_bytes([buf[8], buf[9], buf[10], buf[11]]);
        if body_len as usize > limits.max_frame_bytes {
            return Err(WireError::BodyTooLarge {
                got: body_len,
                max: limits.max_frame_bytes,
            });
        }
        let request_id = u64::from_le_bytes(buf[12..20].try_into().unwrap());
        let channel_id = u64::from_le_bytes(buf[20..28].try_into().unwrap());
        let attachment_count = u16::from_le_bytes([buf[28], buf[29]]);
        if attachment_count as usize > limits.max_attachments {
            return Err(WireError::TooManyAttachments {
                got: attachment_count,
                max: limits.max_attachments,
            });
        }
        let reserved = u16::from_le_bytes([buf[30], buf[31]]);
        if reserved != 0 {
            return Err(WireError::ReservedNonZero(reserved));
        }
        Ok(Header {
            magic,
            major,
            minor,
            kind,
            flags,
            body_len,
            request_id,
            channel_id,
            attachment_count,
            reserved,
        })
    }
}

/// Attachment descriptor carried in body-adjacent table (not raw HANDLE).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AttachmentDesc {
    pub transfer_id: [u8; 16],
    pub index: u16,
    pub object_kind: u8, // 1=Endpoint 2=Native 3=Shared 4=PipeProducer 5=PipeConsumer
    pub authority_kind: u8,
    pub native_expected: bool,
    pub object_id: [u8; 16],
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::limits::Limits;
    #[test]
    fn roundtrip() {
        let h = Header {
            magic: MAGIC,
            major: CURRENT_MAJOR,
            minor: CURRENT_MINOR,
            kind: Kind::Request,
            flags: 0,
            body_len: 42,
            request_id: 7,
            channel_id: 99,
            attachment_count: 2,
            reserved: 0,
        };
        let mut buf = [0u8; 32];
        h.encode(&mut buf);
        assert_eq!(Header::decode(&buf, &Limits::default()).unwrap(), h);
    }
    #[test]
    fn bad_magic() {
        let mut buf = [0u8; 32];
        buf[0..4].copy_from_slice(&0xDEADu32.to_le_bytes());
        assert!(matches!(
            Header::decode(&buf, &Limits::default()),
            Err(WireError::BadMagic(_))
        ));
    }
    #[test]
    fn reserved_rejected() {
        let h = Header {
            magic: MAGIC,
            major: CURRENT_MAJOR,
            minor: CURRENT_MINOR,
            kind: Kind::Control,
            flags: 0,
            body_len: 0,
            request_id: 0,
            channel_id: 0,
            attachment_count: 0,
            reserved: 1,
        };
        let mut buf = [0u8; 32];
        h.encode(&mut buf);
        assert!(matches!(
            Header::decode(&buf, &Limits::default()),
            Err(WireError::ReservedNonZero(_))
        ));
    }
}
