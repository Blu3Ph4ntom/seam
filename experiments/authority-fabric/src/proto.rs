//! Hand-written typed protocol for the experiment (NO IDL, NO codegen —
//! deliberately; RUN 002 tests authority/lifecycle semantics, not
//! ergonomics). Encoding: one tag byte + LE payloads. Experimental and NOT
//! Seam's final wire format.

use crate::fabric_error::FabError;

pub const TAG_PING: u8 = 1;
pub const TAG_OPEN_COUNTER: u8 = 2;
pub const TAG_PONG: u8 = 3;
pub const TAG_COUNTER: u8 = 4;
pub const TAG_INCREMENT: u8 = 5;
pub const TAG_GET: u8 = 6;
pub const TAG_INCREMENTED: u8 = 7;
pub const TAG_VALUE: u8 = 8;
pub const TAG_CTRL_READY_TO_KILL: u8 = 10;
pub const TAG_CTRL_DONE: u8 = 11;
pub const TAG_CTRL_ACK: u8 = 12;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RootRequest {
    Ping,
    OpenCounter,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RootResponse {
    Pong,
    /// The capability is attachment index 0 of the reply.
    Counter,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CounterRequest {
    Increment,
    Get,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CounterResponse {
    Incremented(u64),
    Value(u64),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ControlMsg {
    ReadyToKill,
    Done,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ControlAck {
    Ack,
}

fn enc_tag(out: &mut Vec<u8>, tag: u8) {
    out.push(tag);
}

fn dec_tag(buf: &[u8]) -> Result<(u8, &[u8]), FabError> {
    match buf.split_first() {
        Some((t, rest)) => Ok((*t, rest)),
        None => Err(FabError::InvalidMessage("empty payload")),
    }
}

fn put_u64(out: &mut Vec<u8>, v: u64) {
    out.extend_from_slice(&v.to_le_bytes());
}

fn take_u64(buf: &[u8]) -> Result<(u64, &[u8]), FabError> {
    if buf.len() < 8 {
        return Err(FabError::InvalidMessage("short u64"));
    }
    let (b, rest) = buf.split_at(8);
    Ok((u64::from_le_bytes(b.try_into().unwrap()), rest))
}

pub fn encode_root_request(r: RootRequest) -> Vec<u8> {
    let mut v = Vec::with_capacity(1);
    match r {
        RootRequest::Ping => enc_tag(&mut v, TAG_PING),
        RootRequest::OpenCounter => enc_tag(&mut v, TAG_OPEN_COUNTER),
    }
    v
}

pub fn decode_root_request(buf: &[u8]) -> Result<RootRequest, FabError> {
    let (t, rest) = dec_tag(buf)?;
    if !rest.is_empty() {
        return Err(FabError::InvalidMessage("trailing bytes in root request"));
    }
    match t {
        TAG_PING => Ok(RootRequest::Ping),
        TAG_OPEN_COUNTER => Ok(RootRequest::OpenCounter),
        _ => Err(FabError::InvalidMessage("unknown root request tag")),
    }
}

pub fn encode_root_response(r: RootResponse) -> Vec<u8> {
    let mut v = Vec::with_capacity(1);
    match r {
        RootResponse::Pong => enc_tag(&mut v, TAG_PONG),
        RootResponse::Counter => enc_tag(&mut v, TAG_COUNTER),
    }
    v
}

pub fn decode_root_response(buf: &[u8]) -> Result<RootResponse, FabError> {
    let (t, rest) = dec_tag(buf)?;
    if !rest.is_empty() {
        return Err(FabError::InvalidMessage("trailing bytes in root response"));
    }
    match t {
        TAG_PONG => Ok(RootResponse::Pong),
        TAG_COUNTER => Ok(RootResponse::Counter),
        _ => Err(FabError::InvalidMessage("unknown root response tag")),
    }
}

pub fn encode_counter_request(r: CounterRequest) -> Vec<u8> {
    let mut v = Vec::with_capacity(1);
    match r {
        CounterRequest::Increment => enc_tag(&mut v, TAG_INCREMENT),
        CounterRequest::Get => enc_tag(&mut v, TAG_GET),
    }
    v
}

pub fn decode_counter_request(buf: &[u8]) -> Result<CounterRequest, FabError> {
    let (t, rest) = dec_tag(buf)?;
    if !rest.is_empty() {
        return Err(FabError::InvalidMessage(
            "trailing bytes in counter request",
        ));
    }
    match t {
        TAG_INCREMENT => Ok(CounterRequest::Increment),
        TAG_GET => Ok(CounterRequest::Get),
        _ => Err(FabError::InvalidMessage("unknown counter request tag")),
    }
}

pub fn encode_counter_response(r: CounterResponse) -> Vec<u8> {
    let mut v = Vec::with_capacity(9);
    match r {
        CounterResponse::Incremented(n) => {
            enc_tag(&mut v, TAG_INCREMENTED);
            put_u64(&mut v, n);
        }
        CounterResponse::Value(n) => {
            enc_tag(&mut v, TAG_VALUE);
            put_u64(&mut v, n);
        }
    }
    v
}

pub fn decode_counter_response(buf: &[u8]) -> Result<CounterResponse, FabError> {
    let (t, rest) = dec_tag(buf)?;
    let (n, rest) = take_u64(rest)?;
    if !rest.is_empty() {
        return Err(FabError::InvalidMessage(
            "trailing bytes in counter response",
        ));
    }
    match t {
        TAG_INCREMENTED => Ok(CounterResponse::Incremented(n)),
        TAG_VALUE => Ok(CounterResponse::Value(n)),
        _ => Err(FabError::InvalidMessage("unknown counter response tag")),
    }
}

pub fn encode_control(m: ControlMsg) -> Vec<u8> {
    let mut v = Vec::with_capacity(1);
    match m {
        ControlMsg::ReadyToKill => enc_tag(&mut v, TAG_CTRL_READY_TO_KILL),
        ControlMsg::Done => enc_tag(&mut v, TAG_CTRL_DONE),
    }
    v
}

pub fn decode_control(buf: &[u8]) -> Result<ControlMsg, FabError> {
    let (t, rest) = dec_tag(buf)?;
    if !rest.is_empty() {
        return Err(FabError::InvalidMessage("trailing bytes in control msg"));
    }
    match t {
        TAG_CTRL_READY_TO_KILL => Ok(ControlMsg::ReadyToKill),
        TAG_CTRL_DONE => Ok(ControlMsg::Done),
        _ => Err(FabError::InvalidMessage("unknown control tag")),
    }
}

pub fn encode_control_ack(a: ControlAck) -> Vec<u8> {
    let mut v = Vec::with_capacity(1);
    match a {
        ControlAck::Ack => enc_tag(&mut v, TAG_CTRL_ACK),
    }
    v
}

pub fn decode_control_ack(buf: &[u8]) -> Result<ControlAck, FabError> {
    let (t, rest) = dec_tag(buf)?;
    if !rest.is_empty() {
        return Err(FabError::InvalidMessage("trailing bytes in control ack"));
    }
    match t {
        TAG_CTRL_ACK => Ok(ControlAck::Ack),
        _ => Err(FabError::InvalidMessage("unknown control ack tag")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_all_types() {
        for r in [RootRequest::Ping, RootRequest::OpenCounter] {
            assert_eq!(decode_root_request(&encode_root_request(r)).unwrap(), r);
        }
        for r in [RootResponse::Pong, RootResponse::Counter] {
            assert_eq!(decode_root_response(&encode_root_response(r)).unwrap(), r);
        }
        for r in [CounterRequest::Increment, CounterRequest::Get] {
            assert_eq!(
                decode_counter_request(&encode_counter_request(r)).unwrap(),
                r
            );
        }
        for r in [
            CounterResponse::Incremented(u64::MAX),
            CounterResponse::Value(0),
        ] {
            assert_eq!(
                decode_counter_response(&encode_counter_response(r)).unwrap(),
                r
            );
        }
        for r in [ControlMsg::ReadyToKill, ControlMsg::Done] {
            assert_eq!(decode_control(&encode_control(r)).unwrap(), r);
        }
        assert_eq!(
            decode_control_ack(&encode_control_ack(ControlAck::Ack)).unwrap(),
            ControlAck::Ack
        );
    }

    #[test]
    fn garbage_payloads_are_invalid_message_not_crash() {
        assert!(decode_root_request(&[]).is_err());
        assert!(decode_root_request(&[0xAA]).is_err());
        assert!(decode_root_request(&[TAG_PING, 1]).is_err());
        assert!(decode_counter_response(&[TAG_VALUE]).is_err());
        assert!(decode_counter_response(&[TAG_VALUE, 1, 2, 3, 4, 5, 6, 7, 8, 9]).is_err());
    }
}
