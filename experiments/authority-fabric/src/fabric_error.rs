//! Experimental error model. Small by design: only distinctions required to
//! test semantics. Remote failure never masquerades as local success.

use std::io;

/// Why an endpoint/conversation stopped working.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cause {
    /// The holder closed its end deliberately.
    Graceful,
    /// The process behind the conversation died or its transport broke.
    PeerLost,
}

#[derive(Debug)]
pub enum FabError {
    /// The endpoint's conversation is dead. `cause` distinguishes orderly
    /// close from peer death.
    Closed(Cause),
    /// Local handle references authority that no longer exists in the
    /// runtime tables (stale replay defense fired locally).
    StaleEndpoint,
    /// Queue/resource limits hit. The operation was NOT performed.
    Backpressured { queued_msgs: usize, queued_bytes: usize },
    /// A blocking wait exceeded its deadline without an event.
    Timeout,
    /// Transport to the host/fabric is gone. All authority is void.
    FabricLost,
    /// A peer demonstrated protocol corruption; the affected scope failed
    /// closed. Never a panic.
    ProtocolViolation(&'static str),
    /// The typed payload of a delivered message could not be decoded by the
    /// application protocol layer. Fabric stays alive; this affects one
    /// message only.
    InvalidMessage(&'static str),
    Io(io::Error),
}

impl From<io::Error> for FabError {
    fn from(e: io::Error) -> Self {
        FabError::Io(e)
    }
}

impl std::fmt::Display for FabError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FabError::Closed(c) => write!(f, "endpoint closed ({c:?})"),
            FabError::StaleEndpoint => write!(f, "stale endpoint identity"),
            FabError::Backpressured { queued_msgs, queued_bytes } => write!(
                f,
                "backpressured ({queued_msgs} msgs, {queued_bytes} bytes queued)"
            ),
            FabError::Timeout => write!(f, "operation timed out"),
            FabError::FabricLost => write!(f, "fabric transport lost"),
            FabError::ProtocolViolation(why) => write!(f, "protocol violation: {why}"),
            FabError::InvalidMessage(why) => write!(f, "invalid message payload: {why}"),
            FabError::Io(e) => write!(f, "io error: {e}"),
        }
    }
}

impl std::error::Error for FabError {}
