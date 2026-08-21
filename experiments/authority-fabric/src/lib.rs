//! Experimental authority fabric — RUN 002 vertical slice.
//!
//! This crate is an EXPERIMENT. Nothing here is Seam's stable API, wire
//! format, or transport. See `.agent/` (local-only) for the run charter.

pub mod fabric_error;
pub mod frame;
pub mod id;
pub mod limits;
pub mod memstream;
pub mod peer;
pub mod proto;
pub mod queue;
pub mod router;

pub use fabric_error::{Cause, FabError};
pub use frame::FrameError;
pub use id::EpId;
pub use limits::Limits;
pub use peer::{CallResult, Endpoint, Inbound, PeerAccounting, Runtime, RuntimeInner};
pub use queue::Backlog;
pub use router::{Accounting as RouterAccounting, HostDelivery, PeerId, Poison, Router};

/// Emit a structured marker line to stderr. Markers are the demo/e2e
/// evidence channel; tests assert on semantics too, never logs alone.
#[macro_export]
macro_rules! marker {
    ($($arg:tt)*) => {{
        let mut err = std::io::stderr().lock();
        let _ = writeln!(err, "MARK {}", format_args!($($arg)*));
        let _ = err.flush();
    }};
}
