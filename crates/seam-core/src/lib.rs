//! seam-core — pure safe-Rust semantics for Seam V1.
//! No OS APIs. No async runtime. Wire header is exactly 32 bytes LE.

pub mod fabric;
pub mod ids;
pub mod limits;
pub mod transfer;
pub mod wire;

pub use ids::*;
pub use limits::Limits;
pub use wire::{Header, WireError, HEADER_SIZE, MAGIC};

/// Re-export for convenience.
pub mod prelude {
    pub use crate::ids::{
        AttachmentIndex, ChannelId, EndpointId, PeerId, PipeId, RegionId, RequestId, ResourceId,
        TransferId,
    };
    pub use crate::limits::Limits;
}
