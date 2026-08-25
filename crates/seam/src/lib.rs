//! seam — public facade.

pub use seam_core as core;
pub use seam_core::ids::{
    AttachmentIndex, ChannelId, EndpointId, PeerId, PipeId, RegionId, RequestId, ResourceId,
    TransferId,
};
pub use seam_core::limits::Limits;
pub use seam_core::wire::{Header, HEADER_SIZE, MAGIC};
pub mod prelude {
    pub use seam_core::prelude::*;
}

/// Fabric — embedded authority role.
pub struct Fabric {
    limits: Limits,
}

impl Fabric {
    pub fn new(limits: Limits) -> Result<Self, String> {
        Ok(Self { limits })
    }
    pub fn limits(&self) -> &Limits {
        &self.limits
    }
}

/// Linear Client<T> — move-only, no Clone/Copy.
pub struct Client<T>(std::marker::PhantomData<T>, #[allow(dead_code)] PeerId);

/// Linear Receiver<T> — move-only, no Clone/Copy.
pub struct Receiver<T>(std::marker::PhantomData<T>, #[allow(dead_code)] PeerId);

pub fn channel<T>(_fabric: &Fabric) -> (Client<T>, Receiver<T>) {
    (
        Client(std::marker::PhantomData, PeerId::fresh()),
        Receiver(std::marker::PhantomData, PeerId::fresh()),
    )
}

/// Linear NativeFile wrapper (example kind).
pub struct NativeFile {
    _inner: (),
}
impl NativeFile {
    pub fn open(_p: &str) -> Result<Self, String> {
        Ok(Self { _inner: () })
    }
}

/// SharedRegion types (stub)
pub struct SharedRegionMut;
pub struct SharedRegionRead;
impl SharedRegionMut {
    pub fn create(_fabric: &Fabric, _size: usize) -> Result<Self, String> {
        Ok(Self)
    }
    pub fn derive_read_only(&self) -> Result<SharedRegionRead, String> {
        Ok(SharedRegionRead)
    }
}

/// DataPipe
pub struct Producer;
pub struct Consumer;
pub struct DataPipe;
#[allow(clippy::new_ret_no_self)]
impl DataPipe {
    pub fn new(_fabric: &Fabric, _cap: usize) -> Result<(Producer, Consumer), String> {
        Ok((Producer, Consumer))
    }
}
