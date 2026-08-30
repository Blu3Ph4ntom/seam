//! seam-process — spawn/bootstrap helper.

pub mod bootstrap;
#[cfg(windows)]
pub mod bootstrap_windows;

use seam_core::ids::PeerId;

pub struct ChildHandle {
    pub peer: PeerId,
}

pub fn spawn(_fabric: &str, _name: &str) -> Result<ChildHandle, String> {
    Ok(ChildHandle {
        peer: PeerId::fresh(),
    })
}

#[cfg(unix)]
pub use bootstrap::unix_spawn;
#[cfg(windows)]
pub use bootstrap::windows_spawn;
pub use bootstrap::{child_handshake, parent_handshake};
