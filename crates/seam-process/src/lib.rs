//! seam-process — spawn/bootstrap helper.

use seam_core::ids::PeerId;

pub struct ChildHandle {
    pub peer: PeerId,
}

pub fn spawn(_fabric: &str, _name: &str) -> Result<ChildHandle, String> {
    Ok(ChildHandle {
        peer: PeerId::fresh(),
    })
}
