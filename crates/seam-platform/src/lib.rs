//! seam-platform — OS primitives (unsafe isolated).

#[cfg(windows)]
pub mod windows {
    // SAFETY: platform wrappers with documented invariants.
}

#[cfg(unix)]
pub mod unix {}

pub fn hello() -> &'static str {
    "platform"
}
