//! Native resource transfer — experimental file-like kernel resource.
//!
//! One resource per transfer, Host-escrowed, move-only `NativeFile`.
//! Kernel reference != application authority: only one armed `NativeFile`
//! wrapper exists at a time; escrow holds the kernel reference while
//! unresolved.

use std::fs::File;
use std::io::{Read, Write};

use getrandom::fill;

use crate::id::TransferId;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ResourceId(pub [u8; 16]);

impl ResourceId {
    pub fn from_raw(b: [u8; 16]) -> Self {
        ResourceId(b)
    }
    pub fn is_zero(self) -> bool {
        self.0.iter().all(|&b| b == 0)
    }
}

fn draw16() -> [u8; 16] {
    let mut b = [0u8; 16];
    fill(&mut b).expect("OS entropy failed");
    b
}

pub fn fresh_resource_id(taken: &impl ResourceSpace) -> ResourceId {
    loop {
        let id = ResourceId(draw16());
        if !id.is_zero() && !taken.contains(id) {
            return id;
        }
    }
}

pub trait ResourceSpace {
    fn contains(&self, id: ResourceId) -> bool;
}

/// Move-only file-backed native resource. Owns a real `File`.
/// Possession = authority. Not Clone.
pub struct NativeFile {
    id: ResourceId,
    file: Option<File>,
    armed: bool,
}

impl std::fmt::Debug for NativeFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NativeFile").field("id", &self.id.0).finish()
    }
}

impl NativeFile {
    /// Create a new temp file with random nonce written. Used by sender.
    pub fn new_temp(nonce: &[u8]) -> std::io::Result<Self> {
        let mut path = std::env::temp_dir();
        let mut rnd = [0u8; 8];
        fill(&mut rnd).unwrap();
        path.push(format!("seam-native-{:x}.tmp", u64::from_le_bytes(rnd)));
        let mut f = File::create(&path)?;
        f.write_all(nonce)?;
        f.flush()?;
        #[cfg(unix)]
        {
            let _ = std::fs::remove_file(&path);
        }
        let id = ResourceId(draw16());
        use std::io::Seek;
        let _ = f.seek(std::io::SeekFrom::Start(0));
        Ok(NativeFile { id, file: Some(f), armed: true })
    }

    /// Wrap an existing File with a fresh ResourceId (for recipient materialization).
    pub fn from_file(file: File) -> Self {
        let id = ResourceId(draw16());
        NativeFile { id, file: Some(file), armed: true }
    }

    pub fn id(&self) -> ResourceId {
        self.id
    }

    pub fn file(&mut self) -> &mut File {
        self.file.as_mut().expect("disarmed")
    }

    pub fn read_all(&mut self) -> std::io::Result<Vec<u8>> {
        use std::io::Seek;
        let f = self.file.as_mut().expect("disarmed");
        f.seek(std::io::SeekFrom::Start(0))?;
        let mut buf = Vec::new();
        f.read_to_end(&mut buf)?;
        Ok(buf)
    }

    pub fn write_marker(&mut self, marker: &[u8]) -> std::io::Result<()> {
        use std::io::Seek;
        let f = self.file.as_mut().expect("disarmed");
        f.seek(std::io::SeekFrom::End(0))?;
        f.write_all(marker)?;
        f.flush()?;
        Ok(())
    }

    /// Consume the wrapper and return the inner File (for staging). Disarms.
    pub fn into_file(mut self) -> File {
        self.armed = false;
        self.file.take().expect("already taken")
    }

    /// For abort restoration: re-arm a file as NativeFile with same ResourceId
    pub fn restore(id: ResourceId, file: File) -> Self {
        NativeFile { id, file: Some(file), armed: true }
    }
}

impl Drop for NativeFile {
    fn drop(&mut self) {
        if self.armed {
            // File's Drop will close the FD/HANDLE via Option<File> drop
        }
        // if disarmed, file is None, nothing to close
    }
}

// Platform escrow abstraction

#[cfg(unix)]
pub mod unix;
#[cfg(windows)]
pub mod windows;

#[cfg(unix)]
pub use unix::{close_escrow, commit_to_recipient, restore_to_sender, stage_from_sender, Escrowed};

#[cfg(windows)]
pub use windows::{close_escrow, commit_to_recipient, restore_to_sender, stage_from_sender, Escrowed};

/// Host resource table state
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NativeState {
    Escrowed,
    Committed,
    Aborted,
}

pub struct NativeRec {
    pub rid: ResourceId,
    pub tid: TransferId,
    pub state: NativeState,
    pub escrow: Option<Escrowed>,
    pub sender: crate::router::PeerId,
    pub dest: crate::router::PeerId,
}
