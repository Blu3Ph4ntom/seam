//! NativeFile — move-only, stable ResourceId, same underlying OS object.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};

use seam_core::ids::ResourceId;

pub struct NativeFile {
    id: ResourceId,
    file: File,
}

impl NativeFile {
    pub fn from_file(id: ResourceId, file: File) -> Self {
        Self { id, file }
    }

    pub fn new_temp_with_prefix(prefix: &[u8]) -> std::io::Result<Self> {
        let mut path = std::env::temp_dir();
        path.push(format!(
            "seam-native-{}-{}.tmp",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let mut f = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)?;
        f.write_all(prefix)?;
        f.flush()?;
        // Unlink pathname where possible — file remains via open fd
        let _ = std::fs::remove_file(&path);
        let id = ResourceId::fresh();
        f.seek(SeekFrom::Start(0))?;
        Ok(Self { id, file: f })
    }

    pub fn id(&self) -> ResourceId {
        self.id
    }

    pub fn read_at_start(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.file.seek(SeekFrom::Start(0))?;
        self.file.read(buf)
    }

    pub fn read_all_from_start(&mut self) -> std::io::Result<Vec<u8>> {
        self.file.seek(SeekFrom::Start(0))?;
        let mut v = Vec::new();
        self.file.read_to_end(&mut v)?;
        Ok(v)
    }

    pub fn write_at_end(&mut self, data: &[u8]) -> std::io::Result<()> {
        self.file.seek(SeekFrom::End(0))?;
        self.file.write_all(data)?;
        self.file.flush()?;
        Ok(())
    }

    pub fn into_file(self) -> File {
        self.file
    }

    pub fn as_file_mut(&mut self) -> &mut File {
        &mut self.file
    }

    pub fn from_file_with_id(file: File, id: ResourceId) -> Self {
        Self { id, file }
    }
}

impl std::fmt::Debug for NativeFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NativeFile").field("id", &self.id).finish()
    }
}

// Move-only: no Clone/Copy

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn native_file_is_move_only() {
        let f = NativeFile::new_temp_with_prefix(b"hi").unwrap();
        let id = f.id();
        let f2 = f; // move
        assert_eq!(f2.id(), id);
        // let f3 = f2.clone(); // should not compile
    }
}
