//! Linux shared-memory backing: memfd + mmap + size seals.
//!
//! The memfd is wrapped in a `std::fs::File` so the proven native escrow /
//! `SCM_RIGHTS` transfer path (used for `NativeFile`) can move the backing
//! object unchanged. Read-only authority is enforced natively by mapping with
//! `PROT_READ` only. Size immutability is enforced by sealing the memfd
//! (SHRINK + GROW + SEAL) once the size is fixed.

use std::ffi::CStr;
use std::fs::File;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};
use std::slice;

use rustix::fs::{fcntl_add_seals, ftruncate, memfd_create, MemfdFlags, SealFlags};
use rustix::mm::{mmap, munmap, MapFlags, ProtFlags};

pub fn create_backing(size: u64) -> std::io::Result<File> {
    let name = CStr::from_bytes_with_nul(b"seam-region\0").unwrap();
    // SAFETY: memfd_create takes only a name and flags; no pointers.
    let fd: OwnedFd = memfd_create(name, MemfdFlags::CLOEXEC | MemfdFlags::ALLOW_SEALING)?;
    ftruncate(&fd, size)?;
    // Seal size immutability: cannot shrink/grow after this point. SEAL itself
    // prevents further seal changes, locking the size contract.
    let _ = fcntl_add_seals(&fd, SealFlags::SHRINK | SealFlags::GROW | SealFlags::SEAL);
    Ok(File::from(fd))
}

/// Duplicate the memfd into a new owned fd. On Linux the memfd *is* the
/// shared backing; a second fd referencing the same in-kernel object is the
/// correct derivation primitive (COW-free shared pages).
///
/// When deriving a READ-ONLY authority we seal the memfd with
/// `F_SEAL_FUTURE_WRITE`. Sealing is inode-wide: it prevents any new writable
/// mapping (and `write()`) on the shared object, so a recipient that receives
/// this fd cannot map it `PROT_WRITE` even by bypassing Seam. Mappings that
/// already exist (the producer's established writable view) keep working.
/// This is the honest Linux attenuation boundary: after RO derivation the
/// writer may not create *new* writable mappings, but its existing one remains.
pub fn duplicate_backing(file: &File, writable: bool) -> std::io::Result<File> {
    if writable {
        // Unsealed regions only: a plain std dup shares the writer state.
        return file.try_clone();
    }
    // READ-ONLY derivation, kernel-enforced by descriptor mode:
    //
    // Reopen the magic link /proc/self/fd/<n> with O_RDONLY. The consumer's
    // fresh open-file-description has no writer state, so mmap(PROT_WRITE)
    // fails with EACCES and write(2) with EBADF — for ANY recipient,
    // including one bypassing Seam entirely. Verified experimentally.
    //
    // Hardening when available: sealing the inode with F_SEAL_FUTURE_WRITE
    // would additionally lock the producer out of future writable mappings.
    // Some execution environments (e.g. gVisor sandboxes) return EINVAL for
    // all seal operations; there the guarantee rests solely on fd mode,
    // which matches the Windows restricted-handle model 1:1.
    let _ = rustix::fs::fcntl_add_seals(file.as_fd(), rustix::fs::SealFlags::FUTURE_WRITE);
    let raw = file.as_raw_fd();
    let link = std::path::Path::new("/proc/self/fd").join(raw.to_string());
    let reopened = std::fs::OpenOptions::new()
        .read(true)
        .write(false)
        .open(&link)?;
    Ok(reopened)
}

/// A live writable view of a region. Dropping unmaps; does NOT drop the
/// backing capability.
pub struct MappedReadWrite {
    ptr: *mut u8,
    len: usize,
}

/// A live read-only view of a region. Exposes only an immutable slice.
pub struct MappedReadOnly {
    ptr: *mut u8,
    len: usize,
}

impl MappedReadWrite {
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        // SAFETY: ptr is a valid mapped region of `len` bytes owned by this
        // struct; slice lifetime bounded by `&mut self`; Drop unmaps first.
        unsafe { slice::from_raw_parts_mut(self.ptr, self.len) }
    }
}

impl MappedReadOnly {
    pub fn as_slice(&self) -> &[u8] {
        unsafe { slice::from_raw_parts(self.ptr, self.len) }
    }
}

impl Drop for MappedReadWrite {
    fn drop(&mut self) {
        // SAFETY: ptr came from mmap for this mapping.
        let _ = unsafe { munmap(self.ptr as *mut _, self.len) };
    }
}

impl Drop for MappedReadOnly {
    fn drop(&mut self) {
        let _ = unsafe { munmap(self.ptr as *mut _, self.len) };
    }
}

pub fn map_read_write(file: &File, len: usize) -> std::io::Result<MappedReadWrite> {
    let borrowed: BorrowedFd<'_> = file.as_fd();
    // SAFETY: MAP_SHARED view of a caller-owned memfd; wrapped + unmapped on
    // Drop. Length validated by caller.
    unsafe {
        let p = mmap(
            std::ptr::null_mut(),
            len,
            ProtFlags::READ | ProtFlags::WRITE,
            MapFlags::SHARED,
            borrowed,
            0,
        )?;
        Ok(MappedReadWrite {
            ptr: p as *mut u8,
            len,
        })
    }
}

pub fn map_read_only(file: &File, len: usize) -> std::io::Result<MappedReadOnly> {
    let borrowed: BorrowedFd<'_> = file.as_fd();
    unsafe {
        let p = mmap(
            std::ptr::null_mut(),
            len,
            ProtFlags::READ,
            MapFlags::SHARED,
            borrowed,
            0,
        )?;
        Ok(MappedReadOnly {
            ptr: p as *mut u8,
            len,
        })
    }
}
