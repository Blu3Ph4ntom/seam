//! Windows shared-memory backing: pagefile-backed section object + views.
//!
//! The section HANDLE is wrapped in a `std::fs::File` so the proven native
//! escrow / `DuplicateHandle` transfer path (used for `NativeFile`) can move
//! the backing object unchanged. Read-only authority is enforced natively by
//! duplicating the section with `SECTION_MAP_READ`-only access and mapping
//! with `FILE_MAP_READ`.

use std::fs::File;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::slice;

use winapi::um::handleapi::{DuplicateHandle, INVALID_HANDLE_VALUE};
use winapi::um::memoryapi::{
    CreateFileMappingW, MapViewOfFile, UnmapViewOfFile, FILE_MAP_READ, FILE_MAP_WRITE,
};
use winapi::um::processthreadsapi::GetCurrentProcess;
use winapi::um::winnt::{PAGE_READWRITE, SECTION_MAP_READ, SECTION_MAP_WRITE};

/// Section access granted to a writable mapping.
pub const SECTION_RW_ACCESS: u32 = SECTION_MAP_READ | SECTION_MAP_WRITE;
/// Section access granted to a read-only mapping (least privilege).
pub const SECTION_RO_ACCESS: u32 = SECTION_MAP_READ;

/// Create a pagefile-backed section of exactly `size` bytes.
pub fn create_backing(size: u64) -> std::io::Result<File> {
    // SAFETY: standard section-creation call; INVALID_HANDLE_VALUE selects the
    // system paging file as the backing store. No pointer arguments.
    unsafe {
        let h = CreateFileMappingW(
            INVALID_HANDLE_VALUE,
            std::ptr::null_mut(),
            PAGE_READWRITE,
            (size >> 32) as u32,
            (size & 0xffff_ffff) as u32,
            std::ptr::null(),
        );
        if h.is_null() {
            return Err(std::io::Error::last_os_error());
        }
        Ok(File::from(OwnedHandle::from_raw_handle(
            h as *mut std::ffi::c_void,
        )))
    }
}

/// Duplicate the section HANDLE into a new owned object with the access rights
/// implied by `writable`. Used both for `derive_read_only` (single process)
/// and for restricted recipient handles (cross process).
pub fn duplicate_backing(file: &File, writable: bool) -> std::io::Result<File> {
    let access = if writable {
        SECTION_RW_ACCESS
    } else {
        SECTION_RO_ACCESS
    };
    let src = file.as_raw_handle() as *mut winapi::ctypes::c_void;
    let mut out = std::ptr::null_mut();
    // SAFETY: duplicate the caller-owned handle into the current process with
    // explicit, reduced access. `out` is a brand-new handle we own.
    unsafe {
        let ok = DuplicateHandle(
            GetCurrentProcess(),
            src,
            GetCurrentProcess(),
            &mut out,
            access,
            0,
            0,
        );
        if ok == 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(File::from(OwnedHandle::from_raw_handle(
            out as *mut std::ffi::c_void,
        )))
    }
}

/// A live writable view of a region. Dropping unmaps; does NOT drop the
/// backing capability.
/// A live writable view, lifetime-tied to the capability it was mapped
/// from: while it exists the region cannot be moved, dropped or have its
/// authority transferred (enforced by the borrow checker).
pub struct MappedReadWrite<'a> {
    ptr: *mut u8,
    len: usize,
    _owner: std::marker::PhantomData<&'a mut crate::shared::SharedRegion>,
}

/// A live read-only view of a region. Exposes only an immutable slice.
/// A live read-only view tied to its capability borrow.
pub struct MappedReadOnly<'a> {
    ptr: *mut u8,
    len: usize,
    _owner: std::marker::PhantomData<&'a crate::shared::SharedRegion>,
}

impl<'a> MappedReadWrite<'a> {
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        // SAFETY: ptr is a valid mapped region of `len` bytes owned by this
        // struct; the slice lifetime is bounded by `&mut self`. Mapping Drop
        // unmaps before the allocation backing the slice could dangle.
        unsafe { slice::from_raw_parts_mut(self.ptr, self.len) }
    }
}

impl<'a> MappedReadOnly<'a> {
    /// Immutable bytes of this live mapping.
    pub fn as_slice(&self) -> &[u8] {
        // SAFETY: immutable view of a live mapping; no mutable aliasing.
        unsafe { slice::from_raw_parts(self.ptr, self.len) }
    }

    /// Raw parts for lifetime-preserving slice construction in mod.rs.
    /// Bench access to mapping coordinates.
    pub fn raw_parts_pub(&self) -> (*const u8, usize) {
        self.raw_parts()
    }

    pub(crate) fn raw_parts(&self) -> (*const u8, usize) {
        (self.ptr, self.len)
    }
}

impl Drop for MappedReadWrite<'_> {
    fn drop(&mut self) {
        // SAFETY: ptr came from MapViewOfFile for this mapping.
        unsafe {
            UnmapViewOfFile(self.ptr as *mut winapi::ctypes::c_void);
        }
    }
}

impl Drop for MappedReadOnly<'_> {
    fn drop(&mut self) {
        unsafe {
            UnmapViewOfFile(self.ptr as *mut winapi::ctypes::c_void);
        }
    }
}

pub fn map_read_write<'a>(file: &File, len: usize) -> std::io::Result<MappedReadWrite<'a>> {
    // SAFETY: mapping a caller-owned section; view is wrapped and unmapped on
    // Drop. Length is validated by the caller against the region size.
    unsafe {
        let p = MapViewOfFile(
            file.as_raw_handle() as *mut winapi::ctypes::c_void,
            FILE_MAP_WRITE,
            0,
            0,
            0,
        );
        if p.is_null() {
            return Err(std::io::Error::last_os_error());
        }
        Ok(MappedReadWrite {
            ptr: p as *mut u8,
            len,
            _owner: std::marker::PhantomData,
        })
    }
}

pub fn map_read_only<'a>(file: &File, len: usize) -> std::io::Result<MappedReadOnly<'a>> {
    unsafe {
        let p = MapViewOfFile(
            file.as_raw_handle() as *mut winapi::ctypes::c_void,
            FILE_MAP_READ,
            0,
            0,
            0,
        );
        if p.is_null() {
            return Err(std::io::Error::last_os_error());
        }
        Ok(MappedReadOnly {
            ptr: p as *mut u8,
            len,
            _owner: std::marker::PhantomData,
        })
    }
}

/// Bench support: unmap a raw view previously obtained via raw_parts_pub.
pub fn unmap_view(ptr: *const u8) {
    // SAFETY: pointer came from MapViewOfFile for a live mapping owned by
    // the caller's leaked view wrapper.
    unsafe {
        UnmapViewOfFile(ptr as *mut winapi::ctypes::c_void);
    }
}
