//! Windows HANDLE duplication via DuplicateHandle (winapi).

use std::fs::File;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};

use winapi::um::handleapi::DuplicateHandle;
use winapi::um::processthreadsapi::GetCurrentProcess;
use winapi::um::winnt::{DUPLICATE_SAME_ACCESS, HANDLE};

/// Host escrow holds a duplicated HANDLE.
pub struct Escrowed(pub OwnedHandle);

fn current_process_handle() -> HANDLE {
    unsafe { GetCurrentProcess() }
}

/// # Safety
/// `src_handle` must be a live handle valid in `src_process_raw`; the new
/// handle is returned as the sole owned reference.
unsafe fn dup_from_process(
    src_process_raw: HANDLE,
    src_handle: HANDLE,
) -> std::io::Result<OwnedHandle> {
    let mut target: HANDLE = std::ptr::null_mut();
    let ok = unsafe {
        DuplicateHandle(
            src_process_raw,
            src_handle,
            current_process_handle(),
            &mut target,
            0,
            0,
            DUPLICATE_SAME_ACCESS,
        )
    };
    if ok == 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(unsafe { OwnedHandle::from_raw_handle(target as *mut std::ffi::c_void) })
}

/// # Safety
/// `escrow_handle` must be a live handle in the current process.
unsafe fn dup_to_process(
    target_process_raw: HANDLE,
    escrow_handle: HANDLE,
) -> std::io::Result<u64> {
    // Same-access duplication: the recipient's handle inherits the source's
    // exact access rights (dwDesiredAccess must be 0 with this option).
    dup_to_process_opts(
        target_process_raw,
        escrow_handle,
        0,
        winapi::um::winnt::DUPLICATE_SAME_ACCESS,
    )
}

/// Duplicate an escrowed kernel object into the target process with an
/// explicit `dwDesiredAccess` / `dwOptions` pair. Used by shared-region
/// commit delivery to hand the recipient a least-privilege handle
/// (e.g. SECTION_MAP_READ-only for a read-only capability) instead of blind
/// same-access duplication.
///
/// Win32 contract: when `options` contains DUPLICATE_SAME_ACCESS,
/// `desired_access` MUST be 0; otherwise `desired_access` is the exact mask
/// granted to the new handle.
/// # Safety
/// `escrow_handle` must be a live handle in the current process; the target
/// process receives a brand-new handle it solely owns.
#[allow(clippy::not_unsafe_ptr_arg_deref)] // HANDLE = process-relative token
pub fn dup_to_process_opts(
    target_process_raw: HANDLE,
    escrow_handle: HANDLE,
    desired_access: u32,
    options: u32,
) -> std::io::Result<u64> {
    let mut target: HANDLE = std::ptr::null_mut();
    let ok = unsafe {
        DuplicateHandle(
            current_process_handle(),
            escrow_handle,
            target_process_raw,
            &mut target,
            desired_access,
            0,
            options,
        )
    };
    if ok == 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(target as u64)
}

/// # Safety
/// `sender_handle_value` must be a live handle valid in `sender_process`.
#[allow(clippy::not_unsafe_ptr_arg_deref)] // HANDLE = process-relative token
pub fn stage_from_sender(
    sender_process: HANDLE,
    sender_handle_value: u64,
) -> std::io::Result<Escrowed> {
    let src_handle = sender_handle_value as *mut winapi::ctypes::c_void;
    // SAFETY: caller-supplied sender handle value staged for this transfer.
    let owned = unsafe { dup_from_process(sender_process, src_handle) }?;
    Ok(Escrowed(owned))
}

/// # Safety
/// `escrow` must own a live handle; `sender_process` receives the duplicate.
#[allow(clippy::not_unsafe_ptr_arg_deref)] // HANDLE = process-relative token
pub fn restore_to_sender(sender_process: HANDLE, escrow: Escrowed) -> std::io::Result<u64> {
    let escrow_handle = escrow.0.as_raw_handle() as *mut winapi::ctypes::c_void;
    // SAFETY: escrow handle owned by this module until duplication completes.
    let raw = unsafe { dup_to_process(sender_process, escrow_handle) }?;
    drop(escrow);
    Ok(raw)
}

/// # Safety
/// `escrow` must own a live handle; recipient receives the sole new handle.
#[allow(clippy::not_unsafe_ptr_arg_deref)] // HANDLE = process-relative token
pub fn commit_to_recipient(recipient_process: HANDLE, escrow: Escrowed) -> std::io::Result<u64> {
    let escrow_handle = escrow.0.as_raw_handle() as *mut winapi::ctypes::c_void;
    // SAFETY: escrow handle owned by this module until duplication completes.
    let raw = unsafe { dup_to_process(recipient_process, escrow_handle) }?;
    drop(escrow);
    Ok(raw)
}

pub fn close_escrow(escrow: Escrowed) {
    drop(escrow);
}

pub fn handle_to_file(raw: u64) -> File {
    let handle = raw as *mut winapi::ctypes::c_void;
    let owned = unsafe { OwnedHandle::from_raw_handle(handle as *mut std::ffi::c_void) };
    File::from(owned)
}
