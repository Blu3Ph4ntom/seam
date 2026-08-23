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

fn dup_from_process(src_process_raw: HANDLE, src_handle: HANDLE) -> std::io::Result<OwnedHandle> {
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

fn dup_to_process(target_process_raw: HANDLE, escrow_handle: HANDLE) -> std::io::Result<u64> {
    let mut target: HANDLE = std::ptr::null_mut();
    let ok = unsafe {
        DuplicateHandle(
            current_process_handle(),
            escrow_handle,
            target_process_raw,
            &mut target,
            0,
            0,
            DUPLICATE_SAME_ACCESS,
        )
    };
    if ok == 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(target as u64)
}

pub fn stage_from_sender(
    sender_process: HANDLE,
    sender_handle_value: u64,
) -> std::io::Result<Escrowed> {
    let src_handle = sender_handle_value as *mut winapi::ctypes::c_void;
    let owned = dup_from_process(sender_process, src_handle)?;
    Ok(Escrowed(owned))
}

pub fn restore_to_sender(sender_process: HANDLE, escrow: Escrowed) -> std::io::Result<u64> {
    let escrow_handle = escrow.0.as_raw_handle() as *mut winapi::ctypes::c_void;
    let raw = dup_to_process(sender_process, escrow_handle)?;
    drop(escrow);
    Ok(raw)
}

pub fn commit_to_recipient(recipient_process: HANDLE, escrow: Escrowed) -> std::io::Result<u64> {
    let escrow_handle = escrow.0.as_raw_handle() as *mut winapi::ctypes::c_void;
    let raw = dup_to_process(recipient_process, escrow_handle)?;
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
