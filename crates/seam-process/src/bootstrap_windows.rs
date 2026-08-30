//! Windows production bootstrap — private pipes + STARTUPINFOEXW + HANDLE_LIST.
//! Parent permanent handles are NON-INHERITABLE; child-specific duplicates are
//! INHERITABLE and placed in PROC_THREAD_ATTRIBUTE_HANDLE_LIST.
//! No global HandleFlag inheritance window.

#![cfg(windows)]

use std::ffi::OsString;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use winapi::shared::minwindef::{DWORD, FALSE, TRUE};
use winapi::um::processthreadsapi::{
    CreateProcessW, DeleteProcThreadAttributeList, InitializeProcThreadAttributeList,
    UpdateProcThreadAttribute,
};
use winapi::um::winbase::{CREATE_UNICODE_ENVIRONMENT, EXTENDED_STARTUPINFO_PRESENT};
use winapi::um::winnt::HANDLE;

pub struct BootstrapHandles {
    pub child_process: OwnedHandle,
    pub child_thread: OwnedHandle,
    pub parent_read: OwnedHandle,
    pub parent_write: OwnedHandle,
}

/// Spawn a child with a private duplex lane (two anonymous pipes, HANDLE_LIST).
/// Returns child process/thread handles and parent lane ends.
pub fn spawn_bootstrap_windows(command_line: &str) -> std::io::Result<BootstrapHandles> {
    // Create two anonymous pipes for duplex
    let (parent_read, child_write) = create_pipe_pair()?;
    let (child_read, parent_write) = create_pipe_pair()?;

    // Duplicate child ends as inheritable for HANDLE_LIST
    let child_write_inheritable = duplicate_inheritable(&child_write)?;
    let child_read_inheritable = duplicate_inheritable(&child_read)?;

    // Prepare attribute list
    let mut attr_size: usize = 0;
    unsafe { InitializeProcThreadAttributeList(std::ptr::null_mut(), 1, 0, &mut attr_size) };
    let mut attr_mem = vec![0u8; attr_size];
    let attr_list = attr_mem.as_mut_ptr() as *mut winapi::um::winbase::LPPROC_THREAD_ATTRIBUTE_LIST;
    let ok = unsafe { InitializeProcThreadAttributeList(attr_list, 1, 0, &mut attr_size) };
    if ok == 0 {
        return Err(std::io::Error::last_os_error());
    }

    let handles: [HANDLE; 2] = [
        child_write_inheritable.as_raw_handle() as HANDLE,
        child_read_inheritable.as_raw_handle() as HANDLE,
    ];
    let ok = unsafe {
        UpdateProcThreadAttribute(
            attr_list,
            0,
            winapi::um::winbase::PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
            handles.as_ptr() as *mut _,
            (handles.len() * std::mem::size_of::<HANDLE>()) as usize,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    if ok == 0 {
        unsafe { DeleteProcThreadAttributeList(attr_list) };
        return Err(std::io::Error::last_os_error());
    }

    // Prepare STARTUPINFOEXW
    let mut si_ex: winapi::um::winbase::STARTUPINFOEXW = unsafe { std::mem::zeroed() };
    si_ex.StartupInfo.cb = std::mem::size_of::<winapi::um::winbase::STARTUPINFOEXW>() as DWORD;
    si_ex.lpAttributeList = attr_list;

    let mut pi: winapi::um::processthreadsapi::PROCESS_INFORMATION = unsafe { std::mem::zeroed() };
    let mut cmd_w: Vec<u16> = OsString::from(command_line)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    let ok = unsafe {
        CreateProcessW(
            std::ptr::null(),
            cmd_w.as_mut_ptr(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            TRUE, // bInheritHandles
            EXTENDED_STARTUPINFO_PRESENT | CREATE_UNICODE_ENVIRONMENT,
            std::ptr::null_mut(),
            std::ptr::null(),
            &mut si_ex.StartupInfo as *mut _ as *mut winapi::um::winbase::STARTUPINFOW,
            &mut pi,
        )
    };

    unsafe { DeleteProcThreadAttributeList(attr_list) };
    // Close child-specific inheritable duplicates in parent immediately
    drop(child_write_inheritable);
    drop(child_read_inheritable);
    // Close child ends in parent (they were dup'd)
    drop(child_write);
    drop(child_read);

    if ok == 0 {
        return Err(std::io::Error::last_os_error());
    }

    let child_process = unsafe { OwnedHandle::from_raw_handle(pi.hProcess as *mut _) };
    let child_thread = unsafe { OwnedHandle::from_raw_handle(pi.hThread as *mut _) };
    Ok(BootstrapHandles {
        child_process,
        child_thread,
        parent_read,
        parent_write,
    })
}

fn create_pipe_pair() -> std::io::Result<(OwnedHandle, OwnedHandle)> {
    let mut read: HANDLE = std::ptr::null_mut();
    let mut write: HANDLE = std::ptr::null_mut();
    let mut sa = winapi::um::minwinbase::SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<winapi::um::minwinbase::SECURITY_ATTRIBUTES>() as DWORD,
        lpSecurityDescriptor: std::ptr::null_mut(),
        bInheritHandle: FALSE,
    };
    let ok = unsafe { winapi::um::namedpipeapi::CreatePipe(&mut read, &mut write, &mut sa, 0) };
    if ok == 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(unsafe {
        (
            OwnedHandle::from_raw_handle(read as *mut _),
            OwnedHandle::from_raw_handle(write as *mut _),
        )
    })
}

fn duplicate_inheritable(handle: &OwnedHandle) -> std::io::Result<OwnedHandle> {
    let mut dup: HANDLE = std::ptr::null_mut();
    let ok = unsafe {
        winapi::um::handleapi::DuplicateHandle(
            winapi::um::processthreadsapi::GetCurrentProcess(),
            handle.as_raw_handle() as *mut _,
            winapi::um::processthreadsapi::GetCurrentProcess(),
            &mut dup,
            0,
            TRUE,
            winapi::um::winnt::DUPLICATE_SAME_ACCESS,
        )
    };
    if ok == 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(unsafe { OwnedHandle::from_raw_handle(dup as *mut _) })
}
