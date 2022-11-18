//! Educational Rust reimplementation of the original VAC bypass (Daniel Krupinski style).
//! Patches steamservice.dll (JE->JMP), hooks LoadLibraryExW; on each loaded module hooks
//! GetProcAddress, GetSystemInfo, and the failsafe/ID APIs so VAC's page-size check fails.
//!
//! 32-bit only. Build: `cargo build --release --target i686-pc-windows-msvc`

#![cfg(windows)]

use std::ptr::null_mut;
use windows::core::{PCWSTR, PCSTR};
use windows::Win32::Foundation::{BOOL, HANDLE, HMODULE};
use windows::Win32::System::LibraryLoader::{
    GetModuleHandleExW, GetProcAddress, GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
};
use windows::Win32::System::Memory::{VirtualProtect, PAGE_EXECUTE_READ, PAGE_READWRITE};
use windows::Win32::System::ProcessStatus::{GetModuleInformation, MODULEINFO};
use windows::Win32::System::SystemInformation::SYSTEM_INFO;
use windows::Win32::System::Threading::{ExitProcess, GetCurrentProcess};
use windows::Win32::Foundation::FARPROC;
use windows::core::w;

// --- Pattern (from VAC-Bypass-Analysis.md) ---

/// steamservice.dll: JE at start of 74 47 6A 01 6A -> patch to JMP (0xEB).
const STEAMSERVICE_JE_PATTERN: &[u8] = &[0x74, 0x47, 0x6A, 0x01, 0x6A];

// --- Pattern scan ---

/// Find first occurrence of `pattern` in `haystack`. Returns offset or None.
pub fn pattern_find(haystack: &[u8], pattern: &[u8]) -> Option<usize> {
    if pattern.is_empty() || pattern.len() > haystack.len() {
        return None;
    }
    let end = haystack.len().saturating_sub(pattern.len()).saturating_add(1);
    for i in 0..end {
        if haystack[i..].starts_with(pattern) {
            return Some(i);
        }
    }
    None
}

fn pattern_find_in_module(base: *const u8, size: usize, pattern: &[u8]) -> *mut u8 {
    let slice = unsafe { std::slice::from_raw_parts(base, size) };
    pattern_find(slice, pattern)
        .map(|off| (base as usize + off) as *mut u8)
        .unwrap_or(null_mut())
}

// --- Memory patch ---

unsafe fn patch_memory(addr: *mut u8, new_bytes: &[u8]) -> bool {
    if addr.is_null() || new_bytes.is_empty() {
        return false;
    }
    let mut old = PAGE_EXECUTE_READ;
    if VirtualProtect(
        addr as *const _,
        new_bytes.len(),
        PAGE_READWRITE,
        &mut old,
    )
    .is_err()
    {
        return false;
    }
    std::ptr::copy_nonoverlapping(new_bytes.as_ptr(), addr, new_bytes.len());
    let _ = VirtualProtect(addr as *const _, new_bytes.len(), old, &mut old);
    true
}

// --- PE: IAT parsing ---

#[repr(C)]
struct ImageDosHeader {
    e_magic: u16,
    _pad: [u8; 58],
    e_lfanew: i32,
}

#[repr(C)]
struct ImageNtHeaders32 {
    signature: u32,
    file_header: [u8; 20],
    optional_header: [u8; 224],
}

#[repr(C)]
struct ImageImportDescriptor {
    original_first_thunk: u32,
    time_date_stamp: u32,
    forwarder_chain: u32,
    name: u32,
    first_thunk: u32,
}

const IMAGE_NT_OPTIONAL_HDR32_MAGIC: u16 = 0x10b;  // PE32 only (32-bit Steam)

fn get_import_dir_rva(base: *const u8) -> Option<u32> {
    let dos = unsafe { &*(base as *const ImageDosHeader) };
    if dos.e_magic != 0x5A4D {
        return None;
    }
    let nt = unsafe { &*((base as usize + dos.e_lfanew as usize) as *const ImageNtHeaders32) };
    if nt.signature != 0x4550 {
        return None;
    }
    let magic = u16::from_le_bytes([nt.optional_header[0], nt.optional_header[1]]);
    if magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC {
        return None;
    }
    // DataDirectory[1] = Import (offset 104 in PE32 optional header)
    let data_dir_rva = u32::from_le_bytes([
        nt.optional_header[104],
        nt.optional_header[105],
        nt.optional_header[106],
        nt.optional_header[107],
    ]);
    let data_dir_size = u32::from_le_bytes([
        nt.optional_header[108],
        nt.optional_header[109],
        nt.optional_header[110],
        nt.optional_header[111],
    ]);
    if data_dir_size == 0 {
        return None;
    }
    Some(data_dir_rva)
}

#[inline]
fn rva_to_ptr(base: *const u8, rva: u32) -> *const u8 {
    (base as usize + rva as usize) as *const u8
}

/// Find IAT slot for a given DLL (name contains `dll_substring`) and function name. Returns (slot_ptr, original).
unsafe fn find_iat_slot(
    module_base: *const u8,
    dll_substring: &str,
    function_name: &str,
) -> Option<(*mut *const (), *const ())> {
    let import_rva = get_import_dir_rva(module_base)?;
    let mut desc = rva_to_ptr(module_base, import_rva) as *const ImageImportDescriptor;

    while (*desc).name != 0 {
        let dll_name_rva = (*desc).name;
        let name_ptr = rva_to_ptr(module_base, dll_name_rva);
        let name = std::ffi::CStr::from_ptr(name_ptr as *const i8);
        let name_str = name.to_string_lossy();
        if name_str.to_lowercase().contains(&dll_substring.to_lowercase()) {
            let oft = (*desc).original_first_thunk;
            let ft = (*desc).first_thunk;
            if oft == 0 {
                desc = desc.add(1);
                continue;
            }
            let mut thunk = rva_to_ptr(module_base, oft) as *const u32;
            let mut iat_entry = rva_to_ptr(module_base, ft) as *mut *const ();

            while *thunk != 0 {
                let hint_name_rva = *thunk;
                if (hint_name_rva & 0x8000_0000) != 0 {
                    thunk = thunk.add(1);
                    iat_entry = iat_entry.add(1);
                    continue;
                }
                let hint_name = rva_to_ptr(module_base, hint_name_rva);
                let import_name = std::ffi::CStr::from_ptr(hint_name.add(2) as *const i8);
                let import_name_str = import_name.to_string_lossy();
                if import_name_str == function_name {
                    return Some((iat_entry as *mut *const (), *iat_entry));
                }
                thunk = thunk.add(1);
                iat_entry = iat_entry.add(1);
            }
        }
        desc = desc.add(1);
    }
    None
}

/// Overwrite IAT entry with hook; return true on success.
unsafe fn hook_iat(
    module_base: *const u8,
    dll_substring: &str,
    function_name: &str,
    hook_fn: *const (),
) -> bool {
    let Some((slot, _)) = find_iat_slot(module_base, dll_substring, function_name) else {
        return false;
    };
    let mut old = PAGE_EXECUTE_READ;
    if VirtualProtect(
        slot as *const _,
        std::mem::size_of::<*const ()>(),
        PAGE_READWRITE,
        &mut old,
    )
    .is_err()
    {
        return false;
    }
    *slot = hook_fn;
    let _ = VirtualProtect(
        slot as *const _,
        std::mem::size_of::<*const ()>(),
        old,
        &mut old,
    );
    true
}

// --- Originals (from kernel32) ---

type LoadLibraryExWFn = unsafe extern "system" fn(PCWSTR, HANDLE, u32) -> HMODULE;
type GetProcAddressFn = unsafe extern "system" fn(HMODULE, PCSTR) -> FARPROC;
type GetSystemInfoFn = unsafe extern "system" fn(*mut SYSTEM_INFO) -> ();

static mut ORIGINAL_LOAD_LIBRARY_EX_W: Option<LoadLibraryExWFn> = None;
static mut ORIGINAL_GET_PROC_ADDRESS: Option<GetProcAddressFn> = None;
static mut ORIGINAL_GET_SYSTEM_INFO: Option<GetSystemInfoFn> = None;

// --- Hook implementations (original bypass behavior) ---

unsafe extern "system" fn hooked_load_library_ex_w(
    lp_lib_file_name: PCWSTR,
    h_file: HANDLE,
    dw_flags: u32,
) -> HMODULE {
    let real = ORIGINAL_LOAD_LIBRARY_EX_W.expect("hook before init");
    let module = real(lp_lib_file_name, h_file, dw_flags);
    if module.0.is_null() {
        return module;
    }
    let base = module.0 as *const u8;
    hook_iat(base, "kernel32", "GetProcAddress", hooked_get_proc_address as *const ());
    hook_iat(base, "kernel32", "GetSystemInfo", hooked_get_system_info as *const ());
    hook_iat(base, "kernel32", "GetVersionExA", hooked_get_version_ex_a as *const ());
    hook_iat(
        base,
        "kernel32",
        "GetSystemDirectoryW",
        hooked_get_system_directory_w as *const (),
    );
    hook_iat(
        base,
        "kernel32",
        "GetWindowsDirectoryW",
        hooked_get_windows_directory_w as *const (),
    );
    hook_iat(
        base,
        "kernel32",
        "GetCurrentProcessId",
        hooked_get_current_process_id as *const (),
    );
    hook_iat(
        base,
        "kernel32",
        "GetCurrentThreadId",
        hooked_get_current_thread_id as *const (),
    );
    module
}

unsafe extern "system" fn hooked_get_proc_address(h_module: HMODULE, lp_proc_name: PCSTR) -> FARPROC {
    let real = ORIGINAL_GET_PROC_ADDRESS.expect("hook before init");
    if lp_proc_name.0.is_null() {
        return real(h_module, lp_proc_name);
    }
    let name = std::ffi::CStr::from_ptr(lp_proc_name.0 as *const i8);
    let name_str = name.to_string_lossy();
    let hook = match name_str.as_ref() {
        "GetSystemInfo" => hooked_get_system_info as *const (),
        "GetVersionExA" => hooked_get_version_ex_a as *const (),
        "GetSystemDirectoryW" => hooked_get_system_directory_w as *const (),
        "GetWindowsDirectoryW" => hooked_get_windows_directory_w as *const (),
        "GetCurrentProcessId" => hooked_get_current_process_id as *const (),
        "GetCurrentThreadId" => hooked_get_current_thread_id as *const (),
        _ => return real(h_module, lp_proc_name),
    };
    Some(std::mem::transmute(hook))
}

unsafe extern "system" fn hooked_get_system_info(lp_system_info: *mut SYSTEM_INFO) {
    let real = ORIGINAL_GET_SYSTEM_INFO.expect("hook before init");
    real(lp_system_info);
    if !lp_system_info.is_null() {
        (*lp_system_info).dwPageSize = 1337;
    }
}

unsafe extern "system" fn hooked_get_version_ex_a(_lp_version_info: *mut std::ffi::c_void) -> BOOL {
    ExitProcess(1);
}

unsafe extern "system" fn hooked_get_system_directory_w(
    _lp_buffer: *mut u16,
    _u_size: u32,
) -> u32 {
    ExitProcess(1);
}

unsafe extern "system" fn hooked_get_windows_directory_w(
    _lp_buffer: *mut u16,
    _u_size: u32,
) -> u32 {
    ExitProcess(1);
}

unsafe extern "system" fn hooked_get_current_process_id() -> u32 {
    0
}

unsafe extern "system" fn hooked_get_current_thread_id() -> u32 {
    0
}

// --- Init ---

fn init_bypass() {
    unsafe {
        let mut kernel32 = HMODULE::default();
        if GetModuleHandleExW(
            GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            w!("kernel32.dll"),
            &mut kernel32,
        )
        .is_err()
        {
            return;
        }

        if let Some(gpa) = GetProcAddress(kernel32, windows::core::s!("GetProcAddress")) {
            ORIGINAL_GET_PROC_ADDRESS = Some(std::mem::transmute(gpa));
        }
        if let Some(gsa) = GetProcAddress(kernel32, windows::core::s!("GetSystemInfo")) {
            ORIGINAL_GET_SYSTEM_INFO = Some(std::mem::transmute(gsa));
        }

        let mut steam = HMODULE::default();
        if GetModuleHandleExW(
            GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            w!("steamservice.dll"),
            &mut steam,
        )
        .is_err()
        {
            return;
        }
        let base = steam.0 as *const u8;

        let mut mod_info = std::mem::zeroed();
        if GetModuleInformation(
            GetCurrentProcess(),
            steam,
            &mut mod_info,
            std::mem::size_of::<MODULEINFO>() as u32,
        )
        .is_err()
        {
            return;
        }
        let size = mod_info.SizeOfImage as usize;

        let je_addr = pattern_find_in_module(base, size, STEAMSERVICE_JE_PATTERN);
        if !je_addr.is_null() {
            patch_memory(je_addr, &[0xEB]);
        }

        if let Some((slot, original)) = find_iat_slot(base, "kernel32", "LoadLibraryExW") {
            ORIGINAL_LOAD_LIBRARY_EX_W = Some(std::mem::transmute(original));
            let mut old = PAGE_EXECUTE_READ;
            if VirtualProtect(
                slot as *const _,
                std::mem::size_of::<*const ()>(),
                PAGE_READWRITE,
                &mut old,
            )
            .is_ok()
            {
                *slot = hooked_load_library_ex_w as *const ();
                let _ = VirtualProtect(
                    slot as *const _,
                    std::mem::size_of::<*const ()>(),
                    old,
                    &mut old,
                );
            }
        }
    }
}

#[no_mangle]
#[allow(non_snake_case)]
unsafe extern "system" fn DllMain(
    _h_inst_dll: HANDLE,
    fdw_reason: u32,
    _lpv_reserved: *mut std::ffi::c_void,
) -> BOOL {
    const DLL_PROCESS_ATTACH: u32 = 1;
    if fdw_reason == DLL_PROCESS_ATTACH {
        init_bypass();
    }
    BOOL::from(true)
}

// --- Tests ---

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pattern_find_finds_steam_je() {
        let mut buf = vec![0u8; 256];
        let at = 40;
        buf[at..at + STEAMSERVICE_JE_PATTERN.len()].copy_from_slice(STEAMSERVICE_JE_PATTERN);
        let off = pattern_find(&buf, STEAMSERVICE_JE_PATTERN);
        assert_eq!(off, Some(at));
    }

    #[test]
    fn pattern_find_empty_miss() {
        assert!(pattern_find(&[], STEAMSERVICE_JE_PATTERN).is_none());
        assert!(pattern_find(&[0x74, 0x47], STEAMSERVICE_JE_PATTERN).is_none());
    }
}
