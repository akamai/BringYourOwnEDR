//! Benign MTA COM **test target** for the injection PoC.
//!
//! Why this exists: a real PPL target (MsMpEng) crashes when our injected thread
//! faults on start, and idle STA GUI apps (regedit) don't service IRundown. This
//! process:
//!   * initialises a **multi-threaded apartment**;
//!   * **generates its COM process secret** (`s_guidOle32Secret`) by marshalling
//!     its context envoy via `IMarshalEnvoy` - the exact value the injector reads
//!     back (just `CoInitializeEx` / marshalling a free-threaded `IStream` does
//!     NOT generate it);
//!   * marshals an interface so RPCSS registers an OXID / serviceable IRundown;
//!   * is **not protected**, so the injector reads its secret/context live;
//!   * is built with **Control Flow Guard enabled** (see `.cargo/config.toml`),
//!     reproducing MsMpEng's CFG mitigation.
//!
//! So you can develop and validate map -> execute -> CFG-bypass against this,
//! crashing it freely, without ever touching a real protected process.

#![allow(non_snake_case)]

use std::ffi::c_void;
use std::{thread, time::Duration};

use windows::core::*;
use windows::Win32::System::Com::Marshal::CoMarshalInterface;
use windows::Win32::System::Com::{
    CoGetObjectContext, CoInitializeEx, IStream, COINIT_MULTITHREADED, MSHCTX, MSHCTX_INPROC,
    MSHCTX_LOCAL, MSHLFLAGS_NORMAL,
};
use windows::Win32::System::LibraryLoader::LoadLibraryA;
use windows::Win32::UI::Shell::SHCreateMemStream;

// The same interface `locate.rs` uses. Marshalling the context envoy is what
// makes combase generate this process's `s_guidOle32Secret`.
#[interface("000001c8-0000-0000-C000-000000000046")]
unsafe trait IMarshalEnvoy: IUnknown {
    fn GetEnvoyUnmarshalClass(&self, dwDestContext: u32, pclsid: *mut GUID) -> HRESULT;
    fn GetEnvoySizeMax(&self, dwDestContext: u32, pcb: *mut u32) -> HRESULT;
    fn MarshalEnvoy(&self, pstm: *mut c_void, dwDestContext: MSHCTX) -> HRESULT;
}

fn main() {
    unsafe {
        CoInitializeEx(None, COINIT_MULTITHREADED).expect("CoInitializeEx(MTA) failed");

        // 0) Load the DLLs whose `.data` tails the injector uses as scratch, so
        //    those addresses are valid here (a real target like MsMpEng already
        //    has them loaded; this minimal process otherwise would not).
        for dll in [
            "combase.dll\0",
            "rpcrt4.dll\0",
            "kernel32.dll\0",
            "ntdll.dll\0",
            "shell32.dll\0",
            "win32u.dll\0",
            "bcryptprimitives.dll\0",
            "user32.dll\0",
            "advapi32.dll\0",
        ] {
            let _ = LoadLibraryA(PCSTR(dll.as_ptr()));
        }

        // 1) Generate this process's COM secret by marshalling our context envoy.
        match CoGetObjectContext::<IMarshalEnvoy>() {
            Ok(envoy) => {
                let stream: IStream = SHCreateMemStream(None).expect("SHCreateMemStream(envoy)");
                let hr = envoy.MarshalEnvoy(stream.as_raw(), MSHCTX_INPROC);
                if hr.is_err() {
                    eprintln!("[test-target] MarshalEnvoy returned {hr:?}");
                }
            }
            Err(e) => eprintln!("[test-target] CoGetObjectContext(IMarshalEnvoy) failed: {e}"),
        }

        // 2) Register an OXID / serviceable IRundown by marshalling an interface.
        let obj: IStream = SHCreateMemStream(None).expect("SHCreateMemStream(obj)");
        let into: IStream = SHCreateMemStream(None).expect("SHCreateMemStream(into)");
        CoMarshalInterface(
            &into,
            &IStream::IID,
            &obj,
            MSHCTX_LOCAL.0 as u32,
            None,
            MSHLFLAGS_NORMAL.0 as u32,
        )
        .expect("CoMarshalInterface failed");

        println!(
            "[test-target] ready - PID {}, MTA COM apartment with secret + registered OXID.",
            std::process::id()
        );
        println!(
            "[test-target] leave this running, then inject with:  ./orchestrate.ps1 -Mode test"
        );

        loop {
            thread::sleep(Duration::from_secs(3600));
        }
    }
}
