# PPLSystem — COM-remoting process injection PoC

A proof-of-concept that injects unsigned code into another process using James
Forshaw's **IRundown `DoCallback`** COM-remoting technique. It is a cleaned-up,
documented fork of [PPLSystem](https://blog.slowerzs.net/posts/pplsystem) and
demonstrates two targets:

| Mode | Target | Secret/context source | Needs |
| --- | --- | --- | --- |
| **`regedit`** (default) | a normal COM process (regedit.exe) | read directly via `ReadProcessMemory` | Admin only |
| **`ppl`** (advanced) | a PPL process (e.g. MsMpEng / Defender) | read natively from a livedump (no debugger) | Admin + SentinelHelper COM |

The bundled payload is **benign**: when it runs inside the target it writes
`C:\Users\Public\inject_proof.txt` (containing the host PID) and pops a
MessageBox — nothing else. It exists only to prove that code executed.

---

## ⚠️ Legal / authorized-use notice

This is an **educational security-research tool**. The underlying technique is
public and well documented (links under *Credits*). Use it **only** on systems
you own or are explicitly authorized in writing to test (your own VM, a CTF, a
sanctioned red-team engagement). Process injection into protected processes and
into software you do not own may be illegal and may violate the terms of your
EDR/AV. **You are solely responsible for how you use this.** The authors provide
it "as is" with no warranty (see `LICENSE`).

---

## How it works (short version)

1. **Locate the target's COM identity.** Every COM-initialized process exposes
   an `IRundown` interface registered in RpcSs. By forging a marshaled `OBJREF`
   pointing at the target's OXID/IPID and unmarshaling it locally, we get a proxy
   whose calls execute *inside the target*.
2. **Turn `DoCallback` into an arbitrary-call primitive.** `IRundown::DoCallback`
   invokes `pfnCallback(pParam)` in the target as long as the supplied
   `guidProcessSecret` matches the target's COM secret. Pointing `pfnCallback` at
   `CStdStubBuffer_AddRef` lets us read/increment arbitrary qwords; pointing it at
   `NdrServerCall2` with a hand-built `RPC_MESSAGE` lets us call arbitrary native
   functions (`NtOpenProcess`, `NtDuplicateObject`, `NtMapViewOfSection`,
   `NtProtectVirtualMemory`, `NtCreateThreadEx`).
3. **Get the secret + context.** For a normal process we read
   `combase!CProcessSecret::s_guidOle32Secret` and `combase!g_pMTAEmptyCtx`
   straight out of the target's memory (they live at a fixed address per boot).
   For a PPL process we can't read its memory, so we livedump it and read those
   globals straight out of the dump with a small native minidump parser
   (`crates/core/src/minidump.rs`) — no debugger required.
4. **Map + run (one COM session).** `pplsystem.exe --execute` maps the payload as
   a `SEC_IMAGE` section at its preferred base, makes the **first page** (the PE
   headers) executable with `NtProtectVirtualMemory` — the sections are already
   mapped executable — and starts a thread, all inside a single warmed-up COM
   session. The default payload is **pe2shc** shellcode (see *Payload* below): the
   thread starts at the **image base (offset 0)**, where a redirect jumps to an
   appended self-loading stub that fixes up imports and relocations before calling
   the real entry point.

   > Notes from getting this reliable: the section is mapped at the PE's
   > **preferred base** (no kernel relocation; the stub self-relocates); only the
   > **first page** is re-protected (a whole-image `NtProtect` spans the
   > read-only-headers and copy-on-write-sections regions and fails remotely); and
   > map+protect+thread run in **one process** (a cold second process's
   > `NtProtect` intermittently no-ops). `shellcode.exe` remains as a standalone
   > stage-2 tool but is no longer used by the orchestrator.

### Payload

The bundled `target.exe` is produced from an ordinary C program
(`payload/payload_pe2shc.c`) and converted to self-loading shellcode with
[**pe2shc**](https://github.com/hasherezade/pe_to_shellcode) (hasherezade):

```
payload_pe2shc.c
  --cl/link-->  normal PE   (relocations + kernel32/user32 imports, NOT /FIXED)
  --pe2shc-->   *.shc.exe   (loader stub appended; redirect written into the PE
                             header; sections realigned so raw == virtual)
  --editor-->   target.exe  (tools/shellcode_editor.py adds a .overlay section so
                             the appended stub is mapped, and marks sections RWX)
```

Because the pe2shc stub relocates and resolves imports at runtime, the payload can
be a normal PE — it does **not** have to be hand-written position-independent code.
`orchestrate.ps1` auto-detects a pe2shc payload (header begins `4D 5A 45 52 E8`)
and tells `shellcode.exe` to start at the base via `--from-base`.

A self-contained, zero-import **PIC** payload (`payload/payload.c`) is also kept;
build it with `./build.ps1 -Payload pic`. It must be started at
`base + AddressOfEntryPoint` (the orchestrator handles this automatically).

---

## Prerequisites

* **Windows 10/11 x64**, run **as Administrator** (the chain needs
  `SeDebugPrivilege` and to read RpcSs / open the target).
* **Rust (MSVC toolchain)** — install from <https://rustup.rs>. The default
  `x86_64-pc-windows-msvc` target is what you want.
* **Visual Studio Build Tools** with **Desktop development with C++** (provides
  `cl.exe` / `link.exe` for the payload, and the linker Rust uses):
  ```powershell
  winget install Microsoft.VisualStudio.2022.BuildTools
  ```
* **`pe2shc.exe`** at the repo root — the pe2shc converter for the default
  payload. A prebuilt copy is shipped here; you can rebuild it from
  [pe_to_shellcode](https://github.com/hasherezade/pe_to_shellcode). (Not needed
  if you only build the PIC payload with `-Payload pic`.)
* **Python 3** on `PATH` — `tools/shellcode_editor.py` finalises the pe2shc
  payload. (Also only needed for the default pe2shc payload.)
* **Internet access** on first run — the tools download `combase.pdb` / `rpcss.pdb`
  symbols from the Microsoft symbol server to resolve a couple of globals.

### Only needed for advanced **`ppl`** mode
* The **SentinelHelper COM** component present on the host (a SentinelOne agent
  component) to perform the PPL livedump. The COM secret/context are then read
  natively from the dump — no debugger (cdb) or Python required.

---

## Build

```powershell
./build.ps1
```

This builds the Cargo workspace, builds the payload (pe2shc by default), and
stages `pplsystem.exe`, `shellcode.exe`, `test-target.exe` and `target.exe` at
the repo root.

Options:
```powershell
./build.ps1 -Configuration Debug
./build.ps1 -Payload pic                 # build the zero-import PIC payload instead
./build.ps1 -Payload pic -PayloadToolchain clang   # PIC via clang (or mingw)
./build.ps1 -SkipPayload                 # don't rebuild target.exe
```

You can sanity-check the payload locally (no admin) — it maps `target.exe` as a
`SEC_IMAGE` section and runs it in-process:
```powershell
./target/release/exec-test.exe target.exe from0   # 'from0' for a pe2shc payload
```

## Run — inject into regedit (default)

From an **elevated** PowerShell:

```powershell
./orchestrate.ps1 -Mode regedit
```

It launches regedit if needed, reads its COM secret/context, maps the payload,
prints the mapped base, executes it, and then verifies success by reading
`C:\Users\Public\inject_proof.txt`. Expected tail:

```
[+] SUCCESS — payload executed inside the target.
[+] C:\Users\Public\inject_proof.txt => Injected into PID <regedit pid>
```

Target a specific instance:
```powershell
./orchestrate.ps1 -Mode regedit -TargetPid 1234
```

## Run — advanced PPL mode

```powershell
./orchestrate.ps1 -Mode ppl -ProcessName MsMpEng
./orchestrate.ps1 -Mode ppl MsMpEng              # process name is positional too
```
Requires only the SentinelHelper component (see prerequisites). It livedumps the
target and reads the COM secret/context natively from the dump — no debugger. The
livedump may briefly freeze the machine. (Tip: add `-WhatIf`-style validation by
running `pplsystem.exe --target ppl --dump <user.dmp> --dry-run` to print the
resolved secret/context without injecting.)

---

## Repository layout

```
Cargo.toml                 Workspace manifest
build.ps1                  Build everything + stage artifacts at repo root
orchestrate.ps1            End-to-end driver (regedit | ppl)
pe2shc.exe                 pe2shc converter (used to build the default payload)
crates/
  core/                    pplsystem_core: IRundown primitive, locator, minidump + dump parsers
  map-exe/                 -> pplsystem.exe (maps the image, prints the base)
  run-from-memory/         -> shellcode.exe (protects + executes; --from-base for pe2shc)
  exec-test/               -> exec-test.exe (local, non-elevated map+run harness)
  test-target/             -> test-target.exe (benign MTA COM target for -Mode test)
  endian_codec/            vendored fork (adds usize/isize + generic array impls)
payload/
  payload_pe2shc.c         Benign payload built as a normal PE -> pe2shc shellcode (default)
  build_payload_pe2shc.ps1 Default payload pipeline (cl/link -> pe2shc -> shellcode_editor)
  payload.c, peb.h         Benign zero-import PIC payload (alternative, -Payload pic)
  build_payload.ps1        PIC payload build (msvc | clang | mingw)
scripts/
  Common.psm1              VS toolchain discovery, admin checks, helpers
  run_elevated.ps1         Self-elevating runner: runs orchestrate.ps1 + logs to last_run.log
tools/
  shellcode_editor.py      Adds the .overlay section + RWX for a pe2shc payload
  pe2shc.exe               Self-built pe2shc (fallback if the repo-root one is absent)
```

---

## Troubleshooting

* **"failed finding IPID/OXID … has most likely not initialised COM"** — the
  target hasn't created an `IRundown`. regedit does this at startup; give it a
  moment, or interact with it once. The orchestrator retries automatically.
* **"NULL MTA context"** — same cause; the target hasn't fully initialised COM yet.
* **"cdb.exe not found"** — only matters for `ppl` mode. Install Debugging Tools
  for Windows or pass `-CdbPath`.
* **Symbol download fails** — ensure outbound HTTPS to `msdl.microsoft.com`.
* **pe2shc: "The PE must have relocations!"** — the payload PE was linked without
  a relocation table. The default payload forces relocations via a file-scope
  pointer array; if you customise it, keep some global absolute-address data and
  do **not** link `/FIXED`.
* **`pe2shc.exe` / Python not found** — only the default pe2shc payload needs
  them. Put `pe2shc.exe` at the repo root (or pass `-Pe2shc`), ensure Python 3 is
  on `PATH`, or build the PIC payload with `./build.ps1 -Payload pic`.
* **Proof marker didn't appear** — first reproduce locally with
  `exec-test.exe target.exe from0`. If that works but injection doesn't, the issue
  is injection-specific (COM secret/context, OXID), not the payload. For the PIC
  payload, also confirm `dumpbin /imports target.exe` is empty.

---

## Credits

* **[Slowerzs](https://blog.slowerzs.net/posts/pplsystem)** — the original PPLSystem PoC and write-up.
* **[James Forshaw / Project Zero](https://googleprojectzero.blogspot.com/2018/11/injecting-code-into-windows-protected.html)** — injecting code into Windows protected processes via COM remoting.
* **[modexp](https://github.com/mdsecactivebreach/com_inject/)** — `com_inject` implementation.
* **[Axel Souchet (0vercl0k)](https://github.com/0vercl0k/kdmp-parser)** — `kdmp-parser`.
* **endian_codec** by Sylwester Rąpała.

## License

MIT — see [`LICENSE`](LICENSE). Upstream copyright © 2024 Slowerzs is preserved.
