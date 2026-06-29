/*
 * peb.h - minimal, self-contained PEB / loader / PE structures and helpers for
 * a position-independent payload. No CRT, no imports: APIs are resolved at
 * runtime by walking the PEB module list and parsing export directories.
 *
 * x86-64 only.
 */
#ifndef PPLSYSTEM_PEB_H
#define PPLSYSTEM_PEB_H

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h> /* types and constants only - we never *call* an import */
#include <intrin.h>  /* __readgsqword */

/* ----- Loader structures (subset, offsets matched to ntdll) -------------- */

typedef struct _UNICODE_STRING_ {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING_;

typedef struct _LIST_ENTRY_ {
    struct _LIST_ENTRY_ *Flink;
    struct _LIST_ENTRY_ *Blink;
} LIST_ENTRY_;

typedef struct _PEB_LDR_DATA_ {
    ULONG       Length;
    UCHAR       Initialized;
    PVOID       SsHandle;
    LIST_ENTRY_ InLoadOrderModuleList;          /* +0x10 */
    LIST_ENTRY_ InMemoryOrderModuleList;        /* +0x20 */
    LIST_ENTRY_ InInitializationOrderModuleList;/* +0x30 */
} PEB_LDR_DATA_;

typedef struct _LDR_DATA_TABLE_ENTRY_ {
    LIST_ENTRY_     InLoadOrderLinks;           /* +0x00 */
    LIST_ENTRY_     InMemoryOrderLinks;         /* +0x10 */
    LIST_ENTRY_     InInitializationOrderLinks; /* +0x20 */
    PVOID           DllBase;                    /* +0x30 */
    PVOID           EntryPoint;                 /* +0x38 */
    ULONG           SizeOfImage;                /* +0x40 */
    UNICODE_STRING_ FullDllName;                /* +0x48 */
    UNICODE_STRING_ BaseDllName;                /* +0x58 */
} LDR_DATA_TABLE_ENTRY_;

typedef struct _PEB_ {
    UCHAR          Reserved[0x18];
    PEB_LDR_DATA_ *Ldr;                         /* +0x18 */
} PEB_;

/* ----- Tiny string helpers (ASCII + wide, case-insensitive) -------------- */

static char pl_lower(char c) {
    return (c >= 'A' && c <= 'Z') ? (char)(c + 32) : c;
}

/* Case-insensitive ASCII compare. */
static int pl_strieq(const char *a, const char *b) {
    while (*a && *b) {
        if (pl_lower(*a) != pl_lower(*b)) return 0;
        a++; b++;
    }
    return *a == *b;
}

/* Case-insensitive compare of a counted wide string against an ASCII literal. */
static int pl_wstrieq_a(const wchar_t *w, USHORT wlen_bytes, const char *a) {
    USHORT n = (USHORT)(wlen_bytes / sizeof(wchar_t));
    USHORT i;
    for (i = 0; i < n; i++) {
        char wc = (char)w[i];
        if (a[i] == 0) return 0;
        if (pl_lower(wc) != pl_lower(a[i])) return 0;
    }
    return a[n] == 0;
}

/* ----- Module / export resolution ---------------------------------------- */

/* Find a loaded module by base name (e.g. "kernel32.dll") via the PEB. */
static PVOID pl_find_module(const char *name) {
    PEB_ *peb = (PEB_ *)__readgsqword(0x60);
    LIST_ENTRY_ *head = &peb->Ldr->InLoadOrderModuleList;
    LIST_ENTRY_ *cur = head->Flink;
    while (cur != head) {
        LDR_DATA_TABLE_ENTRY_ *ent = (LDR_DATA_TABLE_ENTRY_ *)cur; /* InLoadOrderLinks @ +0 */
        if (ent->BaseDllName.Buffer &&
            pl_wstrieq_a(ent->BaseDllName.Buffer, ent->BaseDllName.Length, name)) {
            return ent->DllBase;
        }
        cur = cur->Flink;
    }
    return NULL;
}

/* Resolve an exported function by name from a module base (export table only;
   forwarders are not followed - none of the functions we need are forwarded). */
static FARPROC pl_get_proc(PVOID base, const char *name) {
    BYTE *b = (BYTE *)base;
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)b;
    IMAGE_NT_HEADERS64 *nt = (IMAGE_NT_HEADERS64 *)(b + dos->e_lfanew);
    IMAGE_DATA_DIRECTORY dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (dir.VirtualAddress == 0) return NULL;

    IMAGE_EXPORT_DIRECTORY *exp = (IMAGE_EXPORT_DIRECTORY *)(b + dir.VirtualAddress);
    DWORD *names = (DWORD *)(b + exp->AddressOfNames);
    WORD  *ords  = (WORD  *)(b + exp->AddressOfNameOrdinals);
    DWORD *funcs = (DWORD *)(b + exp->AddressOfFunctions);

    DWORD i;
    for (i = 0; i < exp->NumberOfNames; i++) {
        const char *fname = (const char *)(b + names[i]);
        if (pl_strieq(fname, name)) {
            return (FARPROC)(b + funcs[ords[i]]);
        }
    }
    return NULL;
}

#endif /* PPLSYSTEM_PEB_H */
