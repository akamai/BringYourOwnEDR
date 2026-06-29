<#
.SYNOPSIS
    Compile the benign PIC payload (payload.c) into a statically-linked,
    zero-import PE image suitable for SEC_IMAGE mapping + remote-thread start.

.PARAMETER Toolchain
    msvc (default), clang or mingw.

.PARAMETER Source
    Payload source file (default: payload.c next to this script).

.PARAMETER Out
    Output PE path (default: ..\target.exe - where the orchestrator expects it).
#>
[CmdletBinding()]
param(
    [ValidateSet('msvc', 'clang', 'mingw')] [string]$Toolchain = 'msvc',
    [string]$Source,
    [string]$Out
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot '..\scripts\Common.psm1') -Force

if (-not $Source) { $Source = Join-Path $PSScriptRoot 'payload.c' }
if (-not $Out) { $Out = Join-Path (Split-Path $PSScriptRoot -Parent) 'target.exe' }

if (-not (Test-Path -LiteralPath $Source)) { throw "Payload source '$Source' not found." }
$Source = (Resolve-Path -LiteralPath $Source).Path

# Resolve $Out to an absolute path even though it does not exist yet.
if (-not [System.IO.Path]::IsPathRooted($Out)) {
    $Out = Join-Path (Get-Location).Path $Out
}
$Out = [System.IO.Path]::GetFullPath($Out)

Write-Host "[*] Building payload ($Toolchain): $Source -> $Out"

function Assert-NoImports-Dumpbin {
    param([string]$Text)
    # dumpbin prints this header only when an import directory exists.
    if ($Text -match 'following imports') {
        Write-Warning "Payload has an import table - it will NOT be position-independent enough for SEC_IMAGE injection. Imports:"
        Write-Host $Text
        throw "Payload is not self-contained (has imports)."
    }
    Write-Host "[+] Verified: payload has no import table."
}

switch ($Toolchain) {
    'msvc' {
        $vsdevcmd = Find-VsDevCmd
        # VsDevCmd.bat shells out to vswhere.exe; ensure the VS Installer dir is on
        # PATH inside the batch (a plain PowerShell 5.1 console often lacks it).
        $installerDir = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer'
        $obj = Join-Path $env:TEMP 'pplsystem_payload.obj'
        $bat = Join-Path $env:TEMP 'pplsystem_build_payload.bat'

        # cl needs %INCLUDE% (windows.h); link uses /NODEFAULTLIB (no CRT/LIB).
        # /GS- + /Gs9999999 avoid stack-cookie/__chkstk CRT references.
        # /FIXED strips relocations (the code is position-independent).
        # /MERGE + /SECTION keep everything the thread touches in one RWX region.
        $lines = @(
            '@echo off'
            "set `"PATH=$installerDir;%PATH%`""
            "call `"$vsdevcmd`" -arch=amd64 -host_arch=amd64 -no_logo || exit /b 1"
            "cl /nologo /c /O2 /GS- /Gs9999999 /TC /Fo`"$obj`" `"$Source`" || exit /b 1"
            ("link /nologo /NODEFAULTLIB /ENTRY:payload_main /SUBSYSTEM:WINDOWS " +
             "/MERGE:.rdata=.text /SECTION:.text,RWE /FIXED /OUT:`"$Out`" `"$obj`" || exit /b 1")
            "dumpbin /nologo /imports `"$Out`""
        )
        Set-Content -LiteralPath $bat -Value $lines -Encoding Ascii

        # Native stderr must not become a terminating error under PS 5.1 + Stop.
        $prevEap = $ErrorActionPreference
        $ErrorActionPreference = 'Continue'
        $output = & cmd /c "`"$bat`"" 2>&1 | Out-String
        $code = $LASTEXITCODE
        $ErrorActionPreference = $prevEap
        Remove-Item -LiteralPath $bat, $obj -ErrorAction SilentlyContinue
        if ($code -ne 0) {
            Write-Host $output
            throw "MSVC payload build failed (exit $code)."
        }
        Assert-NoImports-Dumpbin -Text $output
    }

    'clang' {
        Assert-Command clang "Install LLVM/Clang and ensure clang is on PATH."
        $clangArgs = @(
            '-target', 'x86_64-pc-windows-msvc', '-O2', '-ffreestanding', '-nostdlib',
            '-fno-stack-protector', '-fno-asynchronous-unwind-tables',
            '-Wl,/entry:payload_main', '-Wl,/subsystem:windows', '-Wl,/nodefaultlib',
            '-Wl,/fixed', '-Wl,/merge:.rdata=.text',
            '-o', $Out, $Source
        )
        & clang @clangArgs
        if ($LASTEXITCODE -ne 0) { throw "clang payload build failed." }
        if (Get-Command llvm-objdump -ErrorAction SilentlyContinue) {
            $imp = & llvm-objdump --private-headers "$Out" 2>&1 | Out-String
            if ($imp -match 'IMPORT Name Table') { Write-Warning "Payload appears to have imports." }
        }
        Write-Host "[+] clang build complete."
    }

    'mingw' {
        Assert-Command x86_64-w64-mingw32-gcc "Install MinGW-w64 and ensure the cross gcc is on PATH."
        $gccArgs = @(
            '-O2', '-ffreestanding', '-nostdlib',
            '-fno-stack-protector', '-fno-asynchronous-unwind-tables',
            '-e', 'payload_main', '-Wl,--entry=payload_main',
            '-nostartfiles', '-o', $Out, $Source
        )
        & x86_64-w64-mingw32-gcc @gccArgs
        if ($LASTEXITCODE -ne 0) { throw "MinGW payload build failed." }
        Write-Host "[+] MinGW build complete (verify it is position-independent before use)."
    }
}

if (-not (Test-Path -LiteralPath $Out)) { throw "Payload output '$Out' was not produced." }
Write-Host "[+] Payload ready: $Out"
