<#
.SYNOPSIS
    Build the benign payload as a NORMAL PE (relocations + imports), then convert
    it to self-loading shellcode with pe2shc (hasherezade's pe_to_shellcode) and
    finalise it for SEC_IMAGE injection.

    Pipeline:
      payload_pe2shc.c
        --cl/link-->  payload_pe2shc.exe   (reloc + imports, NOT /FIXED)
        --pe2shc-->   *.shc.exe            (realigned, loader stub appended,
                                            redirect written into the PE header)
        --editor-->   <Out>                (.overlay section for the stub +
                                            every section RWX, SizeOfImage bumped)

    The result is mapped as SEC_IMAGE by the injector, made RWX, and a thread is
    started at the IMAGE BASE (offset 0) - the redirect there jumps to the stub,
    which loads imports/relocations/TLS and calls payload_entry.

.PARAMETER Source   payload source (default: payload_pe2shc.c next to this script)
.PARAMETER Out      final PE the injector maps (default: ..\target.exe)
.PARAMETER Pe2shc   pe2shc.exe path (default: repo-root pe2shc.exe, else tools\pe2shc.exe)
.PARAMETER KeepIntermediate  keep the .exe / .shc.exe intermediates for inspection
#>
[CmdletBinding()]
param(
    [string]$Source,
    [string]$Out,
    [string]$Pe2shc,
    [switch]$KeepIntermediate
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot '..\scripts\Common.psm1') -Force

$repoRoot = Split-Path $PSScriptRoot -Parent
if (-not $Source) { $Source = Join-Path $PSScriptRoot 'payload_pe2shc.c' }
if (-not $Out)    { $Out    = Join-Path $repoRoot 'target.exe' }

if (-not (Test-Path -LiteralPath $Source)) { throw "Payload source '$Source' not found." }
$Source = (Resolve-Path -LiteralPath $Source).Path
if (-not [System.IO.Path]::IsPathRooted($Out)) { $Out = Join-Path (Get-Location).Path $Out }
$Out = [System.IO.Path]::GetFullPath($Out)

# Locate pe2shc.exe: explicit -Pe2shc, else repo root, else tools\.
if (-not $Pe2shc) {
    foreach ($cand in @((Join-Path $repoRoot 'pe2shc.exe'), (Join-Path $repoRoot 'tools\pe2shc.exe'))) {
        if (Test-Path -LiteralPath $cand) { $Pe2shc = $cand; break }
    }
}
if (-not $Pe2shc -or -not (Test-Path -LiteralPath $Pe2shc)) {
    throw "pe2shc.exe not found. Put it in the repo root or pass -Pe2shc <path>. (Build it from https://github.com/hasherezade/pe_to_shellcode)"
}
$Pe2shc = (Resolve-Path -LiteralPath $Pe2shc).Path

$editor = Join-Path $repoRoot 'tools\shellcode_editor.py'
if (-not (Test-Path -LiteralPath $editor)) { throw "tools\shellcode_editor.py not found." }
$python = Get-Command python -ErrorAction SilentlyContinue
if (-not $python) { $python = Get-Command py -ErrorAction SilentlyContinue }
if (-not $python) { throw "Python 3 not found on PATH (needed for shellcode_editor.py)." }

Write-Host "[*] pe2shc payload build: $Source -> $Out"
Write-Host "[*] using pe2shc: $Pe2shc"

$work    = Join-Path $env:TEMP 'pplsystem_pe2shc'
New-Item -ItemType Directory -Force -Path $work | Out-Null
$obj     = Join-Path $work 'payload_pe2shc.obj'
$exe     = Join-Path $work 'payload_pe2shc.exe'
$shc     = Join-Path $work 'payload_pe2shc.shc.exe'
$bat     = Join-Path $work 'build.bat'

$vsdevcmd = Find-VsDevCmd
# VsDevCmd.bat shells out to vswhere.exe; make sure the VS Installer directory
# (vswhere's home) is on PATH inside the batch. A plain Windows PowerShell 5.1
# console often lacks it, so VsDevCmd fails with "'vswhere.exe' is not recognized".
$installerDir = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer'

# Native tools (cmd/cl/link, pe2shc, python) write to stderr; under Windows
# PowerShell 5.1 with -ErrorActionPreference Stop that becomes a terminating
# NativeCommandError even with 2>&1. Use Continue here and rely on exit codes.
$ErrorActionPreference = 'Continue'

# Compile + link a NORMAL PE: relocations (/DYNAMICBASE, NO /FIXED) so pe2shc
# accepts it, and an import table (kernel32/user32) that the stub resolves.
$lines = @(
    '@echo off'
    "set `"PATH=$installerDir;%PATH%`""
    "call `"$vsdevcmd`" -arch=amd64 -host_arch=amd64 -no_logo || exit /b 1"
    "cl /nologo /c /O2 /GS- /TC /Fo`"$obj`" `"$Source`" || exit /b 2"
    ("link /nologo /NODEFAULTLIB /ENTRY:payload_entry /SUBSYSTEM:WINDOWS /DYNAMICBASE " +
     "kernel32.lib user32.lib /OUT:`"$exe`" `"$obj`" || exit /b 3")
)
Set-Content -LiteralPath $bat -Value $lines -Encoding Ascii
$buildOut = & cmd /c "`"$bat`"" 2>&1 | Out-String
if ($LASTEXITCODE -ne 0) { Write-Host $buildOut; throw "MSVC payload build failed (exit $LASTEXITCODE).`n$buildOut" }
if (-not (Test-Path -LiteralPath $exe)) { throw "Compiler did not produce $exe." }
Write-Host "[+] compiled $([System.IO.Path]::GetFileName($exe))"

# pe2shc: PE -> shellcode (appends loader stub, writes the header redirect, realigns).
& $Pe2shc "$exe" "$shc" | Write-Host
if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $shc)) {
    throw "pe2shc failed (exit $LASTEXITCODE). Note: the input PE MUST have relocations."
}
Write-Host "[+] pe2shc -> $([System.IO.Path]::GetFileName($shc))"

# shellcode_editor: add the .overlay section (so the appended stub is mapped by
# SEC_IMAGE) and set every section RWX (so the stub can patch reloc/IAT in place).
& $python.Source "$editor" "$shc" "$Out" | Write-Host
if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $Out)) {
    throw "shellcode_editor.py failed (exit $LASTEXITCODE)."
}

if (-not $KeepIntermediate) {
    Remove-Item -LiteralPath $obj, $exe, $shc, $bat -ErrorAction SilentlyContinue
}
Write-Host "[+] pe2shc payload ready: $Out"
Write-Host "[i] The injector must start the thread at the IMAGE BASE (offset 0), not the entry point."
