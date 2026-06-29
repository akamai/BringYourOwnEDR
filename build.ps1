<#
.SYNOPSIS
    Build everything the orchestrator needs and stage it at the repo root.

    1. Builds the Cargo workspace (pplsystem.exe, shellcode.exe).
    2. Compiles the benign C payload statically (target.exe).
    3. Copies all three executables to the repo root.

.EXAMPLE
    ./build.ps1
    ./build.ps1 -Configuration Debug -PayloadToolchain clang
    ./build.ps1 -SkipPayload
#>
[CmdletBinding()]
param(
    [ValidateSet('Release', 'Debug')] [string]$Configuration = 'Release',
    # pe2shc (default): a normal PE converted to self-loading shellcode (handles
    #   imports + relocations, runs at any base). pic: the zero-import /FIXED blob.
    [ValidateSet('pe2shc', 'pic')] [string]$Payload = 'pe2shc',
    [ValidateSet('msvc', 'clang', 'mingw')] [string]$PayloadToolchain = 'msvc',
    [switch]$SkipPayload
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
Import-Module (Join-Path $root 'scripts\Common.psm1') -Force

Write-Host '=== PPLSystem build ===' -ForegroundColor Cyan

# --- 1. Rust workspace ----------------------------------------------------
Assert-Command cargo 'Install the Rust MSVC toolchain via https://rustup.rs'

$cargoArgs = @('build', '--workspace')
if ($Configuration -eq 'Release') { $cargoArgs += '--release' }

Write-Host "[*] cargo $($cargoArgs -join ' ')"
Push-Location $root
try {
    & cargo @cargoArgs
    if ($LASTEXITCODE -ne 0) { throw "cargo build failed (exit $LASTEXITCODE)." }
} finally {
    Pop-Location
}

$outDir = Join-Path $root ("target\" + $Configuration.ToLower())
$artifacts = @{
    'pplsystem.exe'   = (Join-Path $outDir 'pplsystem.exe')
    'shellcode.exe'   = (Join-Path $outDir 'shellcode.exe')
    'test-target.exe' = (Join-Path $outDir 'test-target.exe')
}
foreach ($name in $artifacts.Keys) {
    $src = $artifacts[$name]
    if (-not (Test-Path -LiteralPath $src)) { throw "Expected build artifact not found: $src" }
    Copy-Item -LiteralPath $src -Destination (Join-Path $root $name) -Force
}
Write-Host '[+] Staged pplsystem.exe, shellcode.exe and test-target.exe at repo root.'

# --- 2. C payload ---------------------------------------------------------
if (-not $SkipPayload) {
    if ($Payload -eq 'pe2shc') {
        Write-Host '[*] Building pe2shc payload (normal PE -> self-loading shellcode)...'
        & (Join-Path $root 'payload\build_payload_pe2shc.ps1') `
            -Out (Join-Path $root 'target.exe')
    } else {
        Write-Host "[*] Building PIC payload ($PayloadToolchain)..."
        & (Join-Path $root 'payload\build_payload.ps1') `
            -Toolchain $PayloadToolchain `
            -Out (Join-Path $root 'target.exe')
    }
    if ($LASTEXITCODE -ne 0) { throw "Payload build failed (exit $LASTEXITCODE)." }
    Write-Host '[+] Staged target.exe (payload) at repo root.'
} else {
    Write-Host '[!] -SkipPayload set: not (re)building target.exe.'
}

Write-Host ''
Write-Host '=== Build complete ===' -ForegroundColor Green
Write-Host 'Artifacts at repo root: pplsystem.exe, shellcode.exe, test-target.exe, target.exe'
Write-Host 'Next (elevated):  ./orchestrate.ps1 -Mode test     # safe CFG-enabled MTA target'
