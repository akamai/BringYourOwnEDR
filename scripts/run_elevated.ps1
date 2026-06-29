<#
.SYNOPSIS
    Convenience runner: launch orchestrate.ps1 elevated (one UAC prompt) and
    capture the full output to last_run.log at the repo root.

.DESCRIPTION
    The injection chain needs Administrator. This wrapper relaunches itself
    elevated, runs the orchestrator with the given parameters, tees everything to
    <repo>\last_run.log, and (in the original window) prints that log when the
    elevated run finishes - so the result is easy to review even though the
    elevated console closes.

.EXAMPLE
    pwsh -NoProfile -ExecutionPolicy Bypass -File scripts\run_elevated.ps1 -Mode test
    pwsh -NoProfile -ExecutionPolicy Bypass -File scripts\run_elevated.ps1 -Mode regedit
#>
[CmdletBinding()]
param(
    [ValidateSet('regedit', 'test', 'ppl')] [string]$Mode = 'test',
    [string]$TargetPid,
    [string]$ProcessName,
    [switch]$KeepProofFile
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$log = Join-Path $root 'last_run.log'

# Forward to orchestrate.ps1 via HASHTABLE splatting (binds by name). An array
# splat would bind positionally and pass '-Mode' as a literal value.
$fwd = @{ Mode = $Mode }
if ($TargetPid)     { $fwd.TargetPid = $TargetPid }
if ($ProcessName)   { $fwd.ProcessName = $ProcessName }
if ($KeepProofFile) { $fwd.KeepProofFile = $true }
$fwdDisplay = "-Mode $Mode" +
    $(if ($TargetPid)     { " -TargetPid $TargetPid" }) +
    $(if ($ProcessName)   { " -ProcessName $ProcessName" }) +
    $(if ($KeepProofFile) { ' -KeepProofFile' })

$principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
$isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Host '[*] Not elevated - relaunching with UAC. Approve the prompt...' -ForegroundColor Yellow
    $childArgs = @(
        '-NoProfile', '-ExecutionPolicy', 'Bypass',
        '-File', "`"$PSCommandPath`"",
        '-Mode', $Mode
    )
    if ($TargetPid)      { $childArgs += @('-TargetPid', $TargetPid) }
    if ($ProcessName)    { $childArgs += @('-ProcessName', $ProcessName) }
    if ($KeepProofFile)  { $childArgs += '-KeepProofFile' }

    Start-Process -FilePath (Get-Process -Id $PID).Path -Verb RunAs -ArgumentList $childArgs -Wait | Out-Null
    Write-Host ''
    Write-Host "===== last_run.log (elevated: orchestrate.ps1 $fwdDisplay) =====" -ForegroundColor Cyan
    if (Test-Path -LiteralPath $log) { Get-Content -LiteralPath $log } else { Write-Warning "No log produced at $log" }
    return
}

# Elevated branch: run the orchestrator under a transcript so EVERYTHING (incl.
# Write-Host and a terminating throw) is captured incrementally to the log - a
# bare `... *>&1 | Tee` loses buffered output when the script throws.
try { Stop-Transcript -ErrorAction SilentlyContinue | Out-Null } catch {}
Start-Transcript -LiteralPath $log -Force | Out-Null
try {
    & (Join-Path $root 'orchestrate.ps1') @fwd
} catch {
    Write-Host "[run_elevated] EXCEPTION: $($_.Exception.Message)"
    Write-Host "[run_elevated] $($_.ScriptStackTrace)"
} finally {
    Stop-Transcript | Out-Null
}
