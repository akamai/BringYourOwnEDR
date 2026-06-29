<#
.SYNOPSIS
    Elevated diagnostic: map the payload into a fresh test-target, then attach
    cdb to the target and dump the real page state at the mapped base. Logs
    everything to <repo>\diag.log. Self-elevates (one UAC prompt).
#>
[CmdletBinding()]
param([string]$Shellcode = 'target.exe')

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$log = Join-Path $root 'diag.log'

$principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host '[*] Relaunching elevated - approve UAC...' -ForegroundColor Yellow
    $a = @('-NoProfile','-ExecutionPolicy','Bypass','-File',"`"$PSCommandPath`"",'-Shellcode',$Shellcode)
    Start-Process -FilePath (Get-Process -Id $PID).Path -Verb RunAs -ArgumentList $a -Wait | Out-Null
    if (Test-Path $log) { Get-Content $log } else { Write-Warning "no $log" }
    return
}

Start-Transcript -LiteralPath $log -Force | Out-Null
try {
    $exe = Join-Path $root 'test-target.exe'
    $ppl = Join-Path $root 'pplsystem.exe'
    $sc  = Join-Path $root $Shellcode

    Write-Host "[*] launching test-target"
    $proc = Start-Process -FilePath $exe -PassThru -WindowStyle Minimized
    Start-Sleep -Seconds 2
    $tpid = $proc.Id
    Write-Host "[*] test-target PID $tpid"

    Write-Host "`n=== Stage 1: map ==="
    $mapOut = & $ppl --target regedit --pid $tpid --shellcode $sc 2>&1 | Out-String
    Write-Host $mapOut
    $base = if ($mapOut -match 'mapped-base:\s*(0x[0-9A-Fa-f]+)') { $Matches[1] } else { '0x140000000' }
    Write-Host "[*] base = $base"

    $cdb = Get-ChildItem "$env:ProgramFiles\WindowsApps\Microsoft.WinDbg_*\amd64\cdb.exe" -ErrorAction SilentlyContinue |
           Sort-Object FullName -Descending | Select-Object -First 1
    if (-not $cdb) {
        $cdb = Get-ChildItem "${env:ProgramFiles(x86)}\Windows Kits\10\Debuggers\x64\cdb.exe" -ErrorAction SilentlyContinue | Select-Object -First 1
    }
    if ($cdb) {
        Write-Host "`n=== cdb probe of $base in PID $tpid (cdb: $($cdb.FullName)) ==="
        $b = [Convert]::ToInt64($base.Substring(2), 16)
        $p1 = '0x{0:x}' -f ($b + 0x1000)   # .text
        $p5 = '0x{0:x}' -f ($b + 0x5000)   # .overlay (pe2shc stub)
        $cmds = "!vprot $base; !vprot $p1; db $p1 L10; !vprot $p5; db $p5 L10; .detach; q"
        & $cdb.FullName -p $tpid -c $cmds 2>&1 | Out-String | Write-Host
    } else {
        Write-Host "[!] cdb not found"
    }

    Stop-Process -Id $tpid -Force -ErrorAction SilentlyContinue
} catch {
    Write-Host "EXCEPTION: $($_.Exception.Message)"
    Write-Host $_.ScriptStackTrace
} finally {
    Stop-Transcript | Out-Null
}
