<#
.SYNOPSIS
    Shared helpers for the PPLSystem build and orchestration scripts:
    administrator/toolchain checks, Visual Studio discovery and small
    filesystem utilities.
#>

Set-StrictMode -Version Latest

function Assert-Administrator {
    [CmdletBinding()] param()
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($id)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "This script must be run from an elevated (Administrator) prompt."
    }
}

function Assert-Command {
    [CmdletBinding()] param(
        [Parameter(Mandatory)] [string]$Name,
        [string]$Hint
    )
    if (-not (Get-Command $Name -ErrorAction SilentlyContinue)) {
        $msg = "Required tool '$Name' was not found on PATH."
        if ($Hint) { $msg += " $Hint" }
        throw $msg
    }
}

function Find-VsInstallPath {
    <# Returns the latest Visual Studio install path with the C++ toolset, or $null. #>
    [CmdletBinding()] param()
    $vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
    if (-not (Test-Path -LiteralPath $vswhere)) { return $null }
    $path = & $vswhere -latest -products * `
        -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 `
        -property installationPath 2>$null
    if ($path) { return $path.Trim() }
    return $null
}

function Find-VsDevCmd {
    <# Returns the path to VsDevCmd.bat (the VS developer environment), or throws. #>
    [CmdletBinding()] param()
    $install = Find-VsInstallPath
    if (-not $install) {
        throw @"
A Visual Studio C++ toolset (cl.exe/link.exe) was not found.
Install 'Visual Studio Build Tools' with the 'Desktop development with C++' workload:
  winget install Microsoft.VisualStudio.2022.BuildTools
Or build the payload with -PayloadToolchain clang|mingw.
"@
    }
    $vsdevcmd = Join-Path $install 'Common7\Tools\VsDevCmd.bat'
    if (-not (Test-Path -LiteralPath $vsdevcmd)) { throw "VsDevCmd.bat not found under '$install'." }
    return $vsdevcmd
}

function Wait-ForFile {
    <#
    .SYNOPSIS
        Wait until a file exists and its size has stopped changing (i.e. the
        writer finished). Returns $true on success, $false on timeout.
    #>
    [CmdletBinding()] param(
        [Parameter(Mandatory)] [string]$Path,
        [int]$TimeoutSec = 30
    )
    $deadline = (Get-Date).AddSeconds($TimeoutSec)
    $lastSize = -1
    while ((Get-Date) -lt $deadline) {
        if (Test-Path -LiteralPath $Path) {
            $size = (Get-Item -LiteralPath $Path).Length
            if ($size -gt 0 -and $size -eq $lastSize) { return $true }
            $lastSize = $size
        }
        Start-Sleep -Milliseconds 300
    }
    return (Test-Path -LiteralPath $Path)
}

function New-RunDir {
    <# Create and return a fresh per-run scratch directory under %TEMP%. #>
    [CmdletBinding()] param()
    $stamp = (Get-Date).ToString('yyyyMMdd_HHmmss')
    $dir = Join-Path $env:TEMP "pplsystem\$stamp"
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
    return $dir
}

Export-ModuleMember -Function `
    Assert-Administrator, Assert-Command, `
    Find-VsInstallPath, Find-VsDevCmd, Wait-ForFile, New-RunDir
