function Get-NetSession {
<#
.SYNOPSIS
    Get net sessions from a remote computer.
    Privileges required: low

    Author: Timothée MENOCHET (@_tmenochet)

.DESCRIPTION
    Get-NetSession queries remote host for net sessions (optionally matching a target user).
    It is a slightly modified version of PowerView's Get-NetSession by @harmj0y.

.PARAMETER ComputerName
    Specifies the host to query for net sessions.

.PARAMETER Credential
    Specifies the account to use.

.PARAMETER Identity
    Specifies a target user to look for in the net sessions.

.EXAMPLE
    PS C:\> Get-NetSession -Identity john.doe -ComputerName SRV.ADATUM.CORP -Credential ADATUM\testuser
#>

    Param(
        [ValidateNotNullOrEmpty()]
        [string]
        $ComputerName = $env:COMPUTERNAME,

        [ValidateNotNullOrEmpty()]
        [string]
        $Identity,

        [ValidateNotNullOrEmpty()]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    # arguments for NetSessionEnum
    $QueryLevel = 10
    $PtrInfo = [IntPtr]::Zero
    $EntriesRead = 0
    $TotalRead = 0
    $ResumeHandle = 0

    # get session information
    $Result = [Netapi32]::NetSessionEnum($ComputerName, '', $Identity, $QueryLevel, [ref]$PtrInfo, -1, [ref]$EntriesRead, [ref]$TotalRead, [ref]$ResumeHandle)

    # locate the offset of the initial intPtr
    $Offset = $PtrInfo.ToInt64()

    # 0 = success
    if (($Result -eq 0) -and ($Offset -gt 0)) {

        # work out how much to increment the pointer by finding out the size of the structure
        $SessionInfo10 = New-Object SESSION_INFO_10
        $SessionInfo10Size = [System.Runtime.InteropServices.Marshal]::SizeOf($SessionInfo10)
        $Increment = $SessionInfo10Size

        # parse all the result structures
        for ($i = 0; ($i -lt $EntriesRead); $i++) {
            # create a new int ptr at the given offset and cast the pointer as our result structure
            $NewIntPtr = New-Object System.Intptr -ArgumentList $Offset
            $Info = [System.Runtime.Interopservices.Marshal]::PtrToStructure($NewIntPtr,[type]$SessionInfo10.GetType())
            $obj = [pscustomobject] @{
                ComputerName = $ComputerName
                UserName = $Info.DomainUser
                SourceIPAddress = $Info.OriginatingHost.Trim('\\')
                SessionTime = $Info.SessionTime
                IdleTime = $Info.IdleTime
            }
            $Offset = $NewIntPtr.ToInt64()
            $Offset += $Increment
            Write-Output $obj
        }

        # free up the result buffer
        $Null = [Netapi32]::NetApiBufferFree($PtrInfo)
    }
    else {
        Write-Verbose "[Get-NetSession] Error: $(([ComponentModel.Win32Exception] $Result).Message)"
    }
}

$source = @"
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

[StructLayout(LayoutKind.Sequential)]
public struct SESSION_INFO_10
{
    [MarshalAs(UnmanagedType.LPWStr)]public string OriginatingHost;
    [MarshalAs(UnmanagedType.LPWStr)]public string DomainUser;
    public uint SessionTime;
    public uint IdleTime;
}

public static class Netapi32
{
    [DllImport("Netapi32.dll", SetLastError=true)]
    public static extern int NetSessionEnum(
        [In,MarshalAs(UnmanagedType.LPWStr)] string ServerName,
        [In,MarshalAs(UnmanagedType.LPWStr)] string UncClientName,
        [In,MarshalAs(UnmanagedType.LPWStr)] string UserName,
        Int32 Level,
        out IntPtr bufptr,
        int prefmaxlen,
        ref Int32 entriesread,
        ref Int32 totalentries,
        ref Int32 resume_handle);
            
    [DllImport("Netapi32.dll", SetLastError=true)]
    public static extern int NetApiBufferFree(
        IntPtr Buffer);
}
"@
Add-Type -TypeDefinition $source