Function Get-NullSessionStatus {
<#
.SYNOPSIS
    Check if null session is allowed for IPC$ share on remote computer.
    Privileges required: none

    Author: Timothée MENOCHET (@_tmenochet)

.DESCRIPTION
    Get-NullSessionStatus attempts an anonymous logon on a remote host via SMB, simulating the command `net use \\%computer%\IPC$ "" /user:`.
    Please note this script does not check MS-RPC null sessions, further investigation should be performed for subsequent named pipe connections (MS-SAMR, MS-LSAT, etc.).

.PARAMETER ComputerName
    Specifies the target host.

.EXAMPLE
    PS C:\> Get-NullSessionStatus -ComputerName SRV.ADATUM.CORP
#>

    [CmdletBinding()]
    Param (
        [ValidateNotNullOrEmpty()]
        [string]
        $ComputerName = $env:COMPUTERNAME
    )

    $path = '\\' + $ComputerName + '\IPC$'
    $netResourceInstance = New-Object Mpr+NETRESOURCEW
    $netResourceInstance.dwType = 1
    $netResourceInstance.lpRemoteName = $path
    $result = [Mpr]::WNetAddConnection2W($netResourceInstance, '', '', [Mpr+AddFlags]::Temporary)
    [Mpr]::WNetCancelConnection2($path, [Mpr+CloseFlags]::None, $true) | Out-Null
    if ($result -eq 0) {
        Write-Output ([pscustomobject] @{ComputerName=$ComputerName; NullSession=$true})
    }
	else {
		Write-Verbose ([pscustomobject] @{ComputerName=$ComputerName; NullSession=$false})
	}
}

Add-Type @"
using System;
using System.Runtime.InteropServices;
public class Mpr {
    [DllImport("Mpr.dll", CharSet = CharSet.Unicode)]
    public static extern UInt32 WNetAddConnection2W(NETRESOURCEW lpNetResource, [MarshalAs(UnmanagedType.LPWStr)] string lpPassword, [MarshalAs(UnmanagedType.LPWStr)] string lpUserName, AddFlags dwFlags);
    [DllImport("Mpr.dll", CharSet = CharSet.Unicode)]
    public static extern UInt32 WNetCancelConnection2([MarshalAs(UnmanagedType.LPWStr)] string lpName, CloseFlags dwFlags, bool fForce);
    [Flags]
    public enum AddFlags : uint {
        UpdateProfile = 0x00000001,
        UpdateRecent = 0x00000002,
        Temporary = 0x00000004,
        Interactive = 0x00000008,
        Prompt = 0x00000010,
        Redirect = 0x00000080,
        CurrentMedia = 0x00000200,
        CommandLine = 0x00000800,
        CmdSaveCred = 0x00001000,
        CredReset = 0x00002000,
    }
    public enum CloseFlags : uint {
        None = 0x00000000,
        UpdateProfile = 0x00000001,
    }
    [Flags]
    public enum ResourceType : uint {
        Any = 0x0000000,
        Disk = 0x00000001,
        Print = 0x00000002,
        Reserved = 0x00000008,
        Unknown = 0xFFFFFFFF,
    }
    public enum ResourceScope : uint {
        Connected = 0x00000001,
        GlobalNet = 0x00000002,
        Remembered = 0x00000003,
        Recent = 0x00000004,
        Context = 0x00000005,
    }
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct NETRESOURCEW {
        public ResourceScope dwScope;
        public ResourceType dwType;
        public UInt32 dwDisplayType;
        public UInt32 dwUsage;
        [MarshalAs(UnmanagedType.LPWStr)] public string lpLocalName;
        [MarshalAs(UnmanagedType.LPWStr)] public string lpRemoteName;
        [MarshalAs(UnmanagedType.LPWStr)] public string lpComment;
        [MarshalAs(UnmanagedType.LPWStr)] public string lpProvider;
    }
}
"@