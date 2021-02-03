Function Get-SecurityService {
<#
.SYNOPSIS
    Detect security services on remote computer.
    Privileges required: low

    Author: Timothée MENOCHET (@_tmenochet)

.DESCRIPTION
    Get-SecurityService enumerates Windows services related to security products on a remote host.
    It is a PowerShell implementation of PingCastle's AntivirusScanner by @mysmartlogon.

.PARAMETER ComputerName
    Specifies the target host.

.EXAMPLE
    PS C:\> Get-SecurityService -ComputerName DC.ADATUM.CORP
#>

    [CmdletBinding()]
    Param (
        [ValidateNotNullOrEmpty()]
        [string]
        $ComputerName = $env:COMPUTERNAME
    )

    $serviceDict = @{
        "avast! Antivirus"                                  = "Avast"
        "aswBcc"                                            = "Avast"
        "Avast Business Console Client Antivirus Service"   = "Avast"
        "epag"                                              = "Bitdefender Endpoint Agent"
        "EPIntegrationService"                              = "Bitdefender Endpoint Integration Service"
        "EPProtectedService"                                = "Bitdefender Endpoint Protected Service"
        "epredline"                                         = "Bitdefender Endpoint Redline Services"
        "EPSecurityService"                                 = "Bitdefender Endpoint Security Service"
        "EPUpdateService"                                   = "Bitdefender Endpoint Update Service"
        "CarbonBlack"                                       = "Carbon Black"
        "carbonblackk"                                      = "Carbon Black"
        "cbstream"                                          = "Carbon Black"
        "CSFalconService"                                   = "CrowdStrike Falcon Sensor Service"
        "CylanceSvc"                                        = "Cylance"
        "epfw"                                              = "ESET"
        "epfwlwf"                                           = "ESET"
        "epfwwfp"                                           = "ESET"
        "xagt"                                              = "FireEye Endpoint Agent"
        "fgprocsvc"                                         = "ForeScout Remote Inspection Service"
        "SecureConnector"                                   = "ForeScout SecureConnector Service"
        "fsdevcon"                                          = "F-Secure"
        "FSDFWD"                                            = "F-Secure"
        "F-Secure Network Request Broker"                   = "F-Secure"
        "FSMA"                                              = "F-Secure"
        "FSORSPClient"                                      = "F-Secure"
        "klif"                                              = "Kasperksky"
        "klim"                                              = "Kasperksky"
        "kltdi"                                             = "Kasperksky"
        "kavfsslp"                                          = "Kasperksky"
        "KAVFSGT"                                           = "Kasperksky"
        "KAVFS"                                             = "Kasperksky"
        "enterceptagent"                                    = "MacAfee"
        "macmnsvc"                                          = "MacAfee Agent Common Services"
        "masvc"                                             = "MacAfee Agent Service"
        "McAfeeFramework"                                   = "MacAfee Agent Backwards Compatiblity Service"
        "McAfeeEngineService"                               = "MacAfee"
        "mfefire"                                           = "MacAfee Firewall Core Service"
        "mfemms"                                            = "MacAfee Service Controller"
        "mfevtp"                                            = "MacAfee Validation Trust Protection Service"
        "mfewc"                                             = "MacAfee Endpoint Security Web Control Service"
        "WinDefend"                                         = "Microsoft Defender Antivirus Service"
        "Sense"                                             = "Microsoft Defender Advanced Threat Protection Service"
        "WdNisSvc"                                          = "Microsoft Defender Antivirus Network Inspection Service"
        "AATPSensor"                                        = "Microsoft Azure Advanced Threat Protection Sensor"
        "cyverak"                                           = "PaloAlto Traps KernelDriver"
        "cyvrmtgn"                                          = "PaloAlto Traps KernelDriver"
        "cyvrfsfd"                                          = "PaloAlto Traps FileSystemDriver"
        "cyserver"                                          = "PaloAlto Traps Reporting Service"
        "CyveraService"                                     = "PaloAlto Traps"
        "tlaservice"                                        = "PaloAlto Traps Local Analysis Service"
        "twdservice"                                        = "PaloAlto Traps Watchdog Service"
        "SentinelAgent"                                     = "SentinelOne"
        "SentinelHelperService"                             = "SentinelOne"
        "SentinelStaticEngine"                              = "SentinelIbe Static Service"
        "LogProcessorService"                               = "SentinelOne Agent Log Processing Service"
        "sophosssp"                                         = "Sophos"
        "Sophos Agent"                                      = "Sophos"
        "Sophos AutoUpdate Service"                         = "Sophos"
        "Sophos Clean Service"                              = "Sophos"
        "Sophos Device Control Service"                     = "Sophos"
        "Sophos File Scanner Service"                       = "Sophos"
        "Sophos Health Service"                             = "Sophos"
        "Sophos MCS Agent"                                  = "Sophos"
        "Sophos MCS Client"                                 = "Sophos"
        "Sophos Message Router"                             = "Sophos"
        "Sophos Safestore Service"                          = "Sophos"
        "Sophos System Protection Service"                  = "Sophos"
        "Sophos Web Control Service"                        = "Sophos"
        "sophossps"                                         = "Sophos"
        "SepMasterService"                                  = "Symantec Endpoint Protection"
        "SNAC"                                              = "Symantec Network Access Control"
        "Symantec System Recovery"                          = "Symantec System Recovery"
        "Smcinst"                                           = "Symantec Connect"
        "SmcService"                                        = "Symantec Connect"
        "Sysmon"                                            = "Sysinternals System Monitor"
        "Sysmon64"                                          = "Sysinternals System Monitor"
        "AMSP"                                              = "Trend"
        "tmcomm"                                            = "Trend"
        "tmactmon"                                          = "Trend"
        "tmevtmgr"                                          = "Trend"
        "ntrtscan"                                          = "Trend Micro Worry Free Business"
        "WRSVC"                                             = "Webroot"
    }

    foreach ($entry in $serviceDict.GetEnumerator()) {
        if ((ConvertTo-SID -AccountName "NT Service\$($entry.Key)" -Computer $ComputerName) -ne $null) {
            $obj = New-Object -TypeName psobject
            $obj | Add-Member -MemberType NoteProperty -Name 'ComputerName' -Value $ComputerName
            $obj | Add-Member -MemberType NoteProperty -Name 'Service' -Value $entry.Key
            $obj | Add-Member -MemberType NoteProperty -Name 'Product' -Value $entry.Value
            Write-Output $obj
        }
    }
}

Function Local:ConvertTo-SID {
    Param (
        [string] $AccountName,
        [string] $Computer
    )
    $NO_ERROR = 0
    $ERROR_INSUFFICIENT_BUFFER = 122
    $ERROR_INVALID_FLAGS = 1004
    [byte[]]$sid = $null
    $cbSid = 0
    $referencedDomainName = New-Object Text.StringBuilder
    $cchReferencedDomainName = $referencedDomainName.Capacity
    $sidUse = New-Object Win32+SID_NAME_USE
    $err = $NO_ERROR
    if ([Win32]::LookupAccountName($Computer, $AccountName, $sid, [ref] $cbSid, $referencedDomainName, [ref] $cchReferencedDomainName, [ref] $sidUse)) {
        return (New-Object Security.Principal.SecurityIdentifier $sid, 0)
    }
    else {
        $err = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        if ($err -eq $ERROR_INSUFFICIENT_BUFFER -or $err -eq $ERROR_INVALID_FLAGS) {
            $sid = New-Object byte[] $cbSid
            $referencedDomainName.EnsureCapacity($cchReferencedDomainName)
            $err = $NO_ERROR
            if ([Win32]::LookupAccountName($null, $AccountName, $sid, [ref] $cbSid, $referencedDomainName, [ref] $cchReferencedDomainName, [ref] $sidUse)) {
                return (New-Object Security.Principal.SecurityIdentifier $sid, 0)
            }
        }
    }
    return $null
}

Add-Type @"
using System;
using System.Runtime.InteropServices;
public class Win32 {
    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool LookupAccountName(
        string lpSystemName,
        string lpAccountName,
        [MarshalAs(UnmanagedType.LPArray)] byte[] Sid,
        ref uint cbSid,
        System.Text.StringBuilder ReferencedDomainName,
        ref uint cchReferencedDomainName,
        out SID_NAME_USE peUse
    );
    public enum SID_NAME_USE {
        SidTypeUser = 1,
        SidTypeGroup,
        SidTypeDomain,
        SidTypeAlias,
        SidTypeWellKnownGroup,
        SidTypeDeletedAccount,
        SidTypeInvalid,
        SidTypeUnknown,
        SidTypeComputer
    }
}
"@