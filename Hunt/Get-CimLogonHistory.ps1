#requires -version 3

function Get-CimLogonHistory {
<#
.SYNOPSIS
    Get logon history from a remote computer.
    Privileges required: high

    Author: Timothée MENOCHET (@_tmenochet)

.DESCRIPTION
    Get-CimLogonHistory queries remote host through WMI for network logon cached information entries (optionally matching a target user).

.PARAMETER ComputerName
    Specifies the host to query.

.PARAMETER Credential
    Specifies the privileged account to use.

.PARAMETER Ping
    Ensures host is up before run.

.PARAMETER Protocol
    Specifies the protocol to use, defaults to DCOM.

.PARAMETER Identity
    Specifies a target user to look for in the logon history.

.EXAMPLE
    PS C:\> Get-CimLogonHistory -ComputerName SRV.ADATUM.CORP -Credential ADATUM\Administrator -Identity john.doe
#>

    [CmdletBinding()]
    Param (
        [ValidateNotNullOrEmpty()]
        [String]
        $ComputerName = $env:COMPUTERNAME,

        [ValidateNotNullOrEmpty()]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty,

        [Switch]
        $Ping,

        [ValidateSet('Dcom', 'Wsman')]
        [String]
        $Protocol = 'Dcom',

        [ValidateNotNullOrEmpty()]
        [string]
        $Identity
    )

    BEGIN {
        if ($Ping -and -not $(Test-Connection -Count 1 -Quiet -ComputerName $ComputerName)) {
            Write-Verbose "[$ComputerName] Host is unreachable."
            break
        }

        $cimOption = New-CimSessionOption -Protocol $Protocol
        try {
            if ($Credential.Username) {
                $cimSession = New-CimSession -ComputerName $ComputerName -Credential $Credential -SessionOption $cimOption -ErrorAction Stop -Verbose:$false
            }
            else {
                $cimSession = New-CimSession -ComputerName $ComputerName -SessionOption $cimOption -ErrorAction Stop -Verbose:$false
            }
        }
        catch [Microsoft.Management.Infrastructure.CimException] {
            Write-Verbose "[$ComputerName] Failed to establish CIM session."
            break
        }

        $filter = $null
        if ($Identity) {
            $filter = "Caption='$Identity'"
        }
    }

    PROCESS {
        Get-CimInstance -ClassName Win32_NetworkLoginProfile -Filter $filter -CimSession $cimSession -Verbose:$false | ForEach-Object {
            if ($_.UserId) {
                if ($_.Privileges -eq 1) {
                    $isLocalAdmin = $false
                }
                elseif ($_.Privileges -eq 2) {
                    $isLocalAdmin = $true
                }
                else {
                    $isLocalAdmin = $null
                }
                $obj = New-Object -TypeName psobject
                $obj | Add-Member -MemberType NoteProperty -Name 'ComputerName' -Value $ComputerName
                $obj | Add-Member -MemberType NoteProperty -Name 'UserName' -Value $_.Caption
                $obj | Add-Member -MemberType NoteProperty -Name 'UserDomain' -Value ($_.Name -split '\\').Get(0)
                $obj | Add-Member -MemberType NoteProperty -Name 'UserRID' -Value $_.UserId
                $obj | Add-Member -MemberType NoteProperty -Name 'IsLocalAdmin' -Value $isLocalAdmin
                $obj | Add-Member -MemberType NoteProperty -Name 'NumberOfLogons' -Value $_.NumberOfLogons
                $obj | Add-Member -MemberType NoteProperty -Name 'LastLogon' -Value $_.LastLogon
                Write-Output $obj
            }
        }
    }

    END {
        Remove-CimSession -CimSession $cimSession
    }
}
