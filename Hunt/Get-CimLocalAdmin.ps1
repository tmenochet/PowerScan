#requires -version 3

function Get-CimLocalAdmin {
<#
.SYNOPSIS
    Get members of local admin group on a remote computer.
    Privileges required: high

    Author: Timothée MENOCHET (@_tmenochet)

.DESCRIPTION
    Get-CimLocalAdmin queries remote host through WMI for local admin accounts.

.PARAMETER ComputerName
    Specifies the host to query.

.PARAMETER Credential
    Specifies the privileged account to use.

.PARAMETER Ping
    Ensures host is up before run.

.PARAMETER Protocol
    Specifies the protocol to use, defaults to DCOM.

.EXAMPLE
    PS C:\> Get-CimLocalAdmin -ComputerName SRV.ADATUM.CORP -Credential ADATUM\Administrator
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
        $Protocol = 'Dcom'
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
    }

    PROCESS {
        Get-CimInstance -ClassName Win32_Group -Filter "SID='S-1-5-32-544'" -CimSession $cimSession -Verbose:$false | Get-CimAssociatedInstance -Association Win32_GroupUser -CimSession $cimSession -Verbose:$false | ForEach-Object {
            $obj = New-Object -TypeName psobject
            $obj | Add-Member -MemberType NoteProperty -Name 'ComputerName' -Value $ComputerName
            $obj | Add-Member -MemberType NoteProperty -Name 'Name' -Value $_.Name
            $obj | Add-Member -MemberType NoteProperty -Name 'Domain' -Value $_.Domain
            $obj | Add-Member -MemberType NoteProperty -Name 'SID' -Value $_.SID
            $obj | Add-Member -MemberType NoteProperty -Name 'Disabled' -Value $_.Disabled
            $obj | Add-Member -MemberType NoteProperty -Name 'Status' -Value $_.Status
            $obj | Add-Member -MemberType NoteProperty -Name 'Lockout' -Value $_.Lockout
            $obj | Add-Member -MemberType NoteProperty -Name 'Class' -Value $_.CimClass.CimClassName
            Write-Output $obj
        }
    }

    END {
        Remove-CimSession -CimSession $cimSession
    }
}
