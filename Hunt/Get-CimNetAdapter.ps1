#requires -version 3

function Get-CimNetAdapter {
<#
.SYNOPSIS
    Get network adapters on a remote computer.
    Privileges required: high

    Author: Timothée MENOCHET (@_tmenochet)

.DESCRIPTION
    Get-CimNetAdapter queries remote host through WMI for network adapters.

.PARAMETER ComputerName
    Specifies the host to query.

.PARAMETER Credential
    Specifies the privileged account to use.

.PARAMETER Ping
    Ensures host is up before run.

.PARAMETER Protocol
    Specifies the protocol to use, defaults to DCOM.

.EXAMPLE
    PS C:\> Get-CimNetAdapter -ComputerName SRV.ADATUM.CORP -Credential ADATUM\Administrator
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
        Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration -Filter "IPEnabled='True'" -CimSession $cimSession -Verbose:$false | ForEach-Object {
            $obj = New-Object -TypeName psobject
            $obj | Add-Member -MemberType NoteProperty -Name 'ComputerName' -Value $ComputerName
            $obj | Add-Member -MemberType NoteProperty -Name 'NetworkAdapter' -Value $_.ServiceName
            $obj | Add-Member -MemberType NoteProperty -Name 'Description' -Value $_.Description
            $obj | Add-Member -MemberType NoteProperty -Name 'MACAddress' -Value $_.MACAddress
            $obj | Add-Member -MemberType NoteProperty -Name 'IPAddress' -Value $_.IPAddress
            $obj | Add-Member -MemberType NoteProperty -Name 'IPSubnet' -Value $_.IPSubnet
            Write-Output $obj
        }
    }

    END {
        Remove-CimSession -CimSession $cimSession
    }
}