#requires -version 3

function Get-CimService {
<#
.SYNOPSIS
    Get Windows services on a remote computer.
    Privileges required: high

    Author: Timothée MENOCHET (@_tmenochet)

.DESCRIPTION
    Get-CimService queries remote host through WMI for services (optionally matching criteria).

.PARAMETER ComputerName
    Specifies the host to query.

.PARAMETER Credential
    Specifies the privileged account to use.

.PARAMETER Ping
    Ensures host is up before run.

.PARAMETER Protocol
    Specifies the protocol to use.

.PARAMETER ServiceName
    Specifies one or more services by name.

.PARAMETER ExecutablePath
    Specifies one or more services by binary file path.

.PARAMETER StartMode
    Specifies one or more services by start mode.

.PARAMETER State
    Specifies one or more services by state.

.EXAMPLE
    PS C:\> Get-CimService -ComputerName SRV.ADATUM.CORP -Credential ADATUM\Administrator -ServiceName 'SysMon'
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
        $ServiceName,

        [ValidateNotNullOrEmpty()]
        [string]
        $ExecutablePath,

        [ValidateSet('Auto', 'Manual', 'Disabled')]
        [string]
        $StartMode,

        [ValidateSet('Stopped', 'Start Pending', 'Stop Pending', 'Running', 'Continue Pending', 'Pause Pending', 'Paused', 'Unknown')]
        [string]
        $State
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
        $filters = New-Object System.Collections.ArrayList
        if ($ServiceName) {
            $filters.Add("Name LIKE '%$ServiceName%'") | Out-Null
        }
        if ($ExecutablePath) {
            $filters.Add($("PathName LIKE '%$ExecutablePath%'" -Replace "\\","_")) | Out-Null
        }
        if ($State) {
            $filters.Add("State='$State'") | Out-Null
        }
        if ($StartMode) {
            $filters.Add("StartMode='$StartMode'") | Out-Null
        }
        if ($filters.Count) {
            $filter = $filters -join ' AND '
        }
    }

    PROCESS {
        Get-CimInstance Win32_Service -Filter $filter -CimSession $cimSession -Verbose:$false | ForEach-Object {
            $obj = New-Object -TypeName psobject
            $obj | Add-Member -MemberType NoteProperty -Name 'ComputerName' -Value $ComputerName
            $obj | Add-Member -MemberType NoteProperty -Name 'ServiceName' -Value $_.Name
            $obj | Add-Member -MemberType NoteProperty -Name 'ServiceType' -Value $_.ServiceType
            $obj | Add-Member -MemberType NoteProperty -Name 'ExecutablePath' -Value $_.PathName
            $obj | Add-Member -MemberType NoteProperty -Name 'UserId' -Value $_.StartName
            $obj | Add-Member -MemberType NoteProperty -Name 'StartMode' -Value $_.StartMode
            $obj | Add-Member -MemberType NoteProperty -Name 'State' -Value $_.State
            $obj | Add-Member -MemberType NoteProperty -Name 'DisplayName' -Value $_.DisplayName
            $obj | Add-Member -MemberType NoteProperty -Name 'Description' -Value $_.Description
            Write-Output $obj
        }
    }

    END {
        Remove-CimSession -CimSession $cimSession
    }
}