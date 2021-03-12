#requires -version 3

function Get-CimAsepStartup {
<#
.SYNOPSIS
    Get common logon artifacts on a remote computer.
    Privileges required: high

    Author: Timothée MENOCHET (@_tmenochet)

.DESCRIPTION
    Get-CimAsepStartup enumerates common AutoStart Extension Points (ASEPs) related to logon on a remote host through WMI.

.PARAMETER ComputerName
    Specifies the target host.

.PARAMETER Credential
    Specifies the privileged account to use.

.PARAMETER Ping
    Ensures host is up before run.

.PARAMETER Protocol
    Specifies the protocol to use, defaults to DCOM.

.PARAMETER UserName
    Specifies autoruns by username.

.PARAMETER UserSID
    Specifies autoruns by user SID.

.PARAMETER Location
    Specifies autoruns by location.

.PARAMETER Command
    Specifies autoruns by launched command.

.EXAMPLE
    PS C:\> Get-CimAsepStartup -ComputerName SRV.ADATUM.CORP -Credential ADATUM\Administrator -Command *AppData\Roaming*
#>

    [CmdletBinding()]
    Param (
        [ValidateNotNullOrEmpty()]
        [string]
        $ComputerName = $env:COMPUTERNAME,

        [ValidateNotNullOrEmpty()]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty,

        [Switch]
        $Ping,

        [ValidateSet('Dcom', 'Wsman')]
        [string]
        $Protocol = 'Dcom',

        [ValidateNotNullOrEmpty()]
        [SupportsWildcards()]
        [string]
        $UserName,

        [ValidateNotNullOrEmpty()]
        [string]
        $UserSID,

        [ValidateNotNullOrEmpty()]
        [SupportsWildcards()]
        [string]
        $Location,

        [ValidateNotNullOrEmpty()]
        [SupportsWildcards()]
        [string]
        $Command
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

        $filters = New-Object System.Collections.ArrayList
        switch ($PSBoundParameters.Keys) {
            "UserName" {
                if ($UserName -match "\*") {
                    $filters.Add("User LIKE '$($UserName.Replace('*','%'))'") | Out-Null
                }
                else {
                    $filters.Add("User = '$UserName'") | Out-Null
                }
            }
            "UserSID" {
                $filters.Add("UserSID = '$UserSID'") | Out-Null
            }
            "Location" {
                if ($Location -match "\*") {
                    $filters.Add("Location LIKE '$($Location.Replace('*','%').Replace('\','_'))'") | Out-Null
                }
                else {
                    $filters.Add("Location = '$($Location.Replace('\','\\'))'") | Out-Null
                }
            }
            "Command" {
                if ($Command -match "\*") {
                    $filters.Add("Command LIKE '$($Command.Replace('*','%').Replace('\','_'))'") | Out-Null
                }
                else {
                    $filters.Add("Command = '$($Command.Replace('\','\\'))'") | Out-Null
                }
            }
            Default {}
        }
        $filter = $null
        if ($filters.Count) {
            $filter = $filters -join ' AND '
        }
    }

    PROCESS {
        Get-CimInstance Win32_StartupCommand -Filter $filter -CimSession $cimSession -Verbose:$false | ForEach-Object {
            $obj = New-Object -TypeName psobject
            $obj | Add-Member -MemberType NoteProperty -Name 'ComputerName' -Value $ComputerName
            $obj | Add-Member -MemberType NoteProperty -Name 'User' -Value $_.User
            $obj | Add-Member -MemberType NoteProperty -Name 'Location' -Value $_.Location
            $obj | Add-Member -MemberType NoteProperty -Name 'Command' -Value $_.Command
            Write-Output $obj
        }
    }

    END {
        Remove-CimSession -CimSession $cimSession
    }
}