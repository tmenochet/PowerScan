#requires -version 3

function Get-CimProcess {
<#
.SYNOPSIS
    Get processes that are running on a remote computer.
    Privileges required: high

    Author: Timothée MENOCHET (@_tmenochet)

.DESCRIPTION
    Get-CimProcess queries remote host through WMI for process (optionally matching criteria).

.PARAMETER ComputerName
    Specifies the host to query.

.PARAMETER Credential
    Specifies the privileged account to use.

.PARAMETER Ping
    Ensures host is up before run.

.PARAMETER Protocol
    Specifies the protocol to use, defaults to DCOM.

.PARAMETER ProcessName
    Specifies one or more processes by process name.

.PARAMETER ExecutablePath
    Specifies one or more processes by binary file path.

.PARAMETER ProcessID
    Specifies one or more processes by process ID (PID).

.PARAMETER ParentProcessID
    Specifies one or more processes by parent process ID (PPID).

.EXAMPLE
    PS C:\> Get-CimProcess -ComputerName SRV.ADATUM.CORP -Credential ADATUM\Administrator -ProcessName 'keepass.exe'
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
        $ProcessName,

        [ValidateNotNullOrEmpty()]
        [SupportsWildcards()]
        [string]
        $ExecutablePath,

        [ValidateNotNullOrEmpty()]
        [uint32]
        $ProcessID,

        [ValidateNotNullOrEmpty()]
        [uint32]
        $ParentProcessID
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
            "ProcessName" {
                if ($ProcessName -match "\*") {
                    $filters.Add("Name LIKE '$($ProcessName.Replace('*','%'))'") | Out-Null
                }
                else {
                    $filters.Add("Name = '$ProcessName'") | Out-Null
                }
            }
            "ExecutablePath" {
                if ($ExecutablePath -match "\*") {
                    $filters.Add("ExecutablePath LIKE '$($ExecutablePath.Replace('*','%').Replace('\','_'))'") | Out-Null
                }
                else {
                    $filters.Add("ExecutablePath = '$($ExecutablePath.Replace('\','\\'))'") | Out-Null
                }
            }
            "ProcessID" {
                $filters.Add("ProcessId = '$ProcessId'") | Out-Null
            }
            "ParentProcessID" {
                $filters.Add("ParentProcessID = '$ParentProcessID'") | Out-Null
            }
            Default {}
        }
        $filter = $null
        if ($filters.Count) {
            $filter = $filters -join ' AND '
        }
    }

    PROCESS {
        Get-CimInstance Win32_Process -Filter $filter -CimSession $cimSession -Verbose:$false | ForEach-Object {
            $owner = Invoke-CimMethod -InputObject $_ -MethodName GetOwner -Verbose:$false
            $owner = $owner.Domain + "\" + $owner.User
            $obj = New-Object -TypeName psobject
            $obj | Add-Member -MemberType NoteProperty -Name 'ComputerName' -Value $ComputerName
            $obj | Add-Member -MemberType NoteProperty -Name 'ProcessName' -Value $_.Name
            $obj | Add-Member -MemberType NoteProperty -Name 'ExecutablePath' -Value $_.ExecutablePath
            $obj | Add-Member -MemberType NoteProperty -Name 'CommandLine' -Value $_.CommandLine
            $obj | Add-Member -MemberType NoteProperty -Name 'CreationDate' -Value $_.CreationDate
            $obj | Add-Member -MemberType NoteProperty -Name 'ProcessOwner' -Value $owner
            $obj | Add-Member -MemberType NoteProperty -Name 'ProcessId' -Value $_.ProcessId
            $obj | Add-Member -MemberType NoteProperty -Name 'ParentProcessId' -Value $_.ParentProcessId
            Write-Output $obj
        }
    }

    END {
        Remove-CimSession -CimSession $cimSession
    }
}