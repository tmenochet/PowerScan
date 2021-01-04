#requires -version 3

function Get-CimScheduledTask {
<#
.SYNOPSIS
    Get scheduled tasks on a remote computer.
    Privileges required: high

    Author: Timothée MENOCHET (@_tmenochet)

.DESCRIPTION
    Get-ComScheduledTask queries remote host through WMI for scheduled tasks (optionally matching criteria).

.PARAMETER ComputerName
    Specifies the target host.

.PARAMETER Credential
    Specifies the privileged account to use.

.PARAMETER Ping
    Ensures host is up before run.

.PARAMETER Protocol
    Specifies the protocol to use.

.PARAMETER TaskName
    Specifies one or more scheduled tasks by name.

.PARAMETER TaskPath
    Specifies one or more scheduled tasks by path.

.EXAMPLE
    PS C:\> Get-ComScheduledTask -ComputerName SRV.ADATUM.CORP -Credential ADATUM\Administrator -TaskName 'update'
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
        $TaskName,

        [ValidateNotNullOrEmpty()]
        [string]
        $TaskPath
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
        Get-ScheduledTask -CimSession $cimSession -TaskName "$TaskName*" -TaskPath "$TaskPath*" | ForEach-Object {
            $task = $_
            $_.Actions | ForEach-Object {
                $action = $_
                $action = switch ($($_.CimClass.CimClassName)) {
                    MSFT_TaskExecAction {
                        if ($action.Arguments) {
                            '{0} {1}' -f $action.Execute, $action.Arguments
                        }
                        else {
                            $action.Execute
                        }
                        break;
                    }
                    MSFT_TaskComHandlerAction {
                        if ($action.Data) {
                            '{0} {1}'-f $action.ClassId, $action.Data
                        }
                        else {
                            $action.ClassId
                        }
                        break;
                    }
                    default {}
                }

                $obj = New-Object -TypeName psobject
                $obj | Add-Member -MemberType NoteProperty -Name 'ComputerName' -Value $ComputerName
                $obj | Add-Member -MemberType NoteProperty -Name 'TaskName' -Value $task.TaskName
                $obj | Add-Member -MemberType NoteProperty -Name 'TaskPath' -Value $task.TaskPath
                $obj | Add-Member -MemberType NoteProperty -Name 'Action' -Value $action
                $obj | Add-Member -MemberType NoteProperty -Name 'UserId' -Value $task.Principal.UserId
                $obj | Add-Member -MemberType NoteProperty -Name 'Enabled' -Value $task.Settings.Enabled
                $obj | Add-Member -MemberType NoteProperty -Name 'State' -Value $task.State
                $obj | Add-Member -MemberType NoteProperty -Name 'Author' -Value $task.Author
                $obj | Add-Member -MemberType NoteProperty -Name 'Description' -Value $task.Description
                Write-Output $obj
            }
        }
    }

    END {
        Remove-CimSession -CimSession $cimSession
    }
}