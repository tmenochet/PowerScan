#requires -version 3

Function Get-CimScheduledTask {
<#
.SYNOPSIS
    Get scheduled tasks on a remote computer.
    Privileges required: high

    Author: Timothée MENOCHET (@_tmenochet)

.DESCRIPTION
    Get-CimScheduledTask queries remote host through WMI for scheduled tasks (optionally matching criteria).

.PARAMETER ComputerName
    Specifies the target host.

.PARAMETER Ping
    Ensures host is up before run.

.PARAMETER Credential
    Specifies the privileged account to use.

.PARAMETER Authentication
    Specifies what authentication method should be used.

.PARAMETER Protocol
    Specifies the protocol to use, defaults to DCOM.

.PARAMETER TaskName
    Specifies one or more scheduled tasks by name.

.PARAMETER TaskPath
    Specifies one or more scheduled tasks by path.

.EXAMPLE
    PS C:\> Get-CimScheduledTask -ComputerName SRV.ADATUM.CORP -Credential ADATUM\Administrator -TaskName 'update'
#>

    [CmdletBinding()]
    Param (
        [ValidateNotNullOrEmpty()]
        [String]
        $ComputerName = $env:COMPUTERNAME,

        [Switch]
        $Ping,

        [ValidateNotNullOrEmpty()]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty,

        [ValidateSet('Default', 'Kerberos', 'Negotiate', 'NtlmDomain')]
        [String]
        $Authentication = 'Default',

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

    Begin {
        # Optionally check host reachability
        if ($Ping -and -not $(Test-Connection -Count 1 -Quiet -ComputerName $ComputerName)) {
            Write-Verbose "[$ComputerName] Host is unreachable."
            continue
        }

        # Init variables
        $cimOption = New-CimSessionOption -Protocol $Protocol
    }

    Process {
        # Init remote session
        try {
            if (-not $PSBoundParameters['ComputerName']) {
                $cimSession = New-CimSession -SessionOption $cimOption -ErrorAction Stop -Verbose:$false
            }
            elseif ($Credential.Username) {
                $cimSession = New-CimSession -ComputerName $ComputerName -Credential $Credential -Authentication $Authentication -SessionOption $cimOption -ErrorAction Stop -Verbose:$false
            }
            else {
                $cimSession = New-CimSession -ComputerName $ComputerName -Authentication $Authentication -SessionOption $cimOption -ErrorAction Stop -Verbose:$false
            }
        }
        catch [System.Management.Automation.PSArgumentOutOfRangeException] {
            Write-Warning "Alternative authentication method and/or protocol should be used with implicit credentials."
            return
        }
        catch [Microsoft.Management.Infrastructure.CimException] {
            if ($Error[0].FullyQualifiedErrorId -eq 'HRESULT 0x8033810c,Microsoft.Management.Infrastructure.CimCmdlets.NewCimSessionCommand') {
                Write-Warning "Alternative authentication method and/or protocol should be used with implicit credentials."
                return
            }
            if ($Error[0].FullyQualifiedErrorId -eq 'HRESULT 0x80070005,Microsoft.Management.Infrastructure.CimCmdlets.NewCimSessionCommand') {
                Write-Verbose "[$ComputerName] Access denied."
                return
            }
            else {
                Write-Verbose "[$ComputerName] Failed to establish CIM session."
                return
            }
        }

        # Process artefact collection
        Get-ScheduledTask -CimSession $cimSession -TaskName "$TaskName*" -TaskPath "$TaskPath*" | ForEach-Object {
            $task = $_
            $taskInfo = $_ | Get-ScheduledTaskInfo
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
                $obj | Add-Member -MemberType NoteProperty -Name 'LastRunTime' -Value $taskInfo.LastRunTime
                $obj | Add-Member -MemberType NoteProperty -Name 'NextRunTime' -Value $taskInfo.NextRunTime
                $obj | Add-Member -MemberType NoteProperty -Name 'RegistrationDate' -Value $task.Date
                $obj | Add-Member -MemberType NoteProperty -Name 'Author' -Value $task.Author
                $obj | Add-Member -MemberType NoteProperty -Name 'Description' -Value $task.Description
                Write-Output $obj
            }
        }
    }

    End {
        # End session
        if ($cimSession) {
            Remove-CimSession -CimSession $cimSession
        }
    }
}
