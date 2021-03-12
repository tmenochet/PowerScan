Function Get-ComScheduledTask {
<#
.SYNOPSIS
    Get scheduled tasks on a remote computer.
    Privileges required: high

    Author: Timothée MENOCHET (@_tmenochet)

.DESCRIPTION
    Get-ComScheduledTask queries remote host through COM for scheduled tasks (optionally matching criteria).

.PARAMETER ComputerName
    Specifies the target host.

.PARAMETER Credential
    Specifies the privileged account to use.

.PARAMETER Ping
    Ensures host is up before run.

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

        try {
            $schedule = New-Object -ComObject ("Schedule.Service")
            if ($Credential.UserName) {
                $username = $Credential.UserName
                $password = $Credential.GetNetworkCredential().Password
                if (([Regex]::Matches($username, '@')).Count) {
                    $temp = $username.Split('@')
                    $username = $temp[0]
                    $domain = $temp[1]
                }
                elseif (([Regex]::Matches($username, '\\')).Count) {
                    $temp = $username.Split('\')
                    $domain = $temp[0]
                    $username = $temp[1]
                }
                else {
                    $domain = $null
                }
                $schedule.Connect($ComputerName, $username, $domain, $password)
            }
            else {
                $schedule.Connect($ComputerName)
            }
        }
        catch {
            Write-Verbose "Failed to connect to $ComputerName"
            break
        }
    }

    PROCESS {
        if ($TaskPath) {
            $folders = Get-TaskSubFolder -TaskService $schedule -Folder $TaskPath -Recurse
        }
        else {
            $folders = Get-TaskSubFolder -TaskService $schedule -Recurse
        }
        foreach ($folder in $folders) {
            if ($TaskName) {
                try {
                    $schedule.GetFolder($folder).GetTask($TaskName) | ForEach-Object {
                        Get-TaskInfo $_
                    }
                }
                catch {}
            }
            else {
                $schedule.GetFolder($folder).GetTasks(1) | ForEach-Object {
                    Get-TaskInfo $_
                }
            }
        }
    }

    END {}
}

Function Local:Get-TaskSubFolder {
    param (
        [__ComObject]
        $TaskService,

        [String]
        $Folder = '\',

        [switch]
        $Recurse
    )

    $Folder
    if ($Recurse) {
        $TaskService.GetFolder($Folder).GetFolders(0) | ForEach-Object {
            Get-TaskSubFolder -TaskService $TaskService -Folder $_.Path -Recurse
        }
    }
    else {
        $TaskService.GetFolder($Folder).GetFolders(0)
    }
}

Function Local:Get-TaskInfo {
    Param (
        [ValidateNotNullOrEmpty()]
        [__ComObject]
        $Task
    )

    $node = ([xml]$Task.Xml).Task.get_ChildNodes() | Where-Object { $_.Name -eq 'Actions'}
    if ($node.HasChildNodes) {
        $node.get_ChildNodes() | ForEach-Object {
            $subnode = $_
            $action = $null
            $action = switch ($_.Name) {
                Exec {
                    if ($subnode.get_ChildNodes() | Where-Object { $_.Name -eq 'Arguments' } | Select-Object -ExpandProperty '#text') {
                        '{0} {1}' -f ($subnode.get_ChildNodes() | Where-Object { $_.Name -eq 'Command' } | Select-Object -ExpandProperty '#text'),
                        ($subnode.get_ChildNodes() | Where-Object { $_.Name -eq 'Arguments' } | Select-Object -ExpandProperty '#text');
                    }
                    else {
                        $subnode.get_ChildNodes() | Where-Object { $_.Name -eq 'Command' } | Select-Object -ExpandProperty '#text' ;
                    }
                    break;
                }
                ComHandler {
                    if ($subnode.get_ChildNodes()| Where-Object { $_.Name -eq 'Data'} | Select-Object -ExpandProperty InnerText) {
                        '{0} {1}'-f ($subnode.get_ChildNodes() | Where-Object { $_.Name -eq 'ClassId'} | Select-Object -ExpandProperty '#text'),
                        ($subnode.get_ChildNodes() | Where-Object { $_.Name -eq 'Data'} | Select-Object -ExpandProperty InnerText);
                    }
                    else {
                        $subnode.get_ChildNodes() | Where-Object { $_.Name -eq 'ClassId'} | Select-Object -ExpandProperty '#text';
                    }
                    break;
                }
                default {}
            }

            [pscustomobject] @{
                'ComputerName' = $ComputerName
                'TaskName' = $task.Name
                'TaskPath' = Split-Path $task.Path
                'Action' =  $action
                'UserId' = ([xml]$task.Xml).Task.Principals.Principal.UserID
                'Enabled' = $task.Enabled
                'State' = switch ($task.State) {
                    0 {'Unknown'}
                    1 {'Disabled'}
                    2 {'Queued'}
                    3 {'Ready'}
                    4 {'Running'}
                    Default {'Unknown'}
                }
                'LastRunTime' = $task.LastRunTime
                'NextRunTime' = $task.NextRuntime
                'RegistrationDate' = ([xml]$task.Xml).Task.RegistrationInfo.Date
                'Author' =  ([xml]$task.Xml).Task.RegistrationInfo.Author
                'Description' = ([xml]$task.Xml).Task.RegistrationInfo.Description
            }
        }
    }
}
