Function Get-EventTaskCreation {
<#
.SYNOPSIS
    Get scheduled task creation events from Security logs on a remote computer.
    Privileges required: high

    Author: Timothée MENOCHET (@_tmenochet)

.DESCRIPTION
    Get-EventTaskCreation queries remote host for scheduled task creation events.

.PARAMETER ComputerName
    Specifies the host to query for events.

.PARAMETER Credential
    Specifies the privileged account to use.

.PARAMETER Limit
    Specifies the maximal number of events to retrieve, defaults to 10

.PARAMETER SubjectSID
    Specifies a service's author SID to look for in the events.

.PARAMETER InvertLogic
    Queries events that do not match specified SubjectSID.

.EXAMPLE
    PS C:\> Get-EventTaskCreation -SubjectSID S-1-5-18 -InvertLogic -ComputerName SRV.ADATUM.CORP -Credential ADATUM\Administrator
#>

    [CmdletBinding()]
    Param (
        [ValidateNotNullOrEmpty()]
        [string]
        $ComputerName = $env:USERDOMAIN,

        [ValidateNotNullOrEmpty()]
        [Management.Automation.PSCredential]
        [Management.Automation.Credential()]
        $Credential = [Management.Automation.PSCredential]::Empty,

        [ValidateNotNullOrEmpty()]
        [Int32]
        $Limit = 10,

        [ValidateNotNullOrEmpty()]
        [String]
        $SubjectSID,

        [switch]
        $InvertLogic
    )

    if ($SubjectSID) {
        if ($InvertLogic) {
            $filterXPath = "*[System[EventID=4698] and EventData[Data[@Name='SubjectUserSid'] !='$SubjectSID']]"
        }
        else {
            $filterXPath = "*[System[EventID=4698] and EventData[Data[@Name='SubjectUserSid'] and (Data='$SubjectSID')]]"
        }
    }
    else {
        $filterXPath = "*[System[EventID=4698]]"
    }
    $params = @{
        'FilterXPath' = $filterXPath
        'LogName' = 'Security'
        'MaxEvents' = $Limit
        'Credential' = $Credential
        'ComputerName' = $ComputerName
    }
    Get-WinEvent @params -ErrorAction SilentlyContinue | ForEach-Object {
        $event = [xml] $_.ToXml()
        $task = [xml] $event.Event.EventData.Data[5].'#text'
        $task.Task.Actions | ForEach-Object {
            if ($action = $_.ComHandler) {
                $action = '{0} {1}'-f $action.ClassId, $action.Data.'#cdata-section'
            }
            elseif ($action = $_.Exec) {
                $action = '{0} {1}'-f $action.Command, $action.Arguments
            }
        }
        Write-Output ([pscustomobject] @{
            ComputerName     = $_.MachineName
            TimeCreated      = $_.TimeCreated
            EventID          = $_.Id
            SubjectSID       = $event.Event.EventData.Data[0].'#text'
            Task             = ($task.Task.RegistrationInfo.URI)
            RunAs            = ($task.Task.Principals.Principal.UserId)
            RunLevel         = ($task.Task.Principals.Principal.RunLevel)
            Action           = $action
            WorkingDirectory = ($task.Task.Actions.Exec.WorkingDirectory)
        })
    }
}
