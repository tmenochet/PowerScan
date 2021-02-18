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

.EXAMPLE
    PS C:\> Get-EventTaskCreation -Author S-1-5-18 -InvertLogic -ComputerName SRV.ADATUM.CORP -Credential ADATUM\Administrator
#>

    [CmdletBinding()]
    Param (
        [ValidateNotNullOrEmpty()]
        [string]
        $ComputerName = $env:USERDOMAIN,

        [ValidateNotNullOrEmpty()]
        [Int32]
        $Limit = 10,

        [ValidateNotNullOrEmpty()]
        [Management.Automation.PSCredential]
        [Management.Automation.Credential()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    $filterXPath = "*[System[EventID=4698]]"
    $params = @{
        'FilterXPath' = $filterXPath
        'LogName' = 'Security'
        'MaxEvents' = $Limit
        'Credential' = $Credential
        'ComputerName' = $ComputerName
    }
    Get-WinEvent @params -ErrorAction SilentlyContinue | ForEach {
        $task = [xml] ([xml] $_.ToXml()).Event.EventData.Data[5].'#text'
        Write-Output ([pscustomobject] @{
            ComputerName = $_.MachineName
            TimeCreated  = $_.TimeCreated
            EventId      = $_.Id
            TaskPath     = ($task.Task.RegistrationInfo.URI)
            UserSid      = ($task.Task.Principals.Principal.UserId)
            RunLevel     = ($task.Task.Principals.Principal.RunLevel)
            Command      = ($task.Task.Actions.Exec.Command)
            Arguments    = ($task.Task.Actions.Exec.Arguments)
            Directory    = ($task.Task.Actions.Exec.WorkingDirectory)
        })
    }
}
