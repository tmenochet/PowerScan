Function Get-EventSuspiciousPS {
<#
.SYNOPSIS
    Get suspicious powershell events on a remote computer.
    Privileges required: high

    Author: Timothée MENOCHET (@_tmenochet)

.DESCRIPTION
    Get-EventSuspiciousPS queries remote host for Event ID 4104 (optionally matching criteria).

.PARAMETER ComputerName
    Specifies the host to query for events.

.PARAMETER Credential
    Specifies the privileged account to use.

.PARAMETER UserSID
    Specifies a user SID to look for in the events.

.PARAMETER InvertLogic
    Queries events that do not match specified UserSID.

.PARAMETER RecordID
    Specifies the event's RecordId to look for.

.PARAMETER ProcessID
    Specifies a ProcessId to look for in the events.

.PARAMETER Limit
    Specifies the maximal number of events to retrieve, defaults to 10

.EXAMPLE
    PS C:\> Get-EventSuspiciousPS -UserSID S-1-5-18 -InvertLogic -ComputerName SRV.ADATUM.CORP -Credential ADATUM\Administrator
#>

    [CmdletBinding()]
    Param (
        [ValidateNotNullOrEmpty()]
        [string]
        $ComputerName = $env:USERDOMAIN,

        [ValidateNotNullOrEmpty()]
        [String]
        $UserSID,

        [switch]
        $InvertLogic,

        [ValidateNotNullOrEmpty()]
        [Int32]
        $RecordID,

        [ValidateNotNullOrEmpty()]
        [Int32]
        $ProcessID,

        [ValidateNotNullOrEmpty()]
        [Int32]
        $Limit = 10,

        [ValidateNotNullOrEmpty()]
        [Management.Automation.PSCredential]
        [Management.Automation.Credential()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    if ($UserSID) {
        if ($InvertLogic) {
            $filterXPath = "*[System[(EventID=4104 and Level>=3) and Security[@UserID!='$UserSID']]]"
        }
        else {
            $filterXPath = "*[System[(EventID=4104 and Level>=3) and Security[@UserID='$UserSID']]]"
        }
    }
    elseif ($RecordID) {
        $filterXPath = "*[System[(EventID=4104 and EventRecordID=$RecordID)]]"
    }
    elseif ($ProcessID) {
        $filterXPath = "*[System[(EventID=4104 and Execution[@ProcessID=$ProcessID])]]"
    }
    else {
        $filterXPath = "*[System[(EventID=4104 and Level>=3)]]"
    }

    $params = @{
        'FilterXPath' = $filterXPath
        'LogName' = 'Microsoft-Windows-PowerShell/Operational'
        'MaxEvents' = $Limit
        'Credential' = $Credential
        'ComputerName' = $ComputerName
    }
    Get-WinEvent @params -ErrorAction SilentlyContinue | ForEach-Object {
        Write-Output ([pscustomobject] @{
            ComputerName = $_.MachineName
            TimeCreated  = $_.TimeCreated
            EventId      = $_.Id
            RecordId     = $_.RecordId
            UserSid      = $_.UserId
            ProcessId    = $_.ProcessId
            Level        = $_.LevelDisplayName
            Category     = $_.TaskDisplayName
            ScriptBlock  = ($_.Message -creplace '(?m)^\s*\r?\n','').Split("`n") | Select-Object -Skip 1
        })
    }
}
