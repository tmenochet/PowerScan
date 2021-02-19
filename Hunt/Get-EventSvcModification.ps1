Function Get-EventSvcModification {
<#
.SYNOPSIS
    Get service modification events on a remote computer.
    Privileges required: high

    Author: Timothée MENOCHET (@_tmenochet)

.DESCRIPTION
    Get-EventSvcModification queries remote host for service modification events (optionally matching the user SID who created the service).

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
    PS C:\> Get-EventSvcModification -SubjectSID S-1-5-18 -InvertLogic -ComputerName SRV.ADATUM.CORP -Credential ADATUM\Administrator
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
            $filterXPath = "*[System[EventID=7040] and System[Security[@UserID!='$SubjectSID']]]"
        }
        else {
            $filterXPath = "*[System[EventID=7040] and System[Security[@UserID='$SubjectSID']]]"
        }
    }
    else {
        $filterXPath = "*[System[EventID=7040]]"
    }
    if ($Credential.UserName) {
        $username = $Credential.UserName
        $password = $Credential.GetNetworkCredential().Password
        WevtUtil query-events System /query:$filterXPath /remote:$ComputerName /username:$username /password:$password /format:XML /count:$Limit /rd /uni | ForEach-Object {
            Write-Output (ParseEventSvcModification([xml]($_)))
        }
    }
    else {
        WevtUtil query-events System /query:$filterXPath /remote:$ComputerName /format:XML /count:$Limit /rd /uni | ForEach-Object {
            Write-Output (ParseEventSvcModification([xml]($_)))
        }
    }
}

Function Local:ParseEventSvcModification($XML) {
    $obj = [pscustomobject] @{
        ComputerName = $XML.Event.System.Computer
        TimeCreated  = $XML.Event.System.TimeCreated.SystemTime
        EventID      = $XML.Event.System.EventID.'#text'
        SubjectSID   = $XML.Event.System.Security.UserID
        ServiceName  = $XML.Event.EventData.Data[3].'#text'
        OldSetting   = $XML.Event.EventData.Data[1].'#text'
        NewSetting   = $XML.Event.EventData.Data[2].'#text'
    }
    return $obj
}
