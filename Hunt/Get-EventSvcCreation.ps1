Function Get-EventSvcCreation {
<#
.SYNOPSIS
    Get service creation events on a remote computer.
    Privileges required: high

    Author: Timothée MENOCHET (@_tmenochet)

.DESCRIPTION
    Get-EventSvcCreation queries remote host for service creation events (optionally matching the user SID who created the service).

.PARAMETER ComputerName
    Specifies the host to query for logon events.

.PARAMETER Credential
    Specifies the privileged account to use.

.PARAMETER AuthorSID
    Specifies a service's author SID to look for in the events.

.PARAMETER InvertLogic
    Queries services that do not match specified AuthorSID.

.PARAMETER Limit
    Specifies the maximal number of events to retrieve for the target user, defaults to 10

.EXAMPLE
    PS C:\> Get-EventSvcCreation -AuthorSID S-1-5-18 -InvertLogic -ComputerName SRV.ADATUM.CORP -Credential ADATUM\Administrator
#>

    Param (
        [ValidateNotNullOrEmpty()]
        [string]
        $ComputerName = $env:USERDOMAIN,

        [ValidateNotNullOrEmpty()]
        [String]
        $AuthorSID,

        [switch]
        $InvertLogic,

        [ValidateNotNullOrEmpty()]
        [Int32]
        $Limit = 10,

        [ValidateNotNullOrEmpty()]
        [Management.Automation.PSCredential]
        [Management.Automation.Credential()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    if ($AuthorSID) {
        if ($InvertLogic) {
            $filterXPath = "*[System[EventID=7045] and System[Security[@UserID!='$AuthorSID']]]"
        }
        else {
            $filterXPath = "*[System[EventID=7045] and System[Security[@UserID='$AuthorSID']]]"
        }
    }
    else {
        $filterXPath = "*[System[EventID=7045]]"
    }
    if ($Credential.UserName) {
        $username = $Credential.UserName
        $password = $Credential.GetNetworkCredential().Password
        WevtUtil query-events System /query:$filterXPath /remote:$ComputerName /username:$username /password:$password /format:XML /count:$Limit /rd | ForEach {
            Write-Output (ParseEventSvcCreation([xml]($_)))
        }
    }
    else {
        WevtUtil query-events System /query:$filterXPath /remote:$ComputerName /format:XML /count:$Limit /rd | ForEach {
            Write-Output (ParseEventSvcCreation([xml]($_)))
        }
    }
}

Function Local:ParseEventSvcCreation($XML) {
    $obj = [pscustomobject] @{
        ComputerName    = $XML.Event.System.Computer
        AuthorSID       = $XML.Event.System.Security.UserID
        TimeCreated        = $XML.Event.System.TimeCreated.SystemTime
        ServiceName        = $XML.Event.EventData.Data[0].'#text'       # ServiceName
        ExecutablePath  = $XML.Event.EventData.Data[1].'#text'          # ImagePath
        UserId          = $XML.Event.EventData.Data[4].'#text'          # AccountName
        ServiceType        = $XML.Event.EventData.Data[2].'#text'       # ServiceType
        StartType        = $XML.Event.EventData.Data[3].'#text'         # StartType
    }
    return $obj
}
