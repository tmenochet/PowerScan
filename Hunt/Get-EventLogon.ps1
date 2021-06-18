Function Get-EventLogon {
<#
.SYNOPSIS
    Get logon events on a remote computer.
    Privileges required: high

    Author: Timothée MENOCHET (@_tmenochet)

.DESCRIPTION
    Get-EventLogon queries remote host for logon events (optionally matching a target user).

.PARAMETER ComputerName
    Specifies the host to query for events.

.PARAMETER Credential
    Specifies the privileged account to use.

.PARAMETER Authentication
    Specifies what authentication method should be used.

.PARAMETER Limit
    Specifies the maximal number of events to retrieve, defaults to 10

.PARAMETER Identity
    Specifies a target user to look for in the logon events.

.PARAMETER All
    Disables default behaviour that groups events by username or by source address for a targeted user.

.EXAMPLE
    PS C:\> Get-EventLogon -Identity john.doe -ComputerName DC.ADATUM.CORP -Credential ADATUM\Administrator
#>

    [CmdletBinding()]
    Param (
        [ValidateNotNullOrEmpty()]
        [string]
        $ComputerName = $env:USERDOMAIN,

        [ValidateNotNullOrEmpty()]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty,

        [ValidateSet('Default', 'Kerberos', 'Negotiate', 'NTLM')]
        [String]
        $Authentication = 'Negotiate',

        [ValidateNotNullOrEmpty()]
        [Int32]
        $Limit = 10,

        [ValidateNotNullOrEmpty()]
        [string]
        $Identity,

        [Switch]
        $All
    )

    $events = New-Object Collections.ArrayList
    if ($Identity) {
        $filterXPath = "*[System[EventID=4624] and EventData[Data[@Name='TargetUserName']='$Identity']]"
    }
    else {
        $filterXPath = "*[System[EventID=4624]
          and EventData[Data[@Name='TargetUserSid']!='S-1-5-18']
          and EventData[Data[@Name='TargetUserSid']!='S-1-5-19']
          and EventData[Data[@Name='TargetUserSid']!='S-1-5-20']
          and EventData[Data[@Name='TargetUserSid']!='S-1-5-90-0-0']
          and EventData[Data[@Name='TargetUserSid']!='S-1-5-90-0-1']
          and EventData[Data[@Name='TargetUserSid']!='S-1-5-90-0-2']
          and EventData[Data[@Name='TargetUserSid']!='S-1-5-96-0-0']
          and EventData[Data[@Name='TargetUserSid']!='S-1-5-96-0-1']
          and EventData[Data[@Name='TargetUserSid']!='S-1-5-96-0-2']
        ]"
    }
    if ($Credential.UserName) {
        $username = $Credential.UserName
        $password = $Credential.GetNetworkCredential().Password
        WevtUtil query-events Security /query:$filterXPath /remote:$ComputerName /username:$username /password:$password /authentication:$Authentication /format:XML /count:$Limit /rd | ForEach-Object {
            [XML] $XML = ($_)
            $status = $XML.Event.System.Keywords
            if ($status -eq "0x8020000000000000") {
                $events.Add((ParseEventLogon($XML))) | Out-Null
            }
        }
    }
    else {
        WevtUtil query-events Security /query:$filterXPath /remote:$ComputerName /authentication:$Authentication /format:XML /count:$Limit /rd | ForEach-Object {
            [XML] $XML = ($_)
            $status = $XML.Event.System.Keywords
            if ($status -eq "0x8020000000000000") {
                $events.Add((ParseEventLogon($XML))) | Out-Null
            }
        }
    }

    if ($All) {
        $events
    }
    elseif ($Identity) {
        $events | Sort-Object -Property 'IpAddress' -Unique
    }
    else {
        $events | Sort-Object -Property 'TargetUserName' -Unique
    }
}

Function Local:ParseEventLogon($XML) {
    $obj = [pscustomobject] @{
        ComputerName          = $XML.Event.System.Computer
        TimeCreated           = $XML.Event.System.TimeCreated.SystemTime
        EventID               = $XML.Event.System.EventID
        UserName              = $XML.Event.EventData.Data[5].'#text'  # TargetUserName
        DomainName            = $XML.Event.EventData.Data[6].'#text'  # TargetDomainName
        SourceIPAddress       = $XML.Event.EventData.Data[18].'#text' # IpAddress
        SourceHostName        = $XML.Event.EventData.Data[11].'#text' # WorkstationName
        LogonType             = $XML.Event.EventData.Data[8].'#text'  # LogonType
        AuthenticationPackage = $XML.Event.EventData.Data[10].'#text' # AuthenticationPackageName
    }
    return $obj
}
