Function Get-EventLogon {
<#
.SYNOPSIS
    Get logon events on a remote computer.
    Privileges required: high

    Author: Timothée MENOCHET (@_tmenochet)

.DESCRIPTION
    Get-EventLogon queries remote host for logon events (optionally matching a target user).

.PARAMETER ComputerName
    Specifies the host to query for logon events.

.PARAMETER Credential
    Specifies the privileged account to use.

.PARAMETER Identity
    Specifies a target user to look for in the logon events.

.PARAMETER Limit
    Specifies the maximal number of events to retrieve for the target user, defaults to 10

.EXAMPLE
    PS C:\> Get-EventLogon -Identity john.doe -ComputerName DC.ADATUM.CORP -Credential ADATUM\Administrator
#>

    Param (
        [ValidateNotNullOrEmpty()]
        [string]
        $ComputerName = $env:USERDOMAIN,

        [ValidateNotNullOrEmpty()]
        [String]
        $Identity,

        [ValidateNotNullOrEmpty()]
        [Int32]
        $Limit = 10,

        [ValidateNotNullOrEmpty()]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    $events = New-Object System.Collections.ArrayList
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
        WevtUtil query-events Security /query:$filterXPath /remote:$ComputerName /username:$username /password:$password /format:XML /count:$Limit | ForEach {
            [XML] $XML = ($_)
            $status = $XML.Event.System.Keywords
            if ($status -eq "0x8020000000000000") {
                $events.Add($(ParseEventLogon($XML))) | Out-Null
            }
        }
    }
    else {
        WevtUtil query-events Security /query:$filterXPath /remote:$ComputerName /format:XML /count:$Limit | ForEach {
            [XML] $XML = ($_)
            $status = $XML.Event.System.Keywords
            if ($status -eq "0x8020000000000000") {
                $events.Add($(ParseEventLogon($XML))) | Out-Null
            }
        }
    }

    if ($Identity) {
        $events | Sort-Object -Property 'IpAddress' -Unique
    }
    else {
        $events | Sort-Object -Property 'TargetUserName' -Unique
    }
}

Function Local:ParseEventLogon($XML) {
    $obj = [pscustomobject] @{
        ComputerName = $XML.Event.System.Computer                       # Computer
        UserName = $XML.Event.EventData.Data[5].'#text'                 # TargetUserName
        DomainName = $XML.Event.EventData.Data[6].'#text'               # TargetDomainName
        SourceIPAddress = $XML.Event.EventData.Data[18].'#text'         # IpAddress
        SourceHostName = $XML.Event.EventData.Data[11].'#text'          # WorkstationName
        LogonType = $XML.Event.EventData.Data[8].'#text'                # LogonType
        AuthenticationPackage = $XML.Event.EventData.Data[10].'#text'   # AuthenticationPackageName
    }
    return $obj
}
