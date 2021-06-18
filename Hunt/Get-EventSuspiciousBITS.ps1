Function Get-EventSuspiciousBITS {
<#
.SYNOPSIS
    Get suspicious BITS events on a remote computer.
    Privileges required: high

    Author: Timothée MENOCHET (@_tmenochet)

.DESCRIPTION
    Get-EventSuspiciousBITS queries remote host for Event ID 59 (optionally matching criteria).

.PARAMETER ComputerName
    Specifies the host to query for events.

.PARAMETER Credential
    Specifies the privileged account to use.

.PARAMETER Authentication
    Specifies what authentication method should be used.

.PARAMETER Limit
    Specifies the maximal number of events to retrieve, defaults to 10.

.PARAMETER SubjectSID
    Specifies a user SID to look for in the events.

.PARAMETER InvertLogic
    Queries events that do not match specified SubjectSID.

.EXAMPLE
    PS C:\> Get-EventSuspiciousBITS -ComputerName SRV.ADATUM.CORP -Credential ADATUM\Administrator
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

        [ValidateSet('Default', 'Kerberos', 'Negotiate', 'NTLM')]
        [String]
        $Authentication = 'Negotiate',

        [ValidateNotNullOrEmpty()]
        [Int32]
        $Limit = 10,

        [ValidateNotNullOrEmpty()]
        [String]
        $SubjectSID,

        [switch]
        $InvertLogic
    )

    $whitelist = @(
        "http*://aka.ms/*",                                      # Microsoft site
        "http*://img-prod-cms-rt-microsoft-com.akamaized.net/*", # Microsoft on Akamai
        "http*://img-s-msn-com.akamaized.net/*",                 # MSN on Akamai
        "http*://*.adobe.com/*",                                 # Adobe
        "http*://*.adobe.com/*",                                 # Adobe
        "http*://*.amazon.com/*",                                # Amazon corporate
        "http*://*.apache.org/*",                                # Apache
        "http*://*.avast.com/*",                                 # Avast
        "http*://*.avcdn.net/*",                                 # Avast cdn
        "http*://*.bing.com/*",                                  # Microsoft Bing
        "http*://*.core.windows.net/*",                          # Microsoft site
        "http*://*.fbcdn.net/*",                                 # Facebook cdn
        "http*://*.google.com/*",                                # Google
        "http*://*.googleapis.com/*",                            # Google api domain
        "http*://*.googleusercontent.com/*",                     # GoogleUsercontent
        "http*://*.gvt1.com/*",                                  # Google chrome
        "http*://*.hp.com/*",                                    # HP domain
        "http*://*.live.com/*",                                  # Microsoft Live
        "http*://*.microsoft.com/*",                             # Microsoft site
        "http*://*.mozilla.net/*",                               # Mozilla
        "http*://*.msn.com/*",                                   # MSN
        "http*://*.nero.com/*",                                  # Nero software
        "http*://*.office365.com/*",                             # Microsoft office 365
        "http*://*.onenote.net/*",                               # OneNote cdn
        "http*://*.oracle.com/*",                                # Oracle domain
        "http*://*.s-msn.com/*",                                 # MSN
        "http*://*.symantec.com/*",                              # Symantec
        "http*://*.thomsonreuters.com/*",                        # News site
        "http*://*.visualstudio.com/*",                          # Microsoft VisualStudio
        "http*://*.windowsupdate.com/*",                         # Windows update
        "http*://*.xboxlive.com/*"                               # Microsoft site
    )

    if ($SubjectSID) {
        if ($InvertLogic) {
            $filterXPath = "*[System[(EventID=59) and Security[@UserID!='$SubjectSID']]]"
        }
        else {
            $filterXPath = "*[System[(EventID=59) and Security[@UserID='$SubjectSID']]]"
        }
    }
    else {
        $filterXPath = "*[System[(EventID=59)]]"
    }

    if ($Credential.UserName) {
        $username = $Credential.UserName
        $password = $Credential.GetNetworkCredential().Password
        WevtUtil query-events 'Microsoft-Windows-Bits-Client/Operational' /query:$filterXPath /remote:$ComputerName /username:$username /password:$password /authentication:$Authentication /format:XML /count:$Limit /rd /uni | ForEach-Object {
            $obj = (ParseEventBITS([xml]($_)))
            foreach ($url in $whitelist){
                if ($obj.URL -like $url){
                    return
                }
            }
            Write-Output $obj
        }
    }
    else {
        WevtUtil query-events 'Microsoft-Windows-Bits-Client/Operational' /query:$filterXPath /remote:$ComputerName /authentication:$Authentication /format:XML /count:$Limit /rd /uni | ForEach-Object {
            $obj = (ParseEventBITS([xml]($_)))
            foreach ($url in $whitelist){
                if ($obj.URL -like $url){
                    return
                }
            }
            Write-Output $obj
        }
    }
}

Function Local:ParseEventBITS($XML) {
    $obj = [pscustomobject] @{
        ComputerName     = $XML.Event.System.Computer
        TimeCreated      = $XML.Event.System.TimeCreated.SystemTime
        EventID          = $XML.Event.System.EventID
        SubjectSID       = $XML.Event.System.Security.UserID
        Name             = $XML.Event.EventData.Data[1].'#text'
        URL              = $XML.Event.EventData.Data[3].'#text'
        TransferId       = $XML.Event.EventData.Data[0].'#text'
        Id               = $XML.Event.EventData.Data[2].'#text'
        FileTime         = $XML.Event.EventData.Data[5].'#text'
        FileLength       = $XML.Event.EventData.Data[6].'#text'
        BytesTotal       = $XML.Event.EventData.Data[7].'#text'
        BytesTransferred = $XML.Event.EventData.Data[8].'#text'
    }
    return $obj
}