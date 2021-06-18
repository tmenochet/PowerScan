#requires -version 3

function Get-CimLogonHistory {
<#
.SYNOPSIS
    Get logon history from a remote computer.
    Privileges required: high

    Author: Timothée MENOCHET (@_tmenochet)

.DESCRIPTION
    Get-CimLogonHistory queries remote host through WMI for network logon cached information entries (optionally matching a target user).

.PARAMETER ComputerName
    Specifies the host to query.

.PARAMETER Ping
    Ensures host is up before run.

.PARAMETER Credential
    Specifies the privileged account to use.

.PARAMETER Authentication
    Specifies what authentication method should be used.

.PARAMETER Protocol
    Specifies the protocol to use, defaults to DCOM.

.PARAMETER Identity
    Specifies a target user to look for in the logon history.

.EXAMPLE
    PS C:\> Get-CimLogonHistory -ComputerName SRV.ADATUM.CORP -Credential ADATUM\Administrator -Identity john.doe
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
        $Identity
    )

    BEGIN {
        if ($Ping -and -not $(Test-Connection -Count 1 -Quiet -ComputerName $ComputerName)) {
            Write-Verbose "[$ComputerName] Host is unreachable."
            break
        }

        $cimOption = New-CimSessionOption -Protocol $Protocol
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
            break
        }
        catch [Microsoft.Management.Infrastructure.CimException] {
            if ($Error[0].FullyQualifiedErrorId -eq 'HRESULT 0x8033810c,Microsoft.Management.Infrastructure.CimCmdlets.NewCimSessionCommand') {
                Write-Warning "Alternative authentication method and/or protocol should be used with implicit credentials."
                break
            }
            if ($Error[0].FullyQualifiedErrorId -eq 'HRESULT 0x80070005,Microsoft.Management.Infrastructure.CimCmdlets.NewCimSessionCommand') {
                Write-Verbose "[$ComputerName] Access denied."
                break
            }
            else {
                Write-Verbose "[$ComputerName] Failed to establish CIM session."
                break
            }
        }

        $filter = $null
        if ($Identity) {
            $filter = "Caption='$Identity'"
        }
    }

    PROCESS {
        Get-CimInstance -ClassName Win32_NetworkLoginProfile -Filter $filter -CimSession $cimSession -Verbose:$false | ForEach-Object {
            if ($_.UserId) {
                if ($_.Privileges -eq 1) {
                    $isLocalAdmin = $false
                }
                elseif ($_.Privileges -eq 2) {
                    $isLocalAdmin = $true
                }
                else {
                    $isLocalAdmin = $null
                }
                $obj = New-Object -TypeName psobject
                $obj | Add-Member -MemberType NoteProperty -Name 'ComputerName' -Value $ComputerName
                $obj | Add-Member -MemberType NoteProperty -Name 'UserName' -Value $_.Caption
                $obj | Add-Member -MemberType NoteProperty -Name 'UserDomain' -Value ($_.Name -split '\\').Get(0)
                $obj | Add-Member -MemberType NoteProperty -Name 'UserRID' -Value $_.UserId
                $obj | Add-Member -MemberType NoteProperty -Name 'IsLocalAdmin' -Value $isLocalAdmin
                $obj | Add-Member -MemberType NoteProperty -Name 'NumberOfLogons' -Value $_.NumberOfLogons
                $obj | Add-Member -MemberType NoteProperty -Name 'LastLogon' -Value $_.LastLogon
                Write-Output $obj
            }
        }
    }

    END {
        Remove-CimSession -CimSession $cimSession
    }
}
