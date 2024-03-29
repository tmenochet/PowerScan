#requires -version 3

Function Get-CimLogonHistory {
<#
.SYNOPSIS
    Get logon history from a remote computer.
    Privileges required: high

    Author: Timothée MENOCHET (@_tmenochet)

.DESCRIPTION
    Get-CimLogonHistory queries remote host through WMI for network logon cached information entries (optionally matching a target user).

.PARAMETER ComputerName
    Specifies the host to query.

.PARAMETER Credential
    Specifies the privileged account to use.

.PARAMETER Authentication
    Specifies what authentication method should be used.

.PARAMETER Protocol
    Specifies the protocol to use, defaults to DCOM.

.PARAMETER Timeout
    Specifies the duration to wait for a response from the target host (in seconds), defaults to 3.

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

        [Int]
        $Timeout = 3,

        [ValidateNotNullOrEmpty()]
        [string]
        $Identity
    )

    Begin {
        # Init variables
        $cimOption = New-CimSessionOption -Protocol $Protocol
        $filter = $null
        if ($Identity) {
            $filter = "Caption='$Identity'"
        }
    }

    Process {
        # Init remote session
        try {
            if (-not $PSBoundParameters['ComputerName']) {
                $cimSession = New-CimSession -SessionOption $cimOption -ErrorAction Stop -Verbose:$false -OperationTimeoutSec $Timeout
            }
            elseif ($Credential.Username) {
                $cimSession = New-CimSession -ComputerName $ComputerName -Credential $Credential -Authentication $Authentication -SessionOption $cimOption -ErrorAction Stop -Verbose:$false -OperationTimeoutSec $Timeout
            }
            else {
                $cimSession = New-CimSession -ComputerName $ComputerName -Authentication $Authentication -SessionOption $cimOption -ErrorAction Stop -Verbose:$false -OperationTimeoutSec $Timeout
            }
        }
        catch [System.Management.Automation.PSArgumentOutOfRangeException] {
            Write-Warning "Alternative authentication method and/or protocol should be used with implicit credentials."
            return
        }
        catch [Microsoft.Management.Infrastructure.CimException] {
            if ($Error[0].FullyQualifiedErrorId -eq 'HRESULT 0x8033810c,Microsoft.Management.Infrastructure.CimCmdlets.NewCimSessionCommand') {
                Write-Warning "Alternative authentication method and/or protocol should be used with implicit credentials."
                return
            }
            if ($Error[0].FullyQualifiedErrorId -eq 'HRESULT 0x80070005,Microsoft.Management.Infrastructure.CimCmdlets.NewCimSessionCommand') {
                Write-Verbose "[$ComputerName] Access denied."
                return
            }
            else {
                Write-Verbose "[$ComputerName] Failed to establish CIM session."
                return
            }
        }

        # Process artefact collection
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

    End {
        # End session
        if ($cimSession) {
            Remove-CimSession -CimSession $cimSession
        }
    }
}
