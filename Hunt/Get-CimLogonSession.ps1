#requires -version 3

function Get-CimLogonSession {
<#
.SYNOPSIS
    Get logon session information from a remote computer.
    Privileges required: high

    Author: Timothée MENOCHET (@_tmenochet)

.DESCRIPTION
    Get-CimLogonSession queries remote host for logon sessions.

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

.EXAMPLE
    PS C:\> Get-CimLogonSession -ComputerName SRV.ADATUM.CORP -Credential ADATUM\Administrator
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
        $Protocol = 'Dcom'
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
    }

    PROCESS {
        Get-CimInstance -ClassName Win32_LogonSession -CimSession $cimSession -Verbose:$false | ForEach-Object {
            $session = $_
            try {
                Get-CimAssociatedInstance -InputObject $session -Association Win32_LoggedOnUser -CimSession $cimSession -ErrorAction Stop -Verbose:$false | ForEach-Object {
                    $obj = New-Object -TypeName psobject
                    $obj | Add-Member -MemberType NoteProperty -Name 'ComputerName' -Value $ComputerName
                    $obj | Add-Member -MemberType NoteProperty -Name 'Created' -Value $session.StartTime
                    $obj | Add-Member -MemberType NoteProperty -Name 'UserName' -Value $_.Name
                    $obj | Add-Member -MemberType NoteProperty -Name 'UserDomain' -Value $_.Domain
                    $obj | Add-Member -MemberType NoteProperty -Name 'UserSID' -Value $_.SID
                    $obj | Add-Member -MemberType NoteProperty -Name 'AuthenticationPackage' -Value $session.AuthenticationPackage
                    $obj | Add-Member -MemberType NoteProperty -Name 'LogonType' -Value $session.LogonType
                    Write-Output $obj
                }
            }
            catch [Microsoft.Management.Infrastructure.CimException] {
                break
            }
        }
    }

    END {
        Remove-CimSession -CimSession $cimSession
    }
}
