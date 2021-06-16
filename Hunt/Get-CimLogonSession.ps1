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

.PARAMETER Credential
    Specifies the privileged account to use.

.PARAMETER Ping
    Ensures host is up before run.

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

        [ValidateNotNullOrEmpty()]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty,

        [Switch]
        $Ping,

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
            if ($Credential.Username) {
                $cimSession = New-CimSession -ComputerName $ComputerName -Credential $Credential -SessionOption $cimOption -ErrorAction Stop -Verbose:$false
            }
            else {
                $cimSession = New-CimSession -ComputerName $ComputerName -SessionOption $cimOption -ErrorAction Stop -Verbose:$false
            }
        }
        catch [Microsoft.Management.Infrastructure.CimException] {
            Write-Verbose "[$ComputerName] Failed to establish CIM session."
            break
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