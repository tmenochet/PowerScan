#requires -version 3

Function Get-CimLocalAdmin {
<#
.SYNOPSIS
    Get members of local admin group on a remote computer.
    Privileges required: high

    Author: Timothée MENOCHET (@_tmenochet)

.DESCRIPTION
    Get-CimLocalAdmin queries remote host through WMI for local admin accounts.

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

.EXAMPLE
    PS C:\> Get-CimLocalAdmin -ComputerName SRV.ADATUM.CORP -Credential ADATUM\Administrator
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
        $Timeout = 3
    )

    Begin {
        # Init variables
        $cimOption = New-CimSessionOption -Protocol $Protocol
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
        Get-CimInstance -ClassName Win32_Group -Filter "SID='S-1-5-32-544'" -CimSession $cimSession -Verbose:$false | Get-CimAssociatedInstance -Association Win32_GroupUser -CimSession $cimSession -Verbose:$false | ForEach-Object {
            $obj = New-Object -TypeName psobject
            $obj | Add-Member -MemberType NoteProperty -Name 'ComputerName' -Value $ComputerName
            $obj | Add-Member -MemberType NoteProperty -Name 'Name' -Value $_.Name
            $obj | Add-Member -MemberType NoteProperty -Name 'Domain' -Value $_.Domain
            $obj | Add-Member -MemberType NoteProperty -Name 'SID' -Value $_.SID
            $obj | Add-Member -MemberType NoteProperty -Name 'Disabled' -Value $_.Disabled
            $obj | Add-Member -MemberType NoteProperty -Name 'Status' -Value $_.Status
            $obj | Add-Member -MemberType NoteProperty -Name 'Lockout' -Value $_.Lockout
            $obj | Add-Member -MemberType NoteProperty -Name 'Class' -Value $_.CimClass.CimClassName
            Write-Output $obj
        }
    }

    End {
        # End session
        if ($cimSession) {
            Remove-CimSession -CimSession $cimSession
        }
    }
}
