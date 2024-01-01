#requires -version 3

Function Get-CimService {
<#
.SYNOPSIS
    Get Windows services on a remote computer.
    Privileges required: high

    Author: Timothée MENOCHET (@_tmenochet)

.DESCRIPTION
    Get-CimService queries remote host through WMI for services (optionally matching criteria).

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

.PARAMETER ServiceName
    Specifies one or more services by name.

.PARAMETER ExecutablePath
    Specifies one or more services by binary file path.

.PARAMETER StartMode
    Specifies one or more services by start mode.

.PARAMETER State
    Specifies one or more services by state.

.PARAMETER InvertLogic
    Queries services that do not match specified criteria.

.EXAMPLE
    PS C:\> Get-CimService -ComputerName SRV.ADATUM.CORP -Credential ADATUM\Administrator -ServiceName sysmon*
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
        [SupportsWildcards()]
        [string]
        $ServiceName,

        [ValidateNotNullOrEmpty()]
        [SupportsWildcards()]
        [string]
        $ExecutablePath,

        [ValidateSet('Auto', 'Manual', 'Disabled')]
        [string]
        $StartMode,

        [ValidateSet('Stopped', 'Start Pending', 'Stop Pending', 'Running', 'Continue Pending', 'Pause Pending', 'Paused', 'Unknown')]
        [string]
        $State,

        [switch]
        $InvertLogic
    )

    Begin {
        # Init variables
        $cimOption = New-CimSessionOption -Protocol $Protocol
        $filters = New-Object System.Collections.ArrayList
        switch ($PSBoundParameters.Keys) {
            "ServiceName" {
                if ($ServiceName -match "\*") {
                    $filters.Add("Name LIKE '$($ServiceName.Replace('*','%'))'") | Out-Null
                }
                else {
                    $filters.Add("Name = '$ServiceName'") | Out-Null
                }
            }
            "ExecutablePath" {
                if ($ExecutablePath -match "\*") {
                    $filters.Add("PathName LIKE '$($ExecutablePath.Replace('*','%').Replace('\','_'))'") | Out-Null
                }
                else {
                    $filters.Add("PathName = '$($ExecutablePath.Replace('\','\\'))'") | Out-Null
                }
            }
            "State" {
                $filters.Add("State = '$State'") | Out-Null
            }
            "StartMode" {
                $filters.Add("StartMode = '$StartMode'") | Out-Null
            }
            Default {}
        }
        $filter = $null
        if ($filters.Count) {
            $filter = $filters -join ' AND '
            if ($InvertLogic) {
                $filter = "NOT $filter"
            }
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
        Get-CimInstance Win32_Service -Filter $filter -CimSession $cimSession -Verbose:$false | ForEach-Object {
            $obj = New-Object -TypeName psobject
            $obj | Add-Member -MemberType NoteProperty -Name 'ComputerName' -Value $ComputerName
            $obj | Add-Member -MemberType NoteProperty -Name 'ServiceName' -Value $_.Name
            $obj | Add-Member -MemberType NoteProperty -Name 'ServiceType' -Value $_.ServiceType
            $obj | Add-Member -MemberType NoteProperty -Name 'ExecutablePath' -Value $_.PathName
            $obj | Add-Member -MemberType NoteProperty -Name 'UserId' -Value $_.StartName
            $obj | Add-Member -MemberType NoteProperty -Name 'StartMode' -Value $_.StartMode
            $obj | Add-Member -MemberType NoteProperty -Name 'State' -Value $_.State
            $obj | Add-Member -MemberType NoteProperty -Name 'DisplayName' -Value $_.DisplayName
            $obj | Add-Member -MemberType NoteProperty -Name 'Description' -Value $_.Description
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