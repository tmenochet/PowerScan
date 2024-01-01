#requires -version 3

Function Get-CimNetTCPConnection {
<#
.SYNOPSIS
    Get current TCP connections on a remote computer.
    Privileges required: high

    Author: Timothée MENOCHET (@_tmenochet)

.DESCRIPTION
    Get-CimNetTCPConnection queries remote host through WMI for current TCP connections (optionally matching criteria).

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

.PARAMETER RemoteAddress
    Specifies one or more connections by remote address.

.PARAMETER RemotePort
    Specifies one or more connections by remote port.

.PARAMETER State
    Specifies one or more connections by state.

.PARAMETER OwningProcess
    Specifies one or more connections by owning process.

.EXAMPLE
    PS C:\> Get-CimNetTCPConnection -ComputerName SRV.ADATUM.CORP -Credential ADATUM\Administrator -RemoteAddress 192.168.1.2 -RemotePort 80,443 -State Established
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
        [string[]]
        $RemoteAddress,

        [ValidateNotNullOrEmpty()]
        [int[]]
        $RemotePort,

        [ValidateSet('Bound', 'Closed', 'CloseWait', 'Closing', 'DeleteTCB', 'Established', 'FinWait1', 'FinWait2', 'LastAck', 'Listen', 'SynReceived', 'SynSent', 'TimeWait')]
        [string]
        $State,

        [ValidateNotNullOrEmpty()]
        [uint32]
        $OwningProcess
    )

    Begin {
        # Init variables
        $cimOption = New-CimSessionOption -Protocol $Protocol
        $states = @{
            'Bound' = '100'
            'Closed' = '1'
            'CloseWait' = '8'
            'Closing' = '9'
            'DeleteTCB' = '12'
            'Established' =  '5'
            'FinWait1' = '6'
            'FinWait2' = '7'
            'LastAck' = '10'
            'Listen' = '2'
            'SynReceived' = '4'
            'SynSent' = '3'
            'TimeWait' = '11'
        }
        $filters = New-Object System.Collections.ArrayList
        switch ($PSBoundParameters.Keys) {
            "RemoteAddress" {
                $f = @()
                foreach ($address in $RemoteAddress) {
                    $f += "RemoteAddress = '$address'"
                }
                $filters.Add(($f -join ' OR ')) | Out-Null
            }
            "RemotePort" {
                $f = @()
                foreach ($port in $RemotePort) {
                    $f += "RemotePort = '$port'"
                }
                $filters.Add(($f -join ' OR ')) | Out-Null
            }
            "State" {
                $filters.Add("State = '$($states[$State])'") | Out-Null
            }
            "OwningProcess" {
                $filters.Add("OwningProcess = '$OwningProcess'") | Out-Null
            }
            Default {}
        }
        $filter = $null
        if ($filters.Count) {
            $filter = $filters -join ' AND '
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
        Get-CimInstance -Namespace 'ROOT/StandardCimv2' -ClassName MSFT_NetTCPConnection -Filter $filter -CimSession $cimSession -Verbose:$false | ForEach-Object {
            $obj = New-Object -TypeName psobject
            $obj | Add-Member -MemberType NoteProperty -Name 'ComputerName' -Value $ComputerName
            $obj | Add-Member -MemberType NoteProperty -Name 'LocalAddress' -Value $_.LocalAddress
            $obj | Add-Member -MemberType NoteProperty -Name 'LocalPort' -Value $_.LocalPort
            $obj | Add-Member -MemberType NoteProperty -Name 'RemoteAddress' -Value $_.RemoteAddress
            $obj | Add-Member -MemberType NoteProperty -Name 'RemotePort' -Value $_.RemotePort
            $obj | Add-Member -MemberType NoteProperty -Name 'State' -Value $_.State
            $obj | Add-Member -MemberType NoteProperty -Name 'OwningProcess' -Value $_.OwningProcess
            $obj | Add-Member -MemberType NoteProperty -Name 'CreationTime' -Value $_.CreationTime
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