#requires -version 3

function Get-CimDNSCache {
<#
.SYNOPSIS
    Get DNS cache entries on a remote computer.
    Privileges required: high

    Author: Timothée MENOCHET (@_tmenochet)

.DESCRIPTION
    Get-CimDNSCache queries remote host through WMI for DNS cache entries (optionally matching criteria).

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

.PARAMETER RecordName
    Specifies one or more records by name.

.PARAMETER RecordData
    Specifies one or more records by data.

.PARAMETER RecordType
    Specifies one or more records by type.

.EXAMPLE
    PS C:\> Get-CimDNSCache -ComputerName SRV.ADATUM.CORP -Credential ADATUM\Administrator -RecordName *.domain.tld
#>

    [CmdletBinding()]
    Param (
        [ValidateNotNullOrEmpty()]
        [string]
        $ComputerName = $env:COMPUTERNAME,

        [ValidateNotNullOrEmpty()]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty,

        [ValidateSet('Default', 'Kerberos', 'Negotiate', 'NtlmDomain')]
        [String]
        $Authentication = 'Default',

        [ValidateSet('Dcom', 'Wsman')]
        [string]
        $Protocol = 'Dcom',

        [Int]
        $Timeout = 3,

        [SupportsWildcards()]
        [string[]]
        $RecordName,

        [SupportsWildcards()]
        [string[]]
        $RecordData,

        [ValidateSet('A', 'NS', 'CNAME', 'SOA', 'PTR', 'MX', 'TXT', 'AAAA', 'SRV')]
        [string[]]
        $RecordType
    )

    Begin {
        # Init variables
        $cimOption = New-CimSessionOption -Protocol $Protocol
        $sections = @{
            '1' = 'Answer' 
            '2' = 'Authority' 
            '3' = 'Additional'
        }
        $status = @{
            '0' = 'Success'
            '9003' = 'NotExist'
            '9701' = 'NoRecords'
        }
        $types = @{
            '1' = 'A'
            '2' = 'NS' 
            '5' = 'CNAME'
            '6' = 'SOA'
            '12' = 'PTR' 
            '15' = 'MX'
            '16' = 'TXT' 
            '28' = 'AAAA' 
            '33' = 'SRV'
        }
        $filters = New-Object System.Collections.ArrayList
        switch ($PSBoundParameters.Keys) {
            "RecordName" {
                $f = @()
                foreach ($r in $RecordName) {
                    if ($r -match "\*") {
                        $f += "Name LIKE '$($r.Replace('*','%'))'"
                    }
                    else {
                        $f += "Name = '$($r)'"
                    }
                }
                $filters.Add(($f -join ' OR ')) | Out-Null
            }
            "RecordData" {
                $f = @()
                foreach ($r in $RecordData) {
                    if ($r -match "\*") {
                        $f += "Data LIKE '$($r.Replace('*','%'))'"
                    }
                    else {
                        $f += "Data = '$($r)'"
                    }
                }
                $filters.Add(($f -join ' OR ')) | Out-Null
            }
            "RecordType"  { 
                $f = @()
                foreach ($r in $RecordType) {
                    $t = $types.GetEnumerator() | ? { $_.Value -eq $r } | ForEach-Object { $_.Key }
                    $f += "Type = '$t'"
                }
                $filters.Add(($f -join ' OR ')) | Out-Null
            }
            Default {}
        }
        $filter = $null
        if ($filters.Count) {
            $filter = $filters -join ' AND '
        }
    }

    Process {
        # Init remote sessions
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
        Get-CimInstance -Namespace 'root/StandardCimv2' -ClassName 'MSFT_DNSClientCache' -Filter $filter -CimSession $cimSession -Verbose:$false | ForEach-Object {
            $obj = New-Object -TypeName psobject
            $obj | Add-Member -MemberType NoteProperty -Name 'ComputerName' -Value $ComputerName
            $obj | Add-Member -MemberType NoteProperty -Name 'Name' -Value $_.Name
            $obj | Add-Member -MemberType NoteProperty -Name 'Entry' -Value $_.Entry
            $obj | Add-Member -MemberType NoteProperty -Name 'Data' -Value $_.Data
            $obj | Add-Member -MemberType NoteProperty -Name 'DataLength' -Value $_.DataLength
            $obj | Add-Member -MemberType NoteProperty -Name 'Section' -Value $sections[$_.Section.ToString()]
            $obj | Add-Member -MemberType NoteProperty -Name 'Status' -Value $status[$_.Status.ToString()]
            $obj | Add-Member -MemberType NoteProperty -Name 'TimeToLive' -Value $_.TimeToLive
            $obj | Add-Member -MemberType NoteProperty -Name 'Type' -Value $types[$_.Type.ToString()]
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