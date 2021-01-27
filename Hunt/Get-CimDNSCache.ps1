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

.PARAMETER Ping
    Ensures host is up before run.

.PARAMETER Protocol
    Specifies the protocol to use, defaults to DCOM.

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

        [Switch]
        $Ping,

        [ValidateSet('Dcom', 'Wsman')]
        [string]
        $Protocol = 'Dcom',

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

    PROCESS {
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

    END {
        Remove-CimSession -CimSession $cimSession
    }
}