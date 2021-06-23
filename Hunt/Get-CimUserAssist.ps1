#requires -version 3

function Get-CimUserAssist {
<#
.SYNOPSIS
    Get user assist execution artefacts from a remote computer.
    Privileges required: high

    Author: Timothée MENOCHET (@_tmenochet)

.DESCRIPTION
    Get-CimUserAssist enumerates user assist entries on a remote host through WMI.
    It is a slightly modified version of CimSweep's Get-CSUserAssist by @secabstraction.

.PARAMETER ComputerName
    Specifies the target host.

.PARAMETER Ping
    Ensures host is up before run.

.PARAMETER Credential
    Specifies the privileged account to use.

.PARAMETER Authentication
    Specifies what authentication method should be used.

.PARAMETER Protocol
    Specifies the protocol to use, defaults to DCOM.

.EXAMPLE
    PS C:\> Get-CimUserAssist -ComputerName SRV.ADATUM.CORP -Credential ADATUM\Administrator
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

        [uint32]$HKU = 2147483651
        $SIDS = Invoke-CimMethod -Class 'StdRegProv' -Name 'EnumKey' -Arguments @{hDefKey=$HKU; sSubKeyName=''} -CimSession $cimSession -Verbose:$false | Select-Object -ExpandProperty sNames | Where-Object {$_ -match 'S-1-5-21-[\d\-]+$'}
    }

    PROCESS {
        $key = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist'
        foreach ($SID in $SIDs) {
            $locations = Get-RegistryKey -CimSession $cimSession -Hive $HKU -SubKey "$SID\$key" -Recurse | Where-Object { $_ -like "*Count" }
            foreach ($location in $locations) {
                $values = (Invoke-CimMethod -Class 'StdRegProv' -Name 'EnumValues' -Arguments @{hDefKey=$HKU; sSubKeyName=$location} -CimSession $cimSession -Verbose:$false).sNames
                foreach ($valueName in $values) {
                    if ($valueContent = (Invoke-CimMethod -Class 'StdRegProv' -Name 'GetBinaryValue' -Arguments @{hDefKey=$HKU; sSubKeyName=$location; sValueName=$valueName} -CimSession $cimSession -Verbose:$false).uValue) {
                        $plainCharList = New-Object Collections.Generic.List[char]
                        foreach ($cipherChar in $valueName.ToCharArray()) {
                            switch ($cipherChar) {
                                { $_ -ge 65 -and $_ -le 90 } { $plainCharList.Add((((($_ - 65 - 13) % 26 + 26) % 26) + 65)) } # Uppercase characters
                                { $_ -ge 97 -and $_ -le 122 } { $plainCharList.Add((((($_ - 97 - 13) % 26 + 26) % 26) + 97)) } # Lowercase characters
                                default { $plainCharList.Add($cipherChar) } # Pass through symbols and numbers
                            }
                        }
                        $lastExecutedTime = switch ($valueContent.Count) {
                            8 { [datetime]::FromFileTime(0) }
                            16 { [datetime]::FromFileTime([BitConverter]::ToInt64($valueContent[8..15],0)) }
                            default { [datetime]::FromFileTime([BitConverter]::ToInt64($valueContent[60..67],0)) }
                        }

                        Write-Output ([pscustomobject] @{
                            ComputerName = $ComputerName
                            UserSID = $SID
                            Entry = -join $plainCharList
                            LastExecutedTime = $lastExecutedTime.ToUniversalTime().ToString('o')
                        })
                    }
                }
            }
        }
    }

    END {
        Remove-CimSession -CimSession $cimSession
    }
}

function Local:Get-RegistryKey {
    param(
        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [Microsoft.Management.Infrastructure.CimSession[]]
        $CimSession,

        [Parameter(Mandatory = $True)]
        [UInt32]
        [ValidateSet(2147483650, 2147483649, 2147483651, 2147483648, 2147483653)]
        $Hive,

        [String]
        $SubKey = '',

        [Switch]
        $Recurse
    )
    $keys = (Invoke-CimMethod -Class 'StdRegProv' -Name 'EnumKey' -Arguments @{hDefKey=$Hive; sSubKeyName=$SubKey} -CimSession $CimSession -Verbose:$false).sNames
    foreach ($key in $keys) {
        $key = $SubKey + '\' + $key
        Write-Output $key
        if ($Recurse) {
            Get-RegistryKey -CimSession $CimSession -Hive $Hive -SubKey $key -Recurse
        }
    }
}

function Local:Get-RegistryTypeMethod($Code) {
    $type = switch ($Code) {
        0  {'REG_NONE'}
        1  {'REG_SZ'}
        2  {'REG_EXPAND_SZ'}
        3  {'REG_BINARY'}
        4  {'REG_DWORD'}
        7  {'REG_MULTI_SZ'}
        8  {'REG_RESOURCE_LIST'} # Just treat this as binary
        9  {'REG_FULL_RESOURCE_DESCRIPTOR'} # Just treat this as binary
        10 {'REG_RESOURCE_REQUIREMENTS_LIST'} # Just treat this as binary
        11 {'REG_QWORD'}
    }

    switch ($type) {
        'REG_NONE' {
            $methodName = 'GetBinaryValue'
            $returnProp = 'uValue'
        }

        'REG_SZ' {
            $methodName = 'GetStringValue'
            $returnProp = 'sValue'
        }

        'REG_EXPAND_SZ' {
            $methodName = 'GetExpandedStringValue'
            $returnProp = 'sValue'
        }

        'REG_MULTI_SZ' {
            $methodName = 'GetMultiStringValue'
            $returnProp = 'sValue'
        }

        'REG_DWORD' {
            $methodName = 'GetDWORDValue'
            $returnProp = 'uValue'
        }

        'REG_QWORD' {
            $methodName = 'GetQWORDValue'
            $returnProp = 'uValue'
        }

        'REG_BINARY' {
            $methodName = 'GetBinaryValue'
            $returnProp = 'uValue'
        }

        'REG_RESOURCE_LIST' {
            $methodName = 'GetBinaryValue'
            $returnProp = 'uValue'
        }

        'REG_FULL_RESOURCE_DESCRIPTOR' {
            $methodName = 'GetBinaryValue'
            $returnProp = 'uValue'
        }

        'REG_RESOURCE_REQUIREMENTS_LIST' {
            $methodName = 'GetBinaryValue'
            $returnProp = 'uValue'
        }
    }
    return [pscustomobject] @{MethodName = $methodName; ReturnProp = $returnProp}
}
