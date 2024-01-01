#requires -version 3

Function Get-CimRegistryValue {
<#
.SYNOPSIS
    Get registry value names from a remote host.
    Privileges required: high

    Author: Timothée MENOCHET (@_tmenochet)

.DESCRIPTION
    Get-CimRegistryValue queries remote host through WMI for registry value names and data types.
    It is a slightly modified version of CimSweep's Get-CSRegistryValue by @mattifestation.

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

.PARAMETER Hive
    Specifies the registry hive.

.PARAMETER SubKey
    Specifies the path that contains the subkeys to be enumerated.

.PARAMETER ValueName
    Specifies the registry value name.

.EXAMPLE
    PS C:\> Get-CimRegistryValue -ComputerName SRV.ADATUM.CORP -Credential ADATUM\Administrator -Hive HKLM -Subkey 'SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ValueName CurrentVersion
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

        [Parameter(Mandatory = $True)]
        [String]
        [ValidateSet('HKLM', 'HKCU', 'HKU')]
        $Hive,

        [String]
        $SubKey = '',

        [String]
        $ValueName
    )

    Begin {
        # Init variables
        $cimOption = New-CimSessionOption -Protocol $Protocol
        switch ($Hive) {
            'HKLM' { $HiveVal = [UInt32] 2147483650 }
            'HKCU' { $HiveVal = [UInt32] 2147483649 }
            'HKU'  { $HiveVal = [UInt32] 2147483651 }
        }
        $trimmedKey = $SubKey.Trim('\')
        $type = @{
            0  = 'REG_NONE'
            1  = 'REG_SZ'
            2  = 'REG_EXPAND_SZ'
            3  = 'REG_BINARY'
            4  = 'REG_DWORD'
            7  = 'REG_MULTI_SZ'
            8  = 'REG_RESOURCE_LIST' # Just treat this as binary
            9  = 'REG_FULL_RESOURCE_DESCRIPTOR' # Just treat this as binary
            10 = 'REG_RESOURCE_REQUIREMENTS_LIST' # Just treat this as binary
            11 = 'REG_QWORD'
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
        if ($Hive -eq 'HKCU') {
            $SIDS = Invoke-CimMethod -Class 'StdRegProv' -Name 'EnumKey' -Arguments @{hDefKey=([UInt32] 2147483651); sSubKeyName=''} -CimSession $cimSession -Verbose:$false | Select-Object -ExpandProperty sNames | Where-Object {$_ -match 'S-1-5-21-[\d\-]+$'}
            foreach ($SID in $SIDs) {
                $newSubKey = "$SID\$trimmedKey".Trim('\')
                if ($ValueName) {
                    if (-not $PSBoundParameters['ComputerName']) {
                        Get-CimRegistryValue -Ping:$Ping -Credential $Credential -Authentication $Authentication -Protocol $Protocol -Hive 'HKU' -SubKey $newSubKey -ValueName $ValueName
                    }
                    else {
                        Get-CimRegistryValue -Ping:$Ping -ComputerName $ComputerName -Credential $Credential -Authentication $Authentication -Protocol $Protocol -Hive 'HKU' -SubKey $newSubKey -ValueName $ValueName
                    }
                }
                else {
                    if (-not $PSBoundParameters['ComputerName']) {
                        Get-CimRegistryValue -Ping:$Ping -Credential $Credential -Authentication $Authentication -Protocol $Protocol -Hive 'HKU' -SubKey $newSubKey
                    }
                    else {
                        Get-CimRegistryValue -Ping:$Ping -ComputerName $ComputerName -Credential $Credential -Authentication $Authentication -Protocol $Protocol -Hive 'HKU' -SubKey $newSubKey
                    }
                }
            }
        }
        else {
            $result = Invoke-CimMethod -Namespace 'root/default' -ClassName 'StdRegProv' -MethodName 'EnumValues' -Arguments @{hDefKey=$HiveVal; sSubKeyName=$trimmedKey} -CimSession $cimSession -Verbose:$false
            if ($result.Types.Length) {
                [String[]] $types = foreach ($value in $result.Types) { $type[$value] }

                $valueNames = $result.sNames

                for ($i = 0; $i -lt $result.Types.Length; $i++) {
                    $valueContent = $null

                    switch ($types[$i]) {
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
                        default {
                            Write-Warning "[$ComputerName] $($Result.Types[$i]) is not a supported registry value type. Hive: $Hive. SubKey: $SubKey"
                            $methodName = 'GetBinaryValue'
                            $returnProp = 'uValue'
                        }
                    }

                    if (($PSBoundParameters.ContainsKey('ValueName') -and ($valueName -eq $valueNames[$i])) -or (-not $PSBoundParameters.ContainsKey('ValueName'))) {
                        $valueName = if ($valueNames[$i]) { $valueNames[$i] } else { '(Default)' }

                        $valueContent = $null
                        $result2 = Invoke-CimMethod -Namespace 'root/default' -ClassName 'StdRegProv' -MethodName $methodName -Arguments @{hDefKey=$HiveVal; sSubKeyName=$trimmedKey; sValueName=$valueNames[$i]} -CimSession $cimSession -Verbose:$false
                        if ($result2.ReturnValue -eq 0) {
                            $valueContent = $result2."$returnProp"
                        }

                        $obj = New-Object -TypeName psobject
                        $obj | Add-Member -MemberType NoteProperty -Name 'ComputerName' -Value $ComputerName
                        $obj | Add-Member -MemberType NoteProperty -Name 'Hive' -Value $Hive
                        $obj | Add-Member -MemberType NoteProperty -Name 'SubKey' -Value $trimmedKey
                        $obj | Add-Member -MemberType NoteProperty -Name 'ValueName' -Value $valueName
                        $obj | Add-Member -MemberType NoteProperty -Name 'Type' -Value $types[$i]
                        $obj | Add-Member -MemberType NoteProperty -Name 'ValueContent' -Value $valueContent
                        Write-Output $obj
                    }
                }
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