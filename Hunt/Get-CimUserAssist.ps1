#requires -version 3

Function Get-CimUserAssist {
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

.PARAMETER Credential
    Specifies the privileged account to use.

.PARAMETER Authentication
    Specifies what authentication method should be used.

.PARAMETER Protocol
    Specifies the protocol to use, defaults to DCOM.

.PARAMETER Timeout
    Specifies the duration to wait for a response from the target host (in seconds), defaults to 3.

.EXAMPLE
    PS C:\> Get-CimUserAssist -ComputerName SRV.ADATUM.CORP -Credential ADATUM\Administrator
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
        [uint32] $HKU = 2147483651
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
        $SIDS = Invoke-CimMethod -Class 'StdRegProv' -Name 'EnumKey' -Arguments @{hDefKey=$HKU; sSubKeyName=''} -CimSession $cimSession -Verbose:$false | Select-Object -ExpandProperty sNames | Where-Object {$_ -match 'S-1-5-21-[\d\-]+$'}
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

    End {
        # End session
        if ($cimSession) {
            Remove-CimSession -CimSession $cimSession
        }
    }
}

Function Local:Get-RegistryKey {
    Param (
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
