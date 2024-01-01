#requires -version 3

Function Get-CimRegistryKey {
<#
.SYNOPSIS
    Get registry subkeys from a remote host.
    Privileges required: high

    Author: Timothée MENOCHET (@_tmenochet)

.DESCRIPTION
    Get-CimRegistryKey queries remote host through WMI for registry key.
    It is a slightly modified version of CimSweep's Get-CSRegistryKey by @mattifestation.

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

.PARAMETER Recurse
    Gets the registry keys in the specified subkey as well as all child keys.

.EXAMPLE
    PS C:\> Get-CimRegistryKey -ComputerName SRV.ADATUM.CORP -Credential ADATUM\Administrator -Hive HKCU -SubKey SOFTWARE\Microsoft\Windows\CurrentVersion\
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
        [string]
        $Authentication = 'Default',

        [ValidateSet('Dcom', 'Wsman')]
        [string]
        $Protocol = 'Dcom',

        [Int]
        $Timeout = 3,

        [Parameter(Mandatory = $True)]
        [ValidateSet('HKLM', 'HKCU', 'HKU')]
        [string]
        $Hive,

        [string]
        $SubKey = '',

        [Switch]
        $Recurse
    )

    Begin {
        # Init variables
        $cimOption = New-CimSessionOption -Protocol $Protocol
        $trimmedKey = $SubKey.Trim('\')
        switch ($Hive) {
            'HKLM' { $HiveVal = [UInt32] 2147483650 }
            'HKCU' { $HiveVal = [UInt32] 2147483649 }
            'HKU'  { $HiveVal = [UInt32] 2147483651 }
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
                write-warning $SID
                $newSubKey = "$SID\$trimmedKey".Trim('\')
                if (-not $PSBoundParameters['ComputerName']) {
                    Get-CimRegistryKey -Ping:$Ping -Credential $Credential -Authentication $Authentication -Protocol $Protocol -Hive 'HKU' -SubKey $newSubKey -Recurse:$Recurse
                }
                else {
                    Get-CimRegistryKey -Ping:$Ping -ComputerName $ComputerName -Credential $Credential -Authentication $Authentication -Protocol $Protocol -Hive 'HKU' -SubKey $newSubKey -Recurse:$Recurse
                }
            }
        }
        else {
            $result = Invoke-CimMethod -Namespace 'root/default' -ClassName 'StdRegProv' -MethodName 'EnumKey' -Arguments @{hDefKey=$HiveVal; sSubKeyName=$trimmedKey} -CimSession $cimSession -Verbose:$false
            if ($result.sNames) {
                foreach ($keyName in $result.sNames) {
                    $newSubKey = "$trimmedKey\$keyName".Trim('\')

                    $obj = New-Object -TypeName psobject
                    $obj | Add-Member -MemberType NoteProperty -Name 'ComputerName' -Value $ComputerName
                    $obj | Add-Member -MemberType NoteProperty -Name 'Hive' -Value $Hive
                    $obj | Add-Member -MemberType NoteProperty -Name 'SubKey' -Value $newSubKey
                    Write-Output $obj

                    if ($PSBoundParameters['Recurse']) {
                        if (-not $PSBoundParameters['ComputerName']) {
                            Get-CimRegistryKey -Ping:$Ping -Credential $Credential -Authentication $Authentication -Protocol $Protocol -Hive $Hive -SubKey $newSubKey -Recurse
                        }
                        else {
                            Get-CimRegistryKey -Ping:$Ping -ComputerName $ComputerName -Credential $Credential -Authentication $Authentication -Protocol $Protocol -Hive $Hive -SubKey $newSubKey -Recurse
                        }
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