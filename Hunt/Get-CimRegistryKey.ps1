#requires -version 3

function Get-CimRegistryKey {
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

.PARAMETER Ping
    Ensures host is up before run.

.PARAMETER Protocol
    Specifies the protocol to use, defaults to DCOM.

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

        [Switch]
        $Ping,

        [ValidateSet('Dcom', 'Wsman')]
        [string]
        $Protocol = 'Dcom',

        [Parameter(Mandatory = $True)]
        [String]
        [ValidateSet('HKLM', 'HKCU', 'HKU')]
        $Hive,

        [String]
        $SubKey = '',

        [Switch]
        $Recurse
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
        switch ($Hive) {
            'HKLM' { $HiveVal = [UInt32] 2147483650 }
            'HKCU' { $HiveVal = [UInt32] 2147483649 }
            'HKU'  { $HiveVal = [UInt32] 2147483651 }
        }

        $trimmedKey = $SubKey.Trim('\')

        if ($Hive -eq 'HKCU') {
            $SIDS = Invoke-CimMethod -Class 'StdRegProv' -Name 'EnumKey' -Arguments @{hDefKey=([UInt32] 2147483651); sSubKeyName=''} -CimSession $cimSession -Verbose:$false | Select-Object -ExpandProperty sNames | Where-Object {$_ -match 'S-1-5-21-[\d\-]+$'}
            foreach ($SID in $SIDs) {
                $newSubKey = "$SID\$trimmedKey".Trim('\')
                Get-CimRegistryKey -Hive 'HKU' -SubKey $newSubKey -Recurse:$Recurse
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
                        Get-CimRegistryKey -Hive $Hive -SubKey $newSubKey -Recurse
                    }
                }
            }
        }
    }

    END {
        Remove-CimSession -CimSession $cimSession
    }
}