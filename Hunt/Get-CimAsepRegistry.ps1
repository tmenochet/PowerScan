#requires -version 3

function Get-CimAsepRegistry {
<#
.SYNOPSIS
    Get registry persistence on a remote computer.
    Privileges required: high

    Author: Timothée MENOCHET (@_tmenochet)

.DESCRIPTION
    Get-CimAsepRegistry enumerates AutoStart Extension Points (ASEPs) related to Windows registry on a remote host through WMI.

.PARAMETER ComputerName
    Specifies the target host.

.PARAMETER Credential
    Specifies the privileged account to use.

.PARAMETER Ping
    Ensures host is up before run.

.PARAMETER Protocol
    Specifies the protocol to use.

.EXAMPLE
    PS C:\> Get-CimAsepRegistry -ComputerName SRV.ADATUM.CORP -Credential ADATUM\Administrator
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

        [Switch]
        $Ping,

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
        $psOption = New-PSSessionOption -NoMachineProfile
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
        [uint32]$HKLM = 2147483650
        $machineStartPaths = @(
            "SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
            "SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
            "SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx"
            "SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices"
            "SOFTWARE\Microsoft\Windows\CurrentVersion\RunServicesOnce"
            "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run"
            "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce"
            "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnceEx"
            "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServices"
            "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce"
            "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"
            "SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\SharedTaskScheduler"
            "SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run"
            "SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run32"
            "SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\StartupFolder"
            "SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders"
            "SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders"
            "SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects"
            "SOFTWARE\Microsoft\Windows\CurrentVersion\ShellServiceObjectDelayLoad"
            "SOFTWARE\Microsoft\Command Processor"
            "SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
            "SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs"
            "SOFTWARE\Microsoft\Windows NT\CurrentVersion\IniFileMapping\system.ini\boot\Shell"
            "SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\osk.exe"
            "SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe"
            "SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\utilman.exe"
            "SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\magnify.exe"
            "SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\narrator.exe"
            "SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\DisplaySwitch.exe"
            "SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\AtBroker.exe"
            "SYSTEM\CurrentControlSet\Control\Session Manager\BootExecute"
            "SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs"
            "SYSTEM\CurrentControlSet\Control\Session Manager\SafeDllSearchMode"
        )

        foreach ($location in $machineStartPaths) {
            $entries = Invoke-CimMethod -Class 'StdRegProv' -Name 'EnumValues' -Arguments @{hDefKey=$HKLM; sSubKeyName=$location} -CimSession $cimSession -Verbose:$false
            $index = 0
            foreach ($result in $entries.Types) {
                $type = Get-RegistryTypeMethod($result)
                $output = Invoke-CimMethod -Class 'StdRegProv' -Name $type.MethodName -Arguments @{hDefKey=$HKLM; sSubKeyName=$location; sValueName=$($entries.sNames[$index])} -CimSession $cimSession -Verbose:$false | Select-Object -ExpandProperty $type.ReturnProp
                [pscustomobject] @{Location = $location; Key=$($entries.sNames[$index]); Value = $output}                
                $index++
            }
        }

        [uint32]$HKU = 2147483651
        $userStartPaths = @(
            "SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
            "SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
            "SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices"
            "SOFTWARE\Microsoft\Windows\CurrentVersion\RunServicesOnce"
            "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce"
            "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"
            "SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run"
            "SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run32"
            "SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\StartupFolder"
            "SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders"
            "SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders"
            "SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows"
            "SOFTWARE\Microsoft\Command Processor"
            "SOFTWARE\Microsoft\Windows\CurrentVersion\Control Panel\CPLs"
            "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Control Panel\CPLs"
        )

        $SIDS = Invoke-CimMethod -Class 'StdRegProv' -Name 'EnumKey' -Arguments @{hDefKey=$HKU; sSubKeyName=''} -CimSession $cimSession -Verbose:$false | Select-Object -ExpandProperty sNames | Where-Object {$_ -match 'S-1-5-21-[\d\-]+$'}
        foreach ($SID in $SIDs) {
            foreach ($location in $userStartPaths) {
                $location = $SID + '\' + $location
                $entries = Invoke-CimMethod -Class 'StdRegProv' -Name 'EnumValues' -Arguments @{hDefKey=$HKU; sSubKeyName=$location} -CimSession $cimSession -Verbose:$false
                $index = 0
                foreach ($result in $entries.Types) {
                    $type = Get-RegistryTypeMethod($result)
                    $output = Invoke-CimMethod -Class 'StdRegProv' -Name $type.MethodName -Arguments @{hDefKey=$HKU; sSubKeyName=$location; sValueName=$($entries.sNames[$index])} -CimSession $cimSession -Verbose:$false | Select-Object -ExpandProperty $type.ReturnProp
                    [pscustomobject] @{Location = $location; Key=$($entries.sNames[$index]); Value = $output}
                    $index++
                }
            }
        }

    }

    END {
        Remove-CimSession -CimSession $cimSession
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
