#requires -version 3

function Get-CimAsepLogon {
<#
.SYNOPSIS
    Get logon artifacts on a remote computer.
    Privileges required: high

    Author: Timothée MENOCHET (@_tmenochet)

.DESCRIPTION
    Get-CimAsepLogon enumerates AutoStart Extension Points (ASEPs) related to logon on a remote host through WMI.

.PARAMETER ComputerName
    Specifies the target host.

.PARAMETER Credential
    Specifies the privileged account to use.

.PARAMETER Ping
    Ensures host is up before run.

.PARAMETER Protocol
    Specifies the protocol to use, defaults to DCOM.

.EXAMPLE
    PS C:\> Get-CimAsepLogon -ComputerName SRV.ADATUM.CORP -Credential ADATUM\Administrator
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

        [uint32]$HKLM = 2147483650
        [uint32]$HKU = 2147483651
        $SIDS = Invoke-CimMethod -Class 'StdRegProv' -Name 'EnumKey' -Arguments @{hDefKey=$HKU; sSubKeyName=''} -CimSession $cimSession -Verbose:$false | Select-Object -ExpandProperty sNames | Where-Object {$_ -match 'S-1-5-21-[\d\-]+$'}
    }

    PROCESS {
        $key = 'SYSTEM\CurrentControlSet\Control\Terminal Server\Wds\rdpwd'
        $value = 'StartupPrograms'
        if ($data = (Invoke-CimMethod -Class 'StdRegProv' -Name 'GetExpandedStringValue' -Arguments @{hDefKey=$HKLM; sSubKeyName=$key; sValueName=$value} -CimSession $cimSession -Verbose:$false).sValue) {
            Write-Output ([pscustomobject] @{ComputerName=$ComputerName; Location=$key; Value=$value; Data=$data})
        }

        $key = 'SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'
        $value = 'InitialProgram'
        if ($data = (Invoke-CimMethod -Class 'StdRegProv' -Name 'GetExpandedStringValue' -Arguments @{hDefKey=$HKLM; sSubKeyName=$key; sValueName=$value} -CimSession $cimSession -Verbose:$false).sValue) {
            Write-Output ([pscustomobject] @{ComputerName=$ComputerName; Location=$key; Value=$value; Data=$data})
        }

        $key = 'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows'
        $value = 'IconServiceLib'
        if ($data = (Invoke-CimMethod -Class 'StdRegProv' -Name 'GetExpandedStringValue' -Arguments @{hDefKey=$HKLM; sSubKeyName=$key; sValueName=$value} -CimSession $cimSession -Verbose:$false).sValue) {
            Write-Output ([pscustomobject] @{ComputerName=$ComputerName; Location=$key; Value=$value; Data=$data})
        }

        $key = 'SYSTEM\CurrentControlSet\Control\SafeBoot'
        $value = 'AlternateShell'
        if ($data = (Invoke-CimMethod -Class 'StdRegProv' -Name 'GetExpandedStringValue' -Arguments @{hDefKey=$HKLM; sSubKeyName=$key; sValueName=$value} -CimSession $cimSession -Verbose:$false).sValue) {
            Write-Output ([pscustomobject] @{ComputerName=$ComputerName; Location=$key; Value=$value; Data=$data})
        }

        $key = 'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
        $values = @('VmApplet','Userinit','Shell','TaskMan','AppSetup')
        foreach ($value in $values) {
            if ($data = (Invoke-CimMethod -Class 'StdRegProv' -Name 'GetExpandedStringValue' -Arguments @{hDefKey=$HKLM; sSubKeyName=$key; sValueName=$value} -CimSession $cimSession -Verbose:$false).sValue) {
                Write-Output ([pscustomobject] @{ComputerName=$ComputerName; Location=$key; Value=$value; Data=$data})
            }
        }

        $keys = @(
            "SOFTWARE\Microsoft\Windows CE Services\AutoStartOnConnect"
            "SOFTWARE\Wow6432Node\Microsoft\Windows CE Services\AutoStartOnConnect"
            "SOFTWARE\Microsoft\Windows CE Services\AutoStartOnDisconnect"
            "SOFTWARE\Wow6432Node\Microsoft\Windows CE Services\AutoStartOnDisconnect"
            "SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\AlternateShells\AvailableShells"
        )
        foreach ($key in $keys) {
            $entries = Invoke-CimMethod -Class 'StdRegProv' -Name 'EnumValues' -Arguments @{hDefKey=$HKLM; sSubKeyName=$key} -CimSession $cimSession -Verbose:$false
            $index = 0
            foreach ($result in $entries.Types) {
                $value = $($entries.sNames[$index])
                $type = Get-RegistryTypeMethod($result)
                if ($data = (Invoke-CimMethod -Class 'StdRegProv' -Name $type.MethodName -Arguments @{hDefKey=$HKLM; sSubKeyName=$key; sValueName=$value} -CimSession $cimSession -Verbose:$false | Select-Object -ExpandProperty $type.ReturnProp)) {
                    Write-Output ([pscustomobject] @{ComputerName=$ComputerName; Location=$key; Value=$value; Data=$data})
                }
                $index++
            }
        }

        $key = "SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\GPExtensions"
        $keys = (Invoke-CimMethod -Class 'StdRegProv' -Name 'EnumKey' -Arguments @{hDefKey=$HKLM; sSubKeyName=$key} -CimSession $cimSession -Verbose:$false).sNames
        $value = "DllName"
        foreach ($location in $keys) {
            $location = $key + '\' + $location
            if ($data = (Invoke-CimMethod -Class 'StdRegProv' -Name 'GetExpandedStringValue' -Arguments @{hDefKey=$HKLM; sSubKeyName=$location; sValueName=$value} -CimSession $cimSession -Verbose:$false).sValue) {
                Write-Output ([pscustomobject] @{ComputerName=$ComputerName; Location=$location; Value=$value; Data=$data})
            }
        }

        $keys = @(
            "SOFTWARE\Microsoft\Active Setup\Installed Components"
            "SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components"
        )
        $value = "StubPath"
        foreach ($key in $keys) {
            $locations = (Invoke-CimMethod -Class 'StdRegProv' -Name 'EnumKey' -Arguments @{hDefKey=$HKLM; sSubKeyName=$key} -CimSession $cimSession -Verbose:$false).sNames
            foreach ($location in $locations) {
                $location = $key + '\' + $location
                if ($data = (Invoke-CimMethod -Class 'StdRegProv' -Name 'GetExpandedStringValue' -Arguments @{hDefKey=$HKLM; sSubKeyName=$location; sValueName=$value} -CimSession $cimSession -Verbose:$false).sValue) {
                    Write-Output ([pscustomobject] @{ComputerName=$ComputerName; Location=$location; Value=$value; Data=$data})
                }
            }
        }

        $keys = @(
            "SOFTWARE\Policies\Microsoft\Windows\System\Scripts\Startup"
            "SOFTWARE\Policies\Microsoft\Windows\System\Scripts\Shutdown"
            "SOFTWARE\Policies\Microsoft\Windows\System\Scripts\Logon"
            "SOFTWARE\Policies\Microsoft\Windows\System\Scripts\Logoff"
        )
        $value = "Script"
        foreach ($key in $keys) {
            $locations = Get-RegistryKey -CimSession $cimSession -Hive $HKLM -SubKey $key -Recurse
            foreach ($location in $locations) {
                if ($data = (Invoke-CimMethod -Class 'StdRegProv' -Name 'GetExpandedStringValue' -Arguments @{hDefKey=$HKLM; sSubKeyName=$location; sValueName=$value} -CimSession $cimSession -Verbose:$false).sValue) {
                    Write-Output ([pscustomobject] @{ComputerName=$ComputerName; Location=$location; Value=$value; Data=$data})
                }
            }
        }

        $keys = @(
            'SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Startup'
            'SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Shutdown'
            'SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Logon'
            'SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Logoff'
        )
        $value = 'Script'
        foreach ($key in $keys) {
            $locations = Get-RegistryKey -CimSession $cimSession -Hive $HKLM -SubKey $key -Recurse
            foreach ($location in $locations) {
                if ($data = (Invoke-CimMethod -Class 'StdRegProv' -Name 'GetExpandedStringValue' -Arguments @{hDefKey=$HKLM; sSubKeyName=$location; sValueName=$value} -CimSession $cimSession -Verbose:$false).sValue) {
                    Write-Output ([pscustomobject] @{ComputerName=$ComputerName; Location=$key; Value=$value; Data=$data})
                }
            }
        }
        foreach ($SID in $SIDs) {
            foreach ($key in $keys) {
                $key = $SID + '\' + $key
                $locations = Get-RegistryKey -CimSession $cimSession -Hive $HKU -SubKey $key -Recurse
                foreach ($location in $locations) {
                    if ($data = (Invoke-CimMethod -Class 'StdRegProv' -Name 'GetExpandedStringValue' -Arguments @{hDefKey=$HKU; sSubKeyName=$location; sValueName=$value} -CimSession $cimSession -Verbose:$false).sValue) {
                        Write-Output ([pscustomobject] @{ComputerName=$ComputerName; Location=$key; Value=$value; Data=$data})
                    }
                }
            }
        }

        $key = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
        $value = 'Shell'
        if ($data = (Invoke-CimMethod -Class 'StdRegProv' -Name 'GetExpandedStringValue' -Arguments @{hDefKey=$HKLM; sSubKeyName=$key; sValueName=$value} -CimSession $cimSession -Verbose:$false).sValue) {
            Write-Output ([pscustomobject] @{ComputerName=$ComputerName; Location=$key; Value=$value; Data=$data})
        }
        foreach ($SID in $SIDs) {
            $location = $SID + '\' + $key
            if ($data = (Invoke-CimMethod -Class 'StdRegProv' -Name 'GetExpandedStringValue' -Arguments @{hDefKey=$HKU; sSubKeyName=$location; sValueName=$value} -CimSession $cimSession -Verbose:$false).sValue) {
                Write-Output ([pscustomobject] @{ComputerName=$ComputerName; Location=$location; Value=$value; Data=$data})
            }
        }

        $key = 'Environment'
        $value = 'UserInitMprLogonScript'
        if ($data = (Invoke-CimMethod -Class 'StdRegProv' -Name 'GetExpandedStringValue' -Arguments @{hDefKey=$HKLM; sSubKeyName=$key; sValueName=$value} -CimSession $cimSession -Verbose:$false).sValue) {
            Write-Output ([pscustomobject] @{ComputerName=$ComputerName; Location=$key; Value=$value; Data=$data})
        }
        foreach ($SID in $SIDs) {
            $location = $SID + '\' + $key
            if ($data = (Invoke-CimMethod -Class 'StdRegProv' -Name 'GetExpandedStringValue' -Arguments @{hDefKey=$HKU; sSubKeyName=$location; sValueName=$value} -CimSession $cimSession -Verbose:$false).sValue) {
                Write-Output ([pscustomobject] @{ComputerName=$ComputerName; Location=$location; Value=$value; Data=$data})
            }
        }

        $key = 'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows'
        $values = @('Load','Run')
        foreach ($SID in $SIDs) {
            $location = $SID + '\' + $key
            foreach ($value in $values) {
                if ($data = (Invoke-CimMethod -Class 'StdRegProv' -Name 'GetExpandedStringValue' -Arguments @{hDefKey=$HKU; sSubKeyName=$location; sValueName=$value} -CimSession $cimSession -Verbose:$false).sValue) {
                    Write-Output ([pscustomobject] @{ComputerName=$ComputerName; Location=$location; Value=$value; Data=$data})
                }
            }
        }

        $keys = @(
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
            "SOFTWARE\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\Run"
            "SOFTWARE\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\RunOnce"
            "SOFTWARE\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\RunOnceEx"
            "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"
        )
        foreach ($key in $keys) {
            $entries = Invoke-CimMethod -Class 'StdRegProv' -Name 'EnumValues' -Arguments @{hDefKey=$HKLM; sSubKeyName=$key} -CimSession $cimSession -Verbose:$false
            $index = 0
            foreach ($result in $entries.Types) {
                $value = $($entries.sNames[$index])
                $type = Get-RegistryTypeMethod($result)
                if ($data = (Invoke-CimMethod -Class 'StdRegProv' -Name $type.MethodName -Arguments @{hDefKey=$HKLM; sSubKeyName=$key; sValueName=$value} -CimSession $cimSession -Verbose:$false | Select-Object -ExpandProperty $type.ReturnProp)) {
                    Write-Output ([pscustomobject] @{ComputerName=$ComputerName; Location=$key; Value=$value; Data=$data})
                }
                $index++
            }
        }
        foreach ($SID in $SIDs) {
            foreach ($key in $keys) {
                $location = $SID + '\' + $key
                $entries = Invoke-CimMethod -Class 'StdRegProv' -Name 'EnumValues' -Arguments @{hDefKey=$HKU; sSubKeyName=$location} -CimSession $cimSession -Verbose:$false
                $index = 0
                foreach ($result in $entries.Types) {
                    $value = $($entries.sNames[$index])
                    $type = Get-RegistryTypeMethod($result)
                    if ($data = Invoke-CimMethod -Class 'StdRegProv' -Name $type.MethodName -Arguments @{hDefKey=$HKU; sSubKeyName=$location; sValueName=$value} -CimSession $cimSession -Verbose:$false | Select-Object -ExpandProperty $type.ReturnProp) {
                        Write-Output ([pscustomobject] @{ComputerName=$ComputerName; Location=$location; Value=$value; Data=$data})
                    }
                    $index++
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
