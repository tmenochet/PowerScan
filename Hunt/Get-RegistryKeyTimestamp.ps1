Function Get-RegistryKeyTimestamp {
<#
.SYNOPSIS
    Get registry key timestamp from a remote host.
    Privileges required: high

    Author: Timothée MENOCHET (@_tmenochet)

.DESCRIPTION
    Get-RegistryKeyTimestamp queries remote host for registry key timestamp.
    It is a slightly modified version of Get-RegistryKeyTimestamp by Boe Prox.

.PARAMETER ComputerName
    Specifies the host to query.

.PARAMETER Credential
    Specifies the privileged account to use.

.PARAMETER Hive
    Specifies the registry hive.

.PARAMETER SubKey
    Specifies the path that contains the subkeys to be enumerated.

.EXAMPLE
    PS C:\> Get-RegistryKeyTimestamp -ComputerName SRV.ADATUM.CORP -Credential ADATUM\Administrator -Hive HKCU -SubKey SOFTWARE\Microsoft\Windows\CurrentVersion\
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

        [Parameter(Mandatory = $True)]
        [ValidateSet('HKLM', 'HKCU', 'HKU')]
        [string]
        $Hive,

        [Parameter()]
        [string]
        $SubKey = ''
    )

    Begin {
        if ($Credential.UserName) {
            $logonToken = Invoke-UserImpersonation -Credential $Credential
        }

        # Init variables
        $regQueryInfoKeyAddr = Get-ProcAddress Advapi32.dll RegQueryInfoKeyA
        $regQueryInfoKeyDelegate = Get-DelegateType @([Microsoft.Win32.SafeHandles.SafeRegistryHandle], [Text.StringBuilder], [UInt32].MakeByRefType(), [UInt32], [UInt32].MakeByRefType(), [UInt32].MakeByRefType(), [UInt32].MakeByRefType(), [UInt32].MakeByRefType(), [UInt32].MakeByRefType(), [UInt32].MakeByRefType(), [UInt32].MakeByRefType(), [long].MakeByRefType()) ([IntPtr])
        $regQueryInfoKey = [Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($regQueryInfoKeyAddr, $regQueryInfoKeyDelegate)
        switch ($Hive) {
            'HKLM' { $registryHive = [Microsoft.Win32.RegistryHive]::LocalMachine }
            'HKCU' { $registryHive = [Microsoft.Win32.RegistryHive]::CurrentUser }
            'HKU'  { $registryHive = [Microsoft.Win32.RegistryHive]::Users }
        }
        $trimmedKey = $SubKey.Trim('\')

    }

    Process {
        if ($Hive -eq 'HKCU') {
            try  {
                $registry = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::Users, $ComputerName)
                $SIDs = $registry.GetSubKeyNames() | Where-Object {$_ -match 'S-1-5-21-[\d\-]+$'}
                $registry.Close()
                foreach ($SID in $SIDs) {
                    $newSubKey = "$SID\$trimmedKey".Trim('\')
                    Get-RegistryKeyTimestamp -ComputerName $ComputerName -Credential $Credential -Hive 'HKU' -SubKey $newSubKey
                }
            }
            catch [Management.Automation.MethodInvocationException] {
                if($Error[0].FullyQualifiedErrorId -eq 'UnauthorizedAccessException') {
                    Write-Verbose "[$ComputerName] Access is denied."
                    return
                }
            }
        }
        else {
            $classLength = 255
            [long] $timestamp = $null
    
            try {
                $registry = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey($registryHive, $ComputerName)
                $registryKey = $registry.OpenSubKey($SubKey)
                if ($registryKey -isnot [Microsoft.Win32.RegistryKey]) {
                    Throw "Cannot open or locate $SubKey on $ComputerName"
                }
                $ClassName = New-Object System.Text.StringBuilder $registryKey.Name
                $registryHandle = $registryKey.Handle

                $return = $regQueryInfoKey.Invoke(
                    $registryHandle,
                    $className,
                    [ref]$classLength,
                    $null,
                    [ref]$null,
                    [ref]$null,
                    [ref]$null,
                    [ref]$null,
                    [ref]$null,
                    [ref]$null,
                    [ref]$null,
                    [ref]$timestamp
                )
                switch ($return) {
                    0 {
                        $result = [pscustomobject] @{
                            ComputerName = $ComputerName
                            RegistryKey = $registryKey.Name
                            LastWriteTime = [datetime]::FromFileTime($timestamp)
                        }
                        Write-Output $result
                    }
                    122 {
                        Throw "ERROR_INSUFFICIENT_BUFFER (0x7a)"
                    }
                    Default {
                        Throw "Error ($return) occurred"
                    }
                }
            }
            catch [Management.Automation.MethodInvocationException] {
                if($Error[0].FullyQualifiedErrorId -eq 'UnauthorizedAccessException') {
                    Write-Verbose "[$ComputerName] Access is denied."
                    return
                }
            }
        }
    }

    End {
        # End session
        if ($registry) {
            $registry.Close()
        }

        if ($logonToken) {
            Invoke-RevertToSelf -TokenHandle $logonToken
        }
    }
}

Function Local:Get-DelegateType {
    Param (
        [Type[]]
        $Parameters = (New-Object Type[](0)),

        [Type]
        $ReturnType = [Void]
    )
    $domain = [AppDomain]::CurrentDomain
    $dynAssembly = New-Object Reflection.AssemblyName('ReflectedDelegate')
    $assemblyBuilder = $domain.DefineDynamicAssembly($dynAssembly, [Reflection.Emit.AssemblyBuilderAccess]::Run)
    $moduleBuilder = $assemblyBuilder.DefineDynamicModule('InMemoryModule', $false)
    $typeBuilder = $moduleBuilder.DefineType('MyDelegateType', 'Class, Public, Sealed, AnsiClass, AutoClass', [MulticastDelegate])
    $constructorBuilder = $typeBuilder.DefineConstructor('RTSpecialName, HideBySig, Public', [Reflection.CallingConventions]::Standard, $Parameters)
    $constructorBuilder.SetImplementationFlags('Runtime, Managed')
    $methodBuilder = $typeBuilder.DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', $ReturnType, $Parameters)
    $methodBuilder.SetImplementationFlags('Runtime, Managed')
    Write-Output $typeBuilder.CreateType()
}

Function Local:Get-ProcAddress {
    Param (
        [Parameter(Mandatory = $True)]
        [String]
        $Module,

        [Parameter(Mandatory = $True)]
        [String]
        $Procedure
    )
    $systemAssembly = [AppDomain]::CurrentDomain.GetAssemblies() | Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1].Equals('System.dll') }
    $unsafeNativeMethods = $systemAssembly.GetType('Microsoft.Win32.UnsafeNativeMethods')
    $getModuleHandle = $unsafeNativeMethods.GetMethod('GetModuleHandle')
    $getProcAddress = $unsafeNativeMethods.GetMethod('GetProcAddress', [Type[]]@([Runtime.InteropServices.HandleRef], [String]))
    $kern32Handle = $getModuleHandle.Invoke($null, @($Module))
    $tmpPtr = New-Object IntPtr
    $handleRef = New-Object Runtime.InteropServices.HandleRef($tmpPtr, $kern32Handle)
    Write-Output $getProcAddress.Invoke($null, @([Runtime.InteropServices.HandleRef]$handleRef, $Procedure))
}

Function Local:Invoke-UserImpersonation {
    Param (
        [Parameter(Mandatory = $True)]
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential
    )

    $logonUserAddr = Get-ProcAddress Advapi32.dll LogonUserA
    $logonUserDelegate = Get-DelegateType @([String], [String], [String], [UInt32], [UInt32], [IntPtr].MakeByRefType()) ([Bool])
    $logonUser = [Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($logonUserAddr, $logonUserDelegate)

    $impersonateLoggedOnUserAddr = Get-ProcAddress Advapi32.dll ImpersonateLoggedOnUser
    $impersonateLoggedOnUserDelegate = Get-DelegateType @([IntPtr]) ([Bool])
    $impersonateLoggedOnUser = [Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($impersonateLoggedOnUserAddr, $impersonateLoggedOnUserDelegate)

    $logonTokenHandle = [IntPtr]::Zero
    $networkCredential = $Credential.GetNetworkCredential()
    $userDomain = $networkCredential.Domain
    $userName = $networkCredential.UserName

    if (-not $logonUser.Invoke($userName, $userDomain, $networkCredential.Password, 9, 3, [ref]$logonTokenHandle)) {
        $lastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        throw "[UserImpersonation] LogonUser error: $(([ComponentModel.Win32Exception] $lastError).Message)"
    }

    if (-not $impersonateLoggedOnUser.Invoke($logonTokenHandle)) {
        throw "[UserImpersonation] ImpersonateLoggedOnUser error: $(([ComponentModel.Win32Exception] $lastError).Message)"
    }
    Write-Output $logonTokenHandle
}

Function Local:Invoke-RevertToSelf {
    Param (
        [ValidateNotNull()]
        [IntPtr]
        $TokenHandle
    )

    $closeHandleAddr = Get-ProcAddress Kernel32.dll CloseHandle
    $closeHandleDelegate = Get-DelegateType @([IntPtr]) ([Bool])
    $closeHandle = [Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($closeHandleAddr, $closeHandleDelegate)

    $revertToSelfAddr = Get-ProcAddress Advapi32.dll RevertToSelf
    $revertToSelfDelegate = Get-DelegateType @() ([Bool])
    $revertToSelf = [Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($revertToSelfAddr, $revertToSelfDelegate)

    if ($PSBoundParameters['TokenHandle']) {
        $closeHandle.Invoke($TokenHandle) | Out-Null
    }
    if (-not $revertToSelf.Invoke()) {
        $lastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        throw "[RevertToSelf] Error: $(([ComponentModel.Win32Exception] $lastError).Message)"
    }
}
