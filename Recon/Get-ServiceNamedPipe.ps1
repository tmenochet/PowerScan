Function Get-ServiceNamedPipe {
<#
.SYNOPSIS
    Detect interesting services on remote computer.
    Privileges required: low

    Author: Timothée MENOCHET (@_tmenochet)

.DESCRIPTION
    Get-ServiceNamedPipe queries remote host for named pipes associated by interesting services.

.PARAMETER ComputerName
    Specifies the target host.

.PARAMETER Credential
    Specifies the account to use.

.PARAMETER ServiceName
    Specifies a service by name.

.EXAMPLE
    PS C:\> Get-ServiceNamedPipe -ComputerName SRV.ADATUM.CORP -Credential ADATUM\testuser
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

        [ValidateSet('Spooler', 'WebClient')]
        [string]
        $ServiceName
    )

    if ($Credential.UserName) {
        $logonToken = Invoke-UserImpersonation -Credential $Credential
    }

    $result = New-Object -TypeName psobject
    $result | Add-Member -MemberType NoteProperty -Name 'ComputerName' -Value $ComputerName

    if ($ServiceName -eq 'WebClient' -or -not $ServiceName) {
        try {
            $null = Get-ChildItem -Path "\\$ComputerName\pipe\DAV RPC SERVICE" -ErrorAction Stop
            $webclientStatus = $true
        }
        catch {
            $webclientStatus = $false
        }
        $result | Add-Member -MemberType NoteProperty -Name 'WebClient' -Value $webclientStatus
    }

    if ($ServiceName -eq 'Spooler' -or -not $ServiceName) {
        try {
            $null = Get-ChildItem -Path "\\$ComputerName\pipe\SPOOLSS" -ErrorAction Stop
            $spoolerStatus = $true
        }
        catch {
            $spoolerStatus = $false
        }
        $result | Add-Member -MemberType NoteProperty -Name 'Spooler' -Value $spoolerStatus
    }

    Write-Output $result

    if ($logonToken) {
        Invoke-RevertToSelf -TokenHandle $logonToken
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
    Param(
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
    [CmdletBinding()]
    Param(
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

