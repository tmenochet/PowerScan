Function Invoke-PowerScan {
<#
.SYNOPSIS
    Query multiple computers via PowerShell script block.

    Author: Timothée MENOCHET (@_tmenochet)

.DESCRIPTION
    Invoke-PowerScan runs PowerShell script block targeting network ranges or Active Directory domain computers instead of a single host.
    Multi-threading part is mostly stolen from PowerView by @harmj0y and @mattifestation.

.PARAMETER ScriptBlock
    Specifies the PowerShell script block to run.

.PARAMETER ScriptParameters
    Specifies the PowerShell script block arguments.

.PARAMETER ComputerArgument
    Specifies the PowerShell script block argument name for target host, defaults to "ComputerName".

.PARAMETER ComputerList
    Specifies the target hosts, such as specific addresses or network ranges (CIDR).

.PARAMETER ComputerDomain
    Specifies an Active Directory domain for enumerating target computers.

.PARAMETER ComputerFilter
    Specifies a specific role for enumerating target controllers, defaults to 'All'.

.PARAMETER Credential
    Specifies the account to use for LDAP bind.

.PARAMETER LAPS
    Adds LAPS credentials to script block parameters (experimental).

.PARAMETER Threads
    Specifies the number of threads to use, defaults to 10.

.PARAMETER Quiet
    Disables console output.

.PARAMETER NoCsv
    Disables CSV output.

.PARAMETER OutputFile
    Specifies CSV output file path, defaults to '.\$CurrentDate_$ModuleName.csv'

.EXAMPLE
    PS C:\> Invoke-PowerScan -ScriptBlock ${Function:Get-OxidBinding} -ComputerList 192.168.1.0/24 -Quiet

.EXAMPLE
    PS C:\> $cred = Get-Credential user@ADATUM.CORP
    PS C:\> Invoke-PowerScan -ScriptBlock ${Function:Get-NetSession} -ScriptParameters @{Credential=$cred; Identity='john.doe'} -ComputerDomain ADATUM.CORP -Credential $cred

.EXAMPLE
    PS C:\> Invoke-PowerScan -ScriptBlock ${Function:Get-LogonEvent} -ScriptParameters @{Identity='john.doe'} -ComputerFilter DomainControllers -NoCsv
#>

    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Management.Automation.ScriptBlock]
        $ScriptBlock,

        [ValidateNotNullOrEmpty()]
        [Hashtable]
        $ScriptParameters = @{},

        [ValidateNotNullOrEmpty()]
        [string]
        $ComputerArgument = 'ComputerName',

        [ValidateNotNullOrEmpty()]
        [string[]]
        $ComputerList,

        [ValidateNotNullOrEmpty()]
        [string]
        $ComputerDomain = $Env:LOGONSERVER,

        [ValidateSet('All', 'DomainControllers', 'Servers', 'Workstations')]
        [String]
        $ComputerFilter = 'All',

        [ValidateNotNullOrEmpty()]
        [Management.Automation.PSCredential]
        [Management.Automation.Credential()]
        $Credential = [Management.Automation.PSCredential]::Empty,

        [Switch]
        $LAPS,

        [ValidateNotNullOrEmpty()]
        [Int]
        $Threads = 10,

        [Switch]
        $Quiet,

        [Switch]
        $NoCsv,

        [ValidateNotNullOrEmpty()]
        [string]
        $OutputFile = "$PWD\$(Get-Date -Format "yyyyMMdd-HH.mm.ss")_$($ScriptBlock.Ast.Name).csv"
    )

    $hostList = New-Object Collections.ArrayList

    foreach ($computer in $ComputerList) {
        if ($computer -Contains '/') {
            $hostList.AddRange($(New-IPv4RangeFromCIDR -CIDR $computer))
        }
        else {
            $hostList.Add($computer) | Out-Null
        }
    }

    if ($PSBoundParameters['ComputerDomain'] -or $PSBoundParameters['ComputerFilter']) {
        switch ($ComputerFilter) {
            'All' {
                $filter = '(&(objectCategory=computer)(!userAccountControl:1.2.840.113556.1.4.803:=2))'
            }
            'DomainControllers' {
                $filter = '(userAccountControl:1.2.840.113556.1.4.803:=8192)'
            }
            'Servers' {
                $filter = '(&(objectCategory=computer)(operatingSystem=*server*)(!userAccountControl:1.2.840.113556.1.4.803:=2)(!userAccountControl:1.2.840.113556.1.4.803:=8192))'
            }
            'Workstations' {
                $filter = '(&(objectCategory=computer)(!operatingSystem=*server*)(!userAccountControl:1.2.840.113556.1.4.803:=2))'
            }
        }
        $searchString = "LDAP://$ComputerDomain/RootDSE"
        $domainObject = New-Object DirectoryServices.DirectoryEntry($searchString, $null, $null)
        $defaultNC = $domainObject.defaultNamingContext[0]
        $adsPath = "LDAP://$ComputerDomain/$defaultNC"
        $computers = Get-LdapObject -ADSpath $adsPath -Filter $filter -Properties 'dnshostname' -Credential $Credential
        foreach ($computer in $computers) {
            if ($computer.dnshostname) {
                $hostList.Add($($computer.dnshostname).ToString()) | Out-Null
            }
        }
    }

    if ($LAPS) {
        # Pass credential to ScriptBlock for Get-LapsCredential call
        $ScriptParameters.Add('Credential', $Credential)

        # Get-LapsCredential call definition
        $lapsBlock = [Environment]::NewLine
        $lapsBlock += 'if ($lapsCreds = Get-LapsCredential -ADSPath "' + $adsPath + '" -Credential $Credential -ComputerName $' + $ComputerArgument + ') {$Credential = $lapsCreds}'
        $lapsBlock += [Environment]::NewLine

        # Modify script block
        $count = 0
        try {
            $finalBlock = $ScriptBlock.Ast.Body.Extent.Text.Substring(1, $ScriptBlock.Ast.Body.ParamBlock.Extent.StartOffset - $ScriptBlock.Ast.Body.Extent.StartOffset - 1)
        }
        catch {
            $finalBlock = ''
        }
        if ($ScriptBlock.Ast.Body.ParamBlock) {
            # Add PARAM block
            $finalBlock += $ScriptBlock.Ast.Body.ParamBlock.ToString()
            $finalBlock += [Environment]::NewLine
        }
        if ($ScriptBlock.Ast.Body.BeginBlock) {
            # Modify BEGIN block
            $finalBlock += 'BEGIN {'
            $finalBlock += $lapsBlock
            foreach ($block in $ScriptBlock.Ast.Body.BeginBlock.Statements) {
                $finalBlock += $block.ToString()
                $finalBlock += [Environment]::NewLine
            }
            $finalBlock += '}'
            $finalBlock += [Environment]::NewLine
            $count++
        }
        if ($ScriptBlock.Ast.Body.ProcessBlock) {
            if ($count) {
                # Add PROCESS block
                $finalBlock += $ScriptBlock.Ast.Body.ProcessBlock.ToString()
            }
            else {
                # Modify PROCESS block
                $finalBlock += 'PROCESS {'
                $finalBlock += $lapsBlock
                foreach ($block in $ScriptBlock.Ast.Body.ProcessBlock.Statements) {
                    $finalBlock += $block.ToString()
                    $finalBlock += [Environment]::NewLine
                }
                $finalBlock += '}'
            }
            $finalBlock += [Environment]::NewLine
            $count++
        }
        if ($ScriptBlock.Ast.Body.EndBlock) {
            if ($count) {
                # Add END block
                $finalBlock += $ScriptBlock.Ast.Body.EndBlock.ToString()
            }
            else {
                # Case where BEGIN/PROCESS/END blocks are not specified
                $finalBlock += $lapsBlock
                $finalBlock += $ScriptBlock.ToString().Substring($ScriptBlock.Ast.Body.ParamBlock.Extent.StartOffset - $ScriptBlock.Ast.Body.Extent.StartOffset + $ScriptBlock.Ast.Body.ParamBlock.Extent.Text.Length)
            }
            $finalBlock += [Environment]::NewLine
            $count++
        }
        $ScriptBlock = [scriptblock]::Create($finalBlock)
    }

    New-ThreadedFunction -ScriptBlock $ScriptBlock -ScriptParameters $ScriptParameters -Collection $hostList -CollectionParameter $ComputerArgument -Threads $Threads | Where-Object {$_} | ForEach-Object {
        if (-not $Quiet) {
            Write-Output $_
        }
        if (-not $NoCsv) {
            Out-CsvFile -InputObject $_ -Path $OutputFile -Append
        }
    }
}

# Adapted from Find-Fruit by @rvrsh3ll
Function Local:New-IPv4RangeFromCIDR {
    Param (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $CIDR
    )

    $hostList = New-Object Collections.ArrayList
    $netPart = $CIDR.split("/")[0]
    [uint32]$maskPart = $CIDR.split("/")[1]

    $address = [Net.IPAddress]::Parse($netPart)
    if ($maskPart -ge $address.GetAddressBytes().Length * 8) {
        throw "Bad host mask"
    }

    $numhosts = [math]::Pow(2, (($address.GetAddressBytes().Length * 8) - $maskPart))

    $startaddress = $address.GetAddressBytes()
    [array]::Reverse($startaddress)

    $startaddress = [BitConverter]::ToUInt32($startaddress, 0)
    [uint32]$startMask = ([math]::Pow(2, $maskPart) - 1) * ([Math]::Pow(2, (32 - $maskPart)))
    $startAddress = $startAddress -band $startMask
    # In powershell 2.0 there are 4 0 bytes padded, so the [0..3] is necessary
    $startAddress = [BitConverter]::GetBytes($startaddress)[0..3]
    [array]::Reverse($startaddress)
    $address = [Net.IPAddress][byte[]]$startAddress

    for ($i = 0; $i -lt $numhosts - 2; $i++) {
        $nextAddress = $address.GetAddressBytes()
        [array]::Reverse($nextAddress)
        $nextAddress = [BitConverter]::ToUInt32($nextAddress, 0)
        $nextAddress++
        $nextAddress = [BitConverter]::GetBytes($nextAddress)[0..3]
        [array]::Reverse($nextAddress)
        $address = [Net.IPAddress][byte[]]$nextAddress
        $hostList.Add($address.IPAddressToString) | Out-Null
    }
    return $hostList
}

# Adapted from PowerView by @harmj0y and @mattifestation
Function Local:New-ThreadedFunction {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $True)]
        [String[]]
        $Collection,

        [ValidateNotNullOrEmpty()]
        [String]
        $CollectionParameter = 'ComputerName',

        [Parameter(Mandatory = $True)]
        [Management.Automation.ScriptBlock]
        $ScriptBlock,

        [Hashtable]
        $ScriptParameters,

        [Int]
        [ValidateRange(1,  100)]
        $Threads = 10,

        [Switch]
        $NoImports
    )

    BEGIN {
        $SessionState = [Management.Automation.Runspaces.InitialSessionState]::CreateDefault()

        # Force a single-threaded apartment state (for token-impersonation stuffz)
        $SessionState.ApartmentState = [Threading.ApartmentState]::STA

        # Import the current session state's variables and functions so the chained functionality can be used by the threaded blocks
        if (-not $NoImports) {
            # Grab all the current variables for this runspace
            $MyVars = Get-Variable -Scope 2

            # These variables are added by Runspace.Open() method and produce Stop errors if added twice
            $VorbiddenVars = @('?','args','ConsoleFileName','Error','ExecutionContext','false','HOME','Host','input','InputObject','MaximumAliasCount','MaximumDriveCount','MaximumErrorCount','MaximumFunctionCount','MaximumHistoryCount','MaximumVariableCount','MyInvocation','null','PID','PSBoundParameters','PSCommandPath','PSCulture','PSDefaultParameterValues','PSHOME','PSScriptRoot','PSUICulture','PSVersionTable','PWD','ShellId','SynchronizedHash','true')

            # Add variables from Parent Scope (current runspace) into the InitialSessionState
            foreach ($Var in $MyVars) {
                if ($VorbiddenVars -NotContains $Var.Name) {
                    $SessionState.Variables.Add((New-Object -TypeName Management.Automation.Runspaces.SessionStateVariableEntry -ArgumentList $Var.name,$Var.Value,$Var.description,$Var.options,$Var.attributes))
                }
            }

            # Add functions from current runspace to the InitialSessionState
            foreach ($Function in (Get-ChildItem Function:)) {
                $SessionState.Commands.Add((New-Object -TypeName Management.Automation.Runspaces.SessionStateFunctionEntry -ArgumentList $Function.Name, $Function.Definition))
            }
        }

        # Create a pool of $Threads runspaces
        $Pool = [RunspaceFactory]::CreateRunspacePool(1, $Threads, $SessionState, $Host)
        $Pool.Open()

        # Get the proper BeginInvoke() method that allows for an output queue
        $Method = $null
        foreach ($M in [PowerShell].GetMethods() | Where-Object { $_.Name -eq 'BeginInvoke' }) {
            $MethodParameters = $M.GetParameters()
            if (($MethodParameters.Count -eq 2) -and $MethodParameters[0].Name -eq 'input' -and $MethodParameters[1].Name -eq 'output') {
                $Method = $M.MakeGenericMethod([Object], [Object])
                break
            }
        }

        $Jobs = @()
        $Collection = $Collection | Where-Object {$_ -and $_.Trim()}
        Write-Verbose "[THREAD] Processing $($Collection.Count) elements with $Threads threads."

        foreach ($Element in $Collection) {
            # Create a "powershell pipeline runner"
            $PowerShell = [PowerShell]::Create()
            $PowerShell.runspacepool = $Pool

            # Add the script block and arguments
            $null = $PowerShell.AddScript($ScriptBlock).AddParameter($CollectionParameter, $Element)
            if ($ScriptParameters) {
                foreach ($Param in $ScriptParameters.GetEnumerator()) {
                    $null = $PowerShell.AddParameter($Param.Name, $Param.Value)
                }
            }

            # Create the output queue
            $Output = New-Object Management.Automation.PSDataCollection[Object]

            # Start job
            $Jobs += @{
                PS = $PowerShell
                Output = $Output
                Result = $Method.Invoke($PowerShell, @($null, [Management.Automation.PSDataCollection[Object]]$Output))
                Element = $Element
            }
        }
    }

    END {
        Write-Verbose "[THREAD] Executing threads"

        # Add element in each job output
        foreach ($Job in $Jobs) {
            $Job.Output | Add-Member -Force -MemberType NoteProperty -Name $CollectionParameter -Value $Job.Element
        }

        # Continuously loop through each job queue, consuming output as appropriate
        do {
            foreach ($Job in $Jobs) {
                $Job.Output.ReadAll()
            }
            Start-Sleep -Seconds 1
        }
        while (($Jobs | Where-Object {-not $_.Result.IsCompleted}).Count -gt 0)

        $SleepSeconds = 100
        Write-Verbose "[THREAD] Waiting $SleepSeconds seconds for final cleanup..."

        # Cleanup
        for ($i=0; $i -lt $SleepSeconds; $i++) {
            foreach ($Job in $Jobs) {
                $Job.Output.ReadAll()
                $Job.PS.Dispose()
            }
            Start-Sleep -Seconds 1
        }

        $Pool.Dispose()
        Write-Verbose "[THREAD] All threads completed"
    }
}

Function Local:Out-CsvFile {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Management.Automation.PSObject[]]
        $InputObject,

        [Parameter(Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Path,

        [ValidateNotNullOrEmpty()]
        [Char]
        $Delimiter = ';',

        [Switch]
        $Append
    )

    BEGIN {
        $outputPath = [IO.Path]::GetFullPath($Path)
        $exists = [IO.File]::Exists($outputPath)

        # Mutex so threaded code doesn't stomp on the output file
        $mutex = New-Object Threading.Mutex $False,'CSVMutex'
        $null = $mutex.WaitOne()

        if ($Append) {
            $fileMode = [IO.FileMode]::Append
        }
        else {
            $fileMode = [IO.FileMode]::Create
            $exists = $False
        }

        $csvStream = New-Object IO.FileStream($outputPath, $fileMode, [IO.FileAccess]::Write, [IO.FileShare]::Read)
        $csvWriter = New-Object IO.StreamWriter($csvStream)
        $csvWriter.AutoFlush = $True
    }

    PROCESS {
        foreach ($entry in $InputObject) {
            # Expand any collection properties
            $entry = $entry | % {
                $_.PSObject.Properties | % { $hash = @{} } { $hash.add($_.name, $_.value -join ", ") } { New-Object -TypeName psobject -Property $hash }
            }
            $objectCSV = ConvertTo-Csv -InputObject $entry -Delimiter $Delimiter -NoTypeInformation

            if (-not $exists) {
                # Output the object field names as well
                $objectCSV | ForEach-Object { $csvWriter.WriteLine($_) }
                $exists = $True
            }
            else {
                # Only output object field data
                $objectCSV[1..($objectCSV.Length-1)] | ForEach-Object { $csvWriter.WriteLine($_) }
            }
        }
    }

    END {
        $mutex.ReleaseMutex()
        $csvWriter.Dispose()
        $csvStream.Dispose()
    }
}

Function Local:Get-LdapObject {
    Param (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $ADSpath,

        [ValidateNotNullOrEmpty()]
        [String]
        $SearchScope = 'Subtree',

        [ValidateNotNullOrEmpty()]
        [String]
        $Filter = '(objectClass=*)',

        [ValidateNotNullOrEmpty()]
        [String[]]
        $Properties = '*',

        [ValidateRange(1,10000)] 
        [Int]
        $PageSize = 200,

        [ValidateNotNullOrEmpty()]
        [Management.Automation.PSCredential]
        [Management.Automation.Credential()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    if ($Credential.UserName) {
        $domainObject = New-Object DirectoryServices.DirectoryEntry($ADSpath, $Credential.UserName, $Credential.GetNetworkCredential().Password)
        $searcher = New-Object DirectoryServices.DirectorySearcher($domainObject)
    }
    else {
        $searcher = New-Object DirectoryServices.DirectorySearcher([ADSI]$ADSpath)
    }
    $searcher.SearchScope = $SearchScope
    $searcher.PageSize = $PageSize
    $searcher.CacheResults = $false
    $searcher.filter = $Filter
    $propertiesToLoad = $Properties | ForEach-Object {$_.Split(',')}
    $searcher.PropertiesToLoad.AddRange($propertiesToLoad) | Out-Null
    try {
        $results = $searcher.FindAll()
        $results | Where-Object {$_} | ForEach-Object {
            $objectProperties = @{}
            $p = $_.Properties
            $p.PropertyNames | ForEach-Object {
                if (($_ -ne 'adspath') -And ($p[$_].count -eq 1)) {
                    $objectProperties[$_] = $p[$_][0]
                }
                elseif ($_ -ne 'adspath') {
                    $objectProperties[$_] = $p[$_]
                }
            }
            New-Object -TypeName PSObject -Property ($objectProperties)
        }
        $results.dispose()
        $searcher.dispose()
    }
    catch {
        Write-Error $_ -ErrorAction Stop
    }
}

Function Local:Get-LapsCredential {
    Param (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $ADSpath,

        [ValidateNotNullOrEmpty()]
        [Management.Automation.PSCredential]
        [Management.Automation.Credential()]
        $Credential = [Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $ComputerName
    )

    BEGIN {
        if ($Credential.UserName) {
            $logonToken = Invoke-UserImpersonation -Credential $Credential
        }
    }

    PROCESS {
        $lapsCredential = $null
        $filter = "(&(sAMAccountType=805306369)(dnshostname=$ComputerName)(ms-MCS-AdmPwd=*))"
        Get-LdapObject -ADSpath $ADSpath -Filter $filter -Credential $Credential | ForEach-Object {
            if ($password = $_.'ms-MCS-AdmPwd') {
                $lapsPassword = ConvertTo-SecureString $password -AsPlainText -Force
                # Search for local group name for SID S-1-5-32-544
                $groupName = ''
                $computerProvider = [ADSI] "WinNT://$ComputerName,computer"
                $computerProvider.psbase.children | Where-Object { $_.psbase.schemaClassName -eq 'group' } | ForEach-Object {
                    $localGroup = [ADSI] $_
                    $groupSid = (New-Object Security.Principal.SecurityIdentifier($localGroup.InvokeGet('ObjectSID'), 0)).Value
                    if ($groupSid -eq 'S-1-5-32-544') {
                        $groupName = $localGroup.InvokeGet('Name')
                        break
                    }
                }
                # Search for local user name for RID 500
                $lapsUsername = 'Administrator' # default value
                if ($groupName) {
                    $groupProvider = [ADSI] "WinNT://$ComputerName/$groupName,group"
                    $groupProvider.psbase.Invoke('Members') | ForEach-Object {
                        $localUser = [ADSI] $_
                        $userSid = (New-Object Security.Principal.SecurityIdentifier($localUser.InvokeGet('ObjectSID'),0)).Value
                        if ($userSid -match '.*-500') {
                            $lapsUsername = $localUser.InvokeGet('Name')
                            break
                        }
                    }
                }
                $lapsCredential = New-Object Management.Automation.PSCredential ($lapsUsername, $lapsPassword)
                break
            }
        }
    }

    END {
        if ($logonToken) {
            Invoke-RevertToSelf -TokenHandle $logonToken
        }
        return $lapsCredential
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
