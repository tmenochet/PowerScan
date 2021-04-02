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

.PARAMETER DomainComputers
    Specifies an Active Directory domain for enumerating target computers.

.PARAMETER DomainControllers
    Specifies an Active Directory domain for enumerating target controllers.

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
    PS C:\> Invoke-PowerScan -ScriptBlock ${Function:Get-OxidBindings} -ComputerList 192.168.1.0/24 -Quiet

.EXAMPLE
    PS C:\> Invoke-PowerScan -ScriptBlock ${Function:Get-NetSession} -ScriptParameters @{'Identity'='john.doe'} -DomainComputers ADATUM.CORP -NoCsv

.EXAMPLE
    PS C:\> $cred = Get-Credential Administrator@ADATUM.CORP
    PS C:\> Invoke-PowerScan -ScriptBlock ${Function:Get-LogonEvent} -ScriptParameters @{'Credential'=$cred; 'Identity'='john.doe'} -DomainControllers ADATUM.CORP -Credential $cred
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
        $DomainComputers,

        [ValidateNotNullOrEmpty()]
        [string]
        $DomainControllers,

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
        if ($computer.contains("/")) {
            $hostList.AddRange($(New-IPv4RangeFromCIDR -CIDR $computer))
        }
        else {
            $hostList.Add($computer) | Out-Null
        }
    }

    if (($Domain = $DomainComputers) -or ($Domain = $DomainControllers)) {
        $searchString = "LDAP://$Domain/RootDSE"
        $domainObject = New-Object DirectoryServices.DirectoryEntry($searchString, $null, $null)
        $defaultNC = $domainObject.defaultNamingContext[0]
        $ADSpath = "LDAP://$Domain/$defaultNC"
        if ($DomainControllers) {
            $filter = "(userAccountControl:1.2.840.113556.1.4.803:=8192)"
        }
        else {
            $filter = "(&(samAccountType=805306369)(!userAccountControl:1.2.840.113556.1.4.803:=2))"
        }
        $computers = Get-LdapObject -ADSpath $ADSpath -Filter $filter -Properties 'dnshostname' -Credential $Credential
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
        $lapsBlock += 'if ($lapsCreds = Get-LapsCredential -ADSPath "' + $ADSpath + '" -Credential $Credential -ComputerName $' + $ComputerArgument + ') {$Credential = $lapsCreds}'
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
        [Parameter(Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
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

# Adapted from PowerView by @harmj0y and @mattifestation
Function Local:Out-CsvFile {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Management.Automation.PSObject[]]
        $InputObject,

        [Parameter(Mandatory = $True, Position = 1)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Path,

        [Parameter(Position = 2)]
        [ValidateNotNullOrEmpty()]
        [Char]
        $Delimiter = ';',

        [Switch]
        $Append
    )

    BEGIN {
        $OutputPath = [IO.Path]::GetFullPath($PSBoundParameters['Path'])
        $Exists = [IO.File]::Exists($OutputPath)

        # Mutex so threaded code doesn't stomp on the output file
        $Mutex = New-Object Threading.Mutex $False,'CSVMutex'
        $null = $Mutex.WaitOne()

        if ($PSBoundParameters['Append']) {
            $FileMode = [IO.FileMode]::Append
        }
        else {
            $FileMode = [IO.FileMode]::Create
            $Exists = $False
        }

        $CSVStream = New-Object IO.FileStream($OutputPath, $FileMode, [IO.FileAccess]::Write, [IO.FileShare]::Read)
        $CSVWriter = New-Object IO.StreamWriter($CSVStream)
        $CSVWriter.AutoFlush = $True
    }

    PROCESS {
        foreach ($Entry in $InputObject) {
            # Expand any collection properties
            $Entry = $Entry | % {
                $_.PSObject.Properties | % { $hash = @{} } { $hash.add($_.name, $_.value -join ", ") } { New-Object -TypeName psobject -Property $hash }
            }
            $ObjectCSV = ConvertTo-Csv -InputObject $Entry -Delimiter $Delimiter -NoTypeInformation

            if (-not $Exists) {
                # Output the object field names as well
                $ObjectCSV | ForEach-Object { $CSVWriter.WriteLine($_) }
                $Exists = $True
            }
            else {
                # Only output object field data
                $ObjectCSV[1..($ObjectCSV.Length-1)] | ForEach-Object { $CSVWriter.WriteLine($_) }
            }
        }
    }

    END {
        $Mutex.ReleaseMutex()
        $CSVWriter.Dispose()
        $CSVStream.Dispose()
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

# Adapted from PowerView by @harmj0y and @mattifestation
Function Local:Invoke-UserImpersonation {
    [OutputType([IntPtr])]
    [CmdletBinding(DefaultParameterSetName = 'Credential')]
    Param(
        [Parameter(Mandatory = $True, ParameterSetName = 'Credential')]
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential,

        [Parameter(Mandatory = $True, ParameterSetName = 'TokenHandle')]
        [ValidateNotNull()]
        [IntPtr]
        $TokenHandle,

        [Switch]
        $Quiet
    )

    if (([Threading.Thread]::CurrentThread.GetApartmentState() -ne 'STA') -and (-not $PSBoundParameters['Quiet'])) {
        Write-Warning "[UserImpersonation] powershell.exe is not currently in a single-threaded apartment state, token impersonation may not work."
    }

    if ($PSBoundParameters['TokenHandle']) {
        $LogonTokenHandle = $TokenHandle
    }
    else {
        $LogonTokenHandle = [IntPtr]::Zero
        $NetworkCredential = $Credential.GetNetworkCredential()
        $UserDomain = $NetworkCredential.Domain
        $UserName = $NetworkCredential.UserName
        Write-Verbose "[UserImpersonation] Executing LogonUser() with user: $($UserDomain)\$($UserName)"

        if (-not [Advapi32]::LogonUserA($UserName, $UserDomain, $NetworkCredential.Password, 9, 3, [ref]$LogonTokenHandle)) {
            $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
            throw "[UserImpersonation] LogonUser() Error: $(([ComponentModel.Win32Exception] $LastError).Message)"
        }
    }

    if (-not [Advapi32]::ImpersonateLoggedOnUser($LogonTokenHandle)) {
        throw "[UserImpersonation] ImpersonateLoggedOnUser() Error: $(([ComponentModel.Win32Exception] $LastError).Message)"
    }
    $LogonTokenHandle
}

# Adapted from PowerView by @harmj0y and @mattifestation
Function Local:Invoke-RevertToSelf {
    [CmdletBinding()]
    Param(
        [ValidateNotNull()]
        [IntPtr]
        $TokenHandle
    )

    if ($PSBoundParameters['TokenHandle']) {
        Write-Verbose "[RevertToSelf] Reverting token impersonation and closing LogonUser() token handle"
        [Kernel32]::CloseHandle($TokenHandle) | Out-Null
    }
    if (-not [Advapi32]::RevertToSelf()) {
        $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        throw "[RevertToSelf] RevertToSelf() Error: $(([ComponentModel.Win32Exception] $LastError).Message)"
    }
}

Add-Type @"
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
public static class Advapi32 {
    [DllImport("advapi32.dll", SetLastError=true)]
    public static extern bool LogonUserA(
        string lpszUserName, 
        string lpszDomain,
        string lpszPassword,
        int dwLogonType, 
        int dwLogonProvider,
        ref IntPtr  phToken
    );
    [DllImport("advapi32.dll", SetLastError=true)]
    public static extern bool ImpersonateLoggedOnUser(IntPtr hToken);
    [DllImport("advapi32.dll", SetLastError=true)]
    public static extern bool RevertToSelf();
}
public static class Kernel32 {
    [DllImport("kernel32.dll", SetLastError=true)]
	public static extern bool CloseHandle(IntPtr hObject);
}
"@
