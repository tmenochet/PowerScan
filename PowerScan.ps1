function Invoke-PowerScan {
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

.PARAMETER DomainComputers
    Specifies an Active Directory domain for enumerating target controllers.

.PARAMETER Credential
    Specifies the account to use for LDAP bind.

.PARAMETER Threads
    Specifies the number of threads to use, defaults to 10.

.PARAMETER NoOutput
    Disables CSV output.

.PARAMETER OutputFile
    Specifies CSV output file path, defaults to '.\$ModuleName.csv'

.EXAMPLE
    PS C:\> Invoke-PowerScan -ScriptBlock ${function:Get-OxidBindings} -ComputerList 192.168.1.0/24

.EXAMPLE
    PS C:\> Invoke-PowerScan -ScriptBlock ${function:Get-NetSession} -ScriptParameters @{'Identity'='john.doe'} -DomainComputers ADATUM.CORP -NoOutput

.EXAMPLE
    PS C:\> $cred = Get-Credential Administrator@ADATUM.CORP
    PS C:\> Invoke-PowerScan -ScriptBlock ${function:Get-LogonEvent} -ScriptParameters @{'Credential'=$cred; 'Identity'='john.doe'} -DomainControllers ADATUM.CORP -Credential $cred
#>

    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [System.Management.Automation.ScriptBlock]
        $ScriptBlock,

        [ValidateNotNullOrEmpty()]
        [Hashtable]
        $ScriptParameters,

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
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty,

        [ValidateNotNullOrEmpty()]
        [Int]
        $Threads = 10,

        [Switch]
        $NoOutput,

        [ValidateNotNullOrEmpty()]
        [string]
        $OutputFile = "$PWD\$($ScriptBlock.Ast.Name).csv"
    )

    $hostList = New-Object System.Collections.ArrayList

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
        $domainObject = New-Object System.DirectoryServices.DirectoryEntry($searchString, $null, $null)
        $rootDN = $domainObject.rootDomainNamingContext[0]
        $ADSpath = "LDAP://$Domain/$rootDN"
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

    New-ThreadedFunction -ScriptBlock $ScriptBlock -ScriptParameters $ScriptParameters -Collection $hostList -CollectionParameter $ComputerArgument -Threads $Threads | Where-Object {$_} | ForEach-Object {
        Write-Output $_
        if (-not $NoOutput) {
            Write-OutputToCsv -InputObject $_ -Path $OutputFile -Append
        }
    }
}

# Adapted from Find-Fruit by @rvrsh3ll
function Local:New-IPv4RangeFromCIDR {
    Param (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $CIDR
    )

    $hostList = New-Object System.Collections.ArrayList
    $netPart = $CIDR.split("/")[0]
    [uint32]$maskPart = $CIDR.split("/")[1]

    $address = [System.Net.IPAddress]::Parse($netPart)
    if ($maskPart -ge $address.GetAddressBytes().Length * 8) {
        throw "Bad host mask"
    }

    $numhosts = [System.math]::Pow(2, (($address.GetAddressBytes().Length * 8) - $maskPart))

    $startaddress = $address.GetAddressBytes()
    [array]::Reverse($startaddress)

    $startaddress = [System.BitConverter]::ToUInt32($startaddress, 0)
    [uint32]$startMask = ([System.math]::Pow(2, $maskPart) - 1) * ([System.Math]::Pow(2, (32 - $maskPart)))
    $startAddress = $startAddress -band $startMask
    # In powershell 2.0 there are 4 0 bytes padded, so the [0..3] is necessary
    $startAddress = [System.BitConverter]::GetBytes($startaddress)[0..3]
    [array]::Reverse($startaddress)
    $address = [System.Net.IPAddress][byte[]]$startAddress

    for ($i = 0; $i -lt $numhosts - 2; $i++) {
        $nextAddress = $address.GetAddressBytes()
        [array]::Reverse($nextAddress)
        $nextAddress = [System.BitConverter]::ToUInt32($nextAddress, 0)
        $nextAddress++
        $nextAddress = [System.BitConverter]::GetBytes($nextAddress)[0..3]
        [array]::Reverse($nextAddress)
        $address = [System.Net.IPAddress][byte[]]$nextAddress
        $hostList.Add($address.IPAddressToString) | Out-Null
    }
    return $hostList
}

function Local:Get-LdapObject {
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
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    if ($Credential.UserName) {
        $domainObject = New-Object System.DirectoryServices.DirectoryEntry($ADSpath, $Credential.UserName, $Credential.GetNetworkCredential().Password)
        $searcher = New-Object System.DirectoryServices.DirectorySearcher($domainObject)
    }
    else {
        $searcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]$ADSpath)
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

# Adapted from PowerView by @harmj0y and @mattifestation
function Local:New-ThreadedFunction {
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
        [System.Management.Automation.ScriptBlock]
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
        $SessionState = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()

        # Force a single-threaded apartment state (for token-impersonation stuffz)
        $SessionState.ApartmentState = [System.Threading.ApartmentState]::STA

        # Import the current session state's variables and functions so the chained functionality can be used by the threaded blocks
        if (-not $NoImports) {
            # Grab all the current variables for this runspace
            $MyVars = Get-Variable -Scope 2

            # These variables are added by Runspace.Open() method and produce Stop errors if added twice
            $VorbiddenVars = @('?','args','ConsoleFileName','Error','ExecutionContext','false','HOME','Host','input','InputObject','MaximumAliasCount','MaximumDriveCount','MaximumErrorCount','MaximumFunctionCount','MaximumHistoryCount','MaximumVariableCount','MyInvocation','null','PID','PSBoundParameters','PSCommandPath','PSCulture','PSDefaultParameterValues','PSHOME','PSScriptRoot','PSUICulture','PSVersionTable','PWD','ShellId','SynchronizedHash','true')

            # Add variables from Parent Scope (current runspace) into the InitialSessionState
            foreach ($Var in $MyVars) {
                if ($VorbiddenVars -NotContains $Var.Name) {
                    $SessionState.Variables.Add((New-Object -TypeName System.Management.Automation.Runspaces.SessionStateVariableEntry -ArgumentList $Var.name,$Var.Value,$Var.description,$Var.options,$Var.attributes))
                }
            }

            # Add functions from current runspace to the InitialSessionState
            foreach ($Function in (Get-ChildItem Function:)) {
                $SessionState.Commands.Add((New-Object -TypeName System.Management.Automation.Runspaces.SessionStateFunctionEntry -ArgumentList $Function.Name, $Function.Definition))
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
            }
        }
    }

    END {
        Write-Verbose "[THREAD] Executing threads"

        # Continuously loop through each job queue, consuming output as appropriate
        do {
            foreach ($Job in $Jobs) {
                $Job.Output.ReadAll()
            }
            Start-Sleep -Seconds 1
        }
        while (($Jobs | Where-Object {-not $_.Result.IsCompleted}).Count -gt 0)

        $SleepSeconds = 10
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
function Local:Write-OutputToCsv {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [System.Management.Automation.PSObject[]]
        $InputObject,

        [Parameter(Mandatory = $True, Position = 1)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Path,

        [Parameter(Position = 2)]
        [ValidateNotNullOrEmpty()]
        [Char]
        $Delimiter = ',',

        [Switch]
        $Append
    )

    BEGIN {
        $OutputPath = [IO.Path]::GetFullPath($PSBoundParameters['Path'])
        $Exists = [System.IO.File]::Exists($OutputPath)

        # Mutex so threaded code doesn't stomp on the output file
        $Mutex = New-Object System.Threading.Mutex $False,'CSVMutex'
        $null = $Mutex.WaitOne()

        if ($PSBoundParameters['Append']) {
            $FileMode = [System.IO.FileMode]::Append
        }
        else {
            $FileMode = [System.IO.FileMode]::Create
            $Exists = $False
        }

        $CSVStream = New-Object IO.FileStream($OutputPath, $FileMode, [System.IO.FileAccess]::Write, [IO.FileShare]::Read)
        $CSVWriter = New-Object System.IO.StreamWriter($CSVStream)
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