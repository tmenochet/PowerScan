#requires -version 3

Function Get-CimAppCompatCache {
<#
.SYNOPSIS
    Get shimcache execution artefacts from a remote computer.
    Privileges required: high

    Author: Timothée MENOCHET (@_tmenochet)

.DESCRIPTION
    Get-CimAppCompatCache extracts shimcache entries on a remote host through WMI.
    It is a slightly modified version of CimSweep's Get-CSAppCompatCache by @secabstraction.

.PARAMETER ComputerName
    Specifies the target host.

.PARAMETER Ping
    Ensures host is up before run.

.PARAMETER Credential
    Specifies the privileged account to use.

.PARAMETER Authentication
    Specifies what authentication method should be used.

.PARAMETER Protocol
    Specifies the protocol to use, defaults to DCOM.

.EXAMPLE
    PS C:\> Get-CimAppCompatCache -ComputerName SRV.ADATUM.CORP -Credential ADATUM\Administrator
#>

    [CmdletBinding()]
    Param (
        [ValidateNotNullOrEmpty()]
        [String]
        $ComputerName = $env:COMPUTERNAME,

        [Switch]
        $Ping,

        [ValidateNotNullOrEmpty()]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty,

        [ValidateSet('Default', 'Kerberos', 'Negotiate', 'NtlmDomain')]
        [String]
        $Authentication = 'Default',

        [ValidateSet('Dcom', 'Wsman')]
        [String]
        $Protocol = 'Dcom'
    )

    Begin {
        # Optionally check host reachability
        if ($Ping -and -not $(Test-Connection -Count 1 -Quiet -ComputerName $ComputerName)) {
            Write-Verbose "[$ComputerName] Host is unreachable."
            continue
        }

        # Init variables
        $cimOption = New-CimSessionOption -Protocol $Protocol
        [uint32] $HKLM = 2147483650
    }

    Process {
        # Init remote session
        try {
            if (-not $PSBoundParameters['ComputerName']) {
                $cimSession = New-CimSession -SessionOption $cimOption -ErrorAction Stop -Verbose:$false
            }
            elseif ($Credential.Username) {
                $cimSession = New-CimSession -ComputerName $ComputerName -Credential $Credential -Authentication $Authentication -SessionOption $cimOption -ErrorAction Stop -Verbose:$false
            }
            else {
                $cimSession = New-CimSession -ComputerName $ComputerName -Authentication $Authentication -SessionOption $cimOption -ErrorAction Stop -Verbose:$false
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
        $OS = Get-CimInstance -ClassName Win32_OperatingSystem -CimSession $cimSession -Verbose:$false
        if ($OS.Version -like "5.1*") { 
            $subKey = 'SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatibility'
            $valueName = ''
        }
        else {
            $subKey = 'SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache'
            $valueName = 'AppCompatCache'
        }
        if ($valueContent = (Invoke-CimMethod -Class 'StdRegProv' -Name 'GetBinaryValue' -Arguments @{hDefKey=$HKLM; sSubKeyName=$subKey; sValueName=$valueName} -CimSession $cimSession -Verbose:$false).uValue) {
            ConvertFrom-AppCompatCacheValue -CacheValue $valueContent -OSVersion $OS.Version -OSArchitecture $OS.OSArchitecture | ForEach-Object {
                Write-Output ([pscustomobject] @{
                    ComputerName = $ComputerName
                    Path = $_.Path
                    LastModifiedTime = $_.LastModifiedTime
                })
            }
        }
    }

    End {
        # End remote session
        if ($cimSession) {
            Remove-CimSession -CimSession $cimSession
        }
    }
}

function Local:ConvertFrom-AppCompatCacheValue {
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [Object]
        $CacheValue,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $OSVersion,

        [Parameter()]
        [string]
        $OSArchitecture
    )

    $BinaryReader = New-Object IO.BinaryReader (New-Object IO.MemoryStream (,$CacheValue))

    $ASCIIEncoding = [Text.Encoding]::ASCII
    $UnicodeEncoding = [Text.Encoding]::Unicode

    switch ($OSVersion) {
        
        { $_ -like '10.*' } { # Windows 10

            $null = $BinaryReader.BaseStream.Seek(48, [IO.SeekOrigin]::Begin)

            # check for magic
            if ($ASCIIEncoding.GetString($BinaryReader.ReadBytes(4)) -ne '10ts') { 
                $null = $BinaryReader.BaseStream.Seek(52, [IO.SeekOrigin]::Begin) # offset shifted in creators update
                if ($ASCIIEncoding.GetString($BinaryReader.ReadBytes(4))  -ne '10ts') { throw 'Not Windows 10' }
            }

            do { # parse entries
                $null = $BinaryReader.BaseStream.Seek(8, [IO.SeekOrigin]::Current) # padding between entries                
                $Path = $UnicodeEncoding.GetString($BinaryReader.ReadBytes($BinaryReader.ReadUInt16()))
                $LastModifiedTime = [DateTimeOffset]::FromFileTime($BinaryReader.ReadInt64()).DateTime
                $null = $BinaryReader.ReadBytes($BinaryReader.ReadInt32()) # skip some bytes
                Write-Output ([PSCustomObject] @{
                    Path = $Path
                    LastModifiedTime = $LastModifiedTime.ToUniversalTime().ToString('o')
                })
            } until ($ASCIIEncoding.GetString($BinaryReader.ReadBytes(4)) -ne '10ts')
        }

        { $_ -like '6.3*' } { # Windows 8.1 / Server 2012 R2

            $null = $BinaryReader.BaseStream.Seek(128, [IO.SeekOrigin]::Begin)

            # check for magic
            if ($ASCIIEncoding.GetString($BinaryReader.ReadBytes(4)) -ne '10ts') { throw 'Not windows 8.1/2012r2' }
            
            do { # parse entries
                $null = $BinaryReader.BaseStream.Seek(8, [IO.SeekOrigin]::Current) # padding & datasize                
                $Path = $UnicodeEncoding.GetString($BinaryReader.ReadBytes($BinaryReader.ReadUInt16()))
                $null = $BinaryReader.ReadBytes(10) # skip insertion/shim flags & padding
                $LastModifiedTime = [DateTimeOffset]::FromFileTime($BinaryReader.ReadInt64()).DateTime
                $null = $BinaryReader.ReadBytes($BinaryReader.ReadInt32()) # skip some bytes
                Write-Output ([PSCustomObject] @{
                    Path = $Path
                    LastModifiedTime = $LastModifiedTime.ToUniversalTime().ToString('o')
                })
            } until ($ASCIIEncoding.GetString($BinaryReader.ReadBytes(4)) -ne '10ts')
        }

        { $_ -like '6.2*' } { # Windows 8.0 / Server 2012

            # check for magic
            $null = $BinaryReader.BaseStream.Seek(128, [IO.SeekOrigin]::Begin)
            if ($ASCIIEncoding.GetString($BinaryReader.ReadBytes(4)) -ne '00ts') { throw 'Not Windows 8/2012' }

            do { # parse entries
                $null = $BinaryReader.BaseStream.Seek(8, [IO.SeekOrigin]::Current) # padding & datasize
                $Path = $UnicodeEncoding.GetString($BinaryReader.ReadBytes($BinaryReader.ReadUInt16()))
                $null = $BinaryReader.BaseStream.Seek(10, [IO.SeekOrigin]::Current) # skip insertion/shim flags & padding
                $LastModifiedTime = [DateTimeOffset]::FromFileTime($BinaryReader.ReadInt64()).DateTime
                $null = $BinaryReader.ReadBytes($BinaryReader.ReadInt32()) # skip some bytes
                Write-Output ([PSCustomObject] @{
                    Path = $Path
                    LastModifiedTime = $LastModifiedTime.ToUniversalTime().ToString('o')
                })
            } until ($ASCIIEncoding.GetString($BinaryReader.ReadBytes(4)) -ne '00ts')
        }
        
        { $_ -like '6.1*' } { # Windows 7 / Server 2008 R2
            
            # check for magic
            if ([BitConverter]::ToString($BinaryReader.ReadBytes(4)[3..0]) -ne 'BA-DC-0F-EE') { throw 'Not Windows 7/2008R2'}
            $NumberOfEntries = $BinaryReader.ReadInt32()
            $null = $BinaryReader.BaseStream.Seek(128, [IO.SeekOrigin]::Begin) # skip padding

            if ($OSArchitecture -eq '32-bit') {

                do {
                    $EntryPosition++                    
                    $PathSize = $BinaryReader.ReadUInt16()
                    $null = $BinaryReader.ReadUInt16() # MaxPathSize
                    $PathOffset = $BinaryReader.ReadInt32()
                    $LastModifiedTime = [DateTimeOffset]::FromFileTime($BinaryReader.ReadInt64()).DateTime
                    $null = $BinaryReader.BaseStream.Seek(16, [IO.SeekOrigin]::Current)
                    $Position = $BinaryReader.BaseStream.Position
                    $null = $BinaryReader.BaseStream.Seek($PathOffset, [IO.SeekOrigin]::Begin)
                    $Path = $UnicodeEncoding.GetString($BinaryReader.ReadBytes($PathSize))
                    $null = $BinaryReader.BaseStream.Seek($Position, [IO.SeekOrigin]::Begin)
                    Write-Output ([PSCustomObject] @{
                        Path = $Path
                        LastModifiedTime = $LastModifiedTime.ToUniversalTime().ToString('o')
                    })
                } until ($EntryPosition -eq $NumberOfEntries)
            }

            else { # 64-bit

                do {
                    $EntryPosition++                    
                    $PathSize = $BinaryReader.ReadUInt16()
                    $null = $BinaryReader.BaseStream.Seek(6, [IO.SeekOrigin]::Current) # Padding
                    $PathOffset = $BinaryReader.ReadInt64()
                    $LastModifiedTime = [DateTimeOffset]::FromFileTime($BinaryReader.ReadInt64()).DateTime
                    $null = $BinaryReader.BaseStream.Seek(24, [IO.SeekOrigin]::Current)
                    $Position = $BinaryReader.BaseStream.Position
                    $null = $BinaryReader.BaseStream.Seek($PathOffset, [IO.SeekOrigin]::Begin)
                    $Path = $UnicodeEncoding.GetString($BinaryReader.ReadBytes($PathSize))
                    $null = $BinaryReader.BaseStream.Seek($Position, [IO.SeekOrigin]::Begin)
                    Write-Output ([PSCustomObject] @{
                        Path = $Path
                        LastModifiedTime = $LastModifiedTime.ToUniversalTime().ToString('o')
                    })
                } until ($EntryPosition -eq $NumberOfEntries)
            }
        }
        
        { $_ -like '6.0*' } { <# Windows Vista / Server 2008 #> }
        
        { $_ -like '5.2*' } { <# Windows XP Pro 64-bit / Server 2003 (R2) #> }
        
        { $_ -like '5.1*' } { # Windows XP 32-bit

            # check for magic
            if ([BitConverter]::ToString($BinaryReader.ReadBytes(4)[3..0]) -ne 'DE-AD-BE-EF') { throw 'Not Windows XP 32-bit'}

            $NumberOfEntries = $BinaryReader.ReadInt32() # this is always 96, even if there aren't 96 entries
            $null = $BinaryReader.BaseStream.Seek(400, [IO.SeekOrigin]::Begin) # skip padding

            do { # parse entries
                $EntryPosition++
                $Path = $UnicodeEncoding.GetString($BinaryReader.ReadBytes(528)).TrimEnd("`0") # 528 == MAX_PATH + 4 unicode chars
                $LastModifiedTime = [DateTimeOffset]::FromFileTime($BinaryReader.ReadInt64()).DateTime
                if (($LastModifiedTime.Year -eq 1600) -and !$Path) { break } # empty entries == end
                $null = $BinaryReader.BaseStream.Seek(16, [IO.SeekOrigin]::Current) # skip some bytes                
                Write-Output ([PSCustomObject] @{
                        Path = $Path
                        LastModifiedTime = $LastModifiedTime.ToUniversalTime().ToString('o')
                })
            } until ($EntryPosition -eq $NumberOfEntries)
        }
    }
    $BinaryReader.BaseStream.Dispose()
    $BinaryReader.Dispose()
}
