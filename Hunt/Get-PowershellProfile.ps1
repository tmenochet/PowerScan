#requires -version 3

function Get-PowershellProfile {
<#
.SYNOPSIS
    Get Powershell profile on a remote computer.
    Privileges required: high

    Author: Timothée MENOCHET (@_tmenochet)

.DESCRIPTION
    Get-PowershellProfile enumerates Powershell profile files on a remote host through WMI and optionally downloads them.

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
    PS C:\> Get-PowershellProfile -ComputerName SRV.ADATUM.CORP -Credential ADATUM\Administrator -Download
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
        catch [System.Management.Automation.Remoting.PSRemotingTransportException] {
            Write-Verbose "[$ComputerName] Failed to establish PSRemoting session."
            break
        }
    }

    PROCESS {
        Get-CimInstance -ClassName Win32_UserProfile -CimSession $cimSession -Verbose:$false | ForEach-Object {
            $profilePath = $_.LocalPath
            $profileDrive = ($profilePath -split ":").Get(0)
            $profileDir = ($profilePath -split ":").Get(1) + "\Documents\WindowsPowershell\" -replace '\\','\\'
            $filter  = "Drive='${profileDrive}:' AND Path='$profileDir' AND FileName='Microsoft.Powershell_profile' AND Extension='ps1'"
            $file = Get-CimInstance -ClassName CIM_LogicalFile -Filter $filter -CimSession $cimSession -Verbose:$false
            if ($file.Name) {
                $obj = New-Object -TypeName psobject
                $obj | Add-Member -MemberType NoteProperty -Name 'ComputerName' -Value $ComputerName
                $obj | Add-Member -MemberType NoteProperty -Name 'SID' -Value $_.SID
                $obj | Add-Member -MemberType NoteProperty -Name 'PowershellProfile' -Value $file.Name
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

    END {
        Remove-CimSession -CimSession $cimSession
        if ($psSession) {
            Remove-PSSession -Session $psSession
        }
    }
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