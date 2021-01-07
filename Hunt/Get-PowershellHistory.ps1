#requires -version 3

function Get-PowershellHistory {
<#
.SYNOPSIS
    Get Powershell history on a remote computer.
    Privileges required: high

    Author: Timothée MENOCHET (@_tmenochet)

.DESCRIPTION
    Get-PowershellHistory enumerates Powershell history files on a remote host through WMI and optionally downloads them.

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
    PS C:\> Get-PowershellHistory -ComputerName SRV.ADATUM.CORP -Credential ADATUM\Administrator -Download
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
        [uint32]$HKU = 2147483651
        $SIDS = Invoke-CimMethod -Class 'StdRegProv' -Name 'EnumKey' -Arguments @{hDefKey=$HKU; sSubKeyName=''} -CimSession $cimSession -Verbose:$false | Select-Object -ExpandProperty sNames | Where-Object {$_ -match 'S-1-5-21-[\d\-]+$'}

        foreach ($SID in $SIDs) {
            $mappedSID = Get-MappedSID -SID $SID -CimSession $cimSession
            $username = Split-Path -Leaf (Split-Path -Leaf ($mappedSID))
            $filter  = "Drive='C:' AND Path='\\Users\\$username\\AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadLine\\' AND FileName='ConsoleHost_history' AND Extension='txt'"
            $file = Get-CimInstance -Class CIM_LogicalFile -Filter $filter -CimSession $cimSession -Verbose:$false
            if ($file.Name) {
                $obj = New-Object -TypeName psobject
                $obj | Add-Member -MemberType NoteProperty -Name 'ComputerName' -Value $ComputerName
                $obj | Add-Member -MemberType NoteProperty -Name 'ConsoleHost_history' -Value $file.Name
                $obj | Add-Member -MemberType NoteProperty -Name 'CreationDate' -Value $file.CreationDate
                $obj | Add-Member -MemberType NoteProperty -Name 'LastModified' -Value $file.LastModified
                Write-Output $obj

                if ($Download) {
                    $fileName = "$($file.FileName).$($file.Extension)"
                    $filePath = "$($file.Path)\$fileName"
                    $outputDir = "$PWD\$ComputerName"
                    $outputFile = "$outputDir\$($username)_$fileName"
                    New-Item -ItemType Directory -Force -Path $outputDir | Out-Null
                    if ($Protocol -eq 'Wsman') {
                        # Download file via PSRemoting
                        Copy-Item -Path "C:$filePath" -Destination $outputFile -FromSession $psSession
                    }
                    else {
                        # Download file via SMB
                        if ($Credential.Username) {
                            $drive = Get-StringHash $ComputerName
                            New-PSDrive -Name $drive -Root "\\$ComputerName\C`$" -PSProvider "FileSystem" -Credential $Credential | Out-Null
                            Copy-Item -Path "${drive}:$filePath" -Destination $outputFile
                            Remove-PSDrive $drive
                        }
                        else {
                            Copy-Item -Path "\\$ComputerName\C`$$filePath" -Destination $outputFile
                        }
                    }
                }
            }
        }
    }

    END {
        Remove-CimSession -CimSession $cimSession
        if ($Download -and $Protocol -eq 'Wsman') {
            Remove-PSSession -Session $psSession
        }
    }
}

function Local:Get-MappedSID {
    Param (
        [ValidateNotNullOrEmpty()]
        [String]
        $SID,

        [Parameter(Mandatory = $True)]
        [CimSession]
        $CimSession
    )

    [uint32]$HKLM = 2147483650
    $path = "SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$SID"
    $key = "ProfileImagePath"
    return (Invoke-CimMethod -CimSession $CimSession -Class 'StdRegProv' -Name 'GetStringValue' -Arguments @{hDefKey=$HKLM; sSubKeyName=$path; sValueName=$key} -Verbose:$false).sValue
}

function Local:Get-StringHash ([String]$String, $Algorithm="MD5") { 
    $stringBuilder = New-Object System.Text.StringBuilder 
    [System.Security.Cryptography.HashAlgorithm]::Create($Algorithm).ComputeHash([System.Text.Encoding]::UTF8.GetBytes($String)) | % { 
        [Void]$stringBuilder.Append($_.ToString("x2")) 
    } 
    $stringBuilder.ToString() 
}