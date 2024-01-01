#requires -version 3

Function Get-CimDirectory {
<#
.SYNOPSIS
    Get a directory listing of folders and files.
    Privileges required: high

    Author: Timothée MENOCHET (@_tmenochet)

.DESCRIPTION
    Get-CimDirectory get a directory listing of folders and files on a remote host through WMI (optionally recursively).

.PARAMETER ComputerName
    Specifies the target host.

.PARAMETER Credential
    Specifies the privileged account to use.

.PARAMETER Authentication
    Specifies what authentication method should be used.

.PARAMETER Protocol
    Specifies the protocol to use, defaults to DCOM.

.PARAMETER Timeout
    Specifies the duration to wait for a response from the target host (in seconds), defaults to 3.

.PARAMETER Path
    Specifies the path of the target directory or file.

.PARAMETER Recurse
    Enables recursive search in subdirectories

.EXAMPLE
    PS C:\> Get-CimDirectory -ComputerName SRV.ADATUM.CORP -Path C:\Temp -Recurse

.EXAMPLE
    PS C:\> Get-CimDirectory -ComputerName SRV.ADATUM.CORP -Credential ADATUM\Administrator -Path C:\Temp\secret.txt
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

        [ValidateSet('Default', 'Kerberos', 'Negotiate', 'NtlmDomain')]
        [String]
        $Authentication = 'Default',

        [ValidateSet('Dcom', 'Wsman')]
        [String]
        $Protocol = 'Dcom',

        [Int]
        $Timeout = 3,

        [Parameter(Mandatory = $True)]
        [ValidateNotNullorEmpty()]
        [String]
        $Path,

        [Switch]
        $Recurse
    )

    Begin {
        # Init variables
        $cimOption = New-CimSessionOption -Protocol $Protocol

        Function Local:New-ItemObject {
            Param (
                [Parameter(Position = 0, Mandatory, ValueFromPipeline)]
                [object]
                $CimObject
            )
            $isDirectory = $false
            if ($CimObject.CimClass.CimClassName -match 'Directory') {
                $isDirectory = $true
            }
            $isRO = $true
            if ($CimObject.Writeable) {
                $isRO = $false
            }
            $item = New-Object -TypeName PSObject
            $item | Add-Member -MemberType NoteProperty -Name 'ComputerName' -Value $CimObject.CSName
            $item | Add-Member -MemberType NoteProperty -Name 'Name' -Value $CimObject.Name
            $item | Add-Member -MemberType NoteProperty -Name 'CreationDate' -Value $CimObject.CreationDate
            $item | Add-Member -MemberType NoteProperty -Name 'LastAccessed' -Value $CimObject.LastAccessed
            $item | Add-Member -MemberType NoteProperty -Name 'LastModified' -Value $CimObject.LastModified
            $item | Add-Member -MemberType NoteProperty -Name 'Type' -Value $CimObject.FileType
            $item | Add-Member -MemberType NoteProperty -Name 'Directory' -Value $isDirectory
            $item | Add-Member -MemberType NoteProperty -Name 'Archive' -Value $CimObject.Archive
            $item | Add-Member -MemberType NoteProperty -Name 'Compressed' -Value $CimObject.Compressed
            $item | Add-Member -MemberType NoteProperty -Name 'Encrypted' -Value $CimObject.Encrypted
            $item | Add-Member -MemberType NoteProperty -Name 'Hidden' -Value $CimObject.Hidden
            $item | Add-Member -MemberType NoteProperty -Name 'System' -Value $CimObject.System
            $item | Add-Member -MemberType NoteProperty -Name 'ReadOnly' -Value $isRO
            Write-Output $item
        }

        Function Local:Get-Directory {
            Param (            
                [Parameter(Mandatory = $True)]
                [ValidateNotNullOrEmpty()]
                [Microsoft.Management.Infrastructure.CimSession]
                $CimSession,

                [Parameter(Mandatory = $True)]
                [ValidateNotNullorEmpty()]
                [String]
                $Path,

                [Switch]
                $Recurse
            )

            $path = $path.TrimEnd("\")
            $cimParams = @{
                ClassName  = "CIM_LogicalFile"
                Filter     = "Name='$($path.Replace("\", "\\"))'"
                CimSession = $cimSession
                Verbose    = $false
            }

            if ($currentObject = Get-CimInstance @cimParams) {
                Write-Output $currentObject | New-ItemObject
            }
            if ($currentObject.CimClass.CimClassName -eq 'Win32_Directory') {
                # Enumerate files
                if ($files = $currentObject | Get-CimAssociatedInstance -ResultClassName CIM_DataFile -Verbose:$false) {
                    foreach ($file in $files) {
                        Write-Output $file | New-ItemObject
                    }
                }
                # Enumerate subfolders
                $subDir = $currentObject | Get-CimAssociatedInstance -ResultClassName Win32_Directory -Verbose:$false |
                    Where-Object { (Split-Path $_.Name) -eq $currentObject.Name } # Filter out the parent folder

                if ($Recurse -and $subDir) {
                    foreach ($directory in $subDir) {
                        Get-Directory -Path $directory.Name -Recurse -CimSession $cimSession
                    }
                }
                elseif ($subDir) {
                    foreach ($directory in $subDir) {
                        Write-Output $directory | New-ItemObject
                    }
                }
            }
        }
    }

    Process {
        # Init remote session
        try {
            if (-not $PSBoundParameters['ComputerName']) {
                $cimSession = New-CimSession -SessionOption $cimOption -ErrorAction Stop -Verbose:$false -OperationTimeoutSec $Timeout
            }
            elseif ($Credential.Username) {
                $cimSession = New-CimSession -ComputerName $ComputerName -Credential $Credential -Authentication $Authentication -SessionOption $cimOption -ErrorAction Stop -Verbose:$false -OperationTimeoutSec $Timeout
            }
            else {
                $cimSession = New-CimSession -ComputerName $ComputerName -Authentication $Authentication -SessionOption $cimOption -ErrorAction Stop -Verbose:$false -OperationTimeoutSec $Timeout
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
        Get-Directory -Path $Path -Recurse:$Recurse -CimSession $cimSession
    }

    End {
        # End session
        if ($cimSession) {
            Remove-CimSession -CimSession $cimSession
        }
    }
}
