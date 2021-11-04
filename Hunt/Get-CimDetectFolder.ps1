#requires -version 3

function Get-CimDetectFolder {
<#
.SYNOPSIS
    Get system drivers on a remote computer.
    Privileges required: high

    Author: William LE BERRE highly inpired by modules of (@_tmenochet)

.DESCRIPTION
    Get-CimDriver queries remote host through WMI for drivers (optionally matching criteria).

.PARAMETER ComputerName
    Specifies the host to query.

.PARAMETER Ping
    Ensures host is up before run.

.PARAMETER Credential
    Specifies the privileged account to use.

.PARAMETER Authentication
    Specifies what authentication method should be used.

.PARAMETER Protocol
    Specifies the protocol to use, defaults to DCOM.

.PARAMETER ServiceName
    Specifies one or more drivers by name.

.PARAMETER ExecutablePath
    Specifies one or more drivers by binary file path.

.PARAMETER StartMode
    Specifies one or more drivers by start mode.

.PARAMETER Path
    Specifies searched file or folder.

.PARAMETER InvertLogic
    Queries services that do not match specified criteria.

.EXAMPLE
    PS C:\> Get-CimDriver -ComputerName SRV.ADATUM.CORP -Credential ADATUM\Administrator -ExecutablePath FeKern.sys
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

        [ValidateNotNullOrEmpty()]
        [string]
        $ServiceName,

        [ValidateNotNullOrEmpty()]
        [string]
        $ExecutablePath,

        [ValidateSet('Boot', 'System', 'Auto', 'Manual', 'Disabled')]
        [string]
        $StartMode,

        [ValidateNotNullOrEmpty()]
        [string]
        $Path,

        [switch]
        $InvertLogic
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

        $wmiPath = ($Path.TrimEnd('\') ).Replace('\','\\')
    }

    PROCESS {
        
      

        Get-CimInstance Win32_Directory -Filter "Name='$wmiPath'" -CimSession $cimSession -Verbose:$false | ForEach-Object {
            $obj = New-Object -TypeName psobject
            $obj | Add-Member -MemberType NoteProperty -Name 'ComputerName' -Value $ComputerName
            $obj | Add-Member -MemberType NoteProperty -Name 'Name' -Value $_.FileName
            $obj | Add-Member -MemberType NoteProperty -Name 'FullPath' -Value $_.EightDotThreeFileName
            $obj | Add-Member -MemberType NoteProperty -Name 'Creation' -Value $_.CreationDate
            $obj | Add-Member -MemberType NoteProperty -Name 'LastAccessed' -Value $_.LastAccessed
            $obj | Add-Member -MemberType NoteProperty -Name 'LastModified' -Value $_.LastModified
            $obj | Add-Member -MemberType NoteProperty -Name 'Hidden' -Value $_.Hidden
            $obj | Add-Member -MemberType NoteProperty -Name 'Type' -Value "Folder"
            Write-Output $obj
        }
        Get-CimInstance CIM_DataFile  -Filter "Name='$wmiPath'" -CimSession $cimSession -Verbose:$false | ForEach-Object {
            $obj = New-Object -TypeName psobject
            $obj | Add-Member -MemberType NoteProperty -Name 'ComputerName' -Value $ComputerName
            $obj | Add-Member -MemberType NoteProperty -Name 'Name' -Value $_.FileName
            $obj | Add-Member -MemberType NoteProperty -Name 'FullPath' -Value $_.EightDotThreeFileName
            $obj | Add-Member -MemberType NoteProperty -Name 'Creation' -Value $_.CreationDate
            $obj | Add-Member -MemberType NoteProperty -Name 'LastAccessed' -Value $_.LastAccessed
            $obj | Add-Member -MemberType NoteProperty -Name 'LastModified' -Value $_.LastModified
            $obj | Add-Member -MemberType NoteProperty -Name 'Hidden' -Value $_.Hidden
            $obj | Add-Member -MemberType NoteProperty -Name 'Type' -Value "File"
            Write-Output $obj
        }
    }

    END {
        Remove-CimSession -CimSession $cimSession
    }
}
