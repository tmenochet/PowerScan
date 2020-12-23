function Get-PowershellHistory {
<#
.SYNOPSIS
    Get Powershell history from a remote computer.
    Privileges required: high

    Author: Timothée MENOCHET (@_tmenochet)

.DESCRIPTION
    Get-PowershellHistory enumerates Powershell history files on a remote host though WMI and optionally downloads them via SMB.

.PARAMETER Download
    Enables file download.

.PARAMETER ComputerName
    Specifies the target host.

.PARAMETER Credential
    Specifies the privileged account to use.

.EXAMPLE
    PS C:\> Get-PowershellHistory -Download -ComputerName SRV.ADATUM.CORP -Credential ADATUM\Administrator
#>

    Param (
        [Switch]
        $Download,

        [ValidateNotNullOrEmpty()]
        [String]
        $ComputerName = $env:COMPUTERNAME,

        [ValidateNotNullOrEmpty()]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    $HKCU = 2147483651
    $SIDS = Invoke-WmiMethod -Class 'StdRegProv' -Name 'EnumKey' -ArgumentList $HKCU,'' -ComputerName $ComputerName -Credential $Credential | Select-Object -ExpandProperty sNames | Where-Object {$_ -match 'S-1-5-21-[\d\-]+$'}
    
    foreach ($SID in $SIDs) {
        $mappedSID = Get-MappedSID -SID $SID -ComputerName $ComputerName -Credential $Credential
        $username = Split-Path -Leaf (Split-Path -Leaf ($mappedSID))
        $filter  = "Drive='C:' AND Path='\\Users\\$username\\AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadLine\\' AND FileName='ConsoleHost_history' AND Extension='txt'"
        $file = Get-WMIObject -Class CIM_LogicalFile -Filter $filter -ComputerName $ComputerName -Credential $Credential
        if ($file.Name) {
            $obj = New-Object -TypeName psobject
            $obj | Add-Member -MemberType NoteProperty -Name 'ComputerName' -Value $ComputerName
            $obj | Add-Member -MemberType NoteProperty -Name 'ConsoleHost_history' -Value $file.Name
            Write-Output $obj
            if ($Download) {
                $filepath = "$PWD\$ComputerName"
                New-Item -ItemType Directory -Force -Path $filepath | Out-Null
                Copy-Item -Path "\\$ComputerName\C`$$($file.Path)\$($file.FileName).$($file.Extension)" -Destination "$filepath\$($username)_$($file.FileName).$($file.Extension)" -Credential $Credential
            }
        }
    }
}

function Local:Get-MappedSID {
    Param (
        [ValidateNotNullOrEmpty()]
        [String]
        $SID,

        [ValidateNotNullOrEmpty()]
        [String]
        $ComputerName,

        [ValidateNotNullOrEmpty()]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    $HKLM = 2147483650
    $path = "SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$SID"
    $key = "ProfileImagePath"
    return (Invoke-WmiMethod -ComputerName $ComputerName -Class 'StdRegProv' -Name 'GetStringValue' -ArgumentList $HKLM, $path, $key -Credential $Credential).sValue
}