Function Get-NBNSInfo {
<#
.SYNOPSIS
    Get NetBIOS information from a remote computer.
    Privileges required: none

    Author: Timothée MENOCHET (@_tmenochet)

.DESCRIPTION
    Get-NBNSInfo queries remote host via NetBIOS protocol.

.PARAMETER ComputerName
    Specifies the host to query.

.EXAMPLE
    PS C:\> Get-NBNSInfo -ComputerName 192.168.38.103
#>

    Param (
        [Parameter(Mandatory = $true)]
        [string]
        $ComputerName
    )

    try {
        $client = New-Object System.Net.Sockets.Udpclient
        $client.Connect($ComputerName, 137)
        $client.Client.ReceiveTimeout = 2500
        [byte[]] $bytes = @(0xff, 0xff, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x43, 0x4b, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x00, 0x00, 0x21, 0x00, 0x01)
        $client.Send($bytes, $bytes.length) | Out-Null
        $remoteendpoint = New-Object System.Net.IpEndpoint([Net.IpAddress]::Any, 0)
        $response = $client.Receive([ref]$remoteendpoint)
        $client.Close()
        if ($response -ge 90) {
            $deviceName = ([Text.Encoding]::ASCII.GetString($response[57..72]) -Replace '\0', ' ').Trim()
            $networkName = ([Text.Encoding]::ASCII.GetString($response[75..90]) -Replace '\0', ' ').Trim()
            $offfset = 56 + $response[56] * 18 + 1
            $macAddress = ""
            for ($i = 0; $i -lt 6; $i++) {
                $macAddress += [BitConverter]::ToString($response[$offfset + $i]) + ":"
            }
            $macAddress = $macAddress -replace ":$"
    
            $obj = New-Object -TypeName psobject
            $obj | Add-Member -MemberType NoteProperty -Name 'ComputerName' -Value $ComputerName
            $obj | Add-Member -MemberType NoteProperty -Name 'DeviceName' -Value $deviceName
            $obj | Add-Member -MemberType NoteProperty -Name 'NetworkName' -Value $networkName
            $obj | Add-Member -MemberType NoteProperty -Name 'PhysicalAddress' -Value $macAddress
            Write-Output $obj
        }
    }
    catch {
        Write-Error $_
    }
}
