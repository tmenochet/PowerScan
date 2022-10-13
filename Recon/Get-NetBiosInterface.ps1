Function Get-NetBiosInterface {
<#
.SYNOPSIS
    Get NetBIOS information from a remote computer, including network interface addresses.
    Privileges required: none

    Author: Timothée MENOCHET (@_tmenochet)

.DESCRIPTION
    Get-NetBiosInterface queries remote host via NetBIOS protocol.
    It can be used to identify a multi-homed Windows computer on the local network.

.PARAMETER ComputerName
    Specifies the host to query.

.EXAMPLE
    PS C:\> Get-NetBiosInterface -ComputerName 192.168.38.103
#>

    [CmdletBinding()]
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
            $ipAddresses = @()
            $netbiosDomain = $([Text.Encoding]::ASCII.GetString($response[57..72])).Trim([char]0).TrimEnd()
            $netbiosName = $([Text.Encoding]::ASCII.GetString($response[75..90])).Trim([char]0).TrimEnd()
            if ($netbiosName -eq $netbiosDomain) {
                $netbiosDomain = $([Text.Encoding]::ASCII.GetString($response[92..107])).Trim([char]0).TrimEnd()
            }

            try {
                $ipAddresses = (Resolve-DnsName -Name $netbiosName -Server $ComputerName -LlmnrNetbiosOnly -ErrorAction Stop).IPAddress
            }
            catch {
                try {
                    $ipAddresses = (Resolve-DnsName -Name $netbiosDomain -Server $ComputerName -LlmnrNetbiosOnly -ErrorAction Stop).IPAddress
                    $temp = $netbiosName
                    $netbiosName = $netbiosDomain
                    $netbiosDomain = $temp
                }
                catch {
                }
            }

            $offset = 56 + $response[56] * 18 + 1
            $hwAddress = ""
            for ($i = 0; $i -lt 6; $i++) {
                $hwAddress += [BitConverter]::ToString($response[$offset + $i]) + ":"
            }
            $hwAddress = $hwAddress.TrimEnd(":")
    
            $obj = New-Object -TypeName psobject
            $obj | Add-Member -MemberType NoteProperty -Name 'ComputerName' -Value $ComputerName
            $obj | Add-Member -MemberType NoteProperty -Name 'NetbiosName' -Value $netbiosName
            $obj | Add-Member -MemberType NoteProperty -Name 'NetbiosDomain' -Value $netbiosDomain
            $obj | Add-Member -MemberType NoteProperty -Name 'IpAddresses' -Value $ipAddresses
            $obj | Add-Member -MemberType NoteProperty -Name 'HardwareAddress' -Value $hwAddress
            Write-Output $obj
        }
    }
    catch {
        Write-Error $_
    }
}
