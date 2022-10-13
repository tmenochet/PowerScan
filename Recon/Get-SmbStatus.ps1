Function Get-SmbStatus {
<#
.SYNOPSIS
    Get the version of the protocol SMB available on remote computer.
    Privileges required: none

    Author: Timothée MENOCHET (@_tmenochet)

.DESCRIPTION
    Get-SmbStatus enumerates SMB versions available on a remote host and check if SMB signing is required or not.
    The code is mostly stolen from Invoke-InveighRelay by @kevin_robertson.

.PARAMETER ComputerName
    Specifies the target host.

.EXAMPLE
    PS C:\> Get-SmbStatus -ComputerName DC.ADATUM.CORP
#>

    [CmdletBinding()]
    Param (
        [ValidateNotNullOrEmpty()]
        [string]
        $ComputerName = $env:COMPUTERNAME
    )

    $SMB1 = Get-SmbVersionStatus -ComputerName $ComputerName -SmbVersion 'SMB1'
    $SMB2 = Get-SmbVersionStatus -ComputerName $ComputerName -SmbVersion 'SMB2'

    if ($SMB1.ServiceStatus -or $SMB2.ServiceStatus) {
        $obj = New-Object -TypeName psobject
        $obj | Add-Member -MemberType NoteProperty -Name 'ComputerName' -Value $ComputerName
        $obj | Add-Member -MemberType NoteProperty -Name 'Smb1Status' -Value $SMB1.VersionStatus
        $obj | Add-Member -MemberType NoteProperty -Name 'Smb1Signing' -Value $SMB1.SigningStatus
        $obj | Add-Member -MemberType NoteProperty -Name 'Smb2Status' -Value $SMB2.VersionStatus
        $obj | Add-Member -MemberType NoteProperty -Name 'Smb2Signing' -Value $SMB2.SigningStatus
        Write-Output $obj
    }
}

function Local:ConvertFrom-PacketOrderedDictionary($packet_ordered_dictionary) {
    foreach ($field in $packet_ordered_dictionary.Values) {
        $byte_array += $field
    }
    return $byte_array
}

function Local:Get-PacketNetBIOSSessionService {
    Param (
        [Int] $packet_header_length,
        [Int] $packet_data_length
    )
    [Byte[]] $packet_netbios_session_service_length = [BitConverter]::GetBytes($packet_header_length + $packet_data_length)
    $packet_NetBIOS_session_service_length = $packet_netbios_session_service_length[2..0]
    $packet_NetBIOSSessionService = New-Object Collections.Specialized.OrderedDictionary
    $packet_NetBIOSSessionService.Add("NetBIOSSessionService_Message_Type",[Byte[]](0x00))
    $packet_NetBIOSSessionService.Add("NetBIOSSessionService_Length",[Byte[]]($packet_netbios_session_service_length))
    return $packet_NetBIOSSessionService
}

function Local:Get-PacketSMBHeader {
    Param (
        [Byte[]] $packet_command,
        [Byte[]] $packet_flags,
        [Byte[]] $packet_flags2,
        [Byte[]] $packet_tree_ID,
        [Byte[]] $packet_process_ID,
        [Byte[]] $packet_user_ID
    )
    $packet_SMBHeader = New-Object Collections.Specialized.OrderedDictionary
    $packet_SMBHeader.Add("SMBHeader_Protocol",[Byte[]](0xff,0x53,0x4d,0x42))
    $packet_SMBHeader.Add("SMBHeader_Command",$packet_command)
    $packet_SMBHeader.Add("SMBHeader_ErrorClass",[Byte[]](0x00))
    $packet_SMBHeader.Add("SMBHeader_Reserved",[Byte[]](0x00))
    $packet_SMBHeader.Add("SMBHeader_ErrorCode",[Byte[]](0x00,0x00))
    $packet_SMBHeader.Add("SMBHeader_Flags",$packet_flags)
    $packet_SMBHeader.Add("SMBHeader_Flags2",$packet_flags2)
    $packet_SMBHeader.Add("SMBHeader_ProcessIDHigh",[Byte[]](0x00,0x00))
    $packet_SMBHeader.Add("SMBHeader_Signature",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
    $packet_SMBHeader.Add("SMBHeader_Reserved2",[Byte[]](0x00,0x00))
    $packet_SMBHeader.Add("SMBHeader_TreeID",$packet_tree_ID)
    $packet_SMBHeader.Add("SMBHeader_ProcessID",$packet_process_ID)
    $packet_SMBHeader.Add("SMBHeader_UserID",$packet_user_ID)
    $packet_SMBHeader.Add("SMBHeader_MultiplexID",[Byte[]](0x00,0x00))
    return $packet_SMBHeader
}

function Local:Get-PacketSMBNegotiateProtocolRequest($packet_version) {
    if ($packet_version -eq 'SMB1') {
        [Byte[]] $packet_byte_count = 0x0c,0x00
    }
    else {
        [Byte[]] $packet_byte_count = 0x22,0x00  
    }
    $packet_SMBNegotiateProtocolRequest = New-Object Collections.Specialized.OrderedDictionary
    $packet_SMBNegotiateProtocolRequest.Add("SMBNegotiateProtocolRequest_WordCount",[Byte[]](0x00))
    $packet_SMBNegotiateProtocolRequest.Add("SMBNegotiateProtocolRequest_ByteCount",$packet_byte_count)
    $packet_SMBNegotiateProtocolRequest.Add("SMBNegotiateProtocolRequest_RequestedDialects_Dialect_BufferFormat",[Byte[]](0x02))
    $packet_SMBNegotiateProtocolRequest.Add("SMBNegotiateProtocolRequest_RequestedDialects_Dialect_Name",[Byte[]](0x4e,0x54,0x20,0x4c,0x4d,0x20,0x30,0x2e,0x31,0x32,0x00))
    if ($packet_version -ne 'SMB1') {
        $packet_SMBNegotiateProtocolRequest.Add("SMBNegotiateProtocolRequest_RequestedDialects_Dialect_BufferFormat2",[Byte[]](0x02))
        $packet_SMBNegotiateProtocolRequest.Add("SMBNegotiateProtocolRequest_RequestedDialects_Dialect_Name2",[Byte[]](0x53,0x4d,0x42,0x20,0x32,0x2e,0x30,0x30,0x32,0x00))
        $packet_SMBNegotiateProtocolRequest.Add("SMBNegotiateProtocolRequest_RequestedDialects_Dialect_BufferFormat3",[Byte[]](0x02))
        $packet_SMBNegotiateProtocolRequest.Add("SMBNegotiateProtocolRequest_RequestedDialects_Dialect_Name3",[Byte[]](0x53,0x4d,0x42,0x20,0x32,0x2e,0x3f,0x3f,0x3f,0x00))
    }
    return $packet_SMBNegotiateProtocolRequest
}

function Local:Get-SmbVersionStatus {
    Param (
        [string] $ComputerName,

        [string] $SmbVersion = 'SMB2'
    )

    $serviceStatus = $false
    $versionStatus = $false
    $signingStatus = $false

    $process_ID = [Diagnostics.Process]::GetCurrentProcess() | Select-Object -expand id
    $process_ID = [BitConverter]::ToString([BitConverter]::GetBytes($process_ID))
    $process_ID = $process_ID.Replace("-00-00","")
    [Byte[]] $process_ID_bytes = $process_ID.Split("-") | ForEach-Object {[Char][Convert]::ToInt16($_,16)}

    $SMB_relay_socket = New-Object Net.Sockets.TCPClient
    $SMB_relay_socket.Client.ReceiveTimeout = 60000

    try {
        $SMB_relay_socket.Connect($ComputerName, "445")
        if ($SMB_relay_socket.connected) {
            $serviceStatus = $true

            $SMB_relay_challenge_stream = $SMB_relay_socket.GetStream()
            $SMB_client_receive = New-Object Byte[] 1024
            $SMB_client_stage = 'NegotiateSMB'

            while($SMB_client_stage -ne 'exit') {
                switch ($SMB_client_stage) {
                    'NegotiateSMB' {
                        $packet_SMB_header = Get-PacketSMBHeader 0x72 0x18 0x01,0x48 0xff,0xff $process_ID_bytes 0x00,0x00       
                        $packet_SMB_data = Get-PacketSMBNegotiateProtocolRequest $SmbVersion
                        $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                        $SMB_data = ConvertFrom-PacketOrderedDictionary $packet_SMB_data
                        $packet_NetBIOS_session_service = Get-PacketNetBIOSSessionService $SMB_header.Length $SMB_data.Length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service
                        $SMB_client_send = $NetBIOS_session_service + $SMB_header + $SMB_data
                        $SMB_relay_challenge_stream.Write($SMB_client_send,0,$SMB_client_send.Length) > $null
                        $SMB_relay_challenge_stream.Flush()
                        $SMB_relay_challenge_stream.Read($SMB_client_receive,0,$SMB_client_receive.Length) > $null
                        if ([BitConverter]::ToString($SMB_client_receive[4..7]) -eq 'ff-53-4d-42') {
                            $SmbVersion = 'SMB1'
                            $SMB_client_stage = 'NTLMSSPNegotiate'
                        }
                        else {
                            $SMB_client_stage = 'NegotiateSMB2'
                        }
                        if (($SmbVersion -eq 'SMB1' -and [BitConverter]::ToString($SMB_client_receive[39]) -eq '0f') -or ($SmbVersion -ne 'SMB1' -and [BitConverter]::ToString($SMB_client_receive[70]) -eq '03')) {
                            $signingStatus = $true
                        }
                        $SMB_relay_socket.Close()
                        $SMB_client_receive = $null
                        $SMB_client_stage = 'exit'
                        $versionStatus = $true
                    }
                }
            }
        }
    }
    catch [System.Management.Automation.MethodInvocationException] {
        Write-Verbose "$SmbVersion is not available on $ComputerName"
    }

    $obj = New-Object -TypeName psobject
    $obj | Add-Member -MemberType NoteProperty -Name 'ServiceStatus' -Value $serviceStatus
    $obj | Add-Member -MemberType NoteProperty -Name 'VersionStatus' -Value $versionStatus
    $obj | Add-Member -MemberType NoteProperty -Name 'SigningStatus' -Value $signingStatus
    return ([pscustomobject] @{ServiceStatus=$serviceStatus; VersionStatus=$versionStatus; SigningStatus=$signingStatus})
}