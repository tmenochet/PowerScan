#requires -version 3

Function Get-CimSmbShare {
<#
.SYNOPSIS
    Get SMB shares on a remote computer.
    Privileges required: high

    Author: Timothée MENOCHET (@_tmenochet)

.DESCRIPTION
    Get-CimService queries remote host through WMI for SMB shares and related permissions.

.PARAMETER ComputerName
    Specifies the host to query.

.PARAMETER Credential
    Specifies the privileged account to use.

.PARAMETER Authentication
    Specifies what authentication method should be used.

.PARAMETER Protocol
    Specifies the protocol to use, defaults to DCOM.

.PARAMETER Timeout
    Specifies the duration to wait for a response from the target host (in seconds), defaults to 3.

.EXAMPLE
    PS C:\> Get-CimSmbShare -ComputerName SRV.ADATUM.CORP -Credential ADATUM\Administrator
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
        $Timeout = 3
    )

    Begin {
        # Init variables
        $cimOption = New-CimSessionOption -Protocol $Protocol
        $permissionFlags = @{
            0x1     = "Read-List"
            0x2     = "Write-Create"
            0x4     = "Append-Create Subdirectory"                      
            0x20    = "Execute file-Traverse directory"
            0x40    = "Delete child"
            0x10000 = "Delete"                     
            0x40000 = "Write access to DACL"
            0x80000 = "Write Owner"
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
        Get-CimInstance -ClassName Win32_Share -Filter "Type=0" -CimSession $cimSession -Verbose:$false | ForEach-Object {
            $shareName = $_.Name
            $sharePath = $_.Path
            $shareDescription = $_.Description

            Get-CimInstance -ClassName Win32_LogicalShareSecuritySetting -Filter "Name='$shareName'" -CimSession $cimSession -Verbose:$false | Invoke-CimMethod -MethodName GetSecurityDescriptor -CimSession $cimSession -Verbose:$false | ForEach-Object {
                foreach ($DACL in $_.Descriptor.DACL) {
                    $accessMask = $DACL.AccessMask
                    $permissions = foreach ($key in $permissionFlags.Keys) {
                        if ($key -band $accessMask) {
                            $permissionFlags[$key]
                        }
                    }
                    if ($DACL.AceType) {$type = "Deny"} else {$type = "Allow"}

                    $obj = New-Object -TypeName psobject
                    $obj | Add-Member -MemberType NoteProperty -Name 'ComputerName' -Value $ComputerName
                    $obj | Add-Member -MemberType NoteProperty -Name 'Share' -Value $shareName
                    $obj | Add-Member -MemberType NoteProperty -Name 'Path' -Value $sharePath
                    $obj | Add-Member -MemberType NoteProperty -Name 'Description' -Value $shareDescription
                    $obj | Add-Member -MemberType NoteProperty -Name 'TrusteeName' -Value $DACL.Trustee.Name
                    $obj | Add-Member -MemberType NoteProperty -Name 'TrusteeDomain' -Value $DACL.Trustee.Domain
                    $obj | Add-Member -MemberType NoteProperty -Name 'TrusteeSID' -Value $DACL.Trustee.SIDString
                    $obj | Add-Member -MemberType NoteProperty -Name 'AccessType' -Value $type
                    $obj | Add-Member -MemberType NoteProperty -Name 'AccessMask' -Value $accessMask
                    $obj | Add-Member -MemberType NoteProperty -Name 'Permissions' -Value $permissions
                    Write-Output $obj
                }
            }
        }
    }

    End {
        # End session
        if ($cimSession) {
            Remove-CimSession -CimSession $cimSession
        }
    }
}