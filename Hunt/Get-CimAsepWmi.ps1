#requires -version 3

Function Get-CimAsepWmi {
<#
.SYNOPSIS
    Get WMI persistences on a remote computer.
    Privileges required: high

    Author: Timothée MENOCHET (@_tmenochet)

.DESCRIPTION
    Get-CimAsepWmi enumerates WMI event subscriptions on a remote host.

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

.EXAMPLE
    PS C:\> Get-CimAsepWmi -ComputerName SRV.ADATUM.CORP -Credential ADATUM\Administrator
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
        Get-WmiInstance -Class '__FilterToConsumerBinding' -CimSession $cimSession | ForEach { 
            if ($_.Consumer -like 'ActiveScriptEventConsumer*' -or $_.Consumer -like 'CommandLineEventConsumer*') {
                $consumer = Get-CimInstance -InputObject $_.Consumer -CimSession $CimSession -Verbose:$false
                $creatorSID = New-Object Security.Principal.SecurityIdentifier([byte[]]$consumer.CreatorSID, 0)
                if ($consumer.ScriptFileName) {
                    $action = $consumer.ScriptFileName
                }
                elseif ($consumer.ScriptText) {
                    $action = $consumer.ScriptText
                }
                else {
                    $action = $consumer.CommandLineTemplate
                }
                $obj = New-Object -TypeName psobject
                $obj | Add-Member -MemberType NoteProperty -Name 'ComputerName' -Value $ComputerName
                $obj | Add-Member -MemberType NoteProperty -Name 'Class' -Value "$($_.PSBase.CimSystemProperties.Namespace) : $($_.PSBase.CimSystemProperties.ClassName)"
                $obj | Add-Member -MemberType NoteProperty -Name 'Filter' -Value "$($_.Filter.PSBase.CimSystemProperties.Namespace) : EventFilter.Name='$($_.Filter.Name)'"
                $obj | Add-Member -MemberType NoteProperty -Name 'Consumer' -Value "$($_.Consumer.PSBase.CimSystemProperties.Namespace) : EventConsumer.Name='$($_.Consumer.Name)'"
                $obj | Add-Member -MemberType NoteProperty -Name 'Action' -Value $action
                $obj | Add-Member -MemberType NoteProperty -Name 'CreatorSID' -Value $creatorSID
                Write-Output $obj
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

function Local:Get-WmiInstance {
    Param (
        [ValidateNotNullOrEmpty()]
        [String]
        $Namespace = 'ROOT',

        [Parameter(Mandatory = $True)]
        [String]
        $Class,

        [Parameter(Mandatory = $True)]
        [CimSession]
        $CimSession
    )

    Get-CimInstance -Namespace $Namespace -Class $Class -CimSession $CimSession -Verbose:$false
    Get-CimInstance -Namespace $Namespace -Class '__Namespace' -CimSession $CimSession -Verbose:$false | % {
        Get-WmiInstance -Namespace "$Namespace\$($_.Name)" -Class $Class -CimSession $CimSession -Verbose:$false
    }
}
