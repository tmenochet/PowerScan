#requires -version 3

function Get-WmiPersistence {
<#
.SYNOPSIS
    Get WMI persistences on a remote computer.
    Privileges required: high

    Author: Timothée MENOCHET (@_tmenochet)

.DESCRIPTION
    Get-WmiPersistence enumerates WMI event subscriptions on a remote host.

.PARAMETER ComputerName
    Specifies the target host.

.PARAMETER Credential
    Specifies the privileged account to use.

.PARAMETER Ping
    Ensures host is up before run.

.PARAMETER Protocol
    Specifies the protocol to use.

.EXAMPLE
    PS C:\> Get-WmiPersistence -ComputerName SRV.ADATUM.CORP -Credential ADATUM\Administrator
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
        $Protocol = 'Dcom'
    )

    BEGIN {
        if ($Ping -and -not $(Test-Connection -Count 1 -Quiet -ComputerName $ComputerName)) {
            Write-Verbose "[$ComputerName] Host is unreachable."
            break
        }

        $cimOption = New-CimSessionOption -Protocol $Protocol
        try {
            if ($Credential.Username) {
                $cimSession = New-CimSession -ComputerName $ComputerName -Credential $Credential -SessionOption $cimOption -ErrorAction Stop -Verbose:$false
            }
            else {
                $cimSession = New-CimSession -ComputerName $ComputerName -SessionOption $cimOption -ErrorAction Stop -Verbose:$false
            }
        }
        catch [Microsoft.Management.Infrastructure.CimException] {
            Write-Verbose "[$ComputerName] Failed to establish CIM session."
            break
        }
    }

    PROCESS {
        Get-WmiInstance -Class '__FilterToConsumerBinding' -CimSession $cimSession | ForEach { 
            if ($_.Consumer -like 'CommandLineEventConsumer*' -or $_.Consumer -like 'ActiveScriptEventConsumer*') {
                $obj = New-Object -TypeName psobject
                $obj | Add-Member -MemberType NoteProperty -Name 'ComputerName' -Value $ComputerName
                $obj | Add-Member -MemberType NoteProperty -Name 'Class' -Value $_.CimClass
                $obj | Add-Member -MemberType NoteProperty -Name 'EventConsumer' -Value $_.Consumer
                $obj | Add-Member -MemberType NoteProperty -Name 'EventFilter' -Value $_.Filter
                Write-Output $obj
            }
        }
    }

    END {
        Remove-CimSession -CimSession $cimSession
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
        Get-CimInstance -Namespace "$Namespace\$($_.Name)" -Class $Class -CimSession $CimSession -Verbose:$false
    }
}