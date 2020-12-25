function Get-WmiPersistence {
<#
.SYNOPSIS
    Get WMI persistences from a remote computer.
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

.EXAMPLE
    PS C:\> Get-WmiPersistence -Download -ComputerName SRV.ADATUM.CORP -Credential ADATUM\Administrator
#>

    Param (
        [ValidateNotNullOrEmpty()]
        [String]
        $ComputerName = $env:COMPUTERNAME,

        [ValidateNotNullOrEmpty()]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty,

        [Switch]
        $Ping
    )

    if ($Ping -and -not $(Test-Connection -Count 1 -Quiet -ComputerName $ComputerName)) {
        return
    }

    Get-WmiInstance -Class '__FilterToConsumerBinding' -ComputerName $ComputerName -Credential $Credential | ForEach { 
        if ($_.Consumer -like 'CommandLineEventConsumer*' -or $_.Consumer -like 'ActiveScriptEventConsumer*') {
            $obj = New-Object -TypeName psobject
            $obj | Add-Member -MemberType NoteProperty -Name 'ComputerName' -Value $ComputerName
            $obj | Add-Member -MemberType NoteProperty -Name 'Namespace' -Value $_.__NAMESPACE
            $obj | Add-Member -MemberType NoteProperty -Name 'EventConsumer' -Value $_.Consumer
            $obj | Add-Member -MemberType NoteProperty -Name 'EventFilter' -Value $_.Filter
            Write-Output $obj
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

        [ValidateNotNullOrEmpty()]
        [String]
        $ComputerName,

        [ValidateNotNullOrEmpty()]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    Get-WmiObject -Namespace $Namespace -Class $Class -ComputerName $ComputerName -Credential $Credential
    Get-WmiObject -Namespace $Namespace -Class '__Namespace' -ComputerName $ComputerName -Credential $Credential | % {
        Get-WmiInstance -Namespace "$Namespace\$($_.Name)" -Class $Class -ComputerName $ComputerName -Credential $Credential
    }
}