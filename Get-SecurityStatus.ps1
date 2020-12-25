function Get-SecurityStatus {
<#
.SYNOPSIS
    Get the status of security softwares on remote computer.
    Privileges required: high

    Author: Timothée MENOCHET (@_tmenochet)

.DESCRIPTION
    Get-SecurityStatus queries a remote host though WMI about firewall and antivirus products.

.PARAMETER ComputerName
    Specifies the target host.

.PARAMETER Credential
    Specifies the privileged account to use.

.PARAMETER Protocol
    Specifies the protocol to use.

.PARAMETER Ping
    Ensures host is up before run.

.EXAMPLE
    PS C:\> Get-SecurityStatus -ComputerName SRV.ADATUM.CORP -Credential ADATUM\Administrator
#>

    Param (
        [ValidateNotNullOrEmpty()]
        [String]
        $ComputerName = $env:COMPUTERNAME,

        [ValidateNotNullOrEmpty()]
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty,

        [ValidateSet('Dcom', 'Wsman')]
        [String]
        $Protocol = 'Dcom',

        [Switch]
        $Ping
    )

    if ($Ping -and -not $(Test-Connection -Count 1 -Quiet -ComputerName $ComputerName)) {
        return
    }

    $option = New-CimSessionOption -Protocol Dcom
    if ($Credential.Username) {
        $session = New-CimSession -ComputerName $ComputerName -Credential $Credential -SessionOption $option -ErrorAction Stop
    }
    else {
        $session = New-CimSession -ComputerName $ComputerName -SessionOption $option -ErrorAction Stop
    }

    $obj = "" | Select-Object -Property "ComputerName","AntiVirus-Status","AntiVirus-LastUpdate","AntiMalware-Status","OnAccessProtection-Status","RealTimeProtection-Status","AntiSpyware-Status","BehaviorMonitor-Status","OfficeProtection-Status","NIS-Status","AntiSpyware-Product","AntiVirus-Product","Firewall-Product","Firewall-DomainProfileStatus"
    $obj.'ComputerName' = $ComputerName

    # Get antimalware status
    try {
        $mpComputerStatus = Get-MpComputerStatus -CimSession $session -ErrorAction Stop | Select-Object -Property PSComputername,Antivirusenabled,AntivirusSignatureLastUpdated,AMServiceEnabled,AntispywareEnabled,BehaviorMonitorEnabled,IoavProtectionEnabled,NISEnabled,OnAccessProtectionEnabled,RealTimeProtectionEnabled
        if ($mpComputerStatus -ne $null) {
            $obj.'AntiVirus-Status' = $mpComputerStatus.AntivirusEnabled
            $obj.'AntiVirus-LastUpdate' = $mpComputerStatus.AntivirusSignatureLastUpdated
            $obj.'AntiMalware-Status' = $mpComputerStatus.AMServiceEnabled
            $obj.'OnAccessProtection-Status' = $mpComputerStatus.OnAccessProtectionEnabled
            $obj.'RealTimeProtection-Status' = $mpComputerStatus.RealTimeProtectionEnabled
            $obj.'AntiSpyware-Status' = $mpComputerStatus.AntispywareEnabled
            $obj.'BehaviorMonitor-Status' = $mpComputerStatus.BehaviorMonitorEnabled
            $obj.'OfficeProtection-Status' = $mpComputerStatus.IoavProtectionEnabled
            $obj.'NIS-Status' = $mpComputerStatus.NISEnabled
        }
    }
    catch {
        if($Error[0].FullyQualifiedErrorId -eq 'HRESULT 0x80041010,Get-MpComputerStatus') {
            $obj.'AntiMalware-Status' = 'False'
        }
    }

    # If the host is a workstation, get details about security products
    $osDetails = Get-CimInstance Win32_OperatingSystem -CimSession $session
    if ($osDetails.ProductType -eq 1) {
        $antiSpywareProduct = Get-CimInstance -Namespace ROOT/SecurityCenter2 -Class AntiSpywareProduct -CimSession $session
        if ($antiSpywareProduct -ne $null) {
            $obj.'AntiSpyware-Product' = $antiSpywareProduct.displayName
        }
        $antiVirusProduct = Get-CimInstance -Namespace ROOT/SecurityCenter2 -Class AntiVirusProduct -CimSession $session
        if ($antiVirusProduct -ne $null) {
            $obj.'AntiVirus-Product' = $antiVirusProduct.displayName
        }
        $firewallProduct = Get-CimInstance -Namespace ROOT/SecurityCenter2 -Class FirewallProduct -CimSession $session
        if ($firewallProduct -ne $null) {
            $obj.'Firewall-Product' = $firewallProduct.displayName
        }
    }

    # Get firewall status
    [uint32]$hive = 2147483650
    $key = 'SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\DomainProfile'
    $value = 'EnableFirewall'
    $firewallDomainProfileStatus = (Invoke-CimMethod -ClassName StdRegProv -Name GetDWordValue -Arguments @{
        hDefKey = $hive
        sSubKeyName = $key
        sValueName = $value
    } -CimSession $session).uValue
    if ($firewallDomainProfileStatus -ne $null) {
        $obj.'Firewall-DomainProfileStatus' = $firewallDomainProfileStatus
    }

    Write-Output $obj
}
