#requires -version 3

function Get-SecurityStatus {
<#
.SYNOPSIS
    Get the status of security softwares on a remote computer.
    Privileges required: high

    Author: Timothée MENOCHET (@_tmenochet)

.DESCRIPTION
    Get-SecurityStatus queries a remote host though WMI about firewall and antivirus products.

.PARAMETER ComputerName
    Specifies the target host.

.PARAMETER Credential
    Specifies the privileged account to use.

.PARAMETER Ping
    Ensures host is up before run.

.PARAMETER Protocol
    Specifies the protocol to use.

.EXAMPLE
    PS C:\> Get-SecurityStatus -ComputerName SRV.ADATUM.CORP -Credential ADATUM\Administrator
#>

    [CmdletBinding()]
    Param (
        [ValidateNotNullOrEmpty()]
        [String]
        $ComputerName = $env:COMPUTERNAME,

        [ValidateNotNullOrEmpty()]
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty,

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

        [uint32]$HKLM = 2147483650
        $obj = "" | Select-Object -Property "ComputerName","AntiVirus-Product","AntiVirus-Status","AntiVirus-LastUpdate","AntiVirus-Exclusions","OnAccessProtection-Status","RealTimeProtection-Status","BehaviorMonitor-Status","OfficeProtection-Status","NIS-Status","AntiMalware-Status","AM-RecentDetections","AntiSpyware-Product","AntiSpyware-Status","AntiSpyware-LastUpdate","Firewall-Product","Firewall-DomainProfileStatus"
        $obj.'ComputerName' = $ComputerName
    }

    PROCESS {
        # Get antimalware status
        try {
            $antiMalwareStatus = Get-CimInstance -Namespace ROOT\Microsoft\SecurityClient -ClassName AntimalwareHealthStatus -CimSession $cimSession -ErrorAction Stop -Verbose:$false
            if ($antiMalwareStatus) {
                $obj.'AntiVirus-Status' = $antiMalwareStatus.AntivirusEnabled
                $obj.'AntiVirus-LastUpdate' = $antiMalwareStatus.AntivirusSignatureUpdateDateTime
                $obj.'AntiSpyware-LastUpdate' = $antiMalwareStatus.AntispywareSignatureUpdateDateTime
                $obj.'AntiMalware-Status' = $antiMalwareStatus.Enabled
                $obj.'OnAccessProtection-Status' = $antiMalwareStatus.OnAccessProtectionEnabled
                $obj.'RealTimeProtection-Status' = $antiMalwareStatus.RtpEnabled
                $obj.'AntiSpyware-Status' = $antiMalwareStatus.AntispywareEnabled
                $obj.'BehaviorMonitor-Status' = $antiMalwareStatus.BehaviorMonitorEnabled
                $obj.'OfficeProtection-Status' = $antiMalwareStatus.IoavProtectionEnabled
                $obj.'NIS-Status' = $antiMalwareStatus.NISEnabled
            }
        }
        catch {
            $obj.'AntiMalware-Status' = 'False'
        }

        # Get infection status
        try {
            $infection = New-Object System.Collections.ArrayList
            $detections = Get-CimInstance -Namespace ROOT\Microsoft\SecurityClient -ClassName Malware -CimSession $cimSession -ErrorAction Stop -Verbose:$false
            foreach ($detection in $detections) {
                $properties = [ordered]@{
                    DetectionTime = $detection.DetectionTime
                    ActionSuccess = $detection.ActionSuccess
                    ThreatName = $detection.ThreatName
                    Process = $detection.Process
                    Path = $detection.Path
                    User = $detection.User
                }
                $infection.Add((New-Object psobject -Property $properties)) | Out-Null
            }
            $obj.'AM-RecentDetections' = $infection
        }
        catch {}

        # If the host is a workstation, get details about security products
        $osDetails = Get-CimInstance -ClassName Win32_OperatingSystem -CimSession $cimSession -Verbose:$false
        if ($osDetails.ProductType -eq 1) {
            if ($osDetails.Version[0] -lt 6) {
                $namespace = "ROOT/SecurityCenter"
            }
            else {
                $namespace = "ROOT/SecurityCenter2"
            }
            $antiSpywareProduct = Get-CimInstance -Namespace $namespace -ClassName AntiSpywareProduct -CimSession $cimSession -Verbose:$false
            if ($antiSpywareProduct) {
                $obj.'AntiSpyware-Product' = $antiSpywareProduct.displayName
            }
            $antiVirusProduct = Get-CimInstance -Namespace $namespace -ClassName AntiVirusProduct -CimSession $cimSession -Verbose:$false
            if ($antiVirusProduct) {
                $obj.'AntiVirus-Product' = $antiVirusProduct.displayName
            }
            $firewallProduct = Get-CimInstance -Namespace $namespace -ClassName FirewallProduct -CimSession $cimSession -Verbose:$false
            if ($firewallProduct) {
                $obj.'Firewall-Product' = $firewallProduct.displayName
            }

            # Get the exclusions if available
            $defenderPaths = @{
                ExcludedPaths = 'SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths\'
                ExcludedExtensions = 'SOFTWARE\Microsoft\Windows Defender\Exclusions\Extensions\'
                ExcludedProcesses = 'SOFTWARE\Microsoft\Windows Defender\Exclusions\Processes\'
            }
            $mcAfeePaths = @{
                Exclusions = 'SOFTWARE\McAfee\AVSolution\OAS\DEFAULT\'
                EmailIncludedProcesses = 'SOFTWARE\McAfee\AVSolution\OAS\EMAIL\'
                ProcessStartupExclusions = 'SOFTWARE\McAfee\AVSolution\HIP\'
            }
            $exclusions = [PSCustomObject] @{}
            if($obj.'AntiVirus-Product' -match 'Windows Defender') {
                $defenderPaths.GetEnumerator() | ForEach-Object {
                    if ($exclusion = $(Invoke-CimMethod -Class 'StdRegProv' -Name EnumValues -Arguments @{hDefKey=$HKLM; sSubKeyName=$($_.Value)} -CimSession $cimSession -Verbose:$false).sNames) {
                        $exclusions | Add-Member -NotePropertyName $_.Key -NotePropertyValue $($exclusion -join ', ')
                    }
                }

            }
            elseif($obj.'AntiVirus-Product' -match 'McAfee') {
                $mcAfeePaths.GetEnumerator() | ForEach-Object {
                    if ($exclusion = $(Invoke-CimMethod -Class 'StdRegProv' -Name EnumValues -Arguments @{hDefKey=$HKLM; sSubKeyName=$($_.Value)} -CimSession $cimSession -Verbose:$false).sNames) {
                        $exclusions | Add-Member -NotePropertyName $_.Key -NotePropertyValue $($exclusion -join ', ')
                    }
                }
            }
            $obj.'AntiVirus-Exclusions' = $exclusions
        }

        # Get firewall status
        $key = 'SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\DomainProfile'
        $value = 'EnableFirewall'
        $firewallDomainProfileStatus = (Invoke-CimMethod -ClassName StdRegProv -Name GetDWordValue -Arguments @{
            hDefKey = $HKLM
            sSubKeyName = $key
            sValueName = $value
        } -CimSession $cimSession -Verbose:$false).uValue
        if ($firewallDomainProfileStatus -eq 1) {
            $firewallStatus = $True
        }
        elseif ($firewallDomainProfileStatus -eq 0) {
            $firewallStatus = $False
        }
        $obj.'Firewall-DomainProfileStatus' = $firewallStatus
        Write-Output $obj
    }

    END {
        Remove-CimSession -CimSession $cimSession
    }
}