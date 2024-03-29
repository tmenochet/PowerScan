# PowerScan

PowerScan runs PowerShell script block targeting network ranges or Active Directory domain computers.

This tool is designed to run PowerShell code locally in order to quietly query multiple hosts in a multi-threaded way.
If you need to run PowerShell script block on remote hosts, please refer to [PowerExec](https://github.com/tmenochet/PowerExec) project.

PowerScan project includes various PowerShell scripts that can be launched within PowerScan as script block for reconnaissance, post-exploitation or threat hunting purposes.

By default, output is written into a CSV file in the current directory. This can be disabled using the switch `-NoCsv`.
Console output can also be disabled using the switch `-Quiet`.


## Functions

### Recon

Reconnaissance functions require either low privileges (typically domain user) or none.

| Function              | Description                                          |
| --------------------- | ---------------------------------------------------- |
| Get-NetBiosInterface  | Get NetBIOS information, including network addresses |
| Get-NetSession        | Get logon session information                        |
| Get-NullSessionStatus | Check if null session to IPC$ is allowed             |
| Get-OxidBinding       | Get addresses of network interfaces                  |
| Get-SecurityService   | Detect security services                             |
| Get-ServiceNamedPipe  | Detect interesting services                          |
| Get-SmbOSVersion      | Get OS version                                       |
| Get-SmbStatus         | Get available versions of the SMB protocol           |
| Get-SpoolerStatus     | Get the status of Print Spooler service              |


### Post

Post-exploitation functions require high privileges (typically administrator).

| Function                     | Description                                                   |
| ---------------------------- | ------------------------------------------------------------- |
| Get-CimDpapiBrowser          | Get credentials from web browsers                             |
| Get-CimDpapiCredential       | Get credentials from Windows Credentials                      |
| Get-CimDpapiVault            | Get credentials from Windows Vault                            |
| Get-CimDpapiWifi             | Get credentials from WiFi profiles                            |
| Get-CimUnprotectedCredential | Get credentials from common registry keys and files           |
| Get-RegistryHiveDump         | Get secrets from registry hives retrieved via remote registry |
| Get-ShadowHiveDump           | Get secrets from registry hives retrieved via shadow copy     |


### Hunt

Hunting functions require high privileges (typically administrator).


| Function                  | Description                                                   |
| ------------------------- | ------------------------------------------------------------- |
| Get-CimAppCompatCache     | Get shimcache execution artefacts                             |
| Get-CimAsepLogon          | Get AutoStart Extension Points related to logon               |
| Get-CimAsepStartup        | Get common AutoStart Extension Points related to logon        |
| Get-CimAsepWmi            | Get WMI persistences                                          |
| Get-CimDNSCache           | Get DNS cache entries                                         |
| Get-CimDirectory          | Get a directory listing of folders and files                  |
| Get-CimDriver             | Get Windows drivers                                           |
| Get-CimLocalAdmin         | Get members of local admin group                              |
| Get-CimLocalUser          | Get local user accounts                                       |
| Get-CimLogonHistory       | Get logon cached information                                  |
| Get-CimLogonSession       | Get logon session information                                 |
| Get-CimNetAdapter         | Get network adapters                                          |
| Get-CimNetTCPConnection   | Get current TCP connections                                   |
| Get-CimProcess            | Get running processes                                         |
| Get-CimRegistryKey        | Get registry subkeys                                          |
| Get-CimRegistryValue      | Get registry value names                                      |
| Get-CimScheduledTask      | Get scheduled tasks                                           |
| Get-CimSecurityHealth     | Get the status of security softwares                          |
| Get-CimService            | Get Windows services                                          |
| Get-CimSmbShare           | Get SMB shares and related permissions                        |
| Get-CimUserAssist         | Get user assist execution artefacts                           |
| Get-ComScheduledTask      | Get scheduled tasks                                           |
| Get-EventLogon            | Get logon events from Windows Security logs                   |
| Get-EventSuspiciousBITS   | Get suspicious BITS events from Windows logs                  |
| Get-EventSuspiciousPS     | Get suspicious Powershell events from Windows logs            |
| Get-EventSvcCreation      | Get service creation events from System logs                  |
| Get-EventSvcModification  | Get service modification events from System logs              |
| Get-EventTaskCreation     | Get scheduled task creation events from Security logs         |
| Get-EventTaskModification | Get scheduled task modification events from Security logs     |
| Get-PowershellHistory     | Get Powershell history files                                  |
| Get-PowershellProfile     | Get Powershell profile files                                  |
| Get-RegistryKeyTimestamp  | Get registry key timestamp                                    |


## Examples

Get available versions of the SMB protocol and signing requirements on a network:

```
PS C:\> IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/tmenochet/PowerScan/master/PowerScan.ps1')
PS C:\> IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/tmenochet/PowerScan/master/Recon/Get-SmbStatus.ps1')
PS C:\> Invoke-PowerScan -ScriptBlock ${Function:Get-SmbStatus} -ComputerList 192.168.1.0/24
```


Get the status of Print Spooler service on all domain controllers (using implicit credentials):

```
PS C:\> IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/tmenochet/PowerScan/master/PowerScan.ps1')
PS C:\> IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/tmenochet/PowerScan/master/Recon/Get-SpoolerStatus.ps1')
PS C:\> Invoke-PowerScan -ScriptBlock ${Function:Get-SpoolerStatus} -ComputerDomain ADATUM.CORP -ComputerFilter DomainControllers -NoCsv
```


Gather credentials from common registry keys and files on all domain computers (using explicit credentials):

```
PS C:\> IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/tmenochet/PowerScan/master/PowerScan.ps1')
PS C:\> IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/tmenochet/PowerScan/master/Post/Get-CimUnprotectedCredential.ps1')
PS C:\> $cred = Get-Credential Administrator@ADATUM.CORP
PS C:\> Invoke-PowerScan -ScriptBlock ${Function:Get-CimUnprotectedCredential} -ScriptParameters @{Credential=$cred; Timeout=2} -ComputerDomain ADATUM.CORP -Credential $cred
```


## Acknowledgments

PowerScan is inspired by the following projects, among others:

  * [CimSweep](https://github.com/PowerShellMafia/CimSweep) by @mattifestation

  * [PSGumshoe](https://github.com/PSGumshoe) by @darkoperator

  * [SessionGopher](https://github.com/Arvanaghi/SessionGopher) by @arvanaghi
