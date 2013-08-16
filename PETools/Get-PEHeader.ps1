function Get-PEHeader
{
<#
.SYNOPSIS

Parses and outputs the PE header of a process in memory or a PE file on disk.

PowerSploit Function: Get-PEHeader
Author: Matthew Graeber (@mattifestation)
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: PETools.format.ps1xml

.DESCRIPTION

Get-PEHeader retrieves PE headers including imports and exports from either a file on disk or a module in memory. Get-PEHeader will operate on single PE header but you can also feed it the output of Get-ChildItem or Get-Process! Get-PEHeader works on both 32 and 64-bit modules.

.PARAMETER FilePath

Specifies the path to the portable executable file on disk

.PARAMETER ProcessID

Specifies the process ID.

.PARAMETER Module

The name of the module. This parameter is typically only used in pipeline expressions

.PARAMETER ModuleBaseAddress

The base address of the module

.PARAMETER GetSectionData

Retrieves raw section data.

.OUTPUTS

System.Object

Returns a custom object consisting of the following: compile time, section headers, module name, DOS header, imports, exports, file header, optional header, and PE signature.

.EXAMPLE

C:\PS> Get-Process cmd | Get-PEHeader

Description
-----------
Returns the full PE headers of every loaded module in memory

.EXAMPLE

C:\PS> Get-ChildItem C:\Windows\*.exe | Get-PEHeader

Description
-----------
Returns the full PE headers of every exe in C:\Windows\

.EXAMPLE

C:\PS> Get-PEHeader C:\Windows\System32\kernel32.dll

Module         : C:\Windows\System32\kernel32.dll
DOSHeader      : PE+_IMAGE_DOS_HEADER
FileHeader     : PE+_IMAGE_FILE_HEADER
OptionalHeader : PE+_IMAGE_OPTIONAL_HEADER32
SectionHeaders : {.text, .data, .rsrc, .reloc}
Imports        : {@{Ordinal=; FunctionName=RtlUnwind; ModuleName=API-MS-Win-Core-RtlSupport-L1-1-0.
                 dll; VA=0x000CB630}, @{Ordinal=; FunctionName=RtlCaptureContext; ModuleName=API-MS
                 -Win-Core-RtlSupport-L1-1-0.dll; VA=0x000CB63C}, @{Ordinal=; FunctionName=RtlCaptu
                 reStackBackTrace; ModuleName=API-MS-Win-Core-RtlSupport-L1-1-0.dll; VA=0x000CB650}
                 , @{Ordinal=; FunctionName=NtCreateEvent; ModuleName=ntdll.dll; VA=0x000CB66C}...}
Exports        : {@{ForwardedName=; FunctionName=lstrlenW; Ordinal=0x0552; VA=0x0F022708}, @{Forwar
                 dedName=; FunctionName=lstrlenA; Ordinal=0x0551; VA=0x0F026A23}, @{ForwardedName=;
                  FunctionName=lstrlen; Ordinal=0x0550; VA=0x0F026A23}, @{ForwardedName=; FunctionN
                 ame=lstrcpynW; Ordinal=0x054F; VA=0x0F04E54E}...}

.EXAMPLE

C:\PS> $Proc = Get-Process cmd
C:\PS> $Kernel32Base = ($Proc.Modules | Where-Object {$_.ModuleName -eq 'kernel32.dll'}).BaseAddress
C:\PS> Get-PEHeader -ProcessId $Proc.Id -ModuleBaseAddress $Kernel32Base

Module         :
DOSHeader      : PE+_IMAGE_DOS_HEADER
FileHeader     : PE+_IMAGE_FILE_HEADER
OptionalHeader : PE+_IMAGE_OPTIONAL_HEADER32
SectionHeaders : {.text, .data, .rsrc, .reloc}
Imports        : {@{Ordinal=; FunctionName=RtlUnwind; ModuleName=API-MS-Win-Core-RtlSupport-L1-1-0.
                 dll; VA=0x77B8B6D9}, @{Ordinal=; FunctionName=RtlCaptureContext; ModuleName=API-MS
                 -Win-Core-RtlSupport-L1-1-0.dll; VA=0x77B8B4CB}, @{Ordinal=; FunctionName=RtlCaptu
                 reStackBackTrace; ModuleName=API-MS-Win-Core-RtlSupport-L1-1-0.dll; VA=0x77B95277}
                 , @{Ordinal=; FunctionName=NtCreateEvent; ModuleName=ntdll.dll; VA=0x77B4FF54}...}
Exports        : {@{ForwardedName=; FunctionName=lstrlenW; Ordinal=0x0552; VA=0x08221720}, @{Forwar
                 dedName=; FunctionName=lstrlenA; Ordinal=0x0551; VA=0x08225A3B}, @{ForwardedName=;
                  FunctionName=lstrlen; Ordinal=0x0550; VA=0x08225A3B}, @{ForwardedName=; FunctionN
                 ame=lstrcpynW; Ordinal=0x054F; VA=0x0824D566}...}

Description
-----------
A PE header is returned upon providing the module's base address. This technique would be useful for dumping the PE header of a rogue module that is invisible to Windows - e.g. a reflectively loaded meterpreter binary (metsrv.dll).

.NOTES

Be careful if you decide to specify a module base address. Get-PEHeader does not check for the existence of an MZ header. An MZ header is not a prerequisite for reflectively loading a module in memory. If you provide an address that is not an actual PE header, you could crash the process.

.LINK

http://www.exploit-monday.com/2012/07/get-peheader.html
#>

    [CmdletBinding(DefaultParameterSetName = 'OnDisk')] Param (
        [Parameter(Position = 0, Mandatory = $True, ParameterSetName = 'OnDisk', ValueFromPipelineByPropertyName = $True)] [Alias('FullName')] [String[]] $FilePath,
        [Parameter(Position = 0, Mandatory = $True, ParameterSetName = 'InMemory', ValueFromPipelineByPropertyName = $True)] [Alias('Id')] [Int] $ProcessID,
        [Parameter(Position = 2, ParameterSetName = 'InMemory', ValueFromPipelineByPropertyName = $True)] [Alias('MainModule')] [Alias('Modules')] [System.Diagnostics.ProcessModule[]] $Module,
        [Parameter(Position = 1, ParameterSetName = 'InMemory')] [IntPtr] $ModuleBaseAddress,
        [Parameter()] [Switch] $GetSectionData
    )

PROCESS {
    
    switch ($PsCmdlet.ParameterSetName) {
        'OnDisk' {
        
            if ($FilePath.Length -gt 1) {
                foreach ($Path in $FilePath) { Get-PEHeader $Path }
            }
            
            if (!(Test-Path $FilePath)) {
                Write-Warning 'Invalid path or file does not exist.'
                return
            }
            
            $FilePath = Resolve-Path $FilePath
            
            if ($FilePath.GetType() -eq [System.Array]) {
                $ModuleName = $FilePath[0]
            } else {
                $ModuleName = $FilePath
            }
            
        }
        'InMemory' {
        
            if ($Module.Length -gt 1) {
                foreach ($Mod in $Module) {
                    $BaseAddr = $Mod.BaseAddress
                    Get-PEHeader -ProcessID $ProcessID -Module $Mod -ModuleBaseAddress $BaseAddr
                }
            }

            if (-not $ModuleBaseAddress) { return }
            
            if ($ProcessID -eq $PID) {
                Write-Warning 'You cannot parse the PE header of the current process. Open another instance of PowerShell.'
                return
            }
            
            if ($Module) {
                $ModuleName = $Module[0].FileName
            } else {
                $ModuleName = ''
            }
            
        }
    }
    
    try { [PE] | Out-Null } catch [Management.Automation.RuntimeException]
    {
        $code = @"
        using System;
        using System.Runtime.InteropServices;

        public class PE
        {
            [Flags]
            public enum IMAGE_DOS_SIGNATURE : ushort
            {
                DOS_SIGNATURE =                 0x5A4D,      // MZ
                OS2_SIGNATURE =                 0x454E,      // NE
                OS2_SIGNATURE_LE =              0x454C,      // LE
                VXD_SIGNATURE =                 0x454C,      // LE 
            }
        
            [Flags]
            public enum IMAGE_NT_SIGNATURE : uint
            {
                VALID_PE_SIGNATURE =                        0x00004550  // PE00
            }
        
            [Flags]
            public enum IMAGE_FILE_MACHINE : ushort
            {
                UNKNOWN =          0,
                I386 =             0x014c,  // Intel 386.
                R3000 =            0x0162,  // MIPS little-endian =0x160 big-endian
                R4000 =            0x0166,  // MIPS little-endian
                R10000 =           0x0168,  // MIPS little-endian
                WCEMIPSV2 =        0x0169,  // MIPS little-endian WCE v2
                ALPHA =            0x0184,  // Alpha_AXP
                SH3 =              0x01a2,  // SH3 little-endian
                SH3DSP =           0x01a3,
                SH3E =             0x01a4,  // SH3E little-endian
                SH4 =              0x01a6,  // SH4 little-endian
                SH5 =              0x01a8,  // SH5
                ARM =              0x01c0,  // ARM Little-Endian
                THUMB =            0x01c2,
                ARMNT =            0x01c4,  // ARM Thumb-2 Little-Endian
                AM33 =             0x01d3,
                POWERPC =          0x01F0,  // IBM PowerPC Little-Endian
                POWERPCFP =        0x01f1,
                IA64 =             0x0200,  // Intel 64
                MIPS16 =           0x0266,  // MIPS
                ALPHA64 =          0x0284,  // ALPHA64
                MIPSFPU =          0x0366,  // MIPS
                MIPSFPU16 =        0x0466,  // MIPS
                AXP64 =            ALPHA64,
                TRICORE =          0x0520,  // Infineon
                CEF =              0x0CEF,
                EBC =              0x0EBC,  // EFI public byte Code
                AMD64 =            0x8664,  // AMD64 (K8)
                M32R =             0x9041,  // M32R little-endian
                CEE =              0xC0EE
            }
        
            [Flags]
            public enum IMAGE_FILE_CHARACTERISTICS : ushort
            {
                IMAGE_RELOCS_STRIPPED =          0x0001,  // Relocation info stripped from file.
                IMAGE_EXECUTABLE_IMAGE =         0x0002,  // File is executable  (i.e. no unresolved external references).
                IMAGE_LINE_NUMS_STRIPPED =       0x0004,  // Line nunbers stripped from file.
                IMAGE_LOCAL_SYMS_STRIPPED =      0x0008,  // Local symbols stripped from file.
                IMAGE_AGGRESIVE_WS_TRIM =        0x0010,  // Agressively trim working set
                IMAGE_LARGE_ADDRESS_AWARE =      0x0020,  // App can handle >2gb addresses
                IMAGE_REVERSED_LO =              0x0080,  // public bytes of machine public ushort are reversed.
                IMAGE_32BIT_MACHINE =            0x0100,  // 32 bit public ushort machine.
                IMAGE_DEBUG_STRIPPED =           0x0200,  // Debugging info stripped from file in .DBG file
                IMAGE_REMOVABLE_RUN_FROM_SWAP =  0x0400,  // If Image is on removable media =copy and run from the swap file.
                IMAGE_NET_RUN_FROM_SWAP =        0x0800,  // If Image is on Net =copy and run from the swap file.
                IMAGE_SYSTEM =                   0x1000,  // System File.
                IMAGE_DLL =                      0x2000,  // File is a DLL.
                IMAGE_UP_SYSTEM_ONLY =           0x4000,  // File should only be run on a UP machine
                IMAGE_REVERSED_HI =              0x8000   // public bytes of machine public ushort are reversed.
            }
        
            [Flags]
            public enum IMAGE_NT_OPTIONAL_HDR_MAGIC : ushort
            {
                PE32 =       0x10b,
                PE64 =       0x20b
            }
        
            [Flags]
            public enum IMAGE_SUBSYSTEM : ushort
            {
                UNKNOWN =                  0,   // Unknown subsystem.
                NATIVE =                   1,   // Image doesn't require a subsystem.
                WINDOWS_GUI =              2,   // Image runs in the Windows GUI subsystem.
                WINDOWS_CUI =              3,   // Image runs in the Windows character subsystem.
                OS2_CUI =                  5,   // image runs in the OS/2 character subsystem.
                POSIX_CUI =                7,   // image runs in the Posix character subsystem.
                NATIVE_WINDOWS =           8,   // image is a native Win9x driver.
                WINDOWS_CE_GUI =           9,   // Image runs in the Windows CE subsystem.
                EFI_APPLICATION =          10,
                EFI_BOOT_SERVICE_DRIVER =  11,
                EFI_RUNTIME_DRIVER =       12,
                EFI_ROM =                  13,
                XBOX =                     14,
                WINDOWS_BOOT_APPLICATION = 16
            }
        
            [Flags]
            public enum IMAGE_DLLCHARACTERISTICS : ushort
            {
                DYNAMIC_BASE =          0x0040,     // DLL can move.
                FORCE_INTEGRITY =       0x0080,     // Code Integrity Image
                NX_COMPAT =             0x0100,     // Image is NX compatible
                NO_ISOLATION =          0x0200,     // Image understands isolation and doesn't want it
                NO_SEH =                0x0400,     // Image does not use SEH.  No SE handler may reside in this image
                NO_BIND =               0x0800,     // Do not bind this image.
                WDM_DRIVER =            0x2000,     // Driver uses WDM model
                TERMINAL_SERVER_AWARE = 0x8000
            }
        
            [Flags]
            public enum IMAGE_SCN : uint
            {
                TYPE_NO_PAD =               0x00000008,  // Reserved.
                CNT_CODE =                  0x00000020,  // Section contains code.
                CNT_INITIALIZED_DATA =      0x00000040,  // Section contains initialized data.
                CNT_UNINITIALIZED_DATA =    0x00000080,  // Section contains uninitialized data.
                LNK_INFO =                  0x00000200,  // Section contains comments or some other type of information.
                LNK_REMOVE =                0x00000800,  // Section contents will not become part of image.
                LNK_COMDAT =                0x00001000,  // Section contents comdat.
                NO_DEFER_SPEC_EXC =         0x00004000,  // Reset speculative exceptions handling bits in the TLB entries for this section.
                GPREL =                     0x00008000,  // Section content can be accessed relative to GP
                MEM_FARDATA =               0x00008000,
                MEM_PURGEABLE =             0x00020000,
                MEM_16BIT =                 0x00020000,
                MEM_LOCKED =                0x00040000,
                MEM_PRELOAD =               0x00080000,
                ALIGN_1BYTES =              0x00100000,
                ALIGN_2BYTES =              0x00200000,
                ALIGN_4BYTES =              0x00300000,
                ALIGN_8BYTES =              0x00400000,
                ALIGN_16BYTES =             0x00500000,  // Default alignment if no others are specified.
                ALIGN_32BYTES =             0x00600000,
                ALIGN_64BYTES =             0x00700000,
                ALIGN_128BYTES =            0x00800000,
                ALIGN_256BYTES =            0x00900000,
                ALIGN_512BYTES =            0x00A00000,
                ALIGN_1024BYTES =           0x00B00000,
                ALIGN_2048BYTES =           0x00C00000,
                ALIGN_4096BYTES =           0x00D00000,
                ALIGN_8192BYTES =           0x00E00000,
                ALIGN_MASK =                0x00F00000,
                LNK_NRELOC_OVFL =           0x01000000,  // Section contains extended relocations.
                MEM_DISCARDABLE =           0x02000000,  // Section can be discarded.
                MEM_NOT_CACHED =            0x04000000,  // Section is not cachable.
                MEM_NOT_PAGED =             0x08000000,  // Section is not pageable.
                MEM_SHARED =                0x10000000,  // Section is shareable.
                MEM_EXECUTE =               0x20000000,  // Section is executable.
                MEM_READ =                  0x40000000,  // Section is readable.
                MEM_WRITE =                 0x80000000   // Section is writeable.
            }
    
            [StructLayout(LayoutKind.Sequential, Pack=1)]
            public struct _IMAGE_DOS_HEADER
            {
                public IMAGE_DOS_SIGNATURE   e_magic;        // Magic number
                public ushort   e_cblp;                      // public bytes on last page of file
                public ushort   e_cp;                        // Pages in file
                public ushort   e_crlc;                      // Relocations
                public ushort   e_cparhdr;                   // Size of header in paragraphs
                public ushort   e_minalloc;                  // Minimum extra paragraphs needed
                public ushort   e_maxalloc;                  // Maximum extra paragraphs needed
                public ushort   e_ss;                        // Initial (relative) SS value
                public ushort   e_sp;                        // Initial SP value
                public ushort   e_csum;                      // Checksum
                public ushort   e_ip;                        // Initial IP value
                public ushort   e_cs;                        // Initial (relative) CS value
                public ushort   e_lfarlc;                    // File address of relocation table
                public ushort   e_ovno;                      // Overlay number
                [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 8)]
                public string   e_res;                       // This will contain 'Detours!' if patched in memory
                public ushort   e_oemid;                     // OEM identifier (for e_oeminfo)
                public ushort   e_oeminfo;                   // OEM information; e_oemid specific
                [MarshalAsAttribute(UnmanagedType.ByValArray, SizeConst=10)] // , ArraySubType=UnmanagedType.U4
                public ushort[] e_res2;                      // Reserved public ushorts
                public int      e_lfanew;                    // File address of new exe header
            }
        
            [StructLayout(LayoutKind.Sequential, Pack=1)]
            public struct _IMAGE_FILE_HEADER
            {
                public IMAGE_FILE_MACHINE    Machine;
                public ushort                NumberOfSections;
                public uint                  TimeDateStamp;
                public uint                  PointerToSymbolTable;
                public uint                  NumberOfSymbols;
                public ushort                SizeOfOptionalHeader;
                public IMAGE_FILE_CHARACTERISTICS    Characteristics;
            }
        
            [StructLayout(LayoutKind.Sequential, Pack=1)]
            public struct _IMAGE_NT_HEADERS32
            {
                public IMAGE_NT_SIGNATURE Signature;
                public _IMAGE_FILE_HEADER FileHeader;
                public _IMAGE_OPTIONAL_HEADER32 OptionalHeader;
            }
        
            [StructLayout(LayoutKind.Sequential, Pack=1)]
            public struct _IMAGE_NT_HEADERS64
            {
                public IMAGE_NT_SIGNATURE Signature;
                public _IMAGE_FILE_HEADER FileHeader;
                public _IMAGE_OPTIONAL_HEADER64 OptionalHeader;
            }
        
            [StructLayout(LayoutKind.Sequential, Pack=1)]
            public struct _IMAGE_OPTIONAL_HEADER32
            {
                public IMAGE_NT_OPTIONAL_HDR_MAGIC    Magic;
                public byte    MajorLinkerVersion;
                public byte    MinorLinkerVersion;
                public uint   SizeOfCode;
                public uint   SizeOfInitializedData;
                public uint   SizeOfUninitializedData;
                public uint   AddressOfEntryPoint;
                public uint   BaseOfCode;
                public uint   BaseOfData;
                public uint   ImageBase;
                public uint   SectionAlignment;
                public uint   FileAlignment;
                public ushort    MajorOperatingSystemVersion;
                public ushort    MinorOperatingSystemVersion;
                public ushort    MajorImageVersion;
                public ushort    MinorImageVersion;
                public ushort    MajorSubsystemVersion;
                public ushort    MinorSubsystemVersion;
                public uint   Win32VersionValue;
                public uint   SizeOfImage;
                public uint   SizeOfHeaders;
                public uint   CheckSum;
                public IMAGE_SUBSYSTEM    Subsystem;
                public IMAGE_DLLCHARACTERISTICS    DllCharacteristics;
                public uint   SizeOfStackReserve;
                public uint   SizeOfStackCommit;
                public uint   SizeOfHeapReserve;
                public uint   SizeOfHeapCommit;
                public uint   LoaderFlags;
                public uint   NumberOfRvaAndSizes;
                [MarshalAsAttribute(UnmanagedType.ByValArray, SizeConst=16)]
                public _IMAGE_DATA_DIRECTORY[] DataDirectory;
            }
        
            [StructLayout(LayoutKind.Sequential, Pack=1)]
            public struct _IMAGE_OPTIONAL_HEADER64
            {
                public IMAGE_NT_OPTIONAL_HDR_MAGIC    Magic;
                public byte      MajorLinkerVersion;
                public byte      MinorLinkerVersion;
                public uint      SizeOfCode;
                public uint      SizeOfInitializedData;
                public uint      SizeOfUninitializedData;
                public uint      AddressOfEntryPoint;
                public uint      BaseOfCode;
                public ulong     ImageBase;
                public uint      SectionAlignment;
                public uint      FileAlignment;
                public ushort    MajorOperatingSystemVersion;
                public ushort    MinorOperatingSystemVersion;
                public ushort    MajorImageVersion;
                public ushort    MinorImageVersion;
                public ushort    MajorSubsystemVersion;
                public ushort    MinorSubsystemVersion;
                public uint      Win32VersionValue;
                public uint      SizeOfImage;
                public uint      SizeOfHeaders;
                public uint      CheckSum;
                public IMAGE_SUBSYSTEM    Subsystem;
                public IMAGE_DLLCHARACTERISTICS    DllCharacteristics;
                public ulong     SizeOfStackReserve;
                public ulong     SizeOfStackCommit;
                public ulong     SizeOfHeapReserve;
                public ulong     SizeOfHeapCommit;
                public uint      LoaderFlags;
                public uint      NumberOfRvaAndSizes;
                [MarshalAsAttribute(UnmanagedType.ByValArray, SizeConst=16)]
                public _IMAGE_DATA_DIRECTORY[] DataDirectory;
            }
        
            [StructLayout(LayoutKind.Sequential, Pack=1)]
            public struct _IMAGE_DATA_DIRECTORY
            {
                public uint      VirtualAddress;
                public uint      Size;
            }
        
            [StructLayout(LayoutKind.Sequential, Pack=1)]
            public struct _IMAGE_EXPORT_DIRECTORY
            {
                public uint      Characteristics;
                public uint      TimeDateStamp;
                public ushort    MajorVersion;
                public ushort    MinorVersion;
                public uint      Name;
                public uint      Base;
                public uint      NumberOfFunctions;
                public uint      NumberOfNames;
                public uint      AddressOfFunctions;     // RVA from base of image
                public uint      AddressOfNames;         // RVA from base of image
                public uint      AddressOfNameOrdinals;  // RVA from base of image
            }
       
            [StructLayout(LayoutKind.Sequential, Pack=1)]
            public struct _IMAGE_SECTION_HEADER
            {
                [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 8)]
                public string Name;
                public uint VirtualSize;
                public uint VirtualAddress;
                public uint SizeOfRawData;
                public uint PointerToRawData;
                public uint PointerToRelocations;
                public uint PointerToLinenumbers;
                public ushort NumberOfRelocations;
                public ushort NumberOfLinenumbers;
                public IMAGE_SCN Characteristics;
            }
        
            [StructLayout(LayoutKind.Sequential, Pack=1)]
            public struct _IMAGE_IMPORT_DESCRIPTOR
            {
                public uint OriginalFirstThunk;     // RVA to original unbound IAT (PIMAGE_THUNK_DATA)
                public uint TimeDateStamp;          // 0 if not bound,
                                                    // -1 if bound, and real date/time stamp
                                                    //     in IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT (new BIND)
                                                    // O.W. date/time stamp of DLL bound to (Old BIND)
                public uint ForwarderChain;         // -1 if no forwarders
                public uint Name;
                public uint FirstThunk;             // RVA to IAT (if bound this IAT has actual addresses)
            }

            [StructLayout(LayoutKind.Sequential, Pack=1)]
            public struct _IMAGE_THUNK_DATA32
            {
                public Int32 AddressOfData;     // PIMAGE_IMPORT_BY_NAME
            }

            [StructLayout(LayoutKind.Sequential, Pack=1)]
            public struct _IMAGE_THUNK_DATA64
            {
                public Int64 AddressOfData;     // PIMAGE_IMPORT_BY_NAME
            }
        
            [StructLayout(LayoutKind.Sequential, Pack=1)]
            public struct _IMAGE_IMPORT_BY_NAME
            {
                public ushort    Hint;
                public char    Name;    
            }
        }
"@

        $compileParams = New-Object System.CodeDom.Compiler.CompilerParameters
        $compileParams.ReferencedAssemblies.AddRange(@('System.dll', 'mscorlib.dll'))
        $compileParams.GenerateInMemory = $True
        Add-Type -TypeDefinition $code -CompilerParameters $compileParams -PassThru -WarningAction SilentlyContinue | Out-Null
    }

    function Get-DelegateType
    {
        Param (
            [Parameter(Position = 0, Mandatory = $True)] [Type[]] $Parameters,
            [Parameter(Position = 1)] [Type] $ReturnType = [Void]
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
        
        return $TypeBuilder.CreateType()
    }

    function Get-ProcAddress
    {
        Param (
            [Parameter(Position = 0, Mandatory = $True)] [String] $Module,
            [Parameter(Position = 1, Mandatory = $True)] [String] $Procedure
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
        
        return $GetProcAddress.Invoke($null, @([System.Runtime.InteropServices.HandleRef]$HandleRef, $Procedure))
    }
    
    $OnDisk = $True
    if ($PsCmdlet.ParameterSetName -eq 'InMemory') { $OnDisk = $False }
    
    
    $OpenProcessAddr = Get-ProcAddress kernel32.dll OpenProcess
    $OpenProcessDelegate = Get-DelegateType @([UInt32], [Bool], [UInt32]) ([IntPtr])
    $OpenProcess = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($OpenProcessAddr, [Type] $OpenProcessDelegate)
    $ReadProcessMemoryAddr = Get-ProcAddress kernel32.dll ReadProcessMemory
    $ReadProcessMemoryDelegate = Get-DelegateType @([IntPtr], [IntPtr], [IntPtr], [Int], [Int].MakeByRefType()) ([Bool])
    $ReadProcessMemory = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($ReadProcessMemoryAddr, [Type] $ReadProcessMemoryDelegate)
    $CloseHandleAddr = Get-ProcAddress kernel32.dll CloseHandle
    $CloseHandleDelegate = Get-DelegateType @([IntPtr]) ([Bool])
    $CloseHandle = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($CloseHandleAddr, [Type] $CloseHandleDelegate)
    
    if ($OnDisk) {
    
        $FileStream = New-Object System.IO.FileStream($FilePath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read)
        $FileByteArray = New-Object Byte[]($FileStream.Length)
        $FileStream.Read($FileByteArray, 0, $FileStream.Length) | Out-Null
        $FileStream.Close()
        $Handle = [System.Runtime.InteropServices.GCHandle]::Alloc($FileByteArray, 'Pinned')
        $PEBaseAddr = $Handle.AddrOfPinnedObject()
        
    } else {
    
        # Size of the memory page allocated for the PE header
        $HeaderSize = 0x1000
        # Allocate space for when the PE header is read from the remote process
        $PEBaseAddr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($HeaderSize + 1)
        # Get handle to the process
        $hProcess = $OpenProcess.Invoke(0x10, $false, $ProcessID) # PROCESS_VM_READ (0x00000010)
        
        # Read PE header from remote process
        if (!$ReadProcessMemory.Invoke($hProcess, $ModuleBaseAddress, $PEBaseAddr, $HeaderSize, [Ref] 0)) {
            if ($ModuleName) {
                Write-Warning "Failed to read PE header of $ModuleName"
            } else {
                Write-Warning "Failed to read PE header of process ID: $ProcessID"
            }
            
            Write-Warning "Error code: 0x$([System.Runtime.InteropServices.Marshal]::GetLastWin32Error().ToString('X8'))"
            $CloseHandle.Invoke($hProcess) | Out-Null
            return
        }
        
    }
    
    $DosHeader = [System.Runtime.InteropServices.Marshal]::PtrToStructure($PEBaseAddr, [Type] [PE+_IMAGE_DOS_HEADER])
    $PointerNtHeader = [IntPtr] ($PEBaseAddr.ToInt64() + $DosHeader.e_lfanew)
    $NtHeader = [System.Runtime.InteropServices.Marshal]::PtrToStructure($PointerNtHeader, [Type] [PE+_IMAGE_NT_HEADERS32])
    $Architecture = ($NtHeader.FileHeader.Machine).ToString()
    
    $BinaryPtrWidth = 4

    # Define relevant structure types depending upon whether the binary is 32 or 64-bit
    if ($Architecture -eq 'AMD64') {
    
        $BinaryPtrWidth = 8

        $PEStruct = @{
            IMAGE_OPTIONAL_HEADER = [PE+_IMAGE_OPTIONAL_HEADER64]
            NT_HEADER = [PE+_IMAGE_NT_HEADERS64]
        }

        $ThunkDataStruct = [PE+_IMAGE_THUNK_DATA64]

        Write-Verbose "Architecture: $Architecture"
        Write-Verbose 'Proceeding with parsing a 64-bit binary.'
        
    } elseif ($Architecture -eq 'I386' -or $Architecture -eq 'ARMNT' -or $Architecture -eq 'THUMB') {
    
        $PEStruct = @{
            IMAGE_OPTIONAL_HEADER = [PE+_IMAGE_OPTIONAL_HEADER32]
            NT_HEADER = [PE+_IMAGE_NT_HEADERS32]
        }

        $ThunkDataStruct = [PE+_IMAGE_THUNK_DATA32]

        Write-Verbose "Architecture: $Architecture"
        Write-Verbose 'Proceeding with parsing a 32-bit binary.'
        
    } else {
    
        Write-Warning 'Get-PEHeader only supports binaries compiled for x86, AMD64, and ARM.'
        return
        
    }
    
    # Need to get a new NT header in case the architecture changed
    $NtHeader = [System.Runtime.InteropServices.Marshal]::PtrToStructure($PointerNtHeader, [Type] $PEStruct['NT_HEADER'])
    # Display all section headers
    $NumSections = $NtHeader.FileHeader.NumberOfSections
    $NumRva = $NtHeader.OptionalHeader.NumberOfRvaAndSizes
    $PointerSectionHeader = [IntPtr] ($PointerNtHeader.ToInt64() + [System.Runtime.InteropServices.Marshal]::SizeOf([Type] $PEStruct['NT_HEADER']))
    $SectionHeaders = New-Object PSObject[]($NumSections)
    foreach ($i in 0..($NumSections - 1))
    {
        $SectionHeaders[$i] = [System.Runtime.InteropServices.Marshal]::PtrToStructure(([IntPtr] ($PointerSectionHeader.ToInt64() + ($i * [System.Runtime.InteropServices.Marshal]::SizeOf([Type] [PE+_IMAGE_SECTION_HEADER])))), [Type] [PE+_IMAGE_SECTION_HEADER])
    }
    
    
    if (!$OnDisk) {
        
        $ReadSize = $NtHeader.OptionalHeader.SizeOfImage
        # Free memory allocated for the PE header
        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($PEBaseAddr)
        $PEBaseAddr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($ReadSize + 1)
        
        # Read process memory of each section header
        foreach ($SectionHeader in $SectionHeaders) {
            if (!$ReadProcessMemory.Invoke($hProcess, [IntPtr] ($ModuleBaseAddress.ToInt64() + $SectionHeader.VirtualAddress), [IntPtr] ($PEBaseAddr.ToInt64() + $SectionHeader.VirtualAddress), $SectionHeader.VirtualSize, [Ref] 0)) {
                if ($ModuleName) {
                    Write-Warning "Failed to read $($SectionHeader.Name) section of $ModuleName"
                } else {
                    Write-Warning "Failed to read $($SectionHeader.Name) section of process ID: $ProcessID"
                }
                
                Write-Warning "Error code: 0x$([System.Runtime.InteropServices.Marshal]::GetLastWin32Error().ToString('X8'))"
                $CloseHandle.Invoke($hProcess) | Out-Null
                return
            }
        }
        
        # Close handle to the remote process since we no longer need to access the process.
        $CloseHandle.Invoke($hProcess) | Out-Null
        
    }

    if ($PSBoundParameters['GetSectionData'])
    {
        foreach ($i in 0..($NumSections - 1))
        {
            $RawBytes = $null

            if ($OnDisk)
            {
                $RawBytes = New-Object Byte[]($SectionHeaders[$i].SizeOfRawData)
                [Runtime.InteropServices.Marshal]::Copy([IntPtr] ($PEBaseAddr.ToInt64() + $SectionHeaders[$i].PointerToRawData), $RawBytes, 0, $SectionHeaders[$i].SizeOfRawData)
            }
            else
            {
                $RawBytes = New-Object Byte[]($SectionHeaders[$i].VirtualSize)
                [Runtime.InteropServices.Marshal]::Copy([IntPtr] ($PEBaseAddr.ToInt64() + $SectionHeaders[$i].VirtualAddress), $RawBytes, 0, $SectionHeaders[$i].VirtualSize)
            }

            $SectionHeaders[$i] = Add-Member -InputObject ($SectionHeaders[$i]) -MemberType NoteProperty -Name RawData -Value $RawBytes -PassThru -Force
        }
    }
    
    function Get-Exports()
    {
    
        if ($NTHeader.OptionalHeader.DataDirectory[0].VirtualAddress -eq 0) {
            Write-Verbose 'Module does not contain any exports'
            return
        }

        # List all function Rvas in the export table
        $ExportPointer = [IntPtr] ($PEBaseAddr.ToInt64() + $NtHeader.OptionalHeader.DataDirectory[0].VirtualAddress)
        # This range will be used to test for the existence of forwarded functions
        $ExportDirLow = $NtHeader.OptionalHeader.DataDirectory[0].VirtualAddress
        if ($OnDisk) { 
            $ExportPointer = Convert-RVAToFileOffset $ExportPointer
            $ExportDirLow = Convert-RVAToFileOffset $ExportDirLow
            $ExportDirHigh = $ExportDirLow.ToInt32() + $NtHeader.OptionalHeader.DataDirectory[0].Size
        } else { $ExportDirHigh = $ExportDirLow + $NtHeader.OptionalHeader.DataDirectory[0].Size }
        
        $ExportDirectory = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ExportPointer, [Type] [PE+_IMAGE_EXPORT_DIRECTORY])
        $AddressOfNamePtr = [IntPtr] ($PEBaseAddr.ToInt64() + $ExportDirectory.AddressOfNames)
        $NameOrdinalAddrPtr = [IntPtr] ($PEBaseAddr.ToInt64() + $ExportDirectory.AddressOfNameOrdinals)
        $AddressOfFunctionsPtr = [IntPtr] ($PEBaseAddr.ToInt64() + $ExportDirectory.AddressOfFunctions)
        $NumNamesFuncs = $ExportDirectory.NumberOfFunctions - $ExportDirectory.NumberOfNames
        $NumNames = $ExportDirectory.NumberOfNames
        $NumFunctions = $ExportDirectory.NumberOfFunctions
        $Base = $ExportDirectory.Base
        
        # Recalculate file offsets based upon relative virtual addresses
        if ($OnDisk) {
            $AddressOfNamePtr = Convert-RVAToFileOffset $AddressOfNamePtr
            $NameOrdinalAddrPtr = Convert-RVAToFileOffset $NameOrdinalAddrPtr
            $AddressOfFunctionsPtr = Convert-RVAToFileOffset $AddressOfFunctionsPtr
        }

        if ($NumFunctions -gt 0) {
        
            # Create an empty hash table that will contain indices to exported functions and their RVAs
            $FunctionHashTable = @{}
        
            foreach ($i in 0..($NumFunctions - 1))
            {
                
                $RvaFunction = [System.Runtime.InteropServices.Marshal]::ReadInt32($AddressOfFunctionsPtr.ToInt64() + ($i * 4))
                # Function is exported by ordinal if $RvaFunction -ne 0. I.E. NumberOfFunction != the number of actual, exported functions.
                if ($RvaFunction) { $FunctionHashTable[[Int]$i] = $RvaFunction }
                
            }
            
            # Create an empty hash table that will contain indices into RVA array and the function's name
            $NameHashTable = @{}
            
            foreach ($i in 0..($NumNames - 1))
            {
            
                $RvaName = [System.Runtime.InteropServices.Marshal]::ReadInt32($AddressOfNamePtr.ToInt64() + ($i * 4))
                $FuncNameAddr = [IntPtr] ($PEBaseAddr.ToInt64() + $RvaName)
                if ($OnDisk) { $FuncNameAddr= Convert-RVAToFileOffset $FuncNameAddr }
                $FuncName = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi($FuncNameAddr)
                $NameOrdinal = [Int][System.Runtime.InteropServices.Marshal]::ReadInt16($NameOrdinalAddrPtr.ToInt64() + ($i * 2))
                $NameHashTable[$NameOrdinal] = $FuncName
                
            }
            
            foreach ($Key in $FunctionHashTable.Keys)
            {
                $Result = @{}
                
                if ($NameHashTable[$Key]) {
                    $Result['FunctionName'] = $NameHashTable[$Key]
                } else {
                    $Result['FunctionName'] = ''
                }
                
                if (($FunctionHashTable[$Key] -ge $ExportDirLow) -and ($FunctionHashTable[$Key] -lt $ExportDirHigh)) {
                    $ForwardedNameAddr = [IntPtr] ($PEBaseAddr.ToInt64() + $FunctionHashTable[$Key])
                    if ($OnDisk) { $ForwardedNameAddr = Convert-RVAToFileOffset $ForwardedNameAddr }
                    $ForwardedName = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi($ForwardedNameAddr)
                    # This script does not attempt to resolve the virtual addresses of forwarded functions
                    $Result['ForwardedName'] = $ForwardedName
                } else {
                    $Result['ForwardedName'] = ''
                }
                
                $Result['Ordinal'] = "0x$(($Key + $Base).ToString('X4'))"
                $Result['RVA'] = "0x$($FunctionHashTable[$Key].ToString("X$($BinaryPtrWidth*2)"))"
                #$Result['VA'] = "0x$(($FunctionHashTable[$Key] + $PEBaseAddr.ToInt64()).ToString("X$($BinaryPtrWidth*2)"))"
                
                $Export = New-Object PSObject -Property $Result
                $Export.PSObject.TypeNames.Insert(0, 'Export')
                
                $Export
                
            }
            
        } else {  Write-Verbose 'Module does not export any functions.' }

    }

    function Get-Imports()
    {
        if ($NTHeader.OptionalHeader.DataDirectory[1].VirtualAddress -eq 0) {
            Write-Verbose 'Module does not contain any imports'
            return
        }
    
        $FirstImageImportDescriptorPtr = [IntPtr] ($PEBaseAddr.ToInt64() + $NtHeader.OptionalHeader.DataDirectory[1].VirtualAddress)
        if ($OnDisk) { $FirstImageImportDescriptorPtr = Convert-RVAToFileOffset $FirstImageImportDescriptorPtr }
        $ImportDescriptorPtr = $FirstImageImportDescriptorPtr
        
        $i = 0
        # Get all imported modules
        while ($true)
        {
            $ImportDescriptorPtr = [IntPtr] ($FirstImageImportDescriptorPtr.ToInt64() + ($i * [System.Runtime.InteropServices.Marshal]::SizeOf([Type] [PE+_IMAGE_IMPORT_DESCRIPTOR])))
            $ImportDescriptor = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ImportDescriptorPtr, [Type] [PE+_IMAGE_IMPORT_DESCRIPTOR])
            if ($ImportDescriptor.OriginalFirstThunk -eq 0) { break }
            $DllNamePtr = [IntPtr] ($PEBaseAddr.ToInt64() + $ImportDescriptor.Name)
            if ($OnDisk) { $DllNamePtr = Convert-RVAToFileOffset $DllNamePtr }
            $DllName = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi($DllNamePtr)
            $FirstFuncAddrPtr = [IntPtr] ($PEBaseAddr.ToInt64() + $ImportDescriptor.FirstThunk)
            if ($OnDisk) { $FirstFuncAddrPtr = Convert-RVAToFileOffset $FirstFuncAddrPtr }
            $FuncAddrPtr = $FirstFuncAddrPtr
            $FirstOFTPtr = [IntPtr] ($PEBaseAddr.ToInt64() + $ImportDescriptor.OriginalFirstThunk)
            if ($OnDisk) { $FirstOFTPtr = Convert-RVAToFileOffset $FirstOFTPtr }
            $OFTPtr = $FirstOFTPtr
            $j = 0
            while ($true)
            {
                $FuncAddrPtr = [IntPtr] ($FirstFuncAddrPtr.ToInt64() + ($j * [System.Runtime.InteropServices.Marshal]::SizeOf([Type] $ThunkDataStruct)))
                $FuncAddr = [System.Runtime.InteropServices.Marshal]::PtrToStructure($FuncAddrPtr, [Type] $ThunkDataStruct)
                $OFTPtr = [IntPtr] ($FirstOFTPtr.ToInt64() + ($j * [System.Runtime.InteropServices.Marshal]::SizeOf([Type] $ThunkDataStruct)))
                $ThunkData = [System.Runtime.InteropServices.Marshal]::PtrToStructure($OFTPtr, [Type] $ThunkDataStruct)
                $Result = @{ ModuleName = $DllName }
                
                if (([System.Convert]::ToString($ThunkData.AddressOfData, 2)).PadLeft(32, '0')[0] -eq '1')
                {
                    # Trim high order bit in order to get the ordinal value
                    $TempOrdinal = [System.Convert]::ToInt64(([System.Convert]::ToString($ThunkData.AddressOfData, 2))[1..63] -join '', 2)
                    $TempOrdinal = $TempOrdinal.ToString('X16')[-1..-4]
                    [Array]::Reverse($TempOrdinal)
                    $Ordinal = ''
                    $TempOrdinal | ForEach-Object { $Ordinal += $_ }
                    $Result['Ordinal'] = "0x$Ordinal"
                    $Result['FunctionName'] = ''
                }
                else
                {
                    $ImportByNamePtr = [IntPtr] ($PEBaseAddr.ToInt64() + [Int64]$ThunkData.AddressOfData + 2)
                    if ($OnDisk) { $ImportByNamePtr = Convert-RVAToFileOffset $ImportByNamePtr }
                    $FuncName = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi($ImportByNamePtr)
                    $Result['Ordinal'] = ''
                    $Result['FunctionName'] = $FuncName
                }
                
                $Result['RVA'] = "0x$($FuncAddr.AddressOfData.ToString("X$($BinaryPtrWidth*2)"))"

                if ($FuncAddr.AddressOfData -eq 0) { break }
                if ($OFTPtr -eq 0) { break }
                
                $Import = New-Object PSObject -Property $Result
                $Import.PSObject.TypeNames.Insert(0, 'Import')
                
                $Import
                
                $j++
                
            }
            
            $i++
            
        }

    }
    
    function Convert-RVAToFileOffset([IntPtr] $Rva)
    {
    
        foreach ($Section in $SectionHeaders) {
            if ((($Rva.ToInt64() - $PEBaseAddr.ToInt64()) -ge $Section.VirtualAddress) -and (($Rva.ToInt64() - $PEBaseAddr.ToInt64()) -lt ($Section.VirtualAddress + $Section.VirtualSize))) {
                return [IntPtr] ($Rva.ToInt64() - ($Section.VirtualAddress - $Section.PointerToRawData))
            }
        }
        
        # Pointer did not fall in the address ranges of the section headers
        return $Rva
        
    }
    
    $PEFields = @{
        Module = $ModuleName
        DOSHeader = $DosHeader
        PESignature = $NTHeader.Signature
        FileHeader = $NTHeader.FileHeader
        OptionalHeader = $NTHeader.OptionalHeader
        SectionHeaders = $SectionHeaders
        Imports = Get-Imports
        Exports = Get-Exports
    }
    
    if ($Ondisk) {
        $Handle.Free()
    } else {
        # Free memory allocated for the PE header
        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($PEBaseAddr)
    }
    
    $PEHeader = New-Object PSObject -Property $PEFields
    $PEHeader.PSObject.TypeNames.Insert(0, 'PEHeader')

    $ScriptBlock = {
        $SymServerURL = 'http://msdl.microsoft.com/download/symbols'
        $FileName = $this.Module.Split('\')[-1]
        $Request = "{0}/{1}/{2:X8}{3:X}/{1}" -f $SymServerURL, $FileName, $this.FileHeader.TimeDateStamp, $this.OptionalHeader.SizeOfImage
        $Request = "$($Request.Substring(0, $Request.Length - 1))_"
        $WebClient = New-Object Net.WebClient
        $WebClient.Headers.Add('User-Agent', 'Microsoft-Symbol-Server/6.6.0007.5')
        Write-Host "Downloading $FileName from the Microsoft symbol server..."
        $CabBytes = $WebClient.DownloadData($Request)
        $CabPath = "$PWD\$($FileName.Split('.')[0]).cab"
        Write-Host "Download complete. Saving it to $("$(Split-Path $CabPath)\$FileName")."
        [IO.File]::WriteAllBytes($CabPath, $CabBytes)
        $Shell = New-Object -Comobject Shell.Application
        $CabFile = $Shell.Namespace($CabPath).Items()
        $Destination = $Shell.Namespace((Split-Path $CabPath))
        $Destination.CopyHere($CabFile)
        Remove-Item $CabPath -Force
    }

    $PEHeader = Add-Member -InputObject $PEHeader -MemberType ScriptMethod -Name DownloadFromMSSymbolServer -Value $ScriptBlock -PassThru -Force

    return $PEHeader
    
}

}