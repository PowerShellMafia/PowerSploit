function Get-KernelModuleInfo
{
<#
.SYNOPSIS

Returns loaded kernel module information.

PowerSploit Module - Get-KernelModuleInfo
Author: Matthew Graeber (@mattifestation)
License: BSD 3-Clause
 
.DESCRIPTION

Get-KernelModuleInfo wraps NtQuerySystemInformation and returns loaded kernel module information. Get-KernelModuleInfo works on both x86 and x86_64 platforms.

.EXAMPLE

C:\PS> Get-KernelModuleInfo

ImageBaseAddress   ImageSize  Flags      Id     Rank   W018   NameOffset Name
----------------   ---------  -----      --     ----   ----   ---------- ----
0xFFFFF800FF200000 0x00749000 0x08804000 0x0000 0x0000 0x0083 0x0015     C:\Windows\system32\ntoskrnl.exe
0xFFFFF800FF949000 0x0006C000 0x08804000 0x0001 0x0000 0x0027 0x0015     C:\Windows\system32\hal.dll
0xFFFFF88000C93000 0x0005F000 0x09104000 0x0003 0x0000 0x0001 0x0015     C:\Windows\system32\mcupdate_GenuineIntel.dll
0xFFFFF88000D71000 0x00015000 0x0D104000 0x0006 0x0000 0x0003 0x0015     C:\Windows\system32\PSHED.dll
0xFFFFF8800101A000 0x000C2000 0x09104000 0x000A 0x0000 0x0001 0x001D     C:\Windows\system32\drivers\Wdf01000.sys
0xFFFFF8800117B000 0x0000A000 0x0D104000 0x000F 0x0000 0x0011 0x001D     C:\Windows\System32\drivers\WMILIB.SYS
0xFFFFF88000F5C000 0x00017000 0x09104000 0x0015 0x0000 0x0001 0x001D     C:\Windows\system32\drivers\pdc.sys
0xFFFFF880011CC000 0x0001A000 0x09104000 0x001C 0x0000 0x0001 0x001D     C:\Windows\System32\drivers\mountmgr.sys
0xFFFFF88001600000 0x0001B000 0x09104000 0x0024 0x0000 0x0015 0x001D     C:\Windows\System32\Drivers\ksecdd.sys
0xFFFFF88001C00000 0x00076000 0x09104000 0x002D 0x0000 0x0001 0x001D     C:\Windows\System32\DRIVERS\fvevol.sys
0xFFFFF88003CCD000 0x0000E000 0x4D104000 0x0042 0x0000 0x0007 0x001D     C:\Windows\system32\DRIVERS\TDI.SYS
0xFFFFF88004200000 0x0001E000 0x49104000 0x005B 0x0000 0x0001 0x001D     C:\Windows\system32\DRIVERS\rassstp.sys
0xFFFFF88005400000 0x0007B000 0x4D104000 0x0069 0x0000 0x0001 0x001D     C:\Windows\System32\drivers\USBPORT.SYS
0xFFFFF88006598000 0x0000A000 0x49104000 0x0078 0x0000 0x0001 0x001D     C:\Windows\System32\drivers\wmiacpi.sys
0xFFFFF880069EB000 0x0000D000 0x49104000 0x0088 0x0000 0x0002 0x001D     C:\Windows\System32\Drivers\dump_diskdump.sys
0xFFFFF88019542000 0x0004B000 0x49104000 0x0099 0x0000 0x0001 0x001D     C:\Windows\system32\DRIVERS\mrxsmb10.sys
0xFFFFF880194C7000 0x0000B000 0x49104000 0x00AB 0x0000 0x0001 0x001D     C:\Windows\System32\drivers\WpdUpFltr.sys

.NOTES

To display the output as seen in the example, ensure that Get-KernelModuleInfo.format.ps1xml resides in the same directory as Get-KernelModuleInfo.ps1.

.LINK

http://www.exploit-monday.com/
#>

    # Load custom object formatting views
    $FormatPath = Join-Path $PSScriptRoot Get-KernelModuleInfo.format.ps1xml
    # Don't load format ps1xml if it doesn't live in the same folder as this script
    if (Test-Path $FormatPath)
    {
       Update-FormatData -PrependPath (Join-Path $PSScriptRoot Get-KernelModuleInfo.format.ps1xml)
    }

    $PinvokeCode = @"
        using System;
        using System.Runtime.InteropServices;

        public class Ntdll
        {
            [Flags]
            public enum _SYSTEM_INFORMATION_CLASS : uint
            {
                SystemModuleInformation = 11,
                SystemHandleInformation = 16
            }
            
            [StructLayout(LayoutKind.Sequential, Pack=1)]
            public struct _SYSTEM_MODULE32
            {
                public ushort              Reserved1;
                public ushort              Reserved2;
                public uint                ImageBaseAddress;
                public uint                ImageSize;
                public uint                Flags;
                public ushort              Id;
                public ushort              Rank;
                public ushort              w018;
                public ushort              NameOffset;
                [MarshalAsAttribute(UnmanagedType.ByValArray, SizeConst=256)]
                public byte[]              Name;
            }

            [StructLayout(LayoutKind.Sequential, Pack=1)]
            public struct _SYSTEM_MODULE64
            {
                public uint                Reserved1;
                public uint                Reserved2;
                public ulong               ImageBaseAddress;
                public uint                ImageSize;
                public uint                Flags;
                public ushort              Id;
                public ushort              Rank;
                public ushort              w018;
                public ushort              NameOffset;
                [MarshalAsAttribute(UnmanagedType.ByValArray, SizeConst=256)]
                public byte[]              Name;
            }
           
            [StructLayout(LayoutKind.Sequential, Pack=1)]
            public struct _SYSTEM_MODULE_INFORMATION
            {
                public uint ModulesCount;
            }
           
            [DllImport("ntdll.dll", CharSet=CharSet.Auto, SetLastError=true)]
            public static extern uint NtQuerySystemInformation(uint InfoType, IntPtr lpStructure, uint StructSize, ref uint returnLength);
        }
"@

    # Returns a string from a byte array
    function Local:Get-String([Byte[]] $Bytes)
    {
        $Char = $Bytes[0]
        $StringArray = New-Object Byte[](0)

        for ($i = 0; $Char -ne 0; $i++)
        {
            $StringArray += $Char; $Char = $Bytes[$i]
        }

        Write-Output (($StringArray | % {[Char] $_}) -join '')
    }

    $CompilerParams = New-Object System.CodeDom.Compiler.CompilerParameters
    $CompilerParams.ReferencedAssemblies.AddRange(@("System.dll", [PsObject].Assembly.Location))
    $CompilerParams.GenerateInMemory = $True
    try { Add-Type -TypeDefinition $PinvokeCode -CompilerParameters $CompilerParams -PassThru | Out-Null } catch {}

    # $TotalLength represents the total size of the returned structures. This will be used to allocate sufficient memory to store each returned structure.
    $TotalLength = 0

    # Call NtQuerySystemInformation first to get the total size of the structures to be returned.
    [Ntdll]::NtQuerySystemInformation([Ntdll+_SYSTEM_INFORMATION_CLASS]::SystemModuleInformation, [IntPtr]::Zero, 0, [Ref] $TotalLength) | Out-Null

    $PtrSystemInformation = [Runtime.InteropServices.Marshal]::AllocHGlobal($TotalLength)

    $Result = [Ntdll]::NtQuerySystemInformation([Ntdll+_SYSTEM_INFORMATION_CLASS]::SystemModuleInformation, $PtrSystemInformation, $TotalLength, [Ref] 0)

    if ($Result -ne 0)
    {
        Throw "An error occured. (NTSTATUS: 0x$($Result.ToString('X8')))"
    }

    if ([IntPtr]::Size -eq 8)
    {
        $SystemModuleType = [Ntdll+_SYSTEM_MODULE64]
        $StructSize = 296
        $PtrModule = [IntPtr]($PtrSystemInformation.ToInt64() + 16)
    }
    else
    {
        $SystemModuleType = [Ntdll+_SYSTEM_MODULE32]
        $StructSize = 284
        $PtrModule = [IntPtr]($PtrSystemInformation.ToInt64() + 8)
    }

    $i = 0
    $AnotherModule = $True

    # Loop through all the returned _SYSTEM_MODULE structs
    while ($AnotherModule) {
        # Move pointer to the next structure
        $PtrModule = [IntPtr] ($PtrModule.ToInt64() + ($i * $StructSize))
        # Cast the next struct in memory to type _SYSTEM_MODULE[32|64]
        $SystemModule = [Runtime.InteropServices.Marshal]::PtrToStructure($PtrModule, [Type] $SystemModuleType)

        if ($SystemModule.Name[0] -ne 0)
        {
            $ModuleInfo = @{
                ImageBaseAddress = $SystemModule.ImageBaseAddress
                ImageSize = $SystemModule.ImageSize
                Flags = $SystemModule.Flags
                Id = $SystemModule.Id
                Rank = $SystemModule.Rank
                w018 = $SystemModule.w018
                NameOffset = $SystemModule.NameOffset
                # Get the full path to the driver and expand SystemRoot in the path
                Name = (Get-String $SystemModule.Name) -replace '\\\\SystemRoot', $Env:SystemRoot
            }

            $Module = New-Object PSObject -Property $ModuleInfo
            $Module.PSObject.TypeNames[0] = 'SystemInformation.SYSTEM_MODULE'

            Write-Output $Module
        }
        else
        {
            # No more modules to iterate through
            $AnotherModule = $False
        }

        $i++
    }

    # Free the unmanaged memory used to store the structures
    [Runtime.InteropServices.Marshal]::FreeHGlobal($PtrSystemInformation)
}