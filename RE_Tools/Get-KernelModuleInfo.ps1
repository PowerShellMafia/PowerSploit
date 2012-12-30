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
    $FormatPath = try { Join-Path $PSScriptRoot Get-KernelModuleInfo.format.ps1xml } catch {}
    # Don't load format ps1xml if it doesn't live in the same folder as this script
    if ($FormatPath -and (Test-Path $FormatPath))
    {
       Update-FormatData -PrependPath (Join-Path $PSScriptRoot Get-KernelModuleInfo.format.ps1xml)
    }

    $Domain = [AppDomain]::CurrentDomain
    $DynAssembly = New-Object System.Reflection.AssemblyName('TestAssembly')
    $AssemblyBuilder = $Domain.DefineDynamicAssembly($DynAssembly, [System.Reflection.Emit.AssemblyBuilderAccess]::Run)
    $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule('TestModule', $False)

    $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
    $TypeBuilder = $ModuleBuilder.DefineType('_SYSTEM_MODULE64', $Attributes, [System.ValueType], 1, 296)
    $TypeBuilder32 = $ModuleBuilder.DefineType('_SYSTEM_MODULE32', $Attributes, [System.ValueType], 1, 284)

    $TypeBuilder.DefineField('Reserved1', [UInt32], 'Public') | Out-Null
    $TypeBuilder.DefineField('Reserved2', [UInt32], 'Public') | Out-Null
    $TypeBuilder.DefineField('ImageBaseAddress', [UInt64], 'Public') | Out-Null
    $TypeBuilder.DefineField('ImageSize', [UInt32], 'Public') | Out-Null
    $TypeBuilder.DefineField('Flags', [UInt32], 'Public') | Out-Null
    $TypeBuilder.DefineField('Id', [UInt16], 'Public') | Out-Null
    $TypeBuilder.DefineField('Rank', [UInt16], 'Public') | Out-Null
    $TypeBuilder.DefineField('w018', [UInt16], 'Public') | Out-Null
    $TypeBuilder.DefineField('NameOffset', [UInt16], 'Public') | Out-Null
    $NameField = $TypeBuilder.DefineField('Name', [String], 'Public, HasFieldMarshal')

    $ConstructorInfo = [System.Runtime.InteropServices.MarshalAsAttribute].GetConstructors()[0]
    $ConstructorValue = [System.Runtime.InteropServices.UnmanagedType]::ByValTStr
    $FieldArray = @([System.Runtime.InteropServices.MarshalAsAttribute].GetField('SizeConst'))
    $AttribBuilder = New-Object System.Reflection.Emit.CustomAttributeBuilder($ConstructorInfo, $ConstructorValue, $FieldArray, @([Int32] 256))
    $NameField.SetCustomAttribute($AttribBuilder)

    $SystemModule64Type = $TypeBuilder.CreateType()

    $TypeBuilder32.DefineField('Reserved1', [UInt16], 'Public') | Out-Null
    $TypeBuilder32.DefineField('Reserved2', [UInt16], 'Public') | Out-Null
    $TypeBuilder32.DefineField('ImageBaseAddress', [UInt32], 'Public') | Out-Null
    $TypeBuilder32.DefineField('ImageSize', [UInt32], 'Public') | Out-Null
    $TypeBuilder32.DefineField('Flags', [UInt32], 'Public') | Out-Null
    $TypeBuilder32.DefineField('Id', [UInt16], 'Public') | Out-Null
    $TypeBuilder32.DefineField('Rank', [UInt16], 'Public') | Out-Null
    $TypeBuilder32.DefineField('w018', [UInt16], 'Public') | Out-Null
    $TypeBuilder32.DefineField('NameOffset', [UInt16], 'Public') | Out-Null
    $NameField = $TypeBuilder32.DefineField('Name', [String], 'Public, HasFieldMarshal')
    $NameField.SetCustomAttribute($AttribBuilder)

    $SystemModule32Type = $TypeBuilder32.CreateType()

    function Local:Get-DelegateType
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

    function Local:Get-ProcAddress
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

    $NtQuerySystemInformationAddr = Get-ProcAddress ntdll.dll NtQuerySystemInformation
    $NtQuerySystemInformationDelegate = Get-DelegateType @([UInt32], [IntPtr], [UInt32], [UInt32].MakeByRefType()) ([Int32])
    $NtQuerySystemInformation = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($NtQuerySystemInformationAddr, $NtQuerySystemInformationDelegate)

    # $TotalLength represents the total size of the returned structures. This will be used to allocate sufficient memory to store each returned structure.
    $TotalLength = 0

    # Call NtQuerySystemInformation first to get the total size of the structures to be returned.
    $NtQuerySystemInformation.Invoke(11, [IntPtr]::Zero, 0, [Ref] $TotalLength) | Out-Null

    $PtrSystemInformation = [Runtime.InteropServices.Marshal]::AllocHGlobal($TotalLength)

    $Result = $NtQuerySystemInformation.Invoke(11, $PtrSystemInformation, $TotalLength, [Ref] 0)

    if ($Result -ne 0)
    {
        Throw "An error occured. (NTSTATUS: 0x$($Result.ToString('X8')))"
    }

    if ([IntPtr]::Size -eq 8)
    {
        $SystemModuleType = $SystemModule64Type
        $StructSize = 296
        $PtrModule = [IntPtr]($PtrSystemInformation.ToInt64() + 16)
    }
    else
    {
        $SystemModuleType = $SystemModule32Type
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

        if ($SystemModule.NameOffset -ne 0 -and $SystemModule.ImageSize -ne 0)
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
                Name = $SystemModule.Name -replace '\\SystemRoot', $Env:SystemRoot
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