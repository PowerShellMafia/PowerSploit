function Get-PEB
{
<#
.SYNOPSIS

Returns the process environment block (PEB) of a process.

PowerSploit Function: Get-PEB
Author: Matthew Graeber (@mattifestation)
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: Get-PEB.format.ps1xml
 
.DESCRIPTION

Get-PEB returns a fully parsed process environment block (PEB) of any process. Because the PEB and its underlying structure differ according to OS version and architecture, Get-PEB builds the PEB dynamically at runtime. Get-PEB is designed to work in Windows XP - Windows 8 32/64-bit. It will also return the PEB of Wow64 processes.

.PARAMETER Id

The process ID of the process whose PEB will be retrieved.

.EXAMPLE

C:\PS> $AllPEBs = Get-Process | Get-PEB

Description
-----------
Get the PEB of every process. Note: To get the PEBs for all processes, run this command from an elevated instance of PowerShell

.EXAMPLE

C:\PS> $NotepadPEB = Get-PEB -Id (ps notepad)
C:\PS> $NotepadPEB.InInitializationOrderModuleList

Description
-----------
Display all loaded modules of the notepad process in initialization order.

.NOTES

Some processes will not issue a handle unless you are running Get-PEB from an elevated instance of PowerShell.

.LINK

http://www.exploit-monday.com/2013/01/Get-PEB.html
http://msdn.microsoft.com/en-us/library/windows/desktop/aa813706(v=vs.85).aspx
#>

    [CmdletBinding()] Param (
        [Parameter(Position = 0, Mandatory = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('PID')]
        [UInt16[]]
        $Id
    )

    BEGIN
    {
        Set-StrictMode -Version 2

        $mscorlib = [AppDomain]::CurrentDomain.GetAssemblies() | ? { $_.FullName.Split(',')[0].ToLower() -eq 'mscorlib' }
        $Win32Native = $mscorlib.GetTypes() | ? { $_.FullName -eq 'Microsoft.Win32.Win32Native' }

        if ($Win32Native -eq $null)
        {
            throw 'Unable to get a reference to type: Microsoft.Win32.Win32Native'
        }

        function Local:Get-NTStatusException
        {
            [CmdletBinding()] Param (
                [Parameter(Position = 0, Mandatory = $True, ValueFromPipeline = $True)]
                [Int32[]]
                $ErrorCode
            )

            BEGIN
            {
                $LsaNtStatusToWinError = $Win32Native.GetMethod('LsaNtStatusToWinError', [Reflection.BindingFlags] 'NonPublic, Static')
                $GetMessage = $Win32Native.GetMethod('GetMessage', [Reflection.BindingFlags] 'NonPublic, Static')
            }
            PROCESS
            {
                foreach ($Error in $ErrorCode)
                {
                    $WinErrorCode = $LsaNtStatusToWinError.Invoke($null, @($ErrorCode))

                    Write-Output $GetMessage.Invoke($null, @($WinErrorCode))
                }
            }
            END{}
        }

        # The return value from Get-WindowsNTDDIVersion will be compared against these values to determine the structure of the PEB.
        $NTDDI_VISTA = 0x06000000
        $NTDDI_WS03 = 0x05020000
        $NTDDI_WINXP = 0x05010000

        function Local:Get-WindowsNTDDIVersion
        {
            # Return Windows version information as NTDDI_VERSION as defined in SdkDdkVer.h
            # This will aid in determining version specific PEB fields to return
            # Could this be accomplished with `Get-WmiObject Win32_OperatingSystem`? Yes, but I prefer not rely upon services that might be turned off.
            $OSVersionInfoEx = $Win32Native.GetNestedTypes('NonPublic') | ? { $_.FullName -eq 'Microsoft.Win32.Win32Native+OSVERSIONINFOEX' }

            if ($OSVersionInfoEx -eq $null)
            {
                Write-Error "Unable to get a reference to kernel32!OSVersionInfoEx."
                return
            }

            $MajorVersion = $OSVersionInfoEx.GetField('MajorVersion', [Reflection.BindingFlags] 'NonPublic, Instance')
            $MinorVersion = $OSVersionInfoEx.GetField('MinorVersion', [Reflection.BindingFlags] 'NonPublic, Instance')
            $ServicePackMajor = $OSVersionInfoEx.GetField('ServicePackMajor', [Reflection.BindingFlags] 'NonPublic, Instance')
            $ServicePackMinor = $OSVersionInfoEx.GetField('ServicePackMinor', [Reflection.BindingFlags] 'NonPublic, Instance')
            $ProductTypeField = $OSVersionInfoEx.GetField('ProductType', [Reflection.BindingFlags] 'NonPublic, Instance')

            $OSVersionInfoContructor = $OSVersionInfoEx.GetConstructors()[0]
            $OSVersionEx = $OSVersionInfoContructor.Invoke($null)
            # This version is present in .NET 2
            $GetVersionEx = $Win32Native.GetMethod('GetVersionEx', [Reflection.BindingFlags] 'NonPublic, Static', $null, @($OSVersionInfoEx), $null)
            if ($GetVersionEx -eq $null)
            {
                # This version is present in .NET 4
                $GetVersionEx = [Environment].GetMethod('GetVersionEx', [Reflection.BindingFlags] 'NonPublic, Static', $null, @($OSVersionInfoEx), $null)
            }
            if ($GetVersionEx -eq $null)
            {
                Write-Error "Unable to get a reference to GetVersionEx method."
                return
            }
            $Success = $GetVersionEx.Invoke($null, @($OSVersionEx))

            if (-not $Success)
            {
                Write-Error ([ComponentModel.Win32Exception][Runtime.InteropServices.Marshal]::GetLastWin32Error())
                return
            }

            # Build the version string
            $Version = [Int32] "0x$($MajorVersion.GetValue($OSVersionEx).ToString('D2'))$($MinorVersion.GetValue($OSVersionEx).ToString('D2'))$($ServicePackMajor.GetValue($OSVersionEx).ToString('D2'))$($ServicePackMinor.GetValue($OSVersionEx).ToString('D2'))"
            $ProductType = $ProductTypeField.GetValue($OSVersionEx)

            if ($Version -lt $NTDDI_WINXP)
            {
                throw 'Could not determine the correct Windows version! Windows ME, Windows 3.1, and OS/2 Warp are not supported. :P'
            }

            Write-Output $Version
        }

        $NTDDI_VERSION = Get-WindowsNTDDIVersion

        try { $NativeMethods = @([AppDomain]::CurrentDomain.GetAssemblies() | % { $_.GetTypes() } | ? { $_.FullName -eq 'Microsoft.Win32.NativeMethods' })[0] } catch {}
        $NtProcessBasicInfo = $NativeMethods.GetNestedType('NtProcessBasicInfo', [Reflection.BindingFlags]::NonPublic)
        $NtProcessBasicInfoConstructor = $NtProcessBasicInfo.GetConstructors()[0]
        $ProcessBasicInfo = $NtProcessBasicInfoConstructor.Invoke($null)

        $GetProcessHandle = [Diagnostics.Process].GetMethod('GetProcessHandle', [Reflection.BindingFlags] 'NonPublic, Instance', $null, @([Int]), $null)
        $PROCESS_QUERY_INFORMATION = 0x400
        $PROCESS_VM_READ = 0x0010

        # Sanity check to make sure that we can proceed. Without proper references, a call to NtQueryInformationProcess will crash PowerShell.
        if ($ProcessBasicInfo -eq $null)
        {
            Write-Error "Unable to get a reference to ProcessBasicInfo."
            return
        }

        $MEMORY_BASIC_INFORMATION = $Win32Native.GetNestedType('MEMORY_BASIC_INFORMATION', [Reflection.BindingFlags] 'NonPublic')

        if ($MEMORY_BASIC_INFORMATION -eq $null)
        {
            Write-Error 'Unable to get a reference to the MEMORY_BASIC_INFORMATION structure.'
            return
        }

        $OSArchitecture = [Int](Get-WmiObject Win32_OperatingSystem).OSArchitecture.Split('-')[0]

        try { $NativeUtils = [NativeUtils] } catch [Management.Automation.RuntimeException] # Only build the assembly if it hasn't already been defined
        {
            $DynAssembly = New-Object Reflection.AssemblyName('MemHacker')
            $AssemblyBuilder = [AppDomain]::CurrentDomain.DefineDynamicAssembly($DynAssembly, [Reflection.Emit.AssemblyBuilderAccess]::Run)
            $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule('MemHacker', $False)
            $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
            $TypeBuilder = $ModuleBuilder.DefineType('NativeUtils', $Attributes, [ValueType])
            $TypeBuilder.DefinePInvokeMethod('ReadProcessMemory', 'kernel32.dll', [Reflection.MethodAttributes] 'Public, Static', [Reflection.CallingConventions]::Standard, [Bool], @([IntPtr], [IntPtr], [IntPtr], [UInt32], [UInt32].MakeByRefType()), [Runtime.InteropServices.CallingConvention]::Winapi, 'Auto') | Out-Null
            $TypeBuilder.DefinePInvokeMethod('VirtualQueryEx', 'kernel32.dll', [Reflection.MethodAttributes] 'Public, Static', [Reflection.CallingConventions]::Standard, [UInt32], @([IntPtr], [IntPtr], $MEMORY_BASIC_INFORMATION.MakeByRefType(), [UInt32]), [Runtime.InteropServices.CallingConvention]::Winapi, 'Auto') | Out-Null
            if ($OSArchitecture -eq 64)
            {
                $TypeBuilder.DefinePInvokeMethod('IsWow64Process', 'kernel32.dll', [Reflection.MethodAttributes] 'Public, Static', [Reflection.CallingConventions]::Standard, [Bool], @([IntPtr], [Bool].MakeByRefType()), [Runtime.InteropServices.CallingConvention]::Winapi, 'Auto') | Out-Null
            }
            $TypeBuilder.DefinePInvokeMethod('NtQueryInformationProcess', 'ntdll.dll', [Reflection.MethodAttributes] 'Public, Static', [Reflection.CallingConventions]::Standard, [UInt32], @([IntPtr], [Int], $NtProcessBasicInfo, [Int], [IntPtr]), [Runtime.InteropServices.CallingConvention]::Winapi, 'Auto') | Out-Null
            $NativeUtils = $TypeBuilder.CreateType()
        }

        #region Determine OS/Process/PowerShell bitness

        # Get PowerShell's bit-ness accordingly to [IntPtr]::Size. The bitness of PowerShell is used as the basis for determining
        # the bitness of the processes you're interested in. For example, calling Get-Process from 32-bit PowerShell will only
        # return 32-bit processes. Get-Process on 64-bit PowerShell however will return 64-bit and Wow64 processes.
        if ([IntPtr]::Size -eq 4)
        {
            $PowerShellArchitecture = 32
        }
        else
        {
            $PowerShellArchitecture = 64
        }
        #endregion

        #region Build PEB structure dynamically
        try
        {
            $PEBStruct = [_PEB]
            $UnicodeStringStruct = [_UNICODE_STRING]
            $ProcessParametersStruct = [_RTL_USER_PROCESS_PARAMETERS]
            $ListEntryStruct = [_LIST_ENTRY]
            $LdrDataStruct = [_PEB_LDR_DATA]
            $BalancedNodeStruct = [_RTL_BALANCED_NODE]
            $LoadReasonEnum = [_LDR_DLL_LOAD_REASON]
            $LdrModuleStruct = [_LDR_DATA_TABLE_ENTRY]
        }
        catch
        {
            # Note: Once this strcuture is built, it cannot be rebuilt or unloaded without restarting PowerShell
            $DynAssembly = New-Object Reflection.AssemblyName('PEBTools')
            $AssemblyBuilder = [AppDomain]::CurrentDomain.DefineDynamicAssembly($DynAssembly, [Reflection.Emit.AssemblyBuilderAccess]::Run)
            $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule('PEBModule', $False)
            $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
            $TypeBuilder = $ModuleBuilder.DefineType('_PEB', $Attributes, [ValueType])

            $ConstructorInfo = [Runtime.InteropServices.MarshalAsAttribute].GetConstructors()[0]
            $ConstructorValue = [Runtime.InteropServices.UnmanagedType]::ByValArray
            $FieldArray = @([Runtime.InteropServices.MarshalAsAttribute].GetField('SizeConst'))

            # Build type for _UNICODE_STRING
            $UnicodeTypeBuilder = $ModuleBuilder.DefineType('_UNICODE_STRING', $Attributes, [ValueType])
            $UnicodeTypeBuilder.DefineField('Length', [UInt16], 'Public') | Out-Null
            $UnicodeTypeBuilder.DefineField('MaximumLength', [UInt16], 'Public') | Out-Null
            $UnicodeTypeBuilder.DefineField('Buffer', [IntPtr], 'Public') | Out-Null
            $UnicodeStringStruct = $UnicodeTypeBuilder.CreateType()

            # Build type for _RTL_USER_PROCESS_PARAMETERS
            $ProcParamTypeBuilder = $ModuleBuilder.DefineType('_RTL_USER_PROCESS_PARAMETERS', $Attributes, [ValueType], 4)
            $ProcParamTypeBuilder.DefineField('MaximumLength', [UInt32], 'Public') | Out-Null
            $ProcParamTypeBuilder.DefineField('Length', [UInt32], 'Public') | Out-Null
            $ProcParamTypeBuilder.DefineField('Flags', [UInt32], 'Public') | Out-Null
            $ProcParamTypeBuilder.DefineField('DebugFlags', [UInt32], 'Public') | Out-Null
            $ProcParamTypeBuilder.DefineField('ConsoleHandle', [IntPtr], 'Public') | Out-Null
            $ProcParamTypeBuilder.DefineField('ConsoleFlags', [UInt32], 'Public') | Out-Null
            $ProcParamTypeBuilder.DefineField('StandardInput', [IntPtr], 'Public') | Out-Null
            $ProcParamTypeBuilder.DefineField('StandardOutput', [IntPtr], 'Public') | Out-Null
            $ProcParamTypeBuilder.DefineField('StandardError', [IntPtr], 'Public') | Out-Null
            $ProcParamTypeBuilder.DefineField('CurrentDirectory', $UnicodeStringStruct, 'Public') | Out-Null
            $ProcParamTypeBuilder.DefineField('CurrentDirectoryHandle', [IntPtr], 'Public') | Out-Null
            $ProcParamTypeBuilder.DefineField('DllPath', $UnicodeStringStruct, 'Public') | Out-Null
            $ProcParamTypeBuilder.DefineField('ImagePathName', $UnicodeStringStruct, 'Public') | Out-Null
            $ProcParamTypeBuilder.DefineField('CommandLine', $UnicodeStringStruct, 'Public') | Out-Null
            $ProcParamTypeBuilder.DefineField('Environment', [IntPtr], 'Public') | Out-Null
            $ProcParamTypeBuilder.DefineField('StartingX', [UInt32], 'Public') | Out-Null
            $ProcParamTypeBuilder.DefineField('StartingY', [UInt32], 'Public') | Out-Null
            $ProcParamTypeBuilder.DefineField('CountX', [UInt32], 'Public') | Out-Null
            $ProcParamTypeBuilder.DefineField('CountY', [UInt32], 'Public') | Out-Null
            $ProcParamTypeBuilder.DefineField('CountCharsX', [UInt32], 'Public') | Out-Null
            $ProcParamTypeBuilder.DefineField('CountCharsY', [UInt32], 'Public') | Out-Null
            $ProcParamTypeBuilder.DefineField('FillAttribute', [UInt32], 'Public') | Out-Null
            $ProcParamTypeBuilder.DefineField('WindowFlags', [UInt32], 'Public') | Out-Null
            $ProcParamTypeBuilder.DefineField('ShowWindowFlags', [UInt32], 'Public') | Out-Null
            $ProcParamTypeBuilder.DefineField('WindowTitle', $UnicodeStringStruct, 'Public') | Out-Null
            $ProcParamTypeBuilder.DefineField('DesktopInfo', $UnicodeStringStruct, 'Public') | Out-Null
            $ProcParamTypeBuilder.DefineField('ShellInfo', $UnicodeStringStruct, 'Public') | Out-Null
            $ProcParamTypeBuilder.DefineField('RuntimeData', $UnicodeStringStruct, 'Public') | Out-Null
            $ProcessParametersStruct = $ProcParamTypeBuilder.CreateType()

            # Build type for _LIST_ENTRY
            $ListEntryTypeBuilder = $ModuleBuilder.DefineType('_LIST_ENTRY', $Attributes, [System.ValueType])
            $ListEntryTypeBuilder.DefineField('Flink', [IntPtr], 'Public') | Out-Null
            $ListEntryTypeBuilder.DefineField('Blink', [IntPtr], 'Public') | Out-Null
            $ListEntryStruct = $ListEntryTypeBuilder.CreateType()

            # Build type for _PEB_LDR_DATA
            $PEBLdrDataTypeBuilder = $ModuleBuilder.DefineType('_PEB_LDR_DATA', $Attributes, [System.ValueType])
            $PEBLdrDataTypeBuilder.DefineField('Length', [UInt32], 'Public') | Out-Null
            $InitializedField = $PEBLdrDataTypeBuilder.DefineField('Initialized', [Byte[]], 'Public')
            $AttribBuilder = New-Object Reflection.Emit.CustomAttributeBuilder($ConstructorInfo, $ConstructorValue, $FieldArray, @([Int32] 4))
            $InitializedField.SetCustomAttribute($AttribBuilder)
            $PEBLdrDataTypeBuilder.DefineField('SsHandle', [IntPtr], 'Public') | Out-Null
            $PEBLdrDataTypeBuilder.DefineField('InLoadOrderModuleList', [_LIST_ENTRY], 'Public') | Out-Null
            $PEBLdrDataTypeBuilder.DefineField('InMemoryOrderModuleList', [_LIST_ENTRY], 'Public') | Out-Null
            $PEBLdrDataTypeBuilder.DefineField('InInitializationOrderModuleList', [_LIST_ENTRY], 'Public') | Out-Null
            $PEBLdrDataTypeBuilder.DefineField('EntryInProgress', [IntPtr], 'Public') | Out-Null
            $ShutdownInProgressField = $PEBLdrDataTypeBuilder.DefineField('ShutdownInProgress', [Byte[]], 'Public')
            $AttribBuilder = New-Object Reflection.Emit.CustomAttributeBuilder($ConstructorInfo, $ConstructorValue, $FieldArray, @([Int32] 2))
            $ShutdownInProgressField.SetCustomAttribute($AttribBuilder)
            $PEBLdrDataTypeBuilder.DefineField('ShutdownThreadId', [IntPtr], 'Public') | Out-Null
            $LdrDataStruct = $PEBLdrDataTypeBuilder.CreateType()

            # Build type for _RTL_BALANCED_NODE
            $BalancedNodeTypeBuilder = $ModuleBuilder.DefineType('_RTL_BALANCED_NODE', $Attributes, [System.ValueType])
            $BalancedNodeTypeBuilder.DefineField('Left', [IntPtr], 'Public') | Out-Null
            $BalancedNodeTypeBuilder.DefineField('Right', [IntPtr], 'Public') | Out-Null
            if ($PowerShellArchitecture -eq 64) { $BalancedNodeTypeBuilder.DefineField('ParentValue', [UInt64], 'Public') | Out-Null }
            else { $BalancedNodeTypeBuilder.DefineField('ParentValue', [UInt32], 'Public') | Out-Null }
            $BalancedNodeStruct = $BalancedNodeTypeBuilder.CreateType()

            # Build type for _LDR_DLL_LOAD_REASON enum
            $EnumBuilder = $ModuleBuilder.DefineEnum('_LDR_DLL_LOAD_REASON', 'Public', [Int32])
            # Define values of the enum
            $EnumBuilder.DefineLiteral('StaticDependency', [Int32] 0) | Out-Null
            $EnumBuilder.DefineLiteral('StaticForwarderDependency', [Int32] 1) | Out-Null
            $EnumBuilder.DefineLiteral('DynamicForwarderDependency', [Int32] 2) | Out-Null
            $EnumBuilder.DefineLiteral('DelayloadDependency', [Int32] 3) | Out-Null
            $EnumBuilder.DefineLiteral('DynamicLoad', [Int32] 4) | Out-Null
            $EnumBuilder.DefineLiteral('AsImageLoad', [Int32] 5) | Out-Null
            $EnumBuilder.DefineLiteral('AsDataLoad', [Int32] 6) | Out-Null
            $EnumBuilder.DefineLiteral('Unknown', [Int32] -1) | Out-Null
            $LoadReasonEnum = $EnumBuilder.CreateType()

            # Build type for _LDR_DATA_TABLE_ENTRY
            $PEBLdrModuleTypeBuilder = $ModuleBuilder.DefineType('_LDR_DATA_TABLE_ENTRY', $Attributes, [System.ValueType])
            $PEBLdrModuleTypeBuilder.DefineField('InLoadOrderModuleList', [_LIST_ENTRY], 'Public') | Out-Null
            $PEBLdrModuleTypeBuilder.DefineField('InMemoryOrderModuleList', [_LIST_ENTRY], 'Public') | Out-Null
            $PEBLdrModuleTypeBuilder.DefineField('InInitializationOrderModuleList', [_LIST_ENTRY], 'Public') | Out-Null
            $PEBLdrModuleTypeBuilder.DefineField('BaseAddress', [IntPtr], 'Public') | Out-Null
            $PEBLdrModuleTypeBuilder.DefineField('EntryPoint', [IntPtr], 'Public') | Out-Null
            $PEBLdrModuleTypeBuilder.DefineField('SizeOfImage', [UInt32], 'Public') | Out-Null
            $PEBLdrModuleTypeBuilder.DefineField('FullDllName', [_UNICODE_STRING], 'Public') | Out-Null
            $PEBLdrModuleTypeBuilder.DefineField('BaseDllName', [_UNICODE_STRING], 'Public') | Out-Null
            $PEBLdrModuleTypeBuilder.DefineField('Flags', [UInt32], 'Public') | Out-Null
            $PEBLdrModuleTypeBuilder.DefineField('ObsoleteLoadCount', [UInt16], 'Public') | Out-Null
            $PEBLdrModuleTypeBuilder.DefineField('TlsIndex', [UInt16], 'Public') | Out-Null
            $PEBLdrModuleTypeBuilder.DefineField('HashLinks', [_LIST_ENTRY], 'Public') | Out-Null
            $PEBLdrModuleTypeBuilder.DefineField('TimeDateStamp', [UInt32], 'Public') | Out-Null
            $PEBLdrModuleTypeBuilder.DefineField('EntryPointActivationContext', [IntPtr], 'Public') | Out-Null
            $PEBLdrModuleTypeBuilder.DefineField('PatchInformation', [IntPtr], 'Public') | Out-Null
            $PEBLdrModuleTypeBuilder.DefineField('DdagNode', [IntPtr], 'Public') | Out-Null
            $PEBLdrModuleTypeBuilder.DefineField('NodeModuleLink', [_LIST_ENTRY], 'Public') | Out-Null
            $PEBLdrModuleTypeBuilder.DefineField('SnapContext', [IntPtr], 'Public') | Out-Null
            $PEBLdrModuleTypeBuilder.DefineField('ParentDllBase', [IntPtr], 'Public') | Out-Null
            $PEBLdrModuleTypeBuilder.DefineField('SwitchBackContext', [IntPtr], 'Public') | Out-Null
            $PEBLdrModuleTypeBuilder.DefineField('BaseAddressIndexNode', [_RTL_BALANCED_NODE], 'Public') | Out-Null
            $PEBLdrModuleTypeBuilder.DefineField('MappingInfoIndexNode', [_RTL_BALANCED_NODE], 'Public') | Out-Null
            if ($PowerShellArchitecture -eq 64) { $PEBLdrModuleTypeBuilder.DefineField('OriginalBase', [UInt64], 'Public') | Out-Null }
            else { $PEBLdrModuleTypeBuilder.DefineField('OriginalBase', [UInt32], 'Public') | Out-Null }
            $PEBLdrModuleTypeBuilder.DefineField('LoadTime', [UInt64], 'Public') | Out-Null
            $PEBLdrModuleTypeBuilder.DefineField('BaseNameHashValue', [UInt32], 'Public') | Out-Null
            $PEBLdrModuleTypeBuilder.DefineField('LoadReason', [_LDR_DLL_LOAD_REASON], 'Public') | Out-Null
            $LdrModuleStruct = $PEBLdrModuleTypeBuilder.CreateType()

            $TypeBuilder.DefineField('InheritedAddressSpace', [Byte], 'Public') | Out-Null
            $TypeBuilder.DefineField('ReadImageFileExecOptions', [Byte], 'Public') | Out-Null
            $TypeBuilder.DefineField('BeingDebugged', [Byte], 'Public') | Out-Null
            $TypeBuilder.DefineField('BitField', [Byte], 'Public') | Out-Null
            if ($PowerShellArchitecture -eq 64) { $TypeBuilder.DefineField('Reserved3', [UInt32], 'Public, HasFieldMarshal') | Out-Null }
            $TypeBuilder.DefineField('Mutant', [IntPtr], 'Public') | Out-Null
            $TypeBuilder.DefineField('ImageBaseAddress', [IntPtr], 'Public') | Out-Null
            $TypeBuilder.DefineField('Ldr', [IntPtr], 'Public') | Out-Null
            $TypeBuilder.DefineField('ProcessParameters', [IntPtr], 'Public') | Out-Null
            $TypeBuilder.DefineField('SubSystemData', [IntPtr], 'Public') | Out-Null
            $TypeBuilder.DefineField('ProcessHeap', [IntPtr], 'Public') | Out-Null
            $TypeBuilder.DefineField('FastPebLock', [IntPtr], 'Public') | Out-Null

            if ($NTDDI_VERSION -ge $NTDDI_VISTA)
            {
                $TypeBuilder.DefineField('AtlThunkSListPtr', [IntPtr], 'Public') | Out-Null
                $TypeBuilder.DefineField('IFEOKey', [IntPtr], 'Public') | Out-Null
                if ($PowerShellArchitecture -eq 64) { $TypeBuilder.DefineField('CrossProcessFlags', [UInt64], 'Public') | Out-Null
                } else { $TypeBuilder.DefineField('CrossProcessFlags', [UInt32], 'Public') | Out-Null }
                $TypeBuilder.DefineField('KernelCallbackTable', [IntPtr], 'Public') | Out-Null
            }
            elseif ($NTDDI_VERSION -ge $NTDDI_WS03)
            {
                $TypeBuilder.DefineField('AtlThunkSListPtr', [IntPtr], 'Public') | Out-Null
                $TypeBuilder.DefineField('SparePtr2', [IntPtr], 'Public') | Out-Null
                $TypeBuilder.DefineField('EnvironmentUpdateCount', [UInt32], 'Public') | Out-Null
                $TypeBuilder.DefineField('KernelCallbackTable', [IntPtr], 'Public') | Out-Null
            }
            else
            {
                $TypeBuilder.DefineField('FastPebLockRoutine', [IntPtr], 'Public') | Out-Null
                $TypeBuilder.DefineField('FastPebUnlockRoutine', [IntPtr], 'Public') | Out-Null
                $TypeBuilder.DefineField('EnvironmentUpdateCount', [UInt32], 'Public') | Out-Null
                $TypeBuilder.DefineField('KernelCallbackTable', [IntPtr], 'Public') | Out-Null
            }
            $TypeBuilder.DefineField('SystemReserved', [UInt32], 'Public') | Out-Null
            $TypeBuilder.DefineField('AtlThunkSListPtr32', [UInt32], 'Public') | Out-Null
            $TypeBuilder.DefineField('ApiSetMap', [IntPtr], 'Public') | Out-Null
            $TypeBuilder.DefineField('TlsExpansionCounter', [UInt32], 'Public') | Out-Null
            $TypeBuilder.DefineField('TlsBitmap', [IntPtr], 'Public') | Out-Null
            $TlsBitmapBitsField = $TypeBuilder.DefineField('TlsBitmapBits', [UInt32[]], 'Public, HasFieldMarshal')
            $AttribBuilder = New-Object Reflection.Emit.CustomAttributeBuilder($ConstructorInfo, $ConstructorValue, $FieldArray, @([Int32] 2))
            $TlsBitmapBitsField.SetCustomAttribute($AttribBuilder)
            $TypeBuilder.DefineField('ReadOnlySharedMemoryBase', [IntPtr], 'Public') | Out-Null
            if ($NTDDI_VERSION -ge $NTDDI_VISTA)
            {
                $TypeBuilder.DefineField('HotpatchInformation', [IntPtr], 'Public') | Out-Null
            }
            else
            {
                $TypeBuilder.DefineField('ReadOnlySharedMemoryHeap', [IntPtr], 'Public') | Out-Null
            }
            $TypeBuilder.DefineField('ReadOnlyStaticServerData', [IntPtr], 'Public') | Out-Null
            $TypeBuilder.DefineField('AnsiCodePageData', [IntPtr], 'Public') | Out-Null
            $TypeBuilder.DefineField('OemCodePageData', [IntPtr], 'Public') | Out-Null
            $TypeBuilder.DefineField('UnicodeCaseTableData', [IntPtr], 'Public') | Out-Null
            $TypeBuilder.DefineField('NumberOfProcessors', [UInt32], 'Public') | Out-Null
            $TypeBuilder.DefineField('NtGlobalFlag', [UInt32], 'Public') | Out-Null
            $TypeBuilder.DefineField('CriticalSectionTimeout', [Int64], 'Public') | Out-Null
            if ($PowerShellArchitecture -eq 64)
            {
                $TypeBuilder.DefineField('HeapSegmentReserve', [UInt64], 'Public') | Out-Null
                $TypeBuilder.DefineField('HeapSegmentCommit', [UInt64], 'Public') | Out-Null
            }
            else
            {
                $TypeBuilder.DefineField('HeapSegmentReserve', [UInt32], 'Public') | Out-Null
                $TypeBuilder.DefineField('HeapSegmentCommit', [UInt32], 'Public') | Out-Null
            }
            $TypeBuilder.DefineField('HeapDeCommitTotalFreeThreshold', [IntPtr], 'Public') | Out-Null
            $TypeBuilder.DefineField('HeapDeCommitFreeBlockThreshold', [IntPtr], 'Public') | Out-Null
            $TypeBuilder.DefineField('NumberOfHeaps', [UInt32], 'Public') | Out-Null
            $TypeBuilder.DefineField('MaximumNumberOfHeaps', [UInt32], 'Public') | Out-Null
            $TypeBuilder.DefineField('ProcessHeaps', [IntPtr], 'Public') | Out-Null
            $TypeBuilder.DefineField('GdiSharedHandleTable', [IntPtr], 'Public') | Out-Null
            $TypeBuilder.DefineField('ProcessStarterHelper', [IntPtr], 'Public') | Out-Null
            $TypeBuilder.DefineField('GdiDCAttributeList', [UInt32], 'Public') | Out-Null
            $TypeBuilder.DefineField('LoaderLock', [IntPtr], 'Public') | Out-Null
            $TypeBuilder.DefineField('OSMajorVersion', [UInt32], 'Public') | Out-Null
            $TypeBuilder.DefineField('OSMinorVersion', [UInt32], 'Public') | Out-Null
            $TypeBuilder.DefineField('OSBuildNumber', [UInt16], 'Public') | Out-Null
            $TypeBuilder.DefineField('OSCSDVersion', [UInt16], 'Public') | Out-Null
            $TypeBuilder.DefineField('OSPlatformId', [UInt32], 'Public') | Out-Null
            $TypeBuilder.DefineField('ImageSubsystem', [UInt32], 'Public') | Out-Null
            $TypeBuilder.DefineField('ImageSubsystemMajorVersion', [UInt32], 'Public') | Out-Null
            $TypeBuilder.DefineField('ImageSubsystemMinorVersion', [UInt32], 'Public') | Out-Null
            $TypeBuilder.DefineField('ActiveProcessAffinityMask', [IntPtr], 'Public') | Out-Null
            $GdiHandleBufferField = $TypeBuilder.DefineField('GdiHandleBuffer', [UInt32[]], 'Public, HasFieldMarshal')
            if ($PowerShellArchitecture -eq 64) { $GDI_HANDLE_BUFFER_SIZE = 60 } else { $GDI_HANDLE_BUFFER_SIZE = 34 }
            $AttribBuilder = New-Object Reflection.Emit.CustomAttributeBuilder($ConstructorInfo, $ConstructorValue, $FieldArray, @([Int32] $GDI_HANDLE_BUFFER_SIZE))
            $GdiHandleBufferField.SetCustomAttribute($AttribBuilder)
            $TypeBuilder.DefineField('PostProcessInitRoutine', [IntPtr], 'Public') | Out-Null
            $TypeBuilder.DefineField('TlsExpansionBitmap', [IntPtr], 'Public') | Out-Null
            $TlsExpansionBitmapBitsField = $TypeBuilder.DefineField('TlsExpansionBitmapBits', [UInt32[]], 'Public, HasFieldMarshal')
            $AttribBuilder = New-Object Reflection.Emit.CustomAttributeBuilder($ConstructorInfo, $ConstructorValue, $FieldArray, @([Int32] 32))
            $TlsExpansionBitmapBitsField.SetCustomAttribute($AttribBuilder)
            $TypeBuilder.DefineField('SessionId', [UInt32], 'Public') | Out-Null

            if ($NTDDI_VERSION -ge $NTDDI_WINXP)
            {
                $TypeBuilder.DefineField('AppCompatFlags', [UInt64], 'Public') | Out-Null
                $TypeBuilder.DefineField('AppCompatFlagsUser', [UInt64], 'Public') | Out-Null
                $TypeBuilder.DefineField('pShimData', [IntPtr], 'Public') | Out-Null
                $TypeBuilder.DefineField('AppCompatInfo', [UInt32], 'Public') | Out-Null
                $TypeBuilder.DefineField('CSDVersion', [_UNICODE_STRING], 'Public') | Out-Null
                $TypeBuilder.DefineField('ActivationContextData', [IntPtr], 'Public') | Out-Null
                $TypeBuilder.DefineField('ProcessAssemblyStorageMap', [IntPtr], 'Public') | Out-Null
                $TypeBuilder.DefineField('SystemDefaultActivationContextData', [IntPtr], 'Public') | Out-Null
                $TypeBuilder.DefineField('SystemAssemblyStorageMap', [IntPtr], 'Public') | Out-Null
                if ($PowerShellArchitecture -eq 64) { $TypeBuilder.DefineField('MinimumStackCommit', [UInt64], 'Public') | Out-Null
                } else { $TypeBuilder.DefineField('MinimumStackCommit', [UInt32], 'Public') | Out-Null }
            }
            if ($NTDDI_VERSION -ge $NTDDI_WS03)
            {
                $TypeBuilder.DefineField('FlsCallback', [IntPtr], 'Public') | Out-Null
                $TypeBuilder.DefineField('FlsListHead', [_LIST_ENTRY], 'Public') | Out-Null
                $TypeBuilder.DefineField('FlsBitmap', [IntPtr], 'Public') | Out-Null
                $FlsBitmapBitsField = $TypeBuilder.DefineField('FlsBitmapBits', [UInt32[]], 'Public')
                $AttribBuilder = New-Object Reflection.Emit.CustomAttributeBuilder($ConstructorInfo, $ConstructorValue, $FieldArray, @([Int32] 4))
                $FlsBitmapBitsField.SetCustomAttribute($AttribBuilder)
                $TypeBuilder.DefineField('FlsHighIndex', [UInt32], 'Public') | Out-Null
            }
            if ($NTDDI_VERSION -ge $NTDDI_VISTA)
            {
                $TypeBuilder.DefineField('WerRegistrationData', [IntPtr], 'Public') | Out-Null
                $TypeBuilder.DefineField('WerShipAssertPtr', [IntPtr], 'Public') | Out-Null
                $TypeBuilder.DefineField('pUnused', [IntPtr], 'Public') | Out-Null
                $TypeBuilder.DefineField('pImageHeaderHash', [IntPtr], 'Public') | Out-Null
                $TypeBuilder.DefineField('TracingFlags', [UInt32], 'Public') | Out-Null
                $TypeBuilder.DefineField('CsrServerReadOnlySharedMemoryBase', [UInt64], 'Public') | Out-Null
            }

            $PEBStruct = $TypeBuilder.CreateType()
        }

        $PEBSize = [Runtime.InteropServices.Marshal]::SizeOf($PEBStruct)
        #endregion

        function Local:Get-StructFromMemory
        {
            [CmdletBinding()] Param (
                [Parameter(Position = 0, Mandatory = $True)]
                [Alias('ProcessId')]
                [UInt16]
                $ProcId,

                [Parameter(Position = 1, Mandatory = $True)]
                [IntPtr]
                $MemoryAddress,

                [Parameter(Position = 2, Mandatory = $True)]
                [Alias('Type')]
                [Type]
                $StructType,

                [ValidateSet('InLoadOrderModuleList','InMemoryOrderModuleList','InInitializationOrderModuleList')]
                [String]
                $LoadOrder,

                [UInt16]
                $UnicodeStringSize
            )

            if (($StructType -eq [String]) -and ($MemoryAddress -eq 0)) { Write-Output ''; return }
            elseif ($MemoryAddress -eq 0) { Write-Output $null; return }

            $PROCESS_VM_READ = 0x0010 # The process permissions we'l ask for when getting a handle to the process

            $GetProcessHandle = [Diagnostics.Process].GetMethod('GetProcessHandle', [Reflection.BindingFlags] 'NonPublic, Instance', $null, @([Int]), $null)

            try
            {
                $Process = Get-Process -Id $ProcId -ErrorVariable GetProcessError
                $Handle = $Process.Handle
            }
            catch [Exception]
            {
                Write-Error $GetProcessError
                return
            }

            if ($Handle -eq $null)
            {
                Write-Error "Unable to obtain a handle for PID $ProcId. You will likely need to run this script elevated."
                return
            }

            $ProtectField = $MEMORY_BASIC_INFORMATION.GetField('Protect', [Reflection.BindingFlags] 'NonPublic, Instance')
            $AllocationBaseField = $MEMORY_BASIC_INFORMATION.GetField('BaseAddress', [Reflection.BindingFlags] 'NonPublic, Instance')
            $RegionSizeField = $MEMORY_BASIC_INFORMATION.GetField('RegionSize', [Reflection.BindingFlags] 'NonPublic, Instance')

            try
            {
                $SafeHandle = $GetProcessHandle.Invoke($Process, @($PROCESS_VM_READ))
                $Handle = $SafeHandle.DangerousGetHandle()
            }
            catch
            {
                Write-Error $Error[0]
                return
            }

            $PAGE_EXECUTE_READ = 0x20
            $PAGE_EXECUTE_READWRITE = 0x40
            $PAGE_READONLY = 2
            $PAGE_READWRITE = 4

            if ($StructType -eq $LdrModuleStruct -and $LoadOrder)
            {
                $OriginalFlink = $MemoryAddress
                $Flink = $OriginalFlink

                do
                {
                    $MemoryBasicInformation = [Activator]::CreateInstance($MEMORY_BASIC_INFORMATION)
                    $NativeUtils::VirtualQueryEx($Handle, $Flink, [Ref] $MemoryBasicInformation, [Runtime.InteropServices.Marshal]::SizeOf($MEMORY_BASIC_INFORMATION)) | Out-Null

                    $Protection = $ProtectField.GetValue($MemoryBasicInformation)
                    $AllocationBaseOriginal = $AllocationBaseField.GetValue($MemoryBasicInformation)
                    $GetPointerValue = $AllocationBaseOriginal.GetType().GetMethod('GetPointerValue', [Reflection.BindingFlags] 'NonPublic, Instance')
                    $AllocationBase = $GetPointerValue.Invoke($AllocationBaseOriginal, $null).ToInt64()
                    $RegionSize = $RegionSizeField.GetValue($MemoryBasicInformation).ToUInt64()

                    if (($Protection -ne $PAGE_READONLY) -and ($Protection -ne $PAGE_READWRITE) -and ($Protection -ne $PAGE_EXECUTE_READ) -and ($Protection -ne $PAGE_EXECUTE_READWRITE))
                    {
                        $SafeHandle.Close()
                        Write-Error 'The address specified does not have read access.'
                        return
                    }

                    $StructSize = [Runtime.InteropServices.Marshal]::SizeOf($LdrModuleStruct)
                    $EndOfAllocation = $AllocationBase + $RegionSize
                    $EndOfStruct = $MemoryAddress.ToInt64() + $StructSize

                    if ($EndOfStruct -gt $EndOfAllocation)
                    {
                        $SafeHandle.Close()
                        Write-Error 'You are attempting to read beyond what was allocated.'
                        return
                    }

                    try
                    {
                        $LocalStructPtr = [Runtime.InteropServices.Marshal]::AllocHGlobal($StructSize)
                    }
                    catch [OutOfMemoryException]
                    {
                        Write-Error $Error[0]
                        return
                    }

                    $ZeroBytes = New-Object Byte[]($StructSize)
                    [Runtime.InteropServices.Marshal]::Copy($ZeroBytes, 0, $LocalStructPtr, $StructSize)

                    $BytesRead = [UInt32] 0

                    if ($NativeUtils::ReadProcessMemory($Handle, $Flink, $LocalStructPtr, $StructSize, [Ref] $BytesRead))
                    {
                        $SafeHandle.Close()
                        [Runtime.InteropServices.Marshal]::FreeHGlobal($LocalStructPtr)
                        Write-Error ([ComponentModel.Win32Exception][Runtime.InteropServices.Marshal]::GetLastWin32Error())
                        return
                    }

                    $ParsedLdrModule = [Runtime.InteropServices.Marshal]::PtrToStructure($LocalStructPtr, $LdrModuleStruct)

                    [Runtime.InteropServices.Marshal]::FreeHGlobal($LocalStructPtr)

                    switch ($LoadOrder)
                    {
                        'InLoadOrderModuleList' { $Flink = $ParsedLdrModule.InLoadOrderModuleList.Flink }
                        'InMemoryOrderModuleList' { $Flink = [IntPtr] ($ParsedLdrModule.InMemoryOrderModuleList.Flink.ToInt64() - [Runtime.InteropServices.Marshal]::SizeOf($ListEntryStruct)) }
                        'InInitializationOrderModuleList' { $Flink = [IntPtr] ($ParsedLdrModule.InInitializationOrderModuleList.Flink.ToInt64() - (2 * [Runtime.InteropServices.Marshal]::SizeOf($ListEntryStruct))) }
                    }

                    $SafeHandle = $GetProcessHandle.Invoke($Process, @($PROCESS_VM_READ))
                    $Handle = $SafeHandle.DangerousGetHandle()

                    if ($ParsedLdrModule.SizeOfImage)
                    {
                        Write-Output $ParsedLdrModule
                    }
                } while (($Flink -ne 0) -and ($Flink -ne $OriginalFlink))

                $SafeHandle.Close()
            }
            elseif ($StructType -eq [String] -and $UnicodeStringSize)
            {
                $MemoryBasicInformation = [Activator]::CreateInstance($MEMORY_BASIC_INFORMATION)
                $NativeUtils::VirtualQueryEx($Handle, $MemoryAddress, [Ref] $MemoryBasicInformation, [Runtime.InteropServices.Marshal]::SizeOf($MEMORY_BASIC_INFORMATION)) | Out-Null

                $Protection = $ProtectField.GetValue($MemoryBasicInformation)
                $AllocationBaseOriginal = $AllocationBaseField.GetValue($MemoryBasicInformation)
                $GetPointerValue = $AllocationBaseOriginal.GetType().GetMethod('GetPointerValue', [Reflection.BindingFlags] 'NonPublic, Instance')
                $AllocationBase = $GetPointerValue.Invoke($AllocationBaseOriginal, $null).ToInt64()
                $RegionSize = $RegionSizeField.GetValue($MemoryBasicInformation).ToUInt64()

                if (($Protection -ne $PAGE_READONLY) -and ($Protection -ne $PAGE_READWRITE) -and ($Protection -ne $PAGE_EXECUTE_READ) -and ($Protection -ne $PAGE_EXECUTE_READWRITE))
                {
                    $SafeHandle.Close()
                    Write-Error 'The address specified does not have read access.'
                    return
                }

                $StructSize = $UnicodeStringSize
                $EndOfAllocation = $AllocationBase + $RegionSize
                $EndOfStruct = $MemoryAddress.ToInt64() + $StructSize

                if ($EndOfStruct -gt $EndOfAllocation)
                {
                    $SafeHandle.Close()
                    Write-Error 'You are attempting to read beyond what was allocated.'
                    return
                }

                try
                {
                    $LocalStructPtr = [Runtime.InteropServices.Marshal]::AllocHGlobal($StructSize)
                }
                catch [OutOfMemoryException]
                {
                    Write-Error $Error[0]
                    return
                }

                $ZeroBytes = New-Object Byte[]($StructSize)
                [Runtime.InteropServices.Marshal]::Copy($ZeroBytes, 0, $LocalStructPtr, $StructSize)

                $BytesRead = [UInt32] 0

                if ($NativeUtils::ReadProcessMemory($Handle, $MemoryAddress, $LocalStructPtr, $StructSize, [Ref] $BytesRead))
                {
                    $SafeHandle.Close()
                    [Runtime.InteropServices.Marshal]::FreeHGlobal($LocalStructPtr)
                    Write-Error ([ComponentModel.Win32Exception][Runtime.InteropServices.Marshal]::GetLastWin32Error())
                    return
                }

                $ParsedStruct = [Runtime.InteropServices.Marshal]::PtrToStringUni($LocalStructPtr)

                [Runtime.InteropServices.Marshal]::FreeHGlobal($LocalStructPtr)
                $SafeHandle.Close()

                Write-Output $ParsedStruct
            }
            else
            {
                $MemoryBasicInformation = [Activator]::CreateInstance($MEMORY_BASIC_INFORMATION)
                $NativeUtils::VirtualQueryEx($Handle, $MemoryAddress, [Ref] $MemoryBasicInformation, [Runtime.InteropServices.Marshal]::SizeOf($MEMORY_BASIC_INFORMATION)) | Out-Null

                $Protection = $ProtectField.GetValue($MemoryBasicInformation)
                $AllocationBaseOriginal = $AllocationBaseField.GetValue($MemoryBasicInformation)
                $GetPointerValue = $AllocationBaseOriginal.GetType().GetMethod('GetPointerValue', [Reflection.BindingFlags] 'NonPublic, Instance')
                $AllocationBase = $GetPointerValue.Invoke($AllocationBaseOriginal, $null).ToInt64()
                $RegionSize = $RegionSizeField.GetValue($MemoryBasicInformation).ToUInt64()

                if (($Protection -ne $PAGE_READONLY) -and ($Protection -ne $PAGE_READWRITE) -and ($Protection -ne $PAGE_EXECUTE_READ) -and ($Protection -ne $PAGE_EXECUTE_READWRITE))
                {
                    $SafeHandle.Close()
                    Write-Error 'The address specified does not have read access.'
                    return
                }

                $StructSize = [Runtime.InteropServices.Marshal]::SizeOf($StructType)
                $EndOfAllocation = $AllocationBase + $RegionSize
                $EndOfStruct = $MemoryAddress.ToInt64() + $StructSize

                if ($EndOfStruct -gt $EndOfAllocation)
                {
                    $SafeHandle.Close()
                    Write-Error 'You are attempting to read beyond what was allocated.'
                    return
                }

                try
                {
                    $LocalStructPtr = [Runtime.InteropServices.Marshal]::AllocHGlobal($StructSize)
                }
                catch [OutOfMemoryException]
                {
                    Write-Error $Error[0]
                    return
                }

                $ZeroBytes = New-Object Byte[]($StructSize)
                [Runtime.InteropServices.Marshal]::Copy($ZeroBytes, 0, $LocalStructPtr, $StructSize)

                $BytesRead = [UInt32] 0

                if ($NativeUtils::ReadProcessMemory($Handle, $MemoryAddress, $LocalStructPtr, $StructSize, [Ref] $BytesRead))
                {
                    $SafeHandle.Close()
                    [Runtime.InteropServices.Marshal]::FreeHGlobal($LocalStructPtr)
                    Write-Error ([ComponentModel.Win32Exception][Runtime.InteropServices.Marshal]::GetLastWin32Error())
                    return
                }

                $ParsedStruct = [Runtime.InteropServices.Marshal]::PtrToStructure($LocalStructPtr, $StructType)

                [Runtime.InteropServices.Marshal]::FreeHGlobal($LocalStructPtr)
                $SafeHandle.Close()

                Write-Output $ParsedStruct
            }
        }
    }

    PROCESS
    {
        foreach ($ProcessId in $Id)
        {
            $Handle = $null

            try
            {
                $Process = Get-Process -Id $ProcessId -ErrorVariable GetProcessError
                # Get the process handle
                $Handle = $Process.Handle
            }
            catch { }

            if ($Handle -eq $null)
            {
                Write-Error "Unable to obtain a handle for PID $ProcessId. You will likely need to run this script elevated."
            }
            else
            {
                $SafeHandle = $GetProcessHandle.Invoke($Process, @($PROCESS_QUERY_INFORMATION -bor $PROCESS_VM_READ))
                $Handle = $SafeHandle.DangerousGetHandle()

                Write-Verbose "ProcessName: $($Process.ProcessName)"
                Write-Verbose "Handle: $Handle"

                if ($OSArchitecture -eq 64)
                {
                    $IsWow64 = $False
                    $NativeUtils::IsWow64Process($Handle, [Ref] $IsWow64) | Out-Null

                    if ($PowerShellArchitecture -eq 32 -and (-not $IsWow64))
                    {
                        $SafeHandle.Close()
                        Write-Error 'Cannot get the PEB of a 64-bit process from a Wow64 process. Use 64-bit PowerShell and try again.'
                        return
                    }
                }

                $ProcessBasicInfo = $NtProcessBasicInfoConstructor.Invoke($null)

                $Status = $NativeUtils::NtQueryInformationProcess($Handle, 0, $ProcessBasicInfo, [Runtime.InteropServices.Marshal]::SizeOf($ProcessBasicInfo), [IntPtr]::Zero)

                Write-Verbose 'ProcessBasicInfo:'
                Write-Verbose ($ProcessBasicInfo | Out-String)

                if ($Status -ne 0)
                {
                    $SafeHandle.Close()
                    Write-Error (Get-NTStatusException $Status)
                    return
                }

                $SafeHandle.Close()

                $PEB = Get-StructFromMemory -ProcId $ProcessId -MemoryAddress ($ProcessBasicInfo.PebBaseAddress) -StructType ($PEBStruct)

                $ProcessParams = Get-StructFromMemory -ProcId $ProcessId -MemoryAddress ($PEB.ProcessParameters) -StructType ($ProcessParametersStruct)
                
                $CurrentDirectory = ''
                $DllPath = ''
                $ImagePathName = ''
                $CommandLine = ''
                $WindowTitle = ''
                $DesktopInfo = ''
                $ShellInfo = ''
                $RuntimeData = ''

                if ($ProcessParams.CurrentDirectory.Buffer) { $CurrentDirectory = Get-StructFromMemory -ProcId $ProcessId -MemoryAddress ($ProcessParams.CurrentDirectory.Buffer) -StructType ([String]) -UnicodeStringSize ($ProcessParams.CurrentDirectory.MaximumLength) }
                if ($ProcessParams.DllPath.Buffer) { $DllPath = Get-StructFromMemory -ProcId $ProcessId -MemoryAddress ($ProcessParams.DllPath.Buffer) -StructType ([String]) -UnicodeStringSize ($ProcessParams.DllPath.MaximumLength) } else { $DllPath = '' }
                if ($ProcessParams.ImagePathName.Buffer) { $ImagePathName = Get-StructFromMemory -ProcId $ProcessId -MemoryAddress ($ProcessParams.ImagePathName.Buffer) -StructType ([String]) -UnicodeStringSize ($ProcessParams.ImagePathName.MaximumLength) }
                if ($ProcessParams.CommandLine.Buffer) { $CommandLine = Get-StructFromMemory -ProcId $ProcessId -MemoryAddress ($ProcessParams.CommandLine.Buffer) -StructType ([String]) -UnicodeStringSize ($ProcessParams.CommandLine.MaximumLength) }
                if ($ProcessParams.WindowTitle.Buffer) { $WindowTitle = Get-StructFromMemory -ProcId $ProcessId -MemoryAddress ($ProcessParams.WindowTitle.Buffer) -StructType ([String]) -UnicodeStringSize ($ProcessParams.WindowTitle.MaximumLength) }
                if ($ProcessParams.DesktopInfo.Buffer) { $DesktopInfo = Get-StructFromMemory -ProcId $ProcessId -MemoryAddress ($ProcessParams.DesktopInfo.Buffer) -StructType ([String]) -UnicodeStringSize ($ProcessParams.DesktopInfo.MaximumLength) }
                if ($ProcessParams.ShellInfo.Buffer) { $ShellInfo = Get-StructFromMemory -ProcId $ProcessId -MemoryAddress ($ProcessParams.ShellInfo.Buffer) -StructType ([String]) -UnicodeStringSize ($ProcessParams.ShellInfo.MaximumLength) }
                if ($ProcessParams.RuntimeData.Buffer) { $RuntimeData = Get-StructFromMemory -ProcId $ProcessId -MemoryAddress ($ProcessParams.RuntimeData.Buffer) -StructType ([String]) -UnicodeStringSize ($ProcessParams.RuntimeData.MaximumLength) }
                
                $ProcessParameters = @{
                    MaximumLength = $ProcessParams.MaximumLength
                    Length = $ProcessParams.Length
                    Flags = $ProcessParams.Flags
                    DebugFlags = $ProcessParams.DebugFlags
                    ConsoleHandle = $ProcessParams.ConsoleHandle
                    ConsoleFlags = $ProcessParams.ConsoleFlags
                    StandardInput = $ProcessParams.StandardInput
                    StandardOutput = $ProcessParams.StandardOutput
                    StandardError = $ProcessParams.StandardError
                    CurrentDirectory = $CurrentDirectory
                    DllPath = $DllPath
                    ImagePathName = $ImagePathName
                    CommandLine = $CommandLine
                    Environment = $ProcessParams.Environment
                    StartingX = $ProcessParams.StartingX
                    StartingY = $ProcessParams.StartingY
                    CountX = $ProcessParams.CountX
                    CountY = $ProcessParams.CountY
                    CountCharsX = $ProcessParams.CountCharsX
                    CountCharsY = $ProcessParams.CountCharsY
                    FillAttribute = $ProcessParams.FillAttribute
                    WindowFlags = $ProcessParams.WindowFlags
                    ShowWindowFlags = $ProcessParams.ShowWindowFlags
                    WindowTitle = $WindowTitle
                    DesktopInfo = $DesktopInfo
                    ShellInfo = $ShellInfo
                    RuntimeData = $RuntimeData
                }

                $ProcessParamsParsed = New-Object PSObject -Property $ProcessParameters
                $ProcessParamsParsed.PSObject.TypeNames[0] = 'PEB.ProcessParameters'

                # Get custom objects for the PEB based upon OS version
                # First, build up the custom object with fields common amongst all versions of the PEB
                $CustomPEB = @{
                    ProcessName = $Process.ProcessName
                    ProcessId = $ProcessId
                    InheritedAddressSpace = if($PEB.InheritedAddressSpace -eq 0){$False}else{$True}
                    ReadImageFileExecOptions = if($PEB.ReadImageFileExecOptions -eq 0){$False}else{$True}
                    BeingDebugged = if($PEB.BeingDebugged -eq 0){$False}else{$True}
                    Mutant = $PEB.Mutant
                    ImageBaseAddress = $PEB.ImageBaseAddress
                    Ldr = Get-StructFromMemory -ProcId $ProcessId -MemoryAddress ($PEB.Ldr) -StructType ($LdrDataStruct)
                    ProcessParameters = $ProcessParamsParsed
                    SubSystemData = $PEB.SubSystemData
                    ProcessHeap = $PEB.ProcessHeap
                    FastPebLock = $PEB.FastPebLock
                    SystemReserved = $PEB.SystemReserved
                    AtlThunkSListPtr32 = $PEB.AtlThunkSListPtr32
                    ApiSetMap = $PEB.ApiSetMap
                    TlsExpansionCounter = $PEB.TlsExpansionCounter
                    TlsBitmap = $PEB.TlsBitmap
                    TlsBitmapBits = $PEB.TlsBitmapBits
                    ReadOnlySharedMemoryBase = $PEB.ReadOnlySharedMemoryBase
                    ReadOnlyStaticServerData = $PEB.ReadOnlyStaticServerData
                    AnsiCodePageData = $PEB.AnsiCodePageData
                    OemCodePageData = $PEB.OemCodePageData
                    UnicodeCaseTableData = $PEB.UnicodeCaseTableData
                    NumberOfProcessors = $PEB.NumberOfProcessors
                    NtGlobalFlag = $PEB.NtGlobalFlag
                    CriticalSectionTimeout = $PEB.CriticalSectionTimeout
                    HeapSegmentReserve = $PEB.HeapSegmentReserve
                    HeapSegmentCommit = $PEB.HeapSegmentCommit
                    HeapDeCommitTotalFreeThreshold = $PEB.HeapDeCommitTotalFreeThreshold
                    HeapDeCommitFreeBlockThreshold = $PEB.HeapDeCommitFreeBlockThreshold
                    NumberOfHeaps = $PEB.NumberOfHeaps
                    MaximumNumberOfHeaps = $PEB.MaximumNumberOfHeaps
                    ProcessHeaps = $PEB.ProcessHeaps
                    GdiSharedHandleTable = $PEB.GdiSharedHandleTable
                    ProcessStarterHelper = $PEB.ProcessStarterHelper
                    GdiDCAttributeList = $PEB.GdiDCAttributeList
                    LoaderLock = $PEB.LoaderLock
                    OSMajorVersion = $PEB.OSMajorVersion
                    OSMinorVersion = $PEB.OSMinorVersion
                    OSBuildNumber = $PEB.OSBuildNumber
                    OSCSDVersion = $PEB.OSCSDVersion
                    OSPlatformId = $PEB.OSPlatformId
                    ImageSubsystem = $PEB.ImageSubsystem
                    ImageSubsystemMajorVersion = $PEB.ImageSubsystemMajorVersion
                    ImageSubsystemMinorVersion = $PEB.ImageSubsystemMinorVersion
                    ActiveProcessAffinityMask = $PEB.ActiveProcessAffinityMask
                    GdiHandleBuffer = $PEB.GdiHandleBuffer
                    PostProcessInitRoutine = $PEB.PostProcessInitRoutine
                    TlsExpansionBitmap = $PEB.TlsExpansionBitmap
                    TlsExpansionBitmapBits = $PEB.TlsExpansionBitmapBits
                    SessionId = $PEB.SessionId
                    AppCompatFlags = $PEB.AppCompatFlags
                    AppCompatFlagsUser = $PEB.AppCompatFlagsUser
                    pShimData = $PEB.pShimData
                    AppCompatInfo = $PEB.AppCompatInfo
                    CSDVersion = Get-StructFromMemory -ProcId $ProcessId -MemoryAddress ($PEB.CSDVersion.Buffer) -StructType ([String]) -UnicodeStringSize ($PEB.CSDVersion.MaximumLength)
                    ActivationContextData = $PEB.ActivationContextData
                    ProcessAssemblyStorageMap = $PEB.ProcessAssemblyStorageMap
                    SystemDefaultActivationContextData = $PEB.SystemDefaultActivationContextData
                    SystemAssemblyStorageMap = $PEB.SystemAssemblyStorageMap
                    MinimumStackCommit = $PEB.MinimumStackCommit
                }

                foreach ($j in 1..3)
                {
                    switch ($j)
                    {
                        1 { $OrderedModules = Get-StructFromMemory -ProcId $ProcessId -MemoryAddress ($CustomPEB['Ldr'].InLoadOrderModuleList.Flink) -StructType ($LdrModuleStruct) -LoadOrder 'InLoadOrderModuleList' }
                        2 { $OrderedModules = Get-StructFromMemory -ProcId $ProcessId -MemoryAddress ([IntPtr] ($CustomPEB['Ldr'].InMemoryOrderModuleList.Flink.ToInt64() - [Runtime.InteropServices.Marshal]::SizeOf($ListEntryStruct))) -StructType ($LdrModuleStruct) -LoadOrder 'InMemoryOrderModuleList' }
                        3 { $OrderedModules = Get-StructFromMemory -ProcId $ProcessId -MemoryAddress ([IntPtr] ($CustomPEB['Ldr'].InInitializationOrderModuleList.Flink.ToInt64() - (2 * [Runtime.InteropServices.Marshal]::SizeOf($ListEntryStruct)))) -StructType ($LdrModuleStruct) -LoadOrder 'InInitializationOrderModuleList' }
                    }

                    $ParsedOrderedModules = New-Object Hashtable[]($OrderedModules.Length)
                    $Modules = New-Object PSObject[]($OrderedModules.Length)

                    $i = 0
                    foreach ($Module in $OrderedModules)
                    {
                        $ParsedOrderedModules[$i] = @{
                            InLoadOrderModuleList = $Module.InLoadOrderModuleList
                            InMemoryOrderModuleList = $Module.InMemoryOrderModuleList
                            InInitializationOrderModuleList = $Module.InInitializationOrderModuleList
                            BaseAddress = $Module.BaseAddress
                            EntryPoint = $Module.EntryPoint
                            SizeOfImage = $Module.SizeOfImage
                            FullDllName = Get-StructFromMemory -ProcId $ProcessId -MemoryAddress ($Module.FullDllName.Buffer) -StructType ([String]) -UnicodeStringSize ($Module.FullDllName.MaximumLength)
                            BaseDllName = Get-StructFromMemory -ProcId $ProcessId -MemoryAddress ($Module.BaseDllName.Buffer) -StructType ([String]) -UnicodeStringSize ($Module.BaseDllName.MaximumLength)
                            PackagedBinary = if(($Module.Flags -band 1) -eq 0){$False}else{$True}
                            MarkedForRemoval = if(($Module.Flags -band 2) -eq 0){$False}else{$True}
                            ImageDll = if(($Module.Flags -band 4) -eq 0){$False}else{$True}
                            LoadNotificationsSent = if(($Module.Flags -band 8) -eq 0){$False}else{$True}
                            TelemetryEntryProcessed = if(($Module.Flags -band 16) -eq 0){$False}else{$True}
                            ProcessStaticImport = if(($Module.Flags -band 32) -eq 0){$False}else{$True}
                            InLegacyLists = if(($Module.Flags -band 64) -eq 0){$False}else{$True}
                            InIndexes = if(($Module.Flags -band 128) -eq 0){$False}else{$True}
                            ShimDll = if(($Module.Flags -band 256) -eq 0){$False}else{$True}
                            InExceptionTable = if(($Module.Flags -band 512) -eq 0){$False}else{$True}
                            LoadInProgress = if(($Module.Flags -band 4096) -eq 0){$False}else{$True}
                            EntryProcessed = if(($Module.Flags -band 16384) -eq 0){$False}else{$True}
                            DontCallForThreads = if(($Module.Flags -band 262144) -eq 0){$False}else{$True}
                            ProcessAttachCalled = if(($Module.Flags -band 524288) -eq 0){$False}else{$True}
                            ProcessAttachFailed = if(($Module.Flags -band 1048576) -eq 0){$False}else{$True}
                            CorDeferredValidate = if(($Module.Flags -band 2097152) -eq 0){$False}else{$True}
                            CorImage = if(($Module.Flags -band 4194304) -eq 0){$False}else{$True}
                            DontRelocate = if(($Module.Flags -band 8388608) -eq 0){$False}else{$True}
                            CorILOnly = if(($Module.Flags -band 16777216) -eq 0){$False}else{$True}
                            Redirected = if(($Module.Flags -band 268435456) -eq 0){$False}else{$True}
                            CompatDatabaseProcessed = if(($Module.Flags -band 2147483648) -eq 0){$False}else{$True}
                            ObsoleteLoadCount = $Module.ObsoleteLoadCount
                            TlsIndex = $Module.TlsIndex
                            HashLinks = $Module.HashLinks
                            TimeDateStamp = (New-Object DateTime(1970, 1, 1, 0, 0, 0)).AddSeconds($Module.TimeDateStamp)
                            EntryPointActivationContext = $Module.EntryPointActivationContext
                            PatchInformation = $Module.PatchInformation
                            DdagNode = $Module.DdagNode
                            NodeModuleLink = $Module.NodeModuleLink
                            SnapContext = $Module.SnapContext
                            ParentDllBase = $Module.ParentDllBase
                            SwitchBackContext = $Module.SwitchBackContext
                            BaseAddressIndexNode = $Module.BaseAddressIndexNode
                            MappingInfoIndexNode = $Module.MappingInfoIndexNode
                            OriginalBase = $Module.OriginalBase
                            LoadTime = $Module.LoadTime
                            BaseNameHashValue = $Module.BaseNameHashValue
                            LoadReason = $Module.LoadReason
                        }

                        $CustomModuleObject = New-Object PSObject -Property $ParsedOrderedModules[$i]
                        $CustomModuleObject.PSObject.TypeNames[0] = 'PEB.ModuleEntry'
                        $Modules[$i] = $CustomModuleObject

                        $i++
                    }

                    switch ($j)
                    {
                        1 { $CustomPEB['InLoadOrderModuleList'] = $Modules }
                        2 { $CustomPEB['InMemoryOrderModuleList'] = $Modules }
                        3 { $CustomPEB['InInitializationOrderModuleList'] = $Modules }
                    }
                }

                if ($NTDDI_VERSION -ge $NTDDI_VISTA)
                {
                    $CustomPEB['ImageUsesLargePages'] = if(($PEB.BitField -band 1) -eq 0){$False}else{$True}
                    $CustomPEB['IsProtectedProcess'] = if(($PEB.BitField -band 2) -eq 0){$False}else{$True}
                    $CustomPEB['IsLegacyProcess'] = if(($PEB.BitField -band 4) -eq 0){$False}else{$True}
                    $CustomPEB['IsImageDynamicallyRelocated'] = if(($PEB.BitField -band 8) -eq 0){$False}else{$True}
                    $CustomPEB['SkipPatchingUser32Forwarders'] = if(($PEB.BitField -band 16) -eq 0){$False}else{$True}
                    $CustomPEB['IsPackagedProcess'] = if(($PEB.BitField -band 32) -eq 0){$False}else{$True}
                    $CustomPEB['IsAppContainer'] = if(($PEB.BitField -band 64) -eq 0){$False}else{$True}
                    $CustomPEB['AtlThunkSListPtr'] = $PEB.AtlThunkSListPtr
                    $CustomPEB['IFEOKey'] = $PEB.IFEOKey
                    $CustomPEB['ProcessInJob'] = if(($PEB.CrossProcessFlags -band 1) -eq 0){$False}else{$True}
                    $CustomPEB['ProcessInitializing'] = if(($PEB.CrossProcessFlags -band 2) -eq 0){$False}else{$True}
                    $CustomPEB['ProcessUsingVEH'] = if(($PEB.CrossProcessFlags -band 4) -eq 0){$False}else{$True}
                    $CustomPEB['ProcessUsingVCH'] = if(($PEB.CrossProcessFlags -band 8) -eq 0){$False}else{$True}
                    $CustomPEB['ProcessUsingFTH'] = if(($PEB.CrossProcessFlags -band 16) -eq 0){$False}else{$True}
                    $CustomPEB['KernelCallbackTable'] = $PEB.KernelCallbackTable
                    $CustomPEB['HotpatchInformation'] = $PEB.HotpatchInformation
                    $CustomPEB['FlsCallback'] = $PEB.FlsCallback
                    $CustomPEB['FlsListHead'] = $PEB.FlsListHead
                    $CustomPEB['FlsBitmap'] = $PEB.FlsBitmap
                    $CustomPEB['FlsBitmapBits'] = $PEB.FlsBitmapBits
                    $CustomPEB['FlsHighIndex'] = $PEB.FlsHighIndex
                    $CustomPEB['WerRegistrationData'] = $PEB.WerRegistrationData
                    $CustomPEB['WerShipAssertPtr'] = $PEB.WerShipAssertPtr
                    $CustomPEB['pUnused'] = $PEB.pUnused
                    $CustomPEB['pImageHeaderHash'] = $PEB.pImageHeaderHash
                    $CustomPEB['HeapTracingEnabled'] = if(($PEB.TracingFlags -band 1) -eq 0){$False}else{$True}
                    $CustomPEB['CritSecTracingEnabled'] = if(($PEB.TracingFlags -band 2) -eq 0){$False}else{$True}
                    $CustomPEB['LibLoaderTracingEnabled'] = if(($PEB.TracingFlags -band 4) -eq 0){$False}else{$True}
                    $CustomPEB['CsrServerReadOnlySharedMemoryBase'] = $PEB.CsrServerReadOnlySharedMemoryBase
                }
                elseif ($NTDDI_VERSION -ge $NTDDI_WS03)
                {
                    $CustomPEB['ImageUsesLargePages'] = if(($PEB.BitField -band 1) -eq 0){$False}else{$True}
                    $CustomPEB['AtlThunkSListPtr'] = $PEB.AtlThunkSListPtr
                    $CustomPEB['SparePtr2'] = $PEB.SparePtr2
                    $CustomPEB['EnvironmentUpdateCount'] = $PEB.EnvironmentUpdateCount
                    $CustomPEB['KernelCallbackTable'] = $PEB.KernelCallbackTable
                    $CustomPEB['ReadOnlySharedMemoryHeap'] = $PEB.ReadOnlySharedMemoryHeap
                    $CustomPEB['FlsCallback'] = $PEB.FlsCallback
                    $CustomPEB['FlsListHead'] = $PEB.FlsListHead
                    $CustomPEB['FlsBitmap'] = $PEB.FlsBitmap
                    $CustomPEB['FlsBitmapBits'] = $PEB.FlsBitmapBits
                    $CustomPEB['FlsHighIndex'] = $PEB.FlsHighIndex
                }
                else
                {
                    $CustomPEB['FastPebLockRoutine'] = $PEB.FastPebLockRoutine
                    $CustomPEB['FastPebUnlockRoutine'] = $PEB.FastPebUnlockRoutine
                    $CustomPEB['EnvironmentUpdateCount'] = $PEB.EnvironmentUpdateCount
                    $CustomPEB['KernelCallbackTable'] = $PEB.KernelCallbackTable
                    $CustomPEB['ReadOnlySharedMemoryHeap'] = $PEB.ReadOnlySharedMemoryHeap
                }

                $NewPEB = New-Object PSObject -Property $CustomPEB

                # _PEB will be interpreted by PowerShell depending upon the detected OS. This only applies if Get-PEB.format.ps1xml was loaded
                if ($NTDDI_VERSION -ge $NTDDI_VISTA)
                {
                    $NewPEB.PSObject.TypeNames[0] = 'PEB.Vista'
                }
                elseif ($NTDDI_VERSION -ge $NTDDI_WS03)
                {
                    $NewPEB.PSObject.TypeNames[0] = 'PEB.Server2003'
                }
                else
                {
                    $NewPEB.PSObject.TypeNames[0] = 'PEB.XP'
                }

                $Handle = $null

                Write-Output $NewPEB
            }
        }
    }

    END{}

}