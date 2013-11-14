function Get-NtSystemInformation
{
<#
.SYNOPSIS

    Returns various forms of internal OS information.

    PowerSploit Function: Get-NtSystemInformation
    Author: Matthew Graeber (@mattifestation)
    License: BSD 3-Clause
    Required Dependencies: None
    Optional Dependencies: None

.DESCRIPTION

    Get-NtSystemInformation is a utility that calls and parses the output of the
    ntdll!NtQuerySystemInformation function. This utility can be used to query
    internal OS information that is typically not made visible to a user.

.PARAMETER PoolTagInformation

    Returns information on tagged kernel pool allocations.

.PARAMETER ModuleInformation

    Returns loaded kernel module information.

.PARAMETER HandleInformation

    Returns handle information about user-mode handles and their respective
    address in the kernel.

.PARAMETER ObjectType

    Specifies the object type to be returned when listing handles. The following
    types are permitted:

    Adapter, ALPC Port, Callback, CompositionSurface, Controller, DebugObject,
    Desktop, Device, Directory, Driver, DxgkSharedResource, DxgkSharedSyncObject,
    EtwConsumer, EtwRegistration, Event, EventPair, File, FilterCommunicationPort,
    FilterConnectionPort, IoCompletion, IoCompletionReserve, IRTimer, Job, Key,
    KeyedEvent, Mutant, PcwObject, Port, PowerRequest, Process, Profile, Section,
    Semaphore, Session, SymbolicLink, Thread, Timer, TmEn, TmRm, TmTm, TmTx, Token,
    TpWorkerFactory, Type, UserApcReserve, WaitablePort, WaitCompletionPacket,
    WindowStation, WmiGuid

.PARAMETER ObjectInformation

    Returns information about user-mode objects and their respective kernel pool
    allocations.

.PARAMETER CodeIntegrityInformation

    Returns user-mode code integrity flags.

.PARAMETER GlobalFlags

    Returns a list of all enabled global flags.

.EXAMPLE

    C:\PS> Get-NtSystemInformation -PoolTagInformation

    Description
    -----------
    Returns information on tagged kernel pool allocations. The output is similar
    to that of poolmon.exe. The output is the result of parsing _SYSTEM_POOLTAG
    structures.

.EXAMPLE

    C:\PS> Get-NtSystemInformation -ModuleInformation

    Description
    -----------
    Returns loaded kernel module information including the base address of
    loaded kernel modules. The output is the result of parsing the
    undocumented _SYSTEM_MODULE_INFORMATION structure.

.EXAMPLE

    C:\PS> Get-NtSystemInformation -HandleInformation

    Description
    -----------
    Returns handle information about user-mode handles and their respective
    address in the kernel. The output is similar to that of handle.exe but
    doesn't require an elevated prompt. handle.exe also doesn't display the
    kernel address of the object that the handle represents. The output is the
    result of parsing _SYSTEM_HANDLE_TABLE_ENTRY_INFO structures.

.EXAMPLE

    C:\PS> Get-NtSystemInformation -ObjectInformation

    Description
    -----------
    Returns information about user-mode objects and their respective kernel pool
    allocations. The output is the result of parsing
    _SYSTEM_OBJECTTYPE_INFORMATION and _SYSTEM_OBJECT_INFORMATION structures.

    Note: FLG_MAINTAIN_OBJECT_TYPELIST (0x4000), FLG_ENABLE_HANDLE_TYPE_TAGGING
    (0x01000000) global flags must be set in order to retrieve the output of this
    command.

.EXAMPLE

    C:\PS> Get-NtSystemInformation -GlobalFlags

    Description
    -----------
    Returns a list of all enabled global flags. This is similar to running
    gflags.exe /r

.LINK

    http://www.exploit-monday.com/
#>

    [CmdletBinding()] Param (
        [Parameter( ParameterSetName = 'PoolTagInformation' )]
        [Switch]
        $PoolTagInformation,

        [Parameter( ParameterSetName = 'ModuleInformation' )]
        [Switch]
        $ModuleInformation,

        [Parameter( ParameterSetName = 'HandleInformation' )]
        [Switch]
        $HandleInformation,

        [Parameter( ParameterSetName = 'HandleInformation' )]
        [ValidateSet('Adapter', 'ALPC Port', 'Callback', 'CompositionSurface', 'Controller', 'DebugObject', 'Desktop', 'Device', 'Directory', 'Driver', 'DxgkSharedResource', 'DxgkSharedSyncObject', 'EtwConsumer', 'EtwRegistration', 'Event', 'EventPair', 'File', 'FilterCommunicationPort', 'FilterConnectionPort', 'IoCompletion', 'IoCompletionReserve', 'IRTimer', 'Job', 'Key', 'KeyedEvent', 'Mutant', 'PcwObject', 'Port', 'PowerRequest', 'Process', 'Profile', 'Section', 'Semaphore', 'Session', 'SymbolicLink', 'Thread', 'Timer', 'TmEn', 'TmRm', 'TmTm', 'TmTx', 'Token', 'TpWorkerFactory', 'Type', 'UserApcReserve', 'WaitablePort', 'WaitCompletionPacket', 'WindowStation', 'WmiGuid')]
        [String]
        $ObjectType,

        [Parameter( ParameterSetName = 'ObjectInformation' )]
        [Switch]
        $ObjectInformation,

        [Parameter( ParameterSetName = 'LockInformation' )]
        [Switch]
        $LockInformation,

        [Parameter( ParameterSetName = 'CodeIntegrityInformation' )]
        [Switch]
        $CodeIntegrityInformation,

        [Parameter( ParameterSetName = 'GlobalFlags' )]
        [Switch]
        $GlobalFlags
    )

#region Define the assembly/module that will hold all of our dynamic types.
    try { $ntdll = [ntdll] } catch [Management.Automation.RuntimeException]
    {
        $DynAssembly = New-Object System.Reflection.AssemblyName('SysUtils')
        $AssemblyBuilder = [AppDomain]::CurrentDomain.DefineDynamicAssembly($DynAssembly, [Reflection.Emit.AssemblyBuilderAccess]::Run)
        $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule('SysUtils', $False)

        # Define [ntdll]::NtQuerySystemInformation method
        $TypeBuilder = $ModuleBuilder.DefineType('ntdll', 'Public, Class')
        $PInvokeMethod = $TypeBuilder.DefinePInvokeMethod('NtQuerySystemInformation', 'ntdll.dll', ([Reflection.MethodAttributes]::Public -bor [Reflection.MethodAttributes]::Static), [Reflection.CallingConventions]::Standard, [Int32], [Type[]]@([UInt32], [IntPtr], [UInt32], [UInt32].MakeByRefType()), [Runtime.InteropServices.CallingConvention]::Winapi, [Runtime.InteropServices.CharSet]::Auto)
        $DllImportConstructor = [Runtime.InteropServices.DllImportAttribute].GetConstructor(@([String]))
        $SetLastError = [Runtime.InteropServices.DllImportAttribute].GetField('SetLastError')
        $SetLastErrorCustomAttribute = New-Object Reflection.Emit.CustomAttributeBuilder($DllImportConstructor, @('ntdll.dll'), [Reflection.FieldInfo[]]@($SetLastError), @($true))
        $PInvokeMethod.SetCustomAttribute($SetLastErrorCustomAttribute)
        $ntdll = $TypeBuilder.CreateType()
    }
#endregion

#region Define global custom attributes
    $LayoutConstructor = [Runtime.InteropServices.StructLayoutAttribute].GetConstructor([Runtime.InteropServices.LayoutKind])
    $CharsetField = [Runtime.InteropServices.StructLayoutAttribute].GetField('CharSet')
    $StructLayoutCustomAttribute = New-Object Reflection.Emit.CustomAttributeBuilder($LayoutConstructor, @([Runtime.InteropServices.LayoutKind]::Explicit), $CharsetField, @([Runtime.InteropServices.CharSet]::Ansi))

    $FlagsConstructor = [FlagsAttribute].GetConstructor(@())
    $FlagsCustomAttribute = New-Object Reflection.Emit.CustomAttributeBuilder($FlagsConstructor, @())

    $MarshalAsConstructor = [Runtime.InteropServices.MarshalAsAttribute].GetConstructor([Runtime.InteropServices.UnmanagedType])
    $SizeConst = [Runtime.InteropServices.MarshalAsAttribute].GetField('SizeConst')

    $StructAttributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
#endregion

#region Define enum types
    try { $SystemInformationClass = [SYSTEM_INFORMATION_CLASS] } catch [Management.Automation.RuntimeException]
    {
        # The entries that are commented out I'll get around to when I feel like it.

        $EnumBuilder = $ModuleBuilder.DefineEnum('SYSTEM_INFORMATION_CLASS', 'Public', [Int32])
        #$EnumBuilder.DefineLiteral('SystemBasicInformation', [Int32] 0x00000000) | Out-Null
        #$EnumBuilder.DefineLiteral('SystemProcessorInformation', [Int32] 0x00000001) | Out-Null
        #$EnumBuilder.DefineLiteral('SystemPerformanceInformation', [Int32] 0x00000002) | Out-Null
        #$EnumBuilder.DefineLiteral('SystemTimeOfDayInformation', [Int32] 0x00000003) | Out-Null
        #$EnumBuilder.DefineLiteral('SystemProcessInformation', [Int32] 0x00000005) | Out-Null
        #$EnumBuilder.DefineLiteral('SystemCallCounts', [Int32] 0x00000006) | Out-Null
        #$EnumBuilder.DefineLiteral('SystemConfigurationInformation', [Int32] 0x00000007) | Out-Null
        #$EnumBuilder.DefineLiteral('SystemProcessorPerformanceInformation', [Int32] 0x00000008) | Out-Null
        $EnumBuilder.DefineLiteral('SystemGlobalFlag', [Int32] 0x00000009) | Out-Null
        $EnumBuilder.DefineLiteral('SystemModuleInformation', [Int32] 0x0000000B) | Out-Null
        $EnumBuilder.DefineLiteral('SystemLockInformation', [Int32] 0x0000000C) | Out-Null
        $EnumBuilder.DefineLiteral('SystemHandleInformation', [Int32] 0x00000010) | Out-Null
        $EnumBuilder.DefineLiteral('SystemObjectInformation', [Int32] 0x00000011) | Out-Null
        #$EnumBuilder.DefineLiteral('SystemPagefileInformation', [Int32] 0x00000012) | Out-Null
        #$EnumBuilder.DefineLiteral('SystemInstructionEmulationCounts', [Int32] 0x00000013) | Out-Null
        $EnumBuilder.DefineLiteral('SystemPoolTagInformation', [Int32] 0x00000016) | Out-Null
        #$EnumBuilder.DefineLiteral('SystemInterruptInformation', [Int32] 0x00000017) | Out-Null
        #$EnumBuilder.DefineLiteral('SystemExceptionInformation', [Int32] 0x00000021) | Out-Null
        #$EnumBuilder.DefineLiteral('SystemRegistryQuotaInformation', [Int32] 0x00000025) | Out-Null
        #$EnumBuilder.DefineLiteral('SystemLookasideInformation', [Int32] 0x0000002D) | Out-Null
        $EnumBuilder.DefineLiteral('SystemCodeIntegrityInformation', [Int32] 0x00000067) | Out-Null
        $SystemInformationClass = $EnumBuilder.CreateType()
    }

    try { $NtStatus = [NTSTATUS] } catch [Management.Automation.RuntimeException]
    {
        $EnumBuilder = $ModuleBuilder.DefineEnum('NTSTATUS', 'Public', [Int32])
        $EnumBuilder.DefineLiteral('STATUS_SUCCESS', [Int32] 0x00000000) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_INFO_LENGTH_MISMATCH', [Int32] 0xC0000004) | Out-Null
        $NtStatus = $EnumBuilder.CreateType()
    }

    try { $LockdownState = [LOCKDOWN_STATE] } catch [Management.Automation.RuntimeException]
    {
        $EnumBuilder = $ModuleBuilder.DefineEnum('LOCKDOWN_STATE', 'Public', [Int32])
        $EnumBuilder.DefineLiteral('UMCINONE', [Int32] 0x00000000) | Out-Null
        $EnumBuilder.DefineLiteral('UMCIENFORCE', [Int32] 0x00000004) | Out-Null
        $EnumBuilder.DefineLiteral('UMCIAUDIT', [Int32] 0xC0000008) | Out-Null
        $LockdownState = $EnumBuilder.CreateType()
    }

    try { $PoolType = [POOL_TYPE] } catch [Management.Automation.RuntimeException]
    {
        $EnumBuilder = $ModuleBuilder.DefineEnum('POOL_TYPE', 'Public', [UInt32])
        $EnumBuilder.DefineLiteral('NonPagedPoolExecute', [UInt32] 0x00000000) | Out-Null
        $EnumBuilder.DefineLiteral('PagedPool', [UInt32] 0x00000001) | Out-Null
        $EnumBuilder.DefineLiteral('NonPagedPoolMustSucceed', [UInt32] 0x00000002) | Out-Null
        $EnumBuilder.DefineLiteral('DontUseThisType', [UInt32] 0x00000003) | Out-Null
        $EnumBuilder.DefineLiteral('NonPagedPoolCacheAligned', [UInt32] 0x00000004) | Out-Null
        $EnumBuilder.DefineLiteral('PagedPoolCacheAligned', [UInt32] 0x00000005) | Out-Null
        $EnumBuilder.DefineLiteral('NonPagedPoolCacheAlignedMustS', [UInt32] 0x00000006) | Out-Null
        $EnumBuilder.DefineLiteral('MaxPoolType', [UInt32] 0x00000007) | Out-Null
        $EnumBuilder.DefineLiteral('NonPagedPoolSession', [UInt32] 0x00000020) | Out-Null
        $EnumBuilder.DefineLiteral('PagedPoolSession', [UInt32] 0x00000021) | Out-Null
        $EnumBuilder.DefineLiteral('NonPagedPoolMustSucceedSession', [UInt32] 0x00000022) | Out-Null
        $EnumBuilder.DefineLiteral('DontUseThisTypeSession', [UInt32] 0x00000023) | Out-Null
        $EnumBuilder.DefineLiteral('NonPagedPoolCacheAlignedSession', [UInt32] 0x00000024) | Out-Null
        $EnumBuilder.DefineLiteral('PagedPoolCacheAlignedSession', [UInt32] 0x00000025) | Out-Null
        $EnumBuilder.DefineLiteral('NonPagedPoolCacheAlignedMustSSession', [UInt32] 0x00000026) | Out-Null
        $EnumBuilder.DefineLiteral('NonPagedPoolNx', [UInt32] 0x00000200) | Out-Null
        $EnumBuilder.DefineLiteral('NonPagedPoolNxCacheAligned', [UInt32] 0x00000204) | Out-Null
        $EnumBuilder.DefineLiteral('NonPagedPoolSessionNx', [UInt32] 0x00000220) | Out-Null
        $PoolType = $EnumBuilder.CreateType()
    }

    try { $HandleFlags = [HANDLE_FLAGS] } catch [Management.Automation.RuntimeException]
    {
        $EnumBuilder = $ModuleBuilder.DefineEnum('HANDLE_FLAGS', 'Public', [Byte])
        $EnumBuilder.DefineLiteral('PROTECT_FROM_CLOSE', [Byte] 1) | Out-Null
        $EnumBuilder.DefineLiteral('INHERIT', [Byte] 2) | Out-Null
        $EnumBuilder.SetCustomAttribute($FlagsCustomAttribute)
        $HandleFlags = $EnumBuilder.CreateType()
    }

    try { $ObjectAttributes = [OBJECT_ATTRIBUTES] } catch [Management.Automation.RuntimeException]
    {
        $EnumBuilder = $ModuleBuilder.DefineEnum('OBJECT_ATTRIBUTES', 'Public', [Int32])
        $EnumBuilder.DefineLiteral('OBJ_INHERIT', [Int32] 0x00000002) | Out-Null
        $EnumBuilder.DefineLiteral('OBJ_PERMANENT', [Int32] 0x00000010) | Out-Null
        $EnumBuilder.DefineLiteral('OBJ_EXCLUSIVE', [Int32] 0x00000020) | Out-Null
        $EnumBuilder.DefineLiteral('OBJ_CASE_INSENSITIVE', [Int32] 0x00000040) | Out-Null
        $EnumBuilder.DefineLiteral('OBJ_OPENIF', [Int32] 0x00000080) | Out-Null
        $EnumBuilder.DefineLiteral('OBJ_OPENLINK', [Int32] 0x00000100) | Out-Null
        $EnumBuilder.SetCustomAttribute($FlagsCustomAttribute)
        $ObjectAttributes = $EnumBuilder.CreateType()
    }

    try { $ObjectFlags = [OBJECT_FLAGS] } catch [Management.Automation.RuntimeException]
    {
        $EnumBuilder = $ModuleBuilder.DefineEnum('OBJECT_FLAGS', 'Public', [UInt16])
        $EnumBuilder.DefineLiteral('SINGLE_HANDLE_ENTRY', [UInt16] 0x0040) | Out-Null
        $EnumBuilder.DefineLiteral('DEFAULT_SECURITY_QUOTA', [UInt16] 0x0020) | Out-Null
        $EnumBuilder.DefineLiteral('PERMANENT', [UInt16] 0x0010) | Out-Null
        $EnumBuilder.DefineLiteral('EXCLUSIVE', [UInt16] 0x0008) | Out-Null
        $EnumBuilder.DefineLiteral('CREATOR_INFO', [UInt16] 0x0004) | Out-Null
        $EnumBuilder.DefineLiteral('KERNEL_MODE', [UInt16] 0x0002) | Out-Null
        $EnumBuilder.SetCustomAttribute($FlagsCustomAttribute)
        $ObjectFlags = $EnumBuilder.CreateType()
    }

    try { $AccessMask = [ACCESS_MASK] } catch [Management.Automation.RuntimeException]
    {
        $EnumBuilder = $ModuleBuilder.DefineEnum('ACCESS_MASK', 'Public', [Int32])
        $EnumBuilder.DefineLiteral('DELETE', [Int32] 0x00010000) | Out-Null
        $EnumBuilder.DefineLiteral('READ_CONTROL', [Int32] 0x00020000) | Out-Null
        $EnumBuilder.DefineLiteral('WRITE_DAC', [Int32] 0x00040000) | Out-Null
        $EnumBuilder.DefineLiteral('WRITE_OWNER', [Int32] 0x00080000) | Out-Null
        $EnumBuilder.DefineLiteral('SYNCHRONIZE', [Int32] 0x00100000) | Out-Null
        $EnumBuilder.DefineLiteral('STANDARD_RIGHTS_REQUIRED', [Int32] 0x000F0000) | Out-Null
        $EnumBuilder.DefineLiteral('STANDARD_RIGHTS_READ', [Int32] 0x00020000) | Out-Null
        $EnumBuilder.DefineLiteral('STANDARD_RIGHTS_WRITE', [Int32] 0x00020000) | Out-Null
        $EnumBuilder.DefineLiteral('STANDARD_RIGHTS_EXECUTE', [Int32] 0x00020000) | Out-Null
        $EnumBuilder.DefineLiteral('STANDARD_RIGHTS_ALL', [Int32] 0x001F0000) | Out-Null
        $EnumBuilder.DefineLiteral('ACCESS_SYSTEM_SECURITY', [Int32] 0x01000000) | Out-Null
        $EnumBuilder.DefineLiteral('GENERIC_READ', [Int32] 0x80000000) | Out-Null
        $EnumBuilder.DefineLiteral('GENERIC_WRITE', [Int32] 0x40000000) | Out-Null
        $EnumBuilder.DefineLiteral('GENERIC_EXECUTE', [Int32] 0x20000000) | Out-Null
        $EnumBuilder.DefineLiteral('GENERIC_ALL', [Int32] 0x10000000) | Out-Null
        $EnumBuilder.SetCustomAttribute($FlagsCustomAttribute)
        $AccessMask = $EnumBuilder.CreateType()
    }

    try { $GFlagsEnum = [GLOBAL_FLAGS] } catch [Management.Automation.RuntimeException]
    {
        $EnumBuilder = $ModuleBuilder.DefineEnum('GLOBAL_FLAGS', 'Public', [Int32])
        $EnumBuilder.DefineLiteral('FLG_DISABLE_DBGPRINT', [Int32] 0x08000000) | Out-Null
        $EnumBuilder.DefineLiteral('FLG_KERNEL_STACK_TRACE_DB', [Int32] 0x00002000) | Out-Null
        $EnumBuilder.DefineLiteral('FLG_USER_STACK_TRACE_DB', [Int32] 0x00001000) | Out-Null
        $EnumBuilder.DefineLiteral('FLG_DEBUG_INITIAL_COMMAND', [Int32] 0x00000004) | Out-Null
        $EnumBuilder.DefineLiteral('FLG_DEBUG_INITIAL_COMMAND_EX', [Int32] 0x04000000) | Out-Null
        $EnumBuilder.DefineLiteral('FLG_HEAP_DISABLE_COALESCING', [Int32] 0x00200000) | Out-Null
        $EnumBuilder.DefineLiteral('FLG_DISABLE_PAGE_KERNEL_STACKS', [Int32] 0x00080000) | Out-Null
        $EnumBuilder.DefineLiteral('FLG_DISABLE_PROTDLLS', [Int32] 0x80000000) | Out-Null
        $EnumBuilder.DefineLiteral('FLG_DISABLE_STACK_EXTENSION', [Int32] 0x00010000) | Out-Null
        $EnumBuilder.DefineLiteral('FLG_CRITSEC_EVENT_CREATION', [Int32] 0x10000000) | Out-Null
        $EnumBuilder.DefineLiteral('FLG_APPLICATION_VERIFIER', [Int32] 0x00000100) | Out-Null
        $EnumBuilder.DefineLiteral('FLG_ENABLE_HANDLE_EXCEPTIONS', [Int32] 0x40000000) | Out-Null
        $EnumBuilder.DefineLiteral('FLG_ENABLE_CLOSE_EXCEPTIONS', [Int32] 0x00400000) | Out-Null
        $EnumBuilder.DefineLiteral('FLG_ENABLE_CSRDEBUG', [Int32] 0x00020000) | Out-Null
        $EnumBuilder.DefineLiteral('FLG_ENABLE_EXCEPTION_LOGGING', [Int32] 0x00800000) | Out-Null
        $EnumBuilder.DefineLiteral('FLG_HEAP_ENABLE_FREE_CHECK', [Int32] 0x00000020) | Out-Null
        $EnumBuilder.DefineLiteral('FLG_HEAP_VALIDATE_PARAMETERS', [Int32] 0x00000040) | Out-Null
        $EnumBuilder.DefineLiteral('FLG_HEAP_ENABLE_TAGGING', [Int32] 0x00000800) | Out-Null
        $EnumBuilder.DefineLiteral('FLG_HEAP_ENABLE_TAG_BY_DLL', [Int32] 0x00008000) | Out-Null
        $EnumBuilder.DefineLiteral('FLG_HEAP_ENABLE_TAIL_CHECK', [Int32] 0x00000010) | Out-Null
        $EnumBuilder.DefineLiteral('FLG_HEAP_VALIDATE_ALL', [Int32] 0x00000080) | Out-Null
        $EnumBuilder.DefineLiteral('FLG_ENABLE_KDEBUG_SYMBOL_LOAD', [Int32] 0x00040000) | Out-Null
        $EnumBuilder.DefineLiteral('FLG_ENABLE_HANDLE_TYPE_TAGGING', [Int32] 0x01000000) | Out-Null
        $EnumBuilder.DefineLiteral('FLG_HEAP_PAGE_ALLOCS', [Int32] 0x02000000) | Out-Null
        $EnumBuilder.DefineLiteral('FLG_POOL_ENABLE_TAGGING', [Int32] 0x00000400) | Out-Null
        $EnumBuilder.DefineLiteral('FLG_ENABLE_SYSTEM_CRIT_BREAKS', [Int32] 0x00100000) | Out-Null
        $EnumBuilder.DefineLiteral('FLG_MAINTAIN_OBJECT_TYPELIST', [Int32] 0x00004000) | Out-Null
        $EnumBuilder.DefineLiteral('FLG_MONITOR_SILENT_PROCESS_EXIT', [Int32] 0x00000200) | Out-Null
        $EnumBuilder.DefineLiteral('FLG_SHOW_LDR_SNAPS', [Int32] 0x00000002) | Out-Null
        $EnumBuilder.DefineLiteral('FLG_STOP_ON_EXCEPTION', [Int32] 0x00000001) | Out-Null
        $EnumBuilder.DefineLiteral('FLG_STOP_ON_HUNG_GUI', [Int32] 0x00000008) | Out-Null
        $EnumBuilder.SetCustomAttribute($FlagsCustomAttribute)
        $GFlagsEnum = $EnumBuilder.CreateType()
    }
#endregion

#region Define structs for each respective SYSTEM_INFORMATION_CLASS
    if ([IntPtr]::Size -eq 8)
    {
        $Size_SYSTEM_MODULE = 296
        $Size_SYSTEM_POOL_TAG_INFORMATION = 40
        $Size_SYSTEM_HANDLE_INFORMATION = 24
        $Size_SYSTEM_OBJECTTYPE_INFORMATION = 64
        $Size_SYSTEM_OBJECT_INFORMATION = 80
        $Size_SYSTEM_LOCK_INFORMATION = 40
    }
    else
    {
        $Size_SYSTEM_MODULE = 284
        $Size_SYSTEM_POOL_TAG_INFORMATION = 28
        $Size_SYSTEM_HANDLE_INFORMATION = 16
        $Size_SYSTEM_OBJECTTYPE_INFORMATION = 56
        $Size_SYSTEM_OBJECT_INFORMATION = 48
        $Size_SYSTEM_LOCK_INFORMATION = 36
    }

    try { $UnicodeStringClass = [_UNICODE_STRING] } catch [Management.Automation.RuntimeException]
    {
        $MarshalAsCustomAttribute = New-Object Reflection.Emit.CustomAttributeBuilder($MarshalAsConstructor, @([Runtime.InteropServices.UnmanagedType]::LPWStr))

        if ([IntPtr]::Size -eq 8)
        {
            $TypeBuilder = $ModuleBuilder.DefineType('_UNICODE_STRING', $StructAttributes, [ValueType], 2, 16)
            $TypeBuilder.SetCustomAttribute($StructLayoutCustomAttribute)

            $TypeBuilder.DefineField('Length', [UInt16], 'Public').SetOffset(0)
            $TypeBuilder.DefineField('MaximumLength', [UInt16], 'Public').SetOffset(2)
            $BufferField = $TypeBuilder.DefineField('Buffer', [String], 'Public, HasFieldMarshal')
            $BufferField.SetCustomAttribute($MarshalAsCustomAttribute)
            $BufferField.SetOffset(8)
        }
        else
        {
            $TypeBuilder = $ModuleBuilder.DefineType('_UNICODE_STRING', $StructAttributes, [ValueType], 2, 8)
            $TypeBuilder.SetCustomAttribute($StructLayoutCustomAttribute)

            $TypeBuilder.DefineField('Length', [UInt16], 'Public').SetOffset(0)
            $TypeBuilder.DefineField('MaximumLength', [UInt16], 'Public').SetOffset(2)
            $BufferField = $TypeBuilder.DefineField('Buffer', [String], 'Public, HasFieldMarshal')
            $BufferField.SetCustomAttribute($MarshalAsCustomAttribute)
            $BufferField.SetOffset(4)
        }

        $UnicodeStringClass = $TypeBuilder.CreateType()
    }

    try { $GenericMappingClass = [_GENERIC_MAPPING] } catch [Management.Automation.RuntimeException]
    {
        $TypeBuilder = $ModuleBuilder.DefineType('_GENERIC_MAPPING', $StructAttributes, [ValueType], 4, 16)

        $TypeBuilder.DefineField('GenericRead', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('GenericWrite', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('GenericExecute', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('GenericAll', [UInt32], 'Public') | Out-Null

        $GenericMappingClass = $TypeBuilder.CreateType()
    }

    try { $HandleInfoClass = [_SYSTEM_HANDLE_INFORMATION] } catch [Management.Automation.RuntimeException]
    {
        $TypeBuilder = $ModuleBuilder.DefineType('_SYSTEM_HANDLE_INFORMATION', $StructAttributes, [ValueType], 1, $Size_SYSTEM_HANDLE_INFORMATION)

        $TypeBuilder.DefineField('UniqueProcessId', [UInt16], 'Public') | Out-Null
        $TypeBuilder.DefineField('CreatorBackTraceIndex', [UInt16], 'Public') | Out-Null
        $TypeBuilder.DefineField('ObjectTypeIndex', [Byte], 'Public') | Out-Null
        $TypeBuilder.DefineField('HandleAttribute', [Byte], 'Public') | Out-Null
        $TypeBuilder.DefineField('HandleValue', [UInt16], 'Public') | Out-Null
        $TypeBuilder.DefineField('Object', [IntPtr], 'Public') | Out-Null
        $TypeBuilder.DefineField('GrantedAccess', [UInt32], 'Public') | Out-Null

        $HandleInfoClass = $TypeBuilder.CreateType()
    }

    try { $ModuleInfoClass = [_SYSTEM_MODULE] } catch [Management.Automation.RuntimeException]
    {
        $MarshalAsCustomAttribute = New-Object Reflection.Emit.CustomAttributeBuilder($MarshalAsConstructor, @([Runtime.InteropServices.UnmanagedType]::ByValTStr), [Reflection.FieldInfo[]]@($SizeConst), @(256))

        if ([IntPtr]::Size -eq 8)
        {
            $TypeBuilder = $ModuleBuilder.DefineType('_SYSTEM_MODULE', $StructAttributes, [ValueType], 1, $Size_SYSTEM_MODULE)

            $TypeBuilder.DefineField('Reserved1', [UInt32], 'Public') | Out-Null
            $TypeBuilder.DefineField('Reserved2', [UInt32], 'Public') | Out-Null
            $TypeBuilder.DefineField('ImageBaseAddress', [UInt64], 'Public') | Out-Null
            $TypeBuilder.DefineField('ImageSize', [UInt32], 'Public') | Out-Null
            $TypeBuilder.DefineField('Flags', [UInt32], 'Public') | Out-Null
            $TypeBuilder.DefineField('Index', [UInt16], 'Public') | Out-Null
            $TypeBuilder.DefineField('Rank', [UInt16], 'Public') | Out-Null
            $TypeBuilder.DefineField('LoadCount', [UInt16], 'Public') | Out-Null
            $TypeBuilder.DefineField('NameOffset', [UInt16], 'Public') | Out-Null
            $NameField = $TypeBuilder.DefineField('Name', [String], 'Public, HasFieldMarshal')
        }
        else
        {
            $TypeBuilder = $ModuleBuilder.DefineType('_SYSTEM_MODULE', $StructAttributes, [ValueType], 1, $Size_SYSTEM_MODULE)

            $TypeBuilder.DefineField('Reserved1', [UInt16], 'Public') | Out-Null
            $TypeBuilder.DefineField('Reserved2', [UInt16], 'Public') | Out-Null
            $TypeBuilder.DefineField('ImageBaseAddress', [UInt32], 'Public') | Out-Null
            $TypeBuilder.DefineField('ImageSize', [UInt32], 'Public') | Out-Null
            $TypeBuilder.DefineField('Flags', [UInt32], 'Public') | Out-Null
            $TypeBuilder.DefineField('Index', [UInt16], 'Public') | Out-Null
            $TypeBuilder.DefineField('Rank', [UInt16], 'Public') | Out-Null
            $TypeBuilder.DefineField('LoadCount', [UInt16], 'Public') | Out-Null
            $TypeBuilder.DefineField('NameOffset', [UInt16], 'Public') | Out-Null
            $NameField = $TypeBuilder.DefineField('Name', [String], 'Public, HasFieldMarshal')
        }

        $NameField.SetCustomAttribute($MarshalAsCustomAttribute)
        $ModuleInfoClass = $TypeBuilder.CreateType()
    }

    try { $LockInfoClass = [_SYSTEM_LOCK_INFORMATION] } catch [Management.Automation.RuntimeException]
    {
        $TypeBuilder = $ModuleBuilder.DefineType('_SYSTEM_LOCK_INFORMATION', $StructAttributes, [ValueType], 1, $Size_SYSTEM_LOCK_INFORMATION)
        $TypeBuilder.SetCustomAttribute($StructLayoutCustomAttribute)

        if ([IntPtr]::Size -eq 8)
        {
            $TypeBuilder.DefineField('Address', [IntPtr], 'Public').SetOffset(0)
            $TypeBuilder.DefineField('Type', [UInt16], 'Public').SetOffset(8)
            $TypeBuilder.DefineField('Reserved1', [UInt16], 'Public').SetOffset(10)
            $TypeBuilder.DefineField('ExclusiveOwnerThreadId', [UInt32], 'Public').SetOffset(16)
            $TypeBuilder.DefineField('ActiveCount', [UInt32], 'Public').SetOffset(24)
            $TypeBuilder.DefineField('ContentionCount', [UInt32], 'Public').SetOffset(28)
            $TypeBuilder.DefineField('Reserved2', [UInt32], 'Public').SetOffset(32)
            $TypeBuilder.DefineField('Reserved3', [UInt32], 'Public').SetOffset(36)
            $TypeBuilder.DefineField('NumberOfSharedWaiters', [UInt32], 'Public').SetOffset(40)
            $TypeBuilder.DefineField('NumberOfExclusiveWaiters', [UInt32], 'Public').SetOffset(44)
        }
        else
        {
            $TypeBuilder.DefineField('Address', [IntPtr], 'Public').SetOffset(0)
            $TypeBuilder.DefineField('Type', [UInt16], 'Public').SetOffset(4)
            $TypeBuilder.DefineField('Reserved1', [UInt16], 'Public').SetOffset(6)
            $TypeBuilder.DefineField('ExclusiveOwnerThreadId', [UInt32], 'Public').SetOffset(8)
            $TypeBuilder.DefineField('ActiveCount', [UInt32], 'Public').SetOffset(12)
            $TypeBuilder.DefineField('ContentionCount', [UInt32], 'Public').SetOffset(16)
            $TypeBuilder.DefineField('Reserved2', [UInt32], 'Public').SetOffset(20)
            $TypeBuilder.DefineField('Reserved3', [UInt32], 'Public').SetOffset(24)
            $TypeBuilder.DefineField('NumberOfSharedWaiters', [UInt32], 'Public').SetOffset(28)
            $TypeBuilder.DefineField('NumberOfExclusiveWaiters', [UInt32], 'Public').SetOffset(32)
        }
        
        $LockInfoClass = $TypeBuilder.CreateType()
    }

    try { $PoolTagInfoClass = [_SYSTEM_POOL_TAG_INFORMATION] } catch [Management.Automation.RuntimeException]
    {
        $TypeBuilder = $ModuleBuilder.DefineType('_SYSTEM_POOL_TAG_INFORMATION', $StructAttributes, [ValueType], 4, $Size_SYSTEM_POOL_TAG_INFORMATION)
        $TypeBuilder.SetCustomAttribute($StructLayoutCustomAttribute)

        if ([IntPtr]::Size -eq 8)
        {
            $TypeBuilder.DefineField('TagValue', [UInt32], 'Public, HasFieldMarshal').SetOffset(0)
            $TypeBuilder.DefineField('PagedPoolAllocs', [UInt32], 'Public').SetOffset(4)
            $TypeBuilder.DefineField('PagedPoolFrees', [UInt32], 'Public').SetOffset(8)
            $TypeBuilder.DefineField('PagedPoolUsage', [UInt32], 'Public').SetOffset(16)
            $TypeBuilder.DefineField('NonPagedPoolAllocs', [UInt32], 'Public').SetOffset(24)
            $TypeBuilder.DefineField('NonPagedPoolFrees', [UInt32], 'Public').SetOffset(28)
            $TypeBuilder.DefineField('NonPagedPoolUsage', [UInt32], 'Public').SetOffset(32)
        }
        else
        {
            $TypeBuilder.DefineField('TagValue', [UInt32], 'Public, HasFieldMarshal').SetOffset(0)
            $TypeBuilder.DefineField('PagedPoolAllocs', [UInt32], 'Public').SetOffset(4)
            $TypeBuilder.DefineField('PagedPoolFrees', [UInt32], 'Public').SetOffset(8)
            $TypeBuilder.DefineField('PagedPoolUsage', [UInt32], 'Public').SetOffset(12)
            $TypeBuilder.DefineField('NonPagedPoolAllocs', [UInt32], 'Public').SetOffset(16)
            $TypeBuilder.DefineField('NonPagedPoolFrees', [UInt32], 'Public').SetOffset(20)
            $TypeBuilder.DefineField('NonPagedPoolUsage', [UInt32], 'Public').SetOffset(24)
        }

        $PoolTagInfoClass = $TypeBuilder.CreateType()
    }

    try { $ObjectTypeClass = [_SYSTEM_OBJECTTYPE_INFORMATION] } catch [Management.Automation.RuntimeException]
    {
        $TypeBuilder = $ModuleBuilder.DefineType('_SYSTEM_OBJECTTYPE_INFORMATION', $StructAttributes, [ValueType], 1, $Size_SYSTEM_OBJECTTYPE_INFORMATION)
        $TypeBuilder.SetCustomAttribute($StructLayoutCustomAttribute)

        $TypeBuilder.DefineField('NextEntryOffset', [UInt32], 'Public').SetOffset(0x00)
        $TypeBuilder.DefineField('NumberOfObjects', [UInt32], 'Public').SetOffset(0x04)
        $TypeBuilder.DefineField('NumberOfHandles', [UInt32], 'Public').SetOffset(0x08)
        $TypeBuilder.DefineField('TypeIndex', [UInt32], 'Public').SetOffset(0x0C)
        $TypeBuilder.DefineField('InvalidAttributes', [UInt32], 'Public').SetOffset(0x10)
        $TypeBuilder.DefineField('GenericMapping', $GenericMappingClass, 'Public').SetOffset(0x14)
        $TypeBuilder.DefineField('ValidAccessMask', [UInt32], 'Public').SetOffset(0x24)
        $TypeBuilder.DefineField('PoolType', $PoolType, 'Public').SetOffset(0x28)
        $TypeBuilder.DefineField('SecurityRequired', [Byte], 'Public').SetOffset(0x2C)
        $TypeBuilder.DefineField('WaitableObject', [Byte], 'Public').SetOffset(0x2D)
        $TypeBuilder.DefineField('TypeName', $UnicodeStringClass, 'Public').SetOffset(0x30)

        $ObjectTypeClass = $TypeBuilder.CreateType()
    }

    try { $ObjectTypeClass = [_SYSTEM_OBJECT_INFORMATION] } catch [Management.Automation.RuntimeException]
    {
        $TypeBuilder = $ModuleBuilder.DefineType('_SYSTEM_OBJECT_INFORMATION', $StructAttributes, [ValueType], 1, $Size_SYSTEM_OBJECT_INFORMATION)
        $TypeBuilder.SetCustomAttribute($StructLayoutCustomAttribute)

        if ([IntPtr]::Size -eq 8)
        {
            $TypeBuilder.DefineField('NextEntryOffset', [UInt32], 'Public').SetOffset(0x00)
            $TypeBuilder.DefineField('Object', [IntPtr], 'Public').SetOffset(0x08)
            $TypeBuilder.DefineField('CreatorUniqueProcess', [IntPtr], 'Public').SetOffset(0x10)
            $TypeBuilder.DefineField('CreatorBackTraceIndex', [UInt16], 'Public').SetOffset(0x018)
            $TypeBuilder.DefineField('Flags', [UInt16], 'Public').SetOffset(0x1A)
            $TypeBuilder.DefineField('PointerCount', [Int32], 'Public').SetOffset(0x1C)
            $TypeBuilder.DefineField('HandleCount', [Int32], 'Public').SetOffset(0x20)
            $TypeBuilder.DefineField('PagedPoolCharge', [UInt32], 'Public').SetOffset(0x24)
            $TypeBuilder.DefineField('NonPagedPoolCharge', [UInt32], 'Public').SetOffset(0x28)
            $TypeBuilder.DefineField('ExclusiveProcessId', [IntPtr], 'Public').SetOffset(0x30)
            $TypeBuilder.DefineField('SecurityDescriptor', [IntPtr], 'Public').SetOffset(0x38)
            $TypeBuilder.DefineField('NameInfo', $UnicodeStringClass, 'Public').SetOffset(0x40)
        }
        else
        {
            $TypeBuilder.DefineField('NextEntryOffset', [UInt32], 'Public').SetOffset(0x00)
            $TypeBuilder.DefineField('Object', [IntPtr], 'Public').SetOffset(0x04)
            $TypeBuilder.DefineField('CreatorUniqueProcess', [IntPtr], 'Public').SetOffset(0x08)
            $TypeBuilder.DefineField('CreatorBackTraceIndex', [UInt16], 'Public').SetOffset(0x0C)
            $TypeBuilder.DefineField('Flags', [UInt16], 'Public').SetOffset(0x0E)
            $TypeBuilder.DefineField('PointerCount', [Int32], 'Public').SetOffset(0x10)
            $TypeBuilder.DefineField('HandleCount', [Int32], 'Public').SetOffset(0x14)
            $TypeBuilder.DefineField('PagedPoolCharge', [UInt32], 'Public').SetOffset(0x18)
            $TypeBuilder.DefineField('NonPagedPoolCharge', [UInt32], 'Public').SetOffset(0x1C)
            $TypeBuilder.DefineField('ExclusiveProcessId', [IntPtr], 'Public').SetOffset(0x20)
            $TypeBuilder.DefineField('SecurityDescriptor', [IntPtr], 'Public').SetOffset(0x24)
            $TypeBuilder.DefineField('NameInfo', $UnicodeStringClass, 'Public').SetOffset(0x28)
        }

        $ObjectClass = $TypeBuilder.CreateType()
    }
#endregion

    # Local helper function for parsing structures returned by NtQuerySystemInformation that begin with a 'Count' field
    function Local:Get-Struct($InformationClass, $StructType, $X86Size, $X64Size, $OffsetMultiplier, $ErrorText)
    {
        $TotalLength = 0
        $ReturnedLength = 0

        if ([IntPtr]::Size -eq 8)
        {
            $StructSize = $X64Size
        }
        else
        {
            $StructSize = $X86Size
        }

        if ((($ntdll::NtQuerySystemInformation($InformationClass, [IntPtr]::Zero, 0, [Ref] $TotalLength) -as $NtStatus) -ne $NtStatus::STATUS_INFO_LENGTH_MISMATCH) -and ($TotalLength -gt 0))
        {
            Write-Error "Unable to obtain $($ErrorText) information."
            return
        }

        $PtrData = [Runtime.InteropServices.Marshal]::AllocHGlobal($TotalLength)
        $ntdll::NtQuerySystemInformation($InformationClass, $PtrData, $TotalLength, [Ref] $ReturnedLength) | Out-Null
        [Runtime.InteropServices.Marshal]::FreeHGlobal($PtrData)

        $PtrData2 = [Runtime.InteropServices.Marshal]::AllocHGlobal($ReturnedLength)

        if (($ntdll::NtQuerySystemInformation($InformationClass, $PtrData2, $ReturnedLength, [Ref] 0) -as $NtStatus) -ne $NtStatus::STATUS_SUCCESS)
        {
            [Runtime.InteropServices.Marshal]::FreeHGlobal($PtrData2)
            Write-Error "Unable to obtain $($ErrorText) information."
            return
        }

        # Retrieve the structure count
        $Count = [Runtime.InteropServices.Marshal]::ReadInt32($PtrData2)

        # Point to the first structure
        $StructAddress = ([IntPtr]($PtrData2.ToInt64() + ([IntPtr]::Size * $OffsetMultiplier)))

        foreach ($i in 0..($Count-1))
        {
            [Runtime.InteropServices.Marshal]::PtrToStructure($StructAddress, [Type] $StructType)
            $StructAddress = ([IntPtr]($StructAddress.ToInt64() + $StructSize))
        }

        [Runtime.InteropServices.Marshal]::FreeHGlobal($PtrData2)    
    }

#region Main program logic
    switch ($PsCmdlet.ParameterSetName)
    {
        'ModuleInformation' {
            $Arguments = @{
                InformationClass = $SystemInformationClass::SystemModuleInformation
                StructType = $ModuleInfoClass
                X86Size = 284
                X64Size = 296
                OffsetMultiplier = 2
                ErrorText = 'system module'
            }

            Get-Struct @Arguments
        }

        'PoolTagInformation' {
            $Arguments = @{
                InformationClass = $SystemInformationClass::SystemPoolTagInformation
                StructType = $PoolTagInfoClass
                X86Size = 28
                X64Size = 40
                OffsetMultiplier = 1
                ErrorText = 'system pool tag'
            }

            Get-Struct @Arguments | % {
                $Result = @{
                    Tag = [Text.Encoding]::ASCII.GetString([BitConverter]::GetBytes($_.TagValue))
                    PagedPoolAllocs = $_.PagedPoolAllocs
                    PagedPoolFrees = $_.PagedPoolFrees
                    PagedPoolUsage = $_.PagedPoolUsage
                    NonPagedPoolAllocs = $_.NonPagedPoolAllocs
                    NonPagedPoolFrees = $_.NonPagedPoolFrees
                    NonPagedPoolUsage = $_.NonPagedPoolUsage
                }

                $PoolTag = New-Object PSObject -Property $Result
                $PoolTag.PSObject.TypeNames.Insert(0, '_SYSTEM_POOL_TAG_INFORMATION')

                Write-Output $PoolTag
            }
        }

        'HandleInformation' {
            # Get OS version info. This will be used to resolve object type index values
            $OSVersion = [Version](Get-WmiObject Win32_OperatingSystem).Version
            $OSMajorMinor = "$($OSVersion.Major).$($OSVersion.Minor)"

            # Type indexes differ according to OS. These values were obtained via some KD-fu
            switch ($OSMajorMinor)
            {
                '6.2' # Windows 8 and Windows Server 2012
                {
                    $IndexTable = @{
                        0x02 = 'Type'
                        0x03 = 'Directory'
                        0x04 = 'SymbolicLink'
                        0x05 = 'Token'
                        0x06 = 'Job'
                        0x07 = 'Process'
                        0x08 = 'Thread'
                        0x09 = 'UserApcReserve'
                        0x0A = 'IoCompletionReserve'
                        0x0B = 'DebugObject'
                        0x0C = 'Event'
                        0x0D = 'EventPair'
                        0x0E = 'Mutant'
                        0x0F = 'Callback'
                        0x10 = 'Semaphore'
                        0x11 = 'Timer'
                        0x12 = 'IRTimer'
                        0x13 = 'Profile'
                        0x14 = 'KeyedEvent'
                        0x15 = 'WindowStation'
                        0x16 = 'Desktop'
                        0x17 = 'CompositionSurface'
                        0x18 = 'TpWorkerFactory'
                        0x19 = 'Adapter'
                        0x1A = 'Controller'
                        0x1B = 'Device'
                        0x1C = 'Driver'
                        0x1D = 'IoCompletion'
                        0x1E = 'WaitCompletionPacket'
                        0x1F = 'File'
                        0x20 = 'TmTm'
                        0x21 = 'TmTx'
                        0x22 = 'TmRm'
                        0x23 = 'TmEn'
                        0x24 = 'Section'
                        0x25 = 'Session'
                        0x26 = 'Key'
                        0x27 = 'ALPC Port'
                        0x28 = 'PowerRequest'
                        0x29 = 'WmiGuid'
                        0x2A = 'EtwRegistration'
                        0x2B = 'EtwConsumer'
                        0x2C = 'FilterConnectionPort'
                        0x2D = 'FilterCommunicationPort'
                        0x2E = 'PcwObject'
                        0x2F = 'DxgkSharedResource'
                        0x30 = 'DxgkSharedSyncObject'
                    }
                }

                '6.1' # Windows 7 and Window Server 2008 R2
                {
                    $IndexTable = @{
                        0x02 = 'Type'
                        0x03 = 'Directory'
                        0x04 = 'SymbolicLink'
                        0x05 = 'Token'
                        0x06 = 'Job'
                        0x07 = 'Process'
                        0x08 = 'Thread'
                        0x09 = 'UserApcReserve'
                        0x0a = 'IoCompletionReserve'
                        0x0b = 'DebugObject'
                        0x0c = 'Event'
                        0x0d = 'EventPair'
                        0x0e = 'Mutant'
                        0x0f = 'Callback'
                        0x10 = 'Semaphore'
                        0x11 = 'Timer'
                        0x12 = 'Profile'
                        0x13 = 'KeyedEvent'
                        0x14 = 'WindowStation'
                        0x15 = 'Desktop'
                        0x16 = 'TpWorkerFactory'
                        0x17 = 'Adapter'
                        0x18 = 'Controller'
                        0x19 = 'Device'
                        0x1a = 'Driver'
                        0x1b = 'IoCompletion'
                        0x1c = 'File'
                        0x1d = 'TmTm'
                        0x1e = 'TmTx'
                        0x1f = 'TmRm'
                        0x20 = 'TmEn'
                        0x21 = 'Section'
                        0x22 = 'Session'
                        0x23 = 'Key'
                        0x24 = 'ALPC Port'
                        0x25 = 'PowerRequest'
                        0x26 = 'WmiGuid'
                        0x27 = 'EtwRegistration'
                        0x28 = 'EtwConsumer'
                        0x29 = 'FilterConnectionPort'
                        0x2a = 'FilterCommunicationPort'
                        0x2b = 'PcwObject'
                    }
                }

                '6.0' # Windows Vista and Windows Server 2008
                {
                    $IndexTable = @{
                        0x01 = 'Type'
                        0x02 = 'Directory'
                        0x03 = 'SymbolicLink'
                        0x04 = 'Token'
                        0x05 = 'Job'
                        0x06 = 'Process'
                        0x07 = 'Thread'
                        0x08 = 'DebugObject'
                        0x09 = 'Event'
                        0x0a = 'EventPair'
                        0x0b = 'Mutant'
                        0x0c = 'Callback'
                        0x0d = 'Semaphore'
                        0x0e = 'Timer'
                        0x0f = 'Profile'
                        0x10 = 'KeyedEvent'
                        0x11 = 'WindowStation'
                        0x12 = 'Desktop'
                        0x13 = 'TpWorkerFactory'
                        0x14 = 'Adapter'
                        0x15 = 'Controller'
                        0x16 = 'Device'
                        0x17 = 'Driver'
                        0x18 = 'IoCompletion'
                        0x19 = 'File'
                        0x1a = 'TmTm'
                        0x1b = 'TmTx'
                        0x1c = 'TmRm'
                        0x1d = 'TmEn'
                        0x1e = 'Section'
                        0x1f = 'Session'
                        0x20 = 'Key'
                        0x21 = 'ALPC Port'
                        0x22 = 'WmiGuid'
                        0x23 = 'EtwRegistration'
                        0x24 = 'FilterConnectionPort'
                        0x25 = 'FilterCommunicationPort'
                    }
                }

                '5.1' # Windows XP
                {
                    $IndexTable = @{
                        0x01 = 'Type'
                        0x02 = 'Directory'
                        0x03 = 'SymbolicLink'
                        0x04 = 'Token'
                        0x05 = 'Process'
                        0x06 = 'Thread'
                        0x07 = 'Job'
                        0x08 = 'DebugObject'
                        0x09 = 'Event'
                        0x0a = 'EventPair'
                        0x0b = 'Mutant'
                        0x0c = 'Callback'
                        0x0d = 'Semaphore'
                        0x0e = 'Timer'
                        0x0f = 'Profile'
                        0x10 = 'KeyedEvent'
                        0x11 = 'WindowStation'
                        0x12 = 'Desktop'
                        0x13 = 'Section'
                        0x14 = 'Key'
                        0x15 = 'Port'
                        0x16 = 'WaitablePort'
                        0x17 = 'Adapter'
                        0x18 = 'Controller'
                        0x19 = 'Device'
                        0x1a = 'Driver'
                        0x1b = 'IoCompletion'
                        0x1c = 'File'
                        0x1d = 'WmiGuid'
                        0x1e = 'FilterConnectionPort'
                        0x1f = 'FilterCommunicationPort'
                    }
                }

                default # I didn't feel like resolving the values for Server 2003
                {
                    $IndexTable = @{}
                }
            }

            $Arguments = @{
                InformationClass = $SystemInformationClass::SystemHandleInformation
                StructType = $HandleInfoClass
                X86Size = 16
                X64Size = 24
                OffsetMultiplier = 1
                ErrorText = 'system handle'
            }

            Get-Struct @Arguments | % {
                $Handle = $_.HandleAttribute -as $HandleFlags
                if ($Handle -eq 0) {$HandleValue = $null} else {$HandleValue = $Handle}

                $Access = ( ($_.GrantedAccess -band 0xFFFF0000) -as $AccessMask )
                if ($Access -eq 0) {$AccessValue = $null} else {$AccessValue = $Access}

                $Result = @{
                    UniqueProcessId = $_.UniqueProcessId
                    CreatorBackTraceIndex = $_.CreatorBackTraceIndex
                    ObjectTypeIndex = $_.ObjectTypeIndex
                    ObjectType = $IndexTable[([Int32]$_.ObjectTypeIndex)]
                    HandleAttribute = $HandleValue
                    HandleValue = $_.HandleValue
                    Object = $_.Object
                    GrantedAccess = $AccessValue
                }

                $Handle = New-Object PSObject -Property $Result
                $Handle.PSObject.TypeNames.Insert(0, '_SYSTEM_HANDLE_INFORMATION')

                if ($PSBoundParameters['ObjectType'])
                {
                    if ($Result['ObjectType'] -eq $ObjectType)
                    {
                        Write-Output $Handle
                    }
                }
                else
                {
                    Write-Output $Handle
                }
            }
        }

        'ObjectInformation' {
            # Get system global flags first to ensure the correct flags are set
            $Flags = Get-NtSystemInformation -GlobalFlags

            $RequiredFlags = [GLOBAL_FLAGS] 'FLG_MAINTAIN_OBJECT_TYPELIST, FLG_ENABLE_HANDLE_TYPE_TAGGING'

            if (($Flags -band $RequiredFlags) -ne $RequiredFlags)
            {
                Write-Error 'Global flags FLG_MAINTAIN_OBJECT_TYPELIST and FLG_ENABLE_HANDLE_TYPE_TAGGING have not been set. They must be set in gflags.exe (i.e. `gflags.exe -r +otl +eot`) or in the registry.'
                return
            }

            Write-Warning 'It can take over a minute to return object information. Please be patient.'

            $TotalLength = 1
            $ReturnedLength = 0
            $PtrData = [Runtime.InteropServices.Marshal]::AllocHGlobal($TotalLength)

            while ((($ntdll::NtQuerySystemInformation($SystemInformationClass::SystemObjectInformation, $PtrData, $TotalLength, [Ref] $ReturnedLength) -as [NTSTATUS]) -eq [NTSTATUS]::STATUS_INFO_LENGTH_MISMATCH))
            {
                if ($TotalLength -ne $ReturnedLength)
                {
                    [Runtime.InteropServices.Marshal]::FreeHGlobal($PtrData)
                    $TotalLength = $ReturnedLength
                    $PtrData = [Runtime.InteropServices.Marshal]::AllocHGlobal($TotalLength)
                }
            }

            $NextTypeOffset = 0

            do
            {
                # Base address of the _SYSTEM_OBJECTTYPE_INFORMATION struct
                $ObjectTypeAbsoluteAddress = [IntPtr]($PtrData.ToInt64() + $NextTypeOffset)

                $Result = [Runtime.InteropServices.Marshal]::PtrToStructure($ObjectTypeAbsoluteAddress, [Type] $ObjectTypeClass)

                if ($Result.NumberOfObjects -gt 0)
                {
                    # Calculate the offset to the first _SYSTEM_OBJECT_INFORMATION structure
                    $NextObjectOffset = $Size_SYSTEM_OBJECTTYPE_INFORMATION + $Result.TypeName.MaximumLength
                    $ObjectBaseAddr = $ObjectTypeAbsoluteAddress

                    $ObjectArray = @()

                    do
                    {
                        $ObjectResult = [Runtime.InteropServices.Marshal]::PtrToStructure(( [IntPtr]($ObjectBaseAddr.ToInt64() + $NextObjectOffset) ), [Type] $ObjectClass)

                        $ResultHashTable2 = @{
                            Object = $ObjectResult.Object
                            CreatorUniqueProcess = $ObjectResult.CreatorUniqueProcess
                            CreatorBackTraceIndex = $ObjectResult.CreatorBackTraceIndex
                            Flags = ($ObjectResult.Flags -as $ObjectFlags)
                            PointerCount = $ObjectResult.PointerCount
                            HandleCount = $ObjectResult.HandleCount
                            PagedPoolCharge = $ObjectResult.PagedPoolCharge
                            NonPagedPoolCharge = $ObjectResult.NonPagedPoolCharge
                            ExclusiveProcessId = $ObjectResult.ExclusiveProcessId
                            SecurityDescriptor = $ObjectResult.SecurityDescriptor
                            NameInfo = $ObjectResult.NameInfo.Buffer
                        }

                        $Object = New-Object PSObject -Property $ResultHashTable2
                        $Object.PSObject.TypeNames.Insert(0, '_SYSTEM_OBJECT_INFORMATION')

                        $ObjectArray += $Object

                        $NextObjectOffset = $ObjectResult.NextEntryOffset
                        $ObjectBaseAddr = $PtrData
                    } while ($ObjectResult.NextEntryOffset -ne 0)
                }

                $Access = ( ($_.ValidAccessMask -band 0xFFFF0000) -as $AccessMask )
                if ($Access -eq 0) {$AccessValue = $null} else {$AccessValue = $Access}

                $ResultHashTable = @{
                    NumberOfObjects = $Result.NumberOfObjects
                    NumberOfHandles = $Result.NumberOfHandles
                    TypeIndex = $Result.TypeIndex
                    InvalidAttributes = ($Result.InvalidAttributes -as $ObjectAttributes)
                    GenericMapping = $Result.GenericMapping
                    ValidAccessMask = $AccessValue
                    PoolType = $Result.PoolType
                    SecurityRequired = $Result.SecurityRequired
                    WaitableObject = $Result.WaitableObject
                    TypeName = $Result.TypeName.Buffer
                    Objects = $ObjectArray
                }

                $ObjectType = New-Object PSObject -Property $ResultHashTable
                $ObjectType.PSObject.TypeNames.Insert(0, '_SYSTEM_OBJECTTYPE_INFORMATION')

                Write-Output $ObjectType

                $NextTypeOffset = $Result.NextEntryOffset
            } while ($NextTypeOffset -ne 0)

            [Runtime.InteropServices.Marshal]::FreeHGlobal($PtrData)
        }

        'LockInformation' {
            $Arguments = @{
                InformationClass = $SystemInformationClass::SystemLockInformation
                StructType = $LockInfoClass
                X86Size = 36
                X64Size = 48
                OffsetMultiplier = 1
                ErrorText = 'system lock'
            }

            Get-Struct @Arguments
        }

        'CodeIntegrityInformation' {
            $CIStructLength = 8
            $PtrData = [Runtime.InteropServices.Marshal]::AllocHGlobal($CIStructLength)
            [Runtime.InteropServices.Marshal]::WriteInt64($PtrData, 0)
            [Runtime.InteropServices.Marshal]::WriteByte($PtrData, 8) # The length field in SYSTEM_CODEINTEGRITY_INFORMATION must be set to 8
            $ntdll::NtQuerySystemInformation($SystemInformationClass::SystemCodeIntegrityInformation, $PtrData, $CIStructLength, [Ref] 0) | Out-Null
            $CIInfo = [Runtime.InteropServices.Marshal]::ReadInt32(([IntPtr]($PtrData.ToInt64() + 4)))
            [Runtime.InteropServices.Marshal]::FreeHGlobal($PtrData)

            $ResultHashTable = @{
                CodeIntegrityOptions = $CIInfo
                LockdownState = ($CIInfo -band 0x1C) -as $LockdownState
            }

            $CodeIntegrityType = New-Object PSObject -Property $ResultHashTable
            $CodeIntegrityType.PSObject.TypeNames.Insert(0, '_SYSTEM_CODEINTEGRITY_INFORMATION')

            Write-Output $CodeIntegrityType
        }

        'GlobalFlags' {
            $TotalLength = 0
            $ReturnedLength = 0

            if ((($ntdll::NtQuerySystemInformation($SystemInformationClass::SystemGlobalFlag, [IntPtr]::Zero, 0, [Ref] $TotalLength) -as [NTSTATUS]) -ne [NTSTATUS]::STATUS_INFO_LENGTH_MISMATCH) -and ($TotalLength -gt 0))
            {
                Write-Error 'Unable to obtain global flags information information.'
            }
            else
            {
                $PtrData = [Runtime.InteropServices.Marshal]::AllocHGlobal($TotalLength)
                $ntdll::NtQuerySystemInformation($SystemInformationClass::SystemGlobalFlag, $PtrData, $TotalLength, [Ref] $ReturnedLength) | Out-Null
                $Gflags = [Runtime.InteropServices.Marshal]::ReadInt32($PtrData) -as $GFlagsEnum
                [Runtime.InteropServices.Marshal]::FreeHGlobal($PtrData)

                Write-Output $Gflags
            }
        }

        default { return }
    }
}
#endregion
