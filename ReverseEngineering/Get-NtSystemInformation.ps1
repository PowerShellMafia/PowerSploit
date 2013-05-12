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

.PARAMETER ObjectInformation

    Returns information about user-mode objects and their respective kernel pool
    allocations.

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

        [Parameter( ParameterSetName = 'ObjectInformation' )]
        [Switch]
        $ObjectInformation,

        [Parameter( ParameterSetName = 'GlobalFlags' )]
        [Switch]
        $GlobalFlags
    )

#region Define the assembly/module that will hold all of our dynamic types.
    try { $ntdll = [ntdll] } catch [Management.Automation.RuntimeException] # Only build the assembly if it hasn't already been defined
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

    $FieldOffsetConstructor = [Runtime.InteropServices.FieldOffsetAttribute].GetConstructor([Int])

    $MarshalAsConstructor = [Runtime.InteropServices.MarshalAsAttribute].GetConstructor([Runtime.InteropServices.UnmanagedType])
    $SizeConst = [Runtime.InteropServices.MarshalAsAttribute].GetField('SizeConst')

    $StructAttributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
#endregion

#region Define enum types
    try { $SystemInformationClass = [SYSTEM_INFORMATION_CLASS] } catch [Management.Automation.RuntimeException] # Only build the assembly if it hasn't already been defined
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
        #$EnumBuilder.DefineLiteral('SystemLockInformation', [Int32] 0x0000000C) | Out-Null
        $EnumBuilder.DefineLiteral('SystemHandleInformation', [Int32] 0x00000010) | Out-Null
        $EnumBuilder.DefineLiteral('SystemObjectInformation', [Int32] 0x00000011) | Out-Null
        #$EnumBuilder.DefineLiteral('SystemPagefileInformation', [Int32] 0x00000012) | Out-Null
        #$EnumBuilder.DefineLiteral('SystemInstructionEmulationCounts', [Int32] 0x00000013) | Out-Null
        $EnumBuilder.DefineLiteral('SystemPoolTagInformation', [Int32] 0x00000016) | Out-Null
        #$EnumBuilder.DefineLiteral('SystemInterruptInformation', [Int32] 0x00000017) | Out-Null
        #$EnumBuilder.DefineLiteral('SystemExceptionInformation', [Int32] 0x00000021) | Out-Null
        #$EnumBuilder.DefineLiteral('SystemRegistryQuotaInformation', [Int32] 0x00000025) | Out-Null
        #$EnumBuilder.DefineLiteral('SystemLookasideInformation', [Int32] 0x0000002D) | Out-Null
        $SystemInformationClass = $EnumBuilder.CreateType()
    }

    try { $NtStatus = [NTSTATUS] } catch [Management.Automation.RuntimeException] # Only build the assembly if it hasn't already been defined
    {
        $EnumBuilder = $ModuleBuilder.DefineEnum('NTSTATUS', 'Public', [Int32])
        # The following is generated code generated with the following regex:
        # $generatedCode = Get-Content .\ntstatus.h | ? {$_ -match '^#define\s+(?<Message>\S+)\s+\(\(NTSTATUS\)(?<HexCode>0x[A-Z0-9]{8})L\)'} | % {'$EnumBuilder.DefineLiteral(' + "'" + $Matches.Message + "'" + ", [Int32] $($Matches.HexCode)) | Out-Null"}
        $EnumBuilder.DefineLiteral('STATUS_SUCCESS', [Int32] 0x00000000) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_WAIT_1', [Int32] 0x00000001) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_WAIT_2', [Int32] 0x00000002) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_WAIT_3', [Int32] 0x00000003) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_WAIT_63', [Int32] 0x0000003F) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_ABANDONED', [Int32] 0x00000080) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_ABANDONED_WAIT_63', [Int32] 0x000000BF) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_USER_APC', [Int32] 0x000000C0) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_KERNEL_APC', [Int32] 0x00000100) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_ALERTED', [Int32] 0x00000101) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_TIMEOUT', [Int32] 0x00000102) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_PENDING', [Int32] 0x00000103) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_REPARSE', [Int32] 0x00000104) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_MORE_ENTRIES', [Int32] 0x00000105) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_NOT_ALL_ASSIGNED', [Int32] 0x00000106) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_SOME_NOT_MAPPED', [Int32] 0x00000107) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_OPLOCK_BREAK_IN_PROGRESS', [Int32] 0x00000108) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_VOLUME_MOUNTED', [Int32] 0x00000109) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_RXACT_COMMITTED', [Int32] 0x0000010A) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_NOTIFY_CLEANUP', [Int32] 0x0000010B) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_NOTIFY_ENUM_DIR', [Int32] 0x0000010C) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_NO_QUOTAS_FOR_ACCOUNT', [Int32] 0x0000010D) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_PRIMARY_TRANSPORT_CONNECT_FAILED', [Int32] 0x0000010E) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_PAGE_FAULT_TRANSITION', [Int32] 0x00000110) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_PAGE_FAULT_DEMAND_ZERO', [Int32] 0x00000111) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_PAGE_FAULT_COPY_ON_WRITE', [Int32] 0x00000112) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_PAGE_FAULT_GUARD_PAGE', [Int32] 0x00000113) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_PAGE_FAULT_PAGING_FILE', [Int32] 0x00000114) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_CACHE_PAGE_LOCKED', [Int32] 0x00000115) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_CRASH_DUMP', [Int32] 0x00000116) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_BUFFER_ALL_ZEROS', [Int32] 0x00000117) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_REPARSE_OBJECT', [Int32] 0x00000118) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_RESOURCE_REQUIREMENTS_CHANGED', [Int32] 0x00000119) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_TRANSLATION_COMPLETE', [Int32] 0x00000120) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_DS_MEMBERSHIP_EVALUATED_LOCALLY', [Int32] 0x00000121) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_NOTHING_TO_TERMINATE', [Int32] 0x00000122) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_PROCESS_NOT_IN_JOB', [Int32] 0x00000123) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_PROCESS_IN_JOB', [Int32] 0x00000124) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_VOLSNAP_HIBERNATE_READY', [Int32] 0x00000125) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FSFILTER_OP_COMPLETED_SUCCESSFULLY', [Int32] 0x00000126) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_INTERRUPT_VECTOR_ALREADY_CONNECTED', [Int32] 0x00000127) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_INTERRUPT_STILL_CONNECTED', [Int32] 0x00000128) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_PROCESS_CLONED', [Int32] 0x00000129) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FILE_LOCKED_WITH_ONLY_READERS', [Int32] 0x0000012A) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FILE_LOCKED_WITH_WRITERS', [Int32] 0x0000012B) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_VALID_IMAGE_HASH', [Int32] 0x0000012C) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_RESOURCEMANAGER_READ_ONLY', [Int32] 0x00000202) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_RING_PREVIOUSLY_EMPTY', [Int32] 0x00000210) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_RING_PREVIOUSLY_FULL', [Int32] 0x00000211) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_RING_PREVIOUSLY_ABOVE_QUOTA', [Int32] 0x00000212) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_RING_NEWLY_EMPTY', [Int32] 0x00000213) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_RING_SIGNAL_OPPOSITE_ENDPOINT', [Int32] 0x00000214) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_OPLOCK_SWITCHED_TO_NEW_HANDLE', [Int32] 0x00000215) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_OPLOCK_HANDLE_CLOSED', [Int32] 0x00000216) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_WAIT_FOR_OPLOCK', [Int32] 0x00000367) | Out-Null
        $EnumBuilder.DefineLiteral('DBG_EXCEPTION_HANDLED', [Int32] 0x00010001) | Out-Null
        $EnumBuilder.DefineLiteral('DBG_CONTINUE', [Int32] 0x00010002) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FLT_IO_COMPLETE', [Int32] 0x001C0001) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_DIS_ATTRIBUTE_BUILT', [Int32] 0x003C0001) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_OBJECT_NAME_EXISTS', [Int32] 0x40000000) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_THREAD_WAS_SUSPENDED', [Int32] 0x40000001) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_WORKING_SET_LIMIT_RANGE', [Int32] 0x40000002) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_IMAGE_NOT_AT_BASE', [Int32] 0x40000003) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_RXACT_STATE_CREATED', [Int32] 0x40000004) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_SEGMENT_NOTIFICATION', [Int32] 0x40000005) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_LOCAL_USER_SESSION_KEY', [Int32] 0x40000006) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_BAD_CURRENT_DIRECTORY', [Int32] 0x40000007) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_SERIAL_MORE_WRITES', [Int32] 0x40000008) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_REGISTRY_RECOVERED', [Int32] 0x40000009) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FT_READ_RECOVERY_FROM_BACKUP', [Int32] 0x4000000A) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FT_WRITE_RECOVERY', [Int32] 0x4000000B) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_SERIAL_COUNTER_TIMEOUT', [Int32] 0x4000000C) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_NULL_LM_PASSWORD', [Int32] 0x4000000D) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_IMAGE_MACHINE_TYPE_MISMATCH', [Int32] 0x4000000E) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_RECEIVE_PARTIAL', [Int32] 0x4000000F) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_RECEIVE_EXPEDITED', [Int32] 0x40000010) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_RECEIVE_PARTIAL_EXPEDITED', [Int32] 0x40000011) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_EVENT_DONE', [Int32] 0x40000012) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_EVENT_PENDING', [Int32] 0x40000013) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_CHECKING_FILE_SYSTEM', [Int32] 0x40000014) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FATAL_APP_EXIT', [Int32] 0x40000015) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_PREDEFINED_HANDLE', [Int32] 0x40000016) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_WAS_UNLOCKED', [Int32] 0x40000017) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_SERVICE_NOTIFICATION', [Int32] 0x40000018) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_WAS_LOCKED', [Int32] 0x40000019) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_LOG_HARD_ERROR', [Int32] 0x4000001A) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_ALREADY_WIN32', [Int32] 0x4000001B) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_WX86_UNSIMULATE', [Int32] 0x4000001C) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_WX86_CONTINUE', [Int32] 0x4000001D) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_WX86_SINGLE_STEP', [Int32] 0x4000001E) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_WX86_BREAKPOINT', [Int32] 0x4000001F) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_WX86_EXCEPTION_CONTINUE', [Int32] 0x40000020) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_WX86_EXCEPTION_LASTCHANCE', [Int32] 0x40000021) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_WX86_EXCEPTION_CHAIN', [Int32] 0x40000022) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_IMAGE_MACHINE_TYPE_MISMATCH_EXE', [Int32] 0x40000023) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_NO_YIELD_PERFORMED', [Int32] 0x40000024) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_TIMER_RESUME_IGNORED', [Int32] 0x40000025) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_ARBITRATION_UNHANDLED', [Int32] 0x40000026) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_CARDBUS_NOT_SUPPORTED', [Int32] 0x40000027) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_WX86_CREATEWX86TIB', [Int32] 0x40000028) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_MP_PROCESSOR_MISMATCH', [Int32] 0x40000029) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_HIBERNATED', [Int32] 0x4000002A) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_RESUME_HIBERNATION', [Int32] 0x4000002B) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FIRMWARE_UPDATED', [Int32] 0x4000002C) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_DRIVERS_LEAKING_LOCKED_PAGES', [Int32] 0x4000002D) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_MESSAGE_RETRIEVED', [Int32] 0x4000002E) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_SYSTEM_POWERSTATE_TRANSITION', [Int32] 0x4000002F) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_ALPC_CHECK_COMPLETION_LIST', [Int32] 0x40000030) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_SYSTEM_POWERSTATE_COMPLEX_TRANSITION', [Int32] 0x40000031) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_ACCESS_AUDIT_BY_POLICY', [Int32] 0x40000032) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_ABANDON_HIBERFILE', [Int32] 0x40000033) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_BIZRULES_NOT_ENABLED', [Int32] 0x40000034) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FT_READ_FROM_COPY', [Int32] 0x40000035) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_IMAGE_AT_DIFFERENT_BASE', [Int32] 0x40000036) | Out-Null
        $EnumBuilder.DefineLiteral('DBG_REPLY_LATER', [Int32] 0x40010001) | Out-Null
        $EnumBuilder.DefineLiteral('DBG_UNABLE_TO_PROVIDE_HANDLE', [Int32] 0x40010002) | Out-Null
        $EnumBuilder.DefineLiteral('DBG_TERMINATE_THREAD', [Int32] 0x40010003) | Out-Null
        $EnumBuilder.DefineLiteral('DBG_TERMINATE_PROCESS', [Int32] 0x40010004) | Out-Null
        $EnumBuilder.DefineLiteral('DBG_CONTROL_C', [Int32] 0x40010005) | Out-Null
        $EnumBuilder.DefineLiteral('DBG_PRINTEXCEPTION_C', [Int32] 0x40010006) | Out-Null
        $EnumBuilder.DefineLiteral('DBG_RIPEXCEPTION', [Int32] 0x40010007) | Out-Null
        $EnumBuilder.DefineLiteral('DBG_CONTROL_BREAK', [Int32] 0x40010008) | Out-Null
        $EnumBuilder.DefineLiteral('DBG_COMMAND_EXCEPTION', [Int32] 0x40010009) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_HEURISTIC_DAMAGE_POSSIBLE', [Int32] 0x40190001) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_GUARD_PAGE_VIOLATION', [Int32] 0x80000001) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_DATATYPE_MISALIGNMENT', [Int32] 0x80000002) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_BREAKPOINT', [Int32] 0x80000003) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_SINGLE_STEP', [Int32] 0x80000004) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_BUFFER_OVERFLOW', [Int32] 0x80000005) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_NO_MORE_FILES', [Int32] 0x80000006) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_WAKE_SYSTEM_DEBUGGER', [Int32] 0x80000007) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_HANDLES_CLOSED', [Int32] 0x8000000A) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_NO_INHERITANCE', [Int32] 0x8000000B) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_GUID_SUBSTITUTION_MADE', [Int32] 0x8000000C) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_PARTIAL_COPY', [Int32] 0x8000000D) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_DEVICE_PAPER_EMPTY', [Int32] 0x8000000E) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_DEVICE_POWERED_OFF', [Int32] 0x8000000F) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_DEVICE_OFF_LINE', [Int32] 0x80000010) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_DEVICE_BUSY', [Int32] 0x80000011) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_NO_MORE_EAS', [Int32] 0x80000012) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_INVALID_EA_NAME', [Int32] 0x80000013) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_EA_LIST_INCONSISTENT', [Int32] 0x80000014) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_INVALID_EA_FLAG', [Int32] 0x80000015) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_VERIFY_REQUIRED', [Int32] 0x80000016) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_EXTRANEOUS_INFORMATION', [Int32] 0x80000017) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_RXACT_COMMIT_NECESSARY', [Int32] 0x80000018) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_NO_MORE_ENTRIES', [Int32] 0x8000001A) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FILEMARK_DETECTED', [Int32] 0x8000001B) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_MEDIA_CHANGED', [Int32] 0x8000001C) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_BUS_RESET', [Int32] 0x8000001D) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_END_OF_MEDIA', [Int32] 0x8000001E) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_BEGINNING_OF_MEDIA', [Int32] 0x8000001F) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_MEDIA_CHECK', [Int32] 0x80000020) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_SETMARK_DETECTED', [Int32] 0x80000021) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_NO_DATA_DETECTED', [Int32] 0x80000022) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_REDIRECTOR_HAS_OPEN_HANDLES', [Int32] 0x80000023) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_SERVER_HAS_OPEN_HANDLES', [Int32] 0x80000024) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_ALREADY_DISCONNECTED', [Int32] 0x80000025) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_LONGJUMP', [Int32] 0x80000026) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_CLEANER_CARTRIDGE_INSTALLED', [Int32] 0x80000027) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_PLUGPLAY_QUERY_VETOED', [Int32] 0x80000028) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_UNWIND_CONSOLIDATE', [Int32] 0x80000029) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_REGISTRY_HIVE_RECOVERED', [Int32] 0x8000002A) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_DLL_MIGHT_BE_INSECURE', [Int32] 0x8000002B) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_DLL_MIGHT_BE_INCOMPATIBLE', [Int32] 0x8000002C) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_STOPPED_ON_SYMLINK', [Int32] 0x8000002D) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_CANNOT_GRANT_REQUESTED_OPLOCK', [Int32] 0x8000002E) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_NO_ACE_CONDITION', [Int32] 0x8000002F) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_DEVICE_SUPPORT_IN_PROGRESS', [Int32] 0x80000030) | Out-Null
        $EnumBuilder.DefineLiteral('DBG_EXCEPTION_NOT_HANDLED', [Int32] 0x80010001) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_CLUSTER_NODE_ALREADY_UP', [Int32] 0x80130001) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_CLUSTER_NODE_ALREADY_DOWN', [Int32] 0x80130002) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_CLUSTER_NETWORK_ALREADY_ONLINE', [Int32] 0x80130003) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_CLUSTER_NETWORK_ALREADY_OFFLINE', [Int32] 0x80130004) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_CLUSTER_NODE_ALREADY_MEMBER', [Int32] 0x80130005) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FLT_BUFFER_TOO_SMALL', [Int32] 0x801C0001) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FVE_PARTIAL_METADATA', [Int32] 0x80210001) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FVE_TRANSIENT_STATE', [Int32] 0x80210002) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_UNSUCCESSFUL', [Int32] 0xC0000001) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_NOT_IMPLEMENTED', [Int32] 0xC0000002) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_INVALID_INFO_CLASS', [Int32] 0xC0000003) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_INFO_LENGTH_MISMATCH', [Int32] 0xC0000004) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_ACCESS_VIOLATION', [Int32] 0xC0000005) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_IN_PAGE_ERROR', [Int32] 0xC0000006) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_PAGEFILE_QUOTA', [Int32] 0xC0000007) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_INVALID_HANDLE', [Int32] 0xC0000008) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_BAD_INITIAL_STACK', [Int32] 0xC0000009) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_BAD_INITIAL_PC', [Int32] 0xC000000A) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_INVALID_CID', [Int32] 0xC000000B) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_TIMER_NOT_CANCELED', [Int32] 0xC000000C) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_INVALID_PARAMETER', [Int32] 0xC000000D) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_NO_SUCH_DEVICE', [Int32] 0xC000000E) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_NO_SUCH_FILE', [Int32] 0xC000000F) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_INVALID_DEVICE_REQUEST', [Int32] 0xC0000010) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_END_OF_FILE', [Int32] 0xC0000011) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_WRONG_VOLUME', [Int32] 0xC0000012) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_NO_MEDIA_IN_DEVICE', [Int32] 0xC0000013) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_UNRECOGNIZED_MEDIA', [Int32] 0xC0000014) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_NONEXISTENT_SECTOR', [Int32] 0xC0000015) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_MORE_PROCESSING_REQUIRED', [Int32] 0xC0000016) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_NO_MEMORY', [Int32] 0xC0000017) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_CONFLICTING_ADDRESSES', [Int32] 0xC0000018) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_NOT_MAPPED_VIEW', [Int32] 0xC0000019) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_UNABLE_TO_FREE_VM', [Int32] 0xC000001A) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_UNABLE_TO_DELETE_SECTION', [Int32] 0xC000001B) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_INVALID_SYSTEM_SERVICE', [Int32] 0xC000001C) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_ILLEGAL_INSTRUCTION', [Int32] 0xC000001D) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_INVALID_LOCK_SEQUENCE', [Int32] 0xC000001E) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_INVALID_VIEW_SIZE', [Int32] 0xC000001F) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_INVALID_FILE_FOR_SECTION', [Int32] 0xC0000020) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_ALREADY_COMMITTED', [Int32] 0xC0000021) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_ACCESS_DENIED', [Int32] 0xC0000022) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_BUFFER_TOO_SMALL', [Int32] 0xC0000023) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_OBJECT_TYPE_MISMATCH', [Int32] 0xC0000024) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_NONCONTINUABLE_EXCEPTION', [Int32] 0xC0000025) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_INVALID_DISPOSITION', [Int32] 0xC0000026) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_UNWIND', [Int32] 0xC0000027) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_BAD_STACK', [Int32] 0xC0000028) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_INVALID_UNWIND_TARGET', [Int32] 0xC0000029) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_NOT_LOCKED', [Int32] 0xC000002A) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_PARITY_ERROR', [Int32] 0xC000002B) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_UNABLE_TO_DECOMMIT_VM', [Int32] 0xC000002C) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_NOT_COMMITTED', [Int32] 0xC000002D) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_INVALID_PORT_ATTRIBUTES', [Int32] 0xC000002E) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_PORT_MESSAGE_TOO_LONG', [Int32] 0xC000002F) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_INVALID_PARAMETER_MIX', [Int32] 0xC0000030) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_INVALID_QUOTA_LOWER', [Int32] 0xC0000031) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_DISK_CORRUPT_ERROR', [Int32] 0xC0000032) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_OBJECT_NAME_INVALID', [Int32] 0xC0000033) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_OBJECT_NAME_NOT_FOUND', [Int32] 0xC0000034) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_OBJECT_NAME_COLLISION', [Int32] 0xC0000035) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_PORT_DISCONNECTED', [Int32] 0xC0000037) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_DEVICE_ALREADY_ATTACHED', [Int32] 0xC0000038) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_OBJECT_PATH_INVALID', [Int32] 0xC0000039) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_OBJECT_PATH_NOT_FOUND', [Int32] 0xC000003A) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_OBJECT_PATH_SYNTAX_BAD', [Int32] 0xC000003B) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_DATA_OVERRUN', [Int32] 0xC000003C) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_DATA_LATE_ERROR', [Int32] 0xC000003D) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_DATA_ERROR', [Int32] 0xC000003E) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_CRC_ERROR', [Int32] 0xC000003F) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_SECTION_TOO_BIG', [Int32] 0xC0000040) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_PORT_CONNECTION_REFUSED', [Int32] 0xC0000041) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_INVALID_PORT_HANDLE', [Int32] 0xC0000042) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_SHARING_VIOLATION', [Int32] 0xC0000043) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_QUOTA_EXCEEDED', [Int32] 0xC0000044) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_INVALID_PAGE_PROTECTION', [Int32] 0xC0000045) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_MUTANT_NOT_OWNED', [Int32] 0xC0000046) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_SEMAPHORE_LIMIT_EXCEEDED', [Int32] 0xC0000047) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_PORT_ALREADY_SET', [Int32] 0xC0000048) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_SECTION_NOT_IMAGE', [Int32] 0xC0000049) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_SUSPEND_COUNT_EXCEEDED', [Int32] 0xC000004A) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_THREAD_IS_TERMINATING', [Int32] 0xC000004B) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_BAD_WORKING_SET_LIMIT', [Int32] 0xC000004C) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_INCOMPATIBLE_FILE_MAP', [Int32] 0xC000004D) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_SECTION_PROTECTION', [Int32] 0xC000004E) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_EAS_NOT_SUPPORTED', [Int32] 0xC000004F) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_EA_TOO_LARGE', [Int32] 0xC0000050) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_NONEXISTENT_EA_ENTRY', [Int32] 0xC0000051) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_NO_EAS_ON_FILE', [Int32] 0xC0000052) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_EA_CORRUPT_ERROR', [Int32] 0xC0000053) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FILE_LOCK_CONFLICT', [Int32] 0xC0000054) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_LOCK_NOT_GRANTED', [Int32] 0xC0000055) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_DELETE_PENDING', [Int32] 0xC0000056) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_CTL_FILE_NOT_SUPPORTED', [Int32] 0xC0000057) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_UNKNOWN_REVISION', [Int32] 0xC0000058) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_REVISION_MISMATCH', [Int32] 0xC0000059) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_INVALID_OWNER', [Int32] 0xC000005A) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_INVALID_PRIMARY_GROUP', [Int32] 0xC000005B) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_NO_IMPERSONATION_TOKEN', [Int32] 0xC000005C) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_CANT_DISABLE_MANDATORY', [Int32] 0xC000005D) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_NO_LOGON_SERVERS', [Int32] 0xC000005E) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_NO_SUCH_LOGON_SESSION', [Int32] 0xC000005F) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_NO_SUCH_PRIVILEGE', [Int32] 0xC0000060) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_PRIVILEGE_NOT_HELD', [Int32] 0xC0000061) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_INVALID_ACCOUNT_NAME', [Int32] 0xC0000062) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_USER_EXISTS', [Int32] 0xC0000063) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_NO_SUCH_USER', [Int32] 0xC0000064) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_GROUP_EXISTS', [Int32] 0xC0000065) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_NO_SUCH_GROUP', [Int32] 0xC0000066) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_MEMBER_IN_GROUP', [Int32] 0xC0000067) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_MEMBER_NOT_IN_GROUP', [Int32] 0xC0000068) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_LAST_ADMIN', [Int32] 0xC0000069) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_WRONG_PASSWORD', [Int32] 0xC000006A) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_ILL_FORMED_PASSWORD', [Int32] 0xC000006B) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_PASSWORD_RESTRICTION', [Int32] 0xC000006C) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_LOGON_FAILURE', [Int32] 0xC000006D) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_ACCOUNT_RESTRICTION', [Int32] 0xC000006E) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_INVALID_LOGON_HOURS', [Int32] 0xC000006F) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_INVALID_WORKSTATION', [Int32] 0xC0000070) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_PASSWORD_EXPIRED', [Int32] 0xC0000071) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_ACCOUNT_DISABLED', [Int32] 0xC0000072) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_NONE_MAPPED', [Int32] 0xC0000073) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_TOO_MANY_LUIDS_REQUESTED', [Int32] 0xC0000074) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_LUIDS_EXHAUSTED', [Int32] 0xC0000075) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_INVALID_SUB_AUTHORITY', [Int32] 0xC0000076) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_INVALID_ACL', [Int32] 0xC0000077) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_INVALID_SID', [Int32] 0xC0000078) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_INVALID_SECURITY_DESCR', [Int32] 0xC0000079) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_PROCEDURE_NOT_FOUND', [Int32] 0xC000007A) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_INVALID_IMAGE_FORMAT', [Int32] 0xC000007B) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_NO_TOKEN', [Int32] 0xC000007C) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_BAD_INHERITANCE_ACL', [Int32] 0xC000007D) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_RANGE_NOT_LOCKED', [Int32] 0xC000007E) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_DISK_FULL', [Int32] 0xC000007F) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_SERVER_DISABLED', [Int32] 0xC0000080) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_SERVER_NOT_DISABLED', [Int32] 0xC0000081) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_TOO_MANY_GUIDS_REQUESTED', [Int32] 0xC0000082) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_GUIDS_EXHAUSTED', [Int32] 0xC0000083) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_INVALID_ID_AUTHORITY', [Int32] 0xC0000084) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_AGENTS_EXHAUSTED', [Int32] 0xC0000085) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_INVALID_VOLUME_LABEL', [Int32] 0xC0000086) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_SECTION_NOT_EXTENDED', [Int32] 0xC0000087) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_NOT_MAPPED_DATA', [Int32] 0xC0000088) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_RESOURCE_DATA_NOT_FOUND', [Int32] 0xC0000089) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_RESOURCE_TYPE_NOT_FOUND', [Int32] 0xC000008A) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_RESOURCE_NAME_NOT_FOUND', [Int32] 0xC000008B) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_ARRAY_BOUNDS_EXCEEDED', [Int32] 0xC000008C) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FLOAT_DENORMAL_OPERAND', [Int32] 0xC000008D) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FLOAT_DIVIDE_BY_ZERO', [Int32] 0xC000008E) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FLOAT_INEXACT_RESULT', [Int32] 0xC000008F) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FLOAT_INVALID_OPERATION', [Int32] 0xC0000090) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FLOAT_OVERFLOW', [Int32] 0xC0000091) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FLOAT_STACK_CHECK', [Int32] 0xC0000092) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FLOAT_UNDERFLOW', [Int32] 0xC0000093) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_INTEGER_DIVIDE_BY_ZERO', [Int32] 0xC0000094) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_INTEGER_OVERFLOW', [Int32] 0xC0000095) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_PRIVILEGED_INSTRUCTION', [Int32] 0xC0000096) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_TOO_MANY_PAGING_FILES', [Int32] 0xC0000097) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FILE_INVALID', [Int32] 0xC0000098) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_ALLOTTED_SPACE_EXCEEDED', [Int32] 0xC0000099) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_INSUFFICIENT_RESOURCES', [Int32] 0xC000009A) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_DFS_EXIT_PATH_FOUND', [Int32] 0xC000009B) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_DEVICE_DATA_ERROR', [Int32] 0xC000009C) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_DEVICE_NOT_CONNECTED', [Int32] 0xC000009D) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_DEVICE_POWER_FAILURE', [Int32] 0xC000009E) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FREE_VM_NOT_AT_BASE', [Int32] 0xC000009F) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_MEMORY_NOT_ALLOCATED', [Int32] 0xC00000A0) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_WORKING_SET_QUOTA', [Int32] 0xC00000A1) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_MEDIA_WRITE_PROTECTED', [Int32] 0xC00000A2) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_DEVICE_NOT_READY', [Int32] 0xC00000A3) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_INVALID_GROUP_ATTRIBUTES', [Int32] 0xC00000A4) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_BAD_IMPERSONATION_LEVEL', [Int32] 0xC00000A5) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_CANT_OPEN_ANONYMOUS', [Int32] 0xC00000A6) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_BAD_VALIDATION_CLASS', [Int32] 0xC00000A7) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_BAD_TOKEN_TYPE', [Int32] 0xC00000A8) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_BAD_MASTER_BOOT_RECORD', [Int32] 0xC00000A9) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_INSTRUCTION_MISALIGNMENT', [Int32] 0xC00000AA) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_INSTANCE_NOT_AVAILABLE', [Int32] 0xC00000AB) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_PIPE_NOT_AVAILABLE', [Int32] 0xC00000AC) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_INVALID_PIPE_STATE', [Int32] 0xC00000AD) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_PIPE_BUSY', [Int32] 0xC00000AE) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_ILLEGAL_FUNCTION', [Int32] 0xC00000AF) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_PIPE_DISCONNECTED', [Int32] 0xC00000B0) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_PIPE_CLOSING', [Int32] 0xC00000B1) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_PIPE_CONNECTED', [Int32] 0xC00000B2) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_PIPE_LISTENING', [Int32] 0xC00000B3) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_INVALID_READ_MODE', [Int32] 0xC00000B4) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_IO_TIMEOUT', [Int32] 0xC00000B5) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FILE_FORCED_CLOSED', [Int32] 0xC00000B6) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_PROFILING_NOT_STARTED', [Int32] 0xC00000B7) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_PROFILING_NOT_STOPPED', [Int32] 0xC00000B8) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_COULD_NOT_INTERPRET', [Int32] 0xC00000B9) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FILE_IS_A_DIRECTORY', [Int32] 0xC00000BA) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_NOT_SUPPORTED', [Int32] 0xC00000BB) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_REMOTE_NOT_LISTENING', [Int32] 0xC00000BC) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_DUPLICATE_NAME', [Int32] 0xC00000BD) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_BAD_NETWORK_PATH', [Int32] 0xC00000BE) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_NETWORK_BUSY', [Int32] 0xC00000BF) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_DEVICE_DOES_NOT_EXIST', [Int32] 0xC00000C0) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_TOO_MANY_COMMANDS', [Int32] 0xC00000C1) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_ADAPTER_HARDWARE_ERROR', [Int32] 0xC00000C2) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_INVALID_NETWORK_RESPONSE', [Int32] 0xC00000C3) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_UNEXPECTED_NETWORK_ERROR', [Int32] 0xC00000C4) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_BAD_REMOTE_ADAPTER', [Int32] 0xC00000C5) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_PRINT_QUEUE_FULL', [Int32] 0xC00000C6) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_NO_SPOOL_SPACE', [Int32] 0xC00000C7) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_PRINT_CANCELLED', [Int32] 0xC00000C8) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_NETWORK_NAME_DELETED', [Int32] 0xC00000C9) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_NETWORK_ACCESS_DENIED', [Int32] 0xC00000CA) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_BAD_DEVICE_TYPE', [Int32] 0xC00000CB) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_BAD_NETWORK_NAME', [Int32] 0xC00000CC) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_TOO_MANY_NAMES', [Int32] 0xC00000CD) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_TOO_MANY_SESSIONS', [Int32] 0xC00000CE) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_SHARING_PAUSED', [Int32] 0xC00000CF) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_REQUEST_NOT_ACCEPTED', [Int32] 0xC00000D0) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_REDIRECTOR_PAUSED', [Int32] 0xC00000D1) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_NET_WRITE_FAULT', [Int32] 0xC00000D2) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_PROFILING_AT_LIMIT', [Int32] 0xC00000D3) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_NOT_SAME_DEVICE', [Int32] 0xC00000D4) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FILE_RENAMED', [Int32] 0xC00000D5) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_VIRTUAL_CIRCUIT_CLOSED', [Int32] 0xC00000D6) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_NO_SECURITY_ON_OBJECT', [Int32] 0xC00000D7) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_CANT_WAIT', [Int32] 0xC00000D8) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_PIPE_EMPTY', [Int32] 0xC00000D9) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_CANT_ACCESS_DOMAIN_INFO', [Int32] 0xC00000DA) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_CANT_TERMINATE_SELF', [Int32] 0xC00000DB) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_INVALID_SERVER_STATE', [Int32] 0xC00000DC) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_INVALID_DOMAIN_STATE', [Int32] 0xC00000DD) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_INVALID_DOMAIN_ROLE', [Int32] 0xC00000DE) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_NO_SUCH_DOMAIN', [Int32] 0xC00000DF) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_DOMAIN_EXISTS', [Int32] 0xC00000E0) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_DOMAIN_LIMIT_EXCEEDED', [Int32] 0xC00000E1) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_OPLOCK_NOT_GRANTED', [Int32] 0xC00000E2) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_INVALID_OPLOCK_PROTOCOL', [Int32] 0xC00000E3) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_INTERNAL_DB_CORRUPTION', [Int32] 0xC00000E4) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_INTERNAL_ERROR', [Int32] 0xC00000E5) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_GENERIC_NOT_MAPPED', [Int32] 0xC00000E6) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_BAD_DESCRIPTOR_FORMAT', [Int32] 0xC00000E7) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_INVALID_USER_BUFFER', [Int32] 0xC00000E8) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_UNEXPECTED_IO_ERROR', [Int32] 0xC00000E9) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_UNEXPECTED_MM_CREATE_ERR', [Int32] 0xC00000EA) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_UNEXPECTED_MM_MAP_ERROR', [Int32] 0xC00000EB) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_UNEXPECTED_MM_EXTEND_ERR', [Int32] 0xC00000EC) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_NOT_LOGON_PROCESS', [Int32] 0xC00000ED) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_LOGON_SESSION_EXISTS', [Int32] 0xC00000EE) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_INVALID_PARAMETER_1', [Int32] 0xC00000EF) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_INVALID_PARAMETER_2', [Int32] 0xC00000F0) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_INVALID_PARAMETER_3', [Int32] 0xC00000F1) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_INVALID_PARAMETER_4', [Int32] 0xC00000F2) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_INVALID_PARAMETER_5', [Int32] 0xC00000F3) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_INVALID_PARAMETER_6', [Int32] 0xC00000F4) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_INVALID_PARAMETER_7', [Int32] 0xC00000F5) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_INVALID_PARAMETER_8', [Int32] 0xC00000F6) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_INVALID_PARAMETER_9', [Int32] 0xC00000F7) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_INVALID_PARAMETER_10', [Int32] 0xC00000F8) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_INVALID_PARAMETER_11', [Int32] 0xC00000F9) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_INVALID_PARAMETER_12', [Int32] 0xC00000FA) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_REDIRECTOR_NOT_STARTED', [Int32] 0xC00000FB) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_REDIRECTOR_STARTED', [Int32] 0xC00000FC) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_STACK_OVERFLOW', [Int32] 0xC00000FD) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_NO_SUCH_PACKAGE', [Int32] 0xC00000FE) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_BAD_FUNCTION_TABLE', [Int32] 0xC00000FF) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_VARIABLE_NOT_FOUND', [Int32] 0xC0000100) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_DIRECTORY_NOT_EMPTY', [Int32] 0xC0000101) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FILE_CORRUPT_ERROR', [Int32] 0xC0000102) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_NOT_A_DIRECTORY', [Int32] 0xC0000103) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_BAD_LOGON_SESSION_STATE', [Int32] 0xC0000104) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_LOGON_SESSION_COLLISION', [Int32] 0xC0000105) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_NAME_TOO_LONG', [Int32] 0xC0000106) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FILES_OPEN', [Int32] 0xC0000107) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_CONNECTION_IN_USE', [Int32] 0xC0000108) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_MESSAGE_NOT_FOUND', [Int32] 0xC0000109) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_PROCESS_IS_TERMINATING', [Int32] 0xC000010A) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_INVALID_LOGON_TYPE', [Int32] 0xC000010B) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_NO_GUID_TRANSLATION', [Int32] 0xC000010C) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_CANNOT_IMPERSONATE', [Int32] 0xC000010D) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_IMAGE_ALREADY_LOADED', [Int32] 0xC000010E) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_ABIOS_NOT_PRESENT', [Int32] 0xC000010F) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_ABIOS_LID_NOT_EXIST', [Int32] 0xC0000110) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_ABIOS_LID_ALREADY_OWNED', [Int32] 0xC0000111) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_ABIOS_NOT_LID_OWNER', [Int32] 0xC0000112) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_ABIOS_INVALID_COMMAND', [Int32] 0xC0000113) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_ABIOS_INVALID_LID', [Int32] 0xC0000114) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_ABIOS_SELECTOR_NOT_AVAILABLE', [Int32] 0xC0000115) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_ABIOS_INVALID_SELECTOR', [Int32] 0xC0000116) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_NO_LDT', [Int32] 0xC0000117) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_INVALID_LDT_SIZE', [Int32] 0xC0000118) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_INVALID_LDT_OFFSET', [Int32] 0xC0000119) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_INVALID_LDT_DESCRIPTOR', [Int32] 0xC000011A) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_INVALID_IMAGE_NE_FORMAT', [Int32] 0xC000011B) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_RXACT_INVALID_STATE', [Int32] 0xC000011C) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_RXACT_COMMIT_FAILURE', [Int32] 0xC000011D) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_MAPPED_FILE_SIZE_ZERO', [Int32] 0xC000011E) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_TOO_MANY_OPENED_FILES', [Int32] 0xC000011F) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_CANCELLED', [Int32] 0xC0000120) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_CANNOT_DELETE', [Int32] 0xC0000121) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_INVALID_COMPUTER_NAME', [Int32] 0xC0000122) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FILE_DELETED', [Int32] 0xC0000123) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_SPECIAL_ACCOUNT', [Int32] 0xC0000124) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_SPECIAL_GROUP', [Int32] 0xC0000125) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_SPECIAL_USER', [Int32] 0xC0000126) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_MEMBERS_PRIMARY_GROUP', [Int32] 0xC0000127) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FILE_CLOSED', [Int32] 0xC0000128) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_TOO_MANY_THREADS', [Int32] 0xC0000129) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_THREAD_NOT_IN_PROCESS', [Int32] 0xC000012A) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_TOKEN_ALREADY_IN_USE', [Int32] 0xC000012B) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_PAGEFILE_QUOTA_EXCEEDED', [Int32] 0xC000012C) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_COMMITMENT_LIMIT', [Int32] 0xC000012D) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_INVALID_IMAGE_LE_FORMAT', [Int32] 0xC000012E) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_INVALID_IMAGE_NOT_MZ', [Int32] 0xC000012F) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_INVALID_IMAGE_PROTECT', [Int32] 0xC0000130) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_INVALID_IMAGE_WIN_16', [Int32] 0xC0000131) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_LOGON_SERVER_CONFLICT', [Int32] 0xC0000132) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_TIME_DIFFERENCE_AT_DC', [Int32] 0xC0000133) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_SYNCHRONIZATION_REQUIRED', [Int32] 0xC0000134) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_DLL_NOT_FOUND', [Int32] 0xC0000135) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_OPEN_FAILED', [Int32] 0xC0000136) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_IO_PRIVILEGE_FAILED', [Int32] 0xC0000137) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_ORDINAL_NOT_FOUND', [Int32] 0xC0000138) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_ENTRYPOINT_NOT_FOUND', [Int32] 0xC0000139) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_CONTROL_C_EXIT', [Int32] 0xC000013A) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_LOCAL_DISCONNECT', [Int32] 0xC000013B) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_REMOTE_DISCONNECT', [Int32] 0xC000013C) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_REMOTE_RESOURCES', [Int32] 0xC000013D) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_LINK_FAILED', [Int32] 0xC000013E) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_LINK_TIMEOUT', [Int32] 0xC000013F) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_INVALID_CONNECTION', [Int32] 0xC0000140) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_INVALID_ADDRESS', [Int32] 0xC0000141) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_DLL_INIT_FAILED', [Int32] 0xC0000142) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_MISSING_SYSTEMFILE', [Int32] 0xC0000143) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_UNHANDLED_EXCEPTION', [Int32] 0xC0000144) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_APP_INIT_FAILURE', [Int32] 0xC0000145) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_PAGEFILE_CREATE_FAILED', [Int32] 0xC0000146) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_NO_PAGEFILE', [Int32] 0xC0000147) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_INVALID_LEVEL', [Int32] 0xC0000148) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_WRONG_PASSWORD_CORE', [Int32] 0xC0000149) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_ILLEGAL_FLOAT_CONTEXT', [Int32] 0xC000014A) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_PIPE_BROKEN', [Int32] 0xC000014B) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_REGISTRY_CORRUPT', [Int32] 0xC000014C) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_REGISTRY_IO_FAILED', [Int32] 0xC000014D) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_NO_EVENT_PAIR', [Int32] 0xC000014E) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_UNRECOGNIZED_VOLUME', [Int32] 0xC000014F) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_SERIAL_NO_DEVICE_INITED', [Int32] 0xC0000150) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_NO_SUCH_ALIAS', [Int32] 0xC0000151) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_MEMBER_NOT_IN_ALIAS', [Int32] 0xC0000152) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_MEMBER_IN_ALIAS', [Int32] 0xC0000153) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_ALIAS_EXISTS', [Int32] 0xC0000154) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_LOGON_NOT_GRANTED', [Int32] 0xC0000155) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_TOO_MANY_SECRETS', [Int32] 0xC0000156) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_SECRET_TOO_LONG', [Int32] 0xC0000157) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_INTERNAL_DB_ERROR', [Int32] 0xC0000158) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FULLSCREEN_MODE', [Int32] 0xC0000159) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_TOO_MANY_CONTEXT_IDS', [Int32] 0xC000015A) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_LOGON_TYPE_NOT_GRANTED', [Int32] 0xC000015B) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_NOT_REGISTRY_FILE', [Int32] 0xC000015C) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_NT_CROSS_ENCRYPTION_REQUIRED', [Int32] 0xC000015D) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_DOMAIN_CTRLR_CONFIG_ERROR', [Int32] 0xC000015E) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FT_MISSING_MEMBER', [Int32] 0xC000015F) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_ILL_FORMED_SERVICE_ENTRY', [Int32] 0xC0000160) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_ILLEGAL_CHARACTER', [Int32] 0xC0000161) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_UNMAPPABLE_CHARACTER', [Int32] 0xC0000162) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_UNDEFINED_CHARACTER', [Int32] 0xC0000163) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FLOPPY_VOLUME', [Int32] 0xC0000164) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FLOPPY_ID_MARK_NOT_FOUND', [Int32] 0xC0000165) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FLOPPY_WRONG_CYLINDER', [Int32] 0xC0000166) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FLOPPY_UNKNOWN_ERROR', [Int32] 0xC0000167) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FLOPPY_BAD_REGISTERS', [Int32] 0xC0000168) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_DISK_RECALIBRATE_FAILED', [Int32] 0xC0000169) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_DISK_OPERATION_FAILED', [Int32] 0xC000016A) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_DISK_RESET_FAILED', [Int32] 0xC000016B) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_SHARED_IRQ_BUSY', [Int32] 0xC000016C) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FT_ORPHANING', [Int32] 0xC000016D) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_BIOS_FAILED_TO_CONNECT_INTERRUPT', [Int32] 0xC000016E) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_PARTITION_FAILURE', [Int32] 0xC0000172) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_INVALID_BLOCK_LENGTH', [Int32] 0xC0000173) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_DEVICE_NOT_PARTITIONED', [Int32] 0xC0000174) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_UNABLE_TO_LOCK_MEDIA', [Int32] 0xC0000175) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_UNABLE_TO_UNLOAD_MEDIA', [Int32] 0xC0000176) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_EOM_OVERFLOW', [Int32] 0xC0000177) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_NO_MEDIA', [Int32] 0xC0000178) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_NO_SUCH_MEMBER', [Int32] 0xC000017A) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_INVALID_MEMBER', [Int32] 0xC000017B) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_KEY_DELETED', [Int32] 0xC000017C) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_NO_LOG_SPACE', [Int32] 0xC000017D) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_TOO_MANY_SIDS', [Int32] 0xC000017E) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_LM_CROSS_ENCRYPTION_REQUIRED', [Int32] 0xC000017F) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_KEY_HAS_CHILDREN', [Int32] 0xC0000180) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_CHILD_MUST_BE_VOLATILE', [Int32] 0xC0000181) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_DEVICE_CONFIGURATION_ERROR', [Int32] 0xC0000182) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_DRIVER_INTERNAL_ERROR', [Int32] 0xC0000183) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_INVALID_DEVICE_STATE', [Int32] 0xC0000184) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_IO_DEVICE_ERROR', [Int32] 0xC0000185) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_DEVICE_PROTOCOL_ERROR', [Int32] 0xC0000186) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_BACKUP_CONTROLLER', [Int32] 0xC0000187) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_LOG_FILE_FULL', [Int32] 0xC0000188) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_TOO_LATE', [Int32] 0xC0000189) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_NO_TRUST_LSA_SECRET', [Int32] 0xC000018A) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_NO_TRUST_SAM_ACCOUNT', [Int32] 0xC000018B) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_TRUSTED_DOMAIN_FAILURE', [Int32] 0xC000018C) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_TRUSTED_RELATIONSHIP_FAILURE', [Int32] 0xC000018D) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_EVENTLOG_FILE_CORRUPT', [Int32] 0xC000018E) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_EVENTLOG_CANT_START', [Int32] 0xC000018F) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_TRUST_FAILURE', [Int32] 0xC0000190) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_MUTANT_LIMIT_EXCEEDED', [Int32] 0xC0000191) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_NETLOGON_NOT_STARTED', [Int32] 0xC0000192) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_ACCOUNT_EXPIRED', [Int32] 0xC0000193) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_POSSIBLE_DEADLOCK', [Int32] 0xC0000194) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_NETWORK_CREDENTIAL_CONFLICT', [Int32] 0xC0000195) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_REMOTE_SESSION_LIMIT', [Int32] 0xC0000196) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_EVENTLOG_FILE_CHANGED', [Int32] 0xC0000197) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_NOLOGON_INTERDOMAIN_TRUST_ACCOUNT', [Int32] 0xC0000198) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_NOLOGON_WORKSTATION_TRUST_ACCOUNT', [Int32] 0xC0000199) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_NOLOGON_SERVER_TRUST_ACCOUNT', [Int32] 0xC000019A) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_DOMAIN_TRUST_INCONSISTENT', [Int32] 0xC000019B) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FS_DRIVER_REQUIRED', [Int32] 0xC000019C) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_IMAGE_ALREADY_LOADED_AS_DLL', [Int32] 0xC000019D) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_INCOMPATIBLE_WITH_GLOBAL_SHORT_NAME_REGISTRY_SETTING', [Int32] 0xC000019E) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_SHORT_NAMES_NOT_ENABLED_ON_VOLUME', [Int32] 0xC000019F) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_SECURITY_STREAM_IS_INCONSISTENT', [Int32] 0xC00001A0) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_INVALID_LOCK_RANGE', [Int32] 0xC00001A1) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_INVALID_ACE_CONDITION', [Int32] 0xC00001A2) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_IMAGE_SUBSYSTEM_NOT_PRESENT', [Int32] 0xC00001A3) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_NOTIFICATION_GUID_ALREADY_DEFINED', [Int32] 0xC00001A4) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_INVALID_EXCEPTION_HANDLER', [Int32] 0xC00001A5) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_DUPLICATE_PRIVILEGES', [Int32] 0xC00001A6) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_NOT_ALLOWED_ON_SYSTEM_FILE', [Int32] 0xC00001A7) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_REPAIR_NEEDED', [Int32] 0xC00001A8) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_QUOTA_NOT_ENABLED', [Int32] 0xC00001A9) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_NO_APPLICATION_PACKAGE', [Int32] 0xC00001AA) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_NETWORK_OPEN_RESTRICTION', [Int32] 0xC0000201) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_NO_USER_SESSION_KEY', [Int32] 0xC0000202) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_USER_SESSION_DELETED', [Int32] 0xC0000203) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_RESOURCE_LANG_NOT_FOUND', [Int32] 0xC0000204) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_INSUFF_SERVER_RESOURCES', [Int32] 0xC0000205) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_INVALID_BUFFER_SIZE', [Int32] 0xC0000206) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_INVALID_ADDRESS_COMPONENT', [Int32] 0xC0000207) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_INVALID_ADDRESS_WILDCARD', [Int32] 0xC0000208) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_TOO_MANY_ADDRESSES', [Int32] 0xC0000209) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_ADDRESS_ALREADY_EXISTS', [Int32] 0xC000020A) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_ADDRESS_CLOSED', [Int32] 0xC000020B) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_CONNECTION_DISCONNECTED', [Int32] 0xC000020C) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_CONNECTION_RESET', [Int32] 0xC000020D) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_TOO_MANY_NODES', [Int32] 0xC000020E) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_TRANSACTION_ABORTED', [Int32] 0xC000020F) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_TRANSACTION_TIMED_OUT', [Int32] 0xC0000210) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_TRANSACTION_NO_RELEASE', [Int32] 0xC0000211) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_TRANSACTION_NO_MATCH', [Int32] 0xC0000212) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_TRANSACTION_RESPONDED', [Int32] 0xC0000213) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_TRANSACTION_INVALID_ID', [Int32] 0xC0000214) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_TRANSACTION_INVALID_TYPE', [Int32] 0xC0000215) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_NOT_SERVER_SESSION', [Int32] 0xC0000216) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_NOT_CLIENT_SESSION', [Int32] 0xC0000217) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_CANNOT_LOAD_REGISTRY_FILE', [Int32] 0xC0000218) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_DEBUG_ATTACH_FAILED', [Int32] 0xC0000219) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_SYSTEM_PROCESS_TERMINATED', [Int32] 0xC000021A) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_DATA_NOT_ACCEPTED', [Int32] 0xC000021B) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_NO_BROWSER_SERVERS_FOUND', [Int32] 0xC000021C) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_VDM_HARD_ERROR', [Int32] 0xC000021D) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_DRIVER_CANCEL_TIMEOUT', [Int32] 0xC000021E) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_REPLY_MESSAGE_MISMATCH', [Int32] 0xC000021F) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_MAPPED_ALIGNMENT', [Int32] 0xC0000220) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_IMAGE_CHECKSUM_MISMATCH', [Int32] 0xC0000221) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_LOST_WRITEBEHIND_DATA', [Int32] 0xC0000222) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_CLIENT_SERVER_PARAMETERS_INVALID', [Int32] 0xC0000223) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_PASSWORD_MUST_CHANGE', [Int32] 0xC0000224) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_NOT_FOUND', [Int32] 0xC0000225) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_NOT_TINY_STREAM', [Int32] 0xC0000226) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_RECOVERY_FAILURE', [Int32] 0xC0000227) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_STACK_OVERFLOW_READ', [Int32] 0xC0000228) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FAIL_CHECK', [Int32] 0xC0000229) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_DUPLICATE_OBJECTID', [Int32] 0xC000022A) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_OBJECTID_EXISTS', [Int32] 0xC000022B) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_CONVERT_TO_LARGE', [Int32] 0xC000022C) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_RETRY', [Int32] 0xC000022D) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FOUND_OUT_OF_SCOPE', [Int32] 0xC000022E) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_ALLOCATE_BUCKET', [Int32] 0xC000022F) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_PROPSET_NOT_FOUND', [Int32] 0xC0000230) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_MARSHALL_OVERFLOW', [Int32] 0xC0000231) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_INVALID_VARIANT', [Int32] 0xC0000232) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_DOMAIN_CONTROLLER_NOT_FOUND', [Int32] 0xC0000233) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_ACCOUNT_LOCKED_OUT', [Int32] 0xC0000234) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_HANDLE_NOT_CLOSABLE', [Int32] 0xC0000235) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_CONNECTION_REFUSED', [Int32] 0xC0000236) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_GRACEFUL_DISCONNECT', [Int32] 0xC0000237) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_ADDRESS_ALREADY_ASSOCIATED', [Int32] 0xC0000238) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_ADDRESS_NOT_ASSOCIATED', [Int32] 0xC0000239) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_CONNECTION_INVALID', [Int32] 0xC000023A) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_CONNECTION_ACTIVE', [Int32] 0xC000023B) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_NETWORK_UNREACHABLE', [Int32] 0xC000023C) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_HOST_UNREACHABLE', [Int32] 0xC000023D) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_PROTOCOL_UNREACHABLE', [Int32] 0xC000023E) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_PORT_UNREACHABLE', [Int32] 0xC000023F) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_REQUEST_ABORTED', [Int32] 0xC0000240) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_CONNECTION_ABORTED', [Int32] 0xC0000241) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_BAD_COMPRESSION_BUFFER', [Int32] 0xC0000242) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_USER_MAPPED_FILE', [Int32] 0xC0000243) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_AUDIT_FAILED', [Int32] 0xC0000244) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_TIMER_RESOLUTION_NOT_SET', [Int32] 0xC0000245) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_CONNECTION_COUNT_LIMIT', [Int32] 0xC0000246) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_LOGIN_TIME_RESTRICTION', [Int32] 0xC0000247) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_LOGIN_WKSTA_RESTRICTION', [Int32] 0xC0000248) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_IMAGE_MP_UP_MISMATCH', [Int32] 0xC0000249) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_INSUFFICIENT_LOGON_INFO', [Int32] 0xC0000250) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_BAD_DLL_ENTRYPOINT', [Int32] 0xC0000251) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_BAD_SERVICE_ENTRYPOINT', [Int32] 0xC0000252) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_LPC_REPLY_LOST', [Int32] 0xC0000253) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_IP_ADDRESS_CONFLICT1', [Int32] 0xC0000254) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_IP_ADDRESS_CONFLICT2', [Int32] 0xC0000255) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_REGISTRY_QUOTA_LIMIT', [Int32] 0xC0000256) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_PATH_NOT_COVERED', [Int32] 0xC0000257) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_NO_CALLBACK_ACTIVE', [Int32] 0xC0000258) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_LICENSE_QUOTA_EXCEEDED', [Int32] 0xC0000259) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_PWD_TOO_SHORT', [Int32] 0xC000025A) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_PWD_TOO_RECENT', [Int32] 0xC000025B) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_PWD_HISTORY_CONFLICT', [Int32] 0xC000025C) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_PLUGPLAY_NO_DEVICE', [Int32] 0xC000025E) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_UNSUPPORTED_COMPRESSION', [Int32] 0xC000025F) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_INVALID_HW_PROFILE', [Int32] 0xC0000260) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_INVALID_PLUGPLAY_DEVICE_PATH', [Int32] 0xC0000261) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_DRIVER_ORDINAL_NOT_FOUND', [Int32] 0xC0000262) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_DRIVER_ENTRYPOINT_NOT_FOUND', [Int32] 0xC0000263) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_RESOURCE_NOT_OWNED', [Int32] 0xC0000264) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_TOO_MANY_LINKS', [Int32] 0xC0000265) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_QUOTA_LIST_INCONSISTENT', [Int32] 0xC0000266) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FILE_IS_OFFLINE', [Int32] 0xC0000267) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_EVALUATION_EXPIRATION', [Int32] 0xC0000268) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_ILLEGAL_DLL_RELOCATION', [Int32] 0xC0000269) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_LICENSE_VIOLATION', [Int32] 0xC000026A) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_DLL_INIT_FAILED_LOGOFF', [Int32] 0xC000026B) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_DRIVER_UNABLE_TO_LOAD', [Int32] 0xC000026C) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_DFS_UNAVAILABLE', [Int32] 0xC000026D) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_VOLUME_DISMOUNTED', [Int32] 0xC000026E) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_WX86_INTERNAL_ERROR', [Int32] 0xC000026F) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_WX86_FLOAT_STACK_CHECK', [Int32] 0xC0000270) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_VALIDATE_CONTINUE', [Int32] 0xC0000271) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_NO_MATCH', [Int32] 0xC0000272) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_NO_MORE_MATCHES', [Int32] 0xC0000273) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_NOT_A_REPARSE_POINT', [Int32] 0xC0000275) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_IO_REPARSE_TAG_INVALID', [Int32] 0xC0000276) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_IO_REPARSE_TAG_MISMATCH', [Int32] 0xC0000277) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_IO_REPARSE_DATA_INVALID', [Int32] 0xC0000278) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_IO_REPARSE_TAG_NOT_HANDLED', [Int32] 0xC0000279) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_PWD_TOO_LONG', [Int32] 0xC000027A) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_STOWED_EXCEPTION', [Int32] 0xC000027B) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_REPARSE_POINT_NOT_RESOLVED', [Int32] 0xC0000280) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_DIRECTORY_IS_A_REPARSE_POINT', [Int32] 0xC0000281) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_RANGE_LIST_CONFLICT', [Int32] 0xC0000282) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_SOURCE_ELEMENT_EMPTY', [Int32] 0xC0000283) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_DESTINATION_ELEMENT_FULL', [Int32] 0xC0000284) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_ILLEGAL_ELEMENT_ADDRESS', [Int32] 0xC0000285) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_MAGAZINE_NOT_PRESENT', [Int32] 0xC0000286) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_REINITIALIZATION_NEEDED', [Int32] 0xC0000287) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_DEVICE_REQUIRES_CLEANING', [Int32] 0x80000288) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_DEVICE_DOOR_OPEN', [Int32] 0x80000289) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_ENCRYPTION_FAILED', [Int32] 0xC000028A) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_DECRYPTION_FAILED', [Int32] 0xC000028B) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_RANGE_NOT_FOUND', [Int32] 0xC000028C) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_NO_RECOVERY_POLICY', [Int32] 0xC000028D) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_NO_EFS', [Int32] 0xC000028E) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_WRONG_EFS', [Int32] 0xC000028F) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_NO_USER_KEYS', [Int32] 0xC0000290) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FILE_NOT_ENCRYPTED', [Int32] 0xC0000291) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_NOT_EXPORT_FORMAT', [Int32] 0xC0000292) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FILE_ENCRYPTED', [Int32] 0xC0000293) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_WAKE_SYSTEM', [Int32] 0x40000294) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_WMI_GUID_NOT_FOUND', [Int32] 0xC0000295) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_WMI_INSTANCE_NOT_FOUND', [Int32] 0xC0000296) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_WMI_ITEMID_NOT_FOUND', [Int32] 0xC0000297) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_WMI_TRY_AGAIN', [Int32] 0xC0000298) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_SHARED_POLICY', [Int32] 0xC0000299) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_POLICY_OBJECT_NOT_FOUND', [Int32] 0xC000029A) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_POLICY_ONLY_IN_DS', [Int32] 0xC000029B) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_VOLUME_NOT_UPGRADED', [Int32] 0xC000029C) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_REMOTE_STORAGE_NOT_ACTIVE', [Int32] 0xC000029D) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_REMOTE_STORAGE_MEDIA_ERROR', [Int32] 0xC000029E) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_NO_TRACKING_SERVICE', [Int32] 0xC000029F) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_SERVER_SID_MISMATCH', [Int32] 0xC00002A0) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_DS_NO_ATTRIBUTE_OR_VALUE', [Int32] 0xC00002A1) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_DS_INVALID_ATTRIBUTE_SYNTAX', [Int32] 0xC00002A2) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_DS_ATTRIBUTE_TYPE_UNDEFINED', [Int32] 0xC00002A3) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_DS_ATTRIBUTE_OR_VALUE_EXISTS', [Int32] 0xC00002A4) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_DS_BUSY', [Int32] 0xC00002A5) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_DS_UNAVAILABLE', [Int32] 0xC00002A6) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_DS_NO_RIDS_ALLOCATED', [Int32] 0xC00002A7) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_DS_NO_MORE_RIDS', [Int32] 0xC00002A8) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_DS_INCORRECT_ROLE_OWNER', [Int32] 0xC00002A9) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_DS_RIDMGR_INIT_ERROR', [Int32] 0xC00002AA) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_DS_OBJ_CLASS_VIOLATION', [Int32] 0xC00002AB) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_DS_CANT_ON_NON_LEAF', [Int32] 0xC00002AC) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_DS_CANT_ON_RDN', [Int32] 0xC00002AD) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_DS_CANT_MOD_OBJ_CLASS', [Int32] 0xC00002AE) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_DS_CROSS_DOM_MOVE_FAILED', [Int32] 0xC00002AF) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_DS_GC_NOT_AVAILABLE', [Int32] 0xC00002B0) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_DIRECTORY_SERVICE_REQUIRED', [Int32] 0xC00002B1) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_REPARSE_ATTRIBUTE_CONFLICT', [Int32] 0xC00002B2) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_CANT_ENABLE_DENY_ONLY', [Int32] 0xC00002B3) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FLOAT_MULTIPLE_FAULTS', [Int32] 0xC00002B4) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FLOAT_MULTIPLE_TRAPS', [Int32] 0xC00002B5) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_DEVICE_REMOVED', [Int32] 0xC00002B6) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_JOURNAL_DELETE_IN_PROGRESS', [Int32] 0xC00002B7) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_JOURNAL_NOT_ACTIVE', [Int32] 0xC00002B8) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_NOINTERFACE', [Int32] 0xC00002B9) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_DS_RIDMGR_DISABLED', [Int32] 0xC00002BA) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_DS_ADMIN_LIMIT_EXCEEDED', [Int32] 0xC00002C1) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_DRIVER_FAILED_SLEEP', [Int32] 0xC00002C2) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_MUTUAL_AUTHENTICATION_FAILED', [Int32] 0xC00002C3) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_CORRUPT_SYSTEM_FILE', [Int32] 0xC00002C4) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_DATATYPE_MISALIGNMENT_ERROR', [Int32] 0xC00002C5) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_WMI_READ_ONLY', [Int32] 0xC00002C6) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_WMI_SET_FAILURE', [Int32] 0xC00002C7) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_COMMITMENT_MINIMUM', [Int32] 0xC00002C8) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_REG_NAT_CONSUMPTION', [Int32] 0xC00002C9) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_TRANSPORT_FULL', [Int32] 0xC00002CA) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_DS_SAM_INIT_FAILURE', [Int32] 0xC00002CB) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_ONLY_IF_CONNECTED', [Int32] 0xC00002CC) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_DS_SENSITIVE_GROUP_VIOLATION', [Int32] 0xC00002CD) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_PNP_RESTART_ENUMERATION', [Int32] 0xC00002CE) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_JOURNAL_ENTRY_DELETED', [Int32] 0xC00002CF) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_DS_CANT_MOD_PRIMARYGROUPID', [Int32] 0xC00002D0) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_SYSTEM_IMAGE_BAD_SIGNATURE', [Int32] 0xC00002D1) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_PNP_REBOOT_REQUIRED', [Int32] 0xC00002D2) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_POWER_STATE_INVALID', [Int32] 0xC00002D3) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_DS_INVALID_GROUP_TYPE', [Int32] 0xC00002D4) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_DS_NO_NEST_GLOBALGROUP_IN_MIXEDDOMAIN', [Int32] 0xC00002D5) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_DS_NO_NEST_LOCALGROUP_IN_MIXEDDOMAIN', [Int32] 0xC00002D6) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_DS_GLOBAL_CANT_HAVE_LOCAL_MEMBER', [Int32] 0xC00002D7) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_DS_GLOBAL_CANT_HAVE_UNIVERSAL_MEMBER', [Int32] 0xC00002D8) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_DS_UNIVERSAL_CANT_HAVE_LOCAL_MEMBER', [Int32] 0xC00002D9) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_DS_GLOBAL_CANT_HAVE_CROSSDOMAIN_MEMBER', [Int32] 0xC00002DA) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_DS_LOCAL_CANT_HAVE_CROSSDOMAIN_LOCAL_MEMBER', [Int32] 0xC00002DB) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_DS_HAVE_PRIMARY_MEMBERS', [Int32] 0xC00002DC) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_WMI_NOT_SUPPORTED', [Int32] 0xC00002DD) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_INSUFFICIENT_POWER', [Int32] 0xC00002DE) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_SAM_NEED_BOOTKEY_PASSWORD', [Int32] 0xC00002DF) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_SAM_NEED_BOOTKEY_FLOPPY', [Int32] 0xC00002E0) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_DS_CANT_START', [Int32] 0xC00002E1) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_DS_INIT_FAILURE', [Int32] 0xC00002E2) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_SAM_INIT_FAILURE', [Int32] 0xC00002E3) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_DS_GC_REQUIRED', [Int32] 0xC00002E4) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_DS_LOCAL_MEMBER_OF_LOCAL_ONLY', [Int32] 0xC00002E5) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_DS_NO_FPO_IN_UNIVERSAL_GROUPS', [Int32] 0xC00002E6) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_DS_MACHINE_ACCOUNT_QUOTA_EXCEEDED', [Int32] 0xC00002E7) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_MULTIPLE_FAULT_VIOLATION', [Int32] 0xC00002E8) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_CURRENT_DOMAIN_NOT_ALLOWED', [Int32] 0xC00002E9) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_CANNOT_MAKE', [Int32] 0xC00002EA) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_SYSTEM_SHUTDOWN', [Int32] 0xC00002EB) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_DS_INIT_FAILURE_CONSOLE', [Int32] 0xC00002EC) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_DS_SAM_INIT_FAILURE_CONSOLE', [Int32] 0xC00002ED) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_UNFINISHED_CONTEXT_DELETED', [Int32] 0xC00002EE) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_NO_TGT_REPLY', [Int32] 0xC00002EF) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_OBJECTID_NOT_FOUND', [Int32] 0xC00002F0) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_NO_IP_ADDRESSES', [Int32] 0xC00002F1) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_WRONG_CREDENTIAL_HANDLE', [Int32] 0xC00002F2) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_CRYPTO_SYSTEM_INVALID', [Int32] 0xC00002F3) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_MAX_REFERRALS_EXCEEDED', [Int32] 0xC00002F4) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_MUST_BE_KDC', [Int32] 0xC00002F5) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_STRONG_CRYPTO_NOT_SUPPORTED', [Int32] 0xC00002F6) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_TOO_MANY_PRINCIPALS', [Int32] 0xC00002F7) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_NO_PA_DATA', [Int32] 0xC00002F8) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_PKINIT_NAME_MISMATCH', [Int32] 0xC00002F9) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_SMARTCARD_LOGON_REQUIRED', [Int32] 0xC00002FA) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_KDC_INVALID_REQUEST', [Int32] 0xC00002FB) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_KDC_UNABLE_TO_REFER', [Int32] 0xC00002FC) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_KDC_UNKNOWN_ETYPE', [Int32] 0xC00002FD) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_SHUTDOWN_IN_PROGRESS', [Int32] 0xC00002FE) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_SERVER_SHUTDOWN_IN_PROGRESS', [Int32] 0xC00002FF) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_NOT_SUPPORTED_ON_SBS', [Int32] 0xC0000300) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_WMI_GUID_DISCONNECTED', [Int32] 0xC0000301) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_WMI_ALREADY_DISABLED', [Int32] 0xC0000302) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_WMI_ALREADY_ENABLED', [Int32] 0xC0000303) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_MFT_TOO_FRAGMENTED', [Int32] 0xC0000304) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_COPY_PROTECTION_FAILURE', [Int32] 0xC0000305) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_CSS_AUTHENTICATION_FAILURE', [Int32] 0xC0000306) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_CSS_KEY_NOT_PRESENT', [Int32] 0xC0000307) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_CSS_KEY_NOT_ESTABLISHED', [Int32] 0xC0000308) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_CSS_SCRAMBLED_SECTOR', [Int32] 0xC0000309) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_CSS_REGION_MISMATCH', [Int32] 0xC000030A) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_CSS_RESETS_EXHAUSTED', [Int32] 0xC000030B) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_PASSWORD_CHANGE_REQUIRED', [Int32] 0xC000030C) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_PKINIT_FAILURE', [Int32] 0xC0000320) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_SMARTCARD_SUBSYSTEM_FAILURE', [Int32] 0xC0000321) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_NO_KERB_KEY', [Int32] 0xC0000322) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_HOST_DOWN', [Int32] 0xC0000350) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_UNSUPPORTED_PREAUTH', [Int32] 0xC0000351) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_EFS_ALG_BLOB_TOO_BIG', [Int32] 0xC0000352) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_PORT_NOT_SET', [Int32] 0xC0000353) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_DEBUGGER_INACTIVE', [Int32] 0xC0000354) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_DS_VERSION_CHECK_FAILURE', [Int32] 0xC0000355) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_AUDITING_DISABLED', [Int32] 0xC0000356) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_PRENT4_MACHINE_ACCOUNT', [Int32] 0xC0000357) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_DS_AG_CANT_HAVE_UNIVERSAL_MEMBER', [Int32] 0xC0000358) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_INVALID_IMAGE_WIN_32', [Int32] 0xC0000359) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_INVALID_IMAGE_WIN_64', [Int32] 0xC000035A) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_BAD_BINDINGS', [Int32] 0xC000035B) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_NETWORK_SESSION_EXPIRED', [Int32] 0xC000035C) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_APPHELP_BLOCK', [Int32] 0xC000035D) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_ALL_SIDS_FILTERED', [Int32] 0xC000035E) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_NOT_SAFE_MODE_DRIVER', [Int32] 0xC000035F) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_ACCESS_DISABLED_BY_POLICY_DEFAULT', [Int32] 0xC0000361) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_ACCESS_DISABLED_BY_POLICY_PATH', [Int32] 0xC0000362) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_ACCESS_DISABLED_BY_POLICY_PUBLISHER', [Int32] 0xC0000363) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_ACCESS_DISABLED_BY_POLICY_OTHER', [Int32] 0xC0000364) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FAILED_DRIVER_ENTRY', [Int32] 0xC0000365) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_DEVICE_ENUMERATION_ERROR', [Int32] 0xC0000366) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_MOUNT_POINT_NOT_RESOLVED', [Int32] 0xC0000368) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_INVALID_DEVICE_OBJECT_PARAMETER', [Int32] 0xC0000369) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_MCA_OCCURED', [Int32] 0xC000036A) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_DRIVER_BLOCKED_CRITICAL', [Int32] 0xC000036B) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_DRIVER_BLOCKED', [Int32] 0xC000036C) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_DRIVER_DATABASE_ERROR', [Int32] 0xC000036D) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_SYSTEM_HIVE_TOO_LARGE', [Int32] 0xC000036E) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_INVALID_IMPORT_OF_NON_DLL', [Int32] 0xC000036F) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_DS_SHUTTING_DOWN', [Int32] 0x40000370) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_NO_SECRETS', [Int32] 0xC0000371) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_ACCESS_DISABLED_NO_SAFER_UI_BY_POLICY', [Int32] 0xC0000372) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FAILED_STACK_SWITCH', [Int32] 0xC0000373) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_HEAP_CORRUPTION', [Int32] 0xC0000374) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_SMARTCARD_WRONG_PIN', [Int32] 0xC0000380) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_SMARTCARD_CARD_BLOCKED', [Int32] 0xC0000381) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_SMARTCARD_CARD_NOT_AUTHENTICATED', [Int32] 0xC0000382) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_SMARTCARD_NO_CARD', [Int32] 0xC0000383) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_SMARTCARD_NO_KEY_CONTAINER', [Int32] 0xC0000384) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_SMARTCARD_NO_CERTIFICATE', [Int32] 0xC0000385) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_SMARTCARD_NO_KEYSET', [Int32] 0xC0000386) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_SMARTCARD_IO_ERROR', [Int32] 0xC0000387) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_DOWNGRADE_DETECTED', [Int32] 0xC0000388) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_SMARTCARD_CERT_REVOKED', [Int32] 0xC0000389) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_ISSUING_CA_UNTRUSTED', [Int32] 0xC000038A) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_REVOCATION_OFFLINE_C', [Int32] 0xC000038B) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_PKINIT_CLIENT_FAILURE', [Int32] 0xC000038C) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_SMARTCARD_CERT_EXPIRED', [Int32] 0xC000038D) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_DRIVER_FAILED_PRIOR_UNLOAD', [Int32] 0xC000038E) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_SMARTCARD_SILENT_CONTEXT', [Int32] 0xC000038F) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_PER_USER_TRUST_QUOTA_EXCEEDED', [Int32] 0xC0000401) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_ALL_USER_TRUST_QUOTA_EXCEEDED', [Int32] 0xC0000402) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_USER_DELETE_TRUST_QUOTA_EXCEEDED', [Int32] 0xC0000403) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_DS_NAME_NOT_UNIQUE', [Int32] 0xC0000404) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_DS_DUPLICATE_ID_FOUND', [Int32] 0xC0000405) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_DS_GROUP_CONVERSION_ERROR', [Int32] 0xC0000406) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_VOLSNAP_PREPARE_HIBERNATE', [Int32] 0xC0000407) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_USER2USER_REQUIRED', [Int32] 0xC0000408) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_STACK_BUFFER_OVERRUN', [Int32] 0xC0000409) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_NO_S4U_PROT_SUPPORT', [Int32] 0xC000040A) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_CROSSREALM_DELEGATION_FAILURE', [Int32] 0xC000040B) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_REVOCATION_OFFLINE_KDC', [Int32] 0xC000040C) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_ISSUING_CA_UNTRUSTED_KDC', [Int32] 0xC000040D) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_KDC_CERT_EXPIRED', [Int32] 0xC000040E) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_KDC_CERT_REVOKED', [Int32] 0xC000040F) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_PARAMETER_QUOTA_EXCEEDED', [Int32] 0xC0000410) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_HIBERNATION_FAILURE', [Int32] 0xC0000411) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_DELAY_LOAD_FAILED', [Int32] 0xC0000412) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_AUTHENTICATION_FIREWALL_FAILED', [Int32] 0xC0000413) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_VDM_DISALLOWED', [Int32] 0xC0000414) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_HUNG_DISPLAY_DRIVER_THREAD', [Int32] 0xC0000415) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_INSUFFICIENT_RESOURCE_FOR_SPECIFIED_SHARED_SECTION_SIZE', [Int32] 0xC0000416) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_INVALID_CRUNTIME_PARAMETER', [Int32] 0xC0000417) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_NTLM_BLOCKED', [Int32] 0xC0000418) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_DS_SRC_SID_EXISTS_IN_FOREST', [Int32] 0xC0000419) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_DS_DOMAIN_NAME_EXISTS_IN_FOREST', [Int32] 0xC000041A) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_DS_FLAT_NAME_EXISTS_IN_FOREST', [Int32] 0xC000041B) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_INVALID_USER_PRINCIPAL_NAME', [Int32] 0xC000041C) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FATAL_USER_CALLBACK_EXCEPTION', [Int32] 0xC000041D) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_ASSERTION_FAILURE', [Int32] 0xC0000420) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_VERIFIER_STOP', [Int32] 0xC0000421) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_CALLBACK_POP_STACK', [Int32] 0xC0000423) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_INCOMPATIBLE_DRIVER_BLOCKED', [Int32] 0xC0000424) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_HIVE_UNLOADED', [Int32] 0xC0000425) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_COMPRESSION_DISABLED', [Int32] 0xC0000426) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FILE_SYSTEM_LIMITATION', [Int32] 0xC0000427) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_INVALID_IMAGE_HASH', [Int32] 0xC0000428) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_NOT_CAPABLE', [Int32] 0xC0000429) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_REQUEST_OUT_OF_SEQUENCE', [Int32] 0xC000042A) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_IMPLEMENTATION_LIMIT', [Int32] 0xC000042B) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_ELEVATION_REQUIRED', [Int32] 0xC000042C) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_NO_SECURITY_CONTEXT', [Int32] 0xC000042D) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_PKU2U_CERT_FAILURE', [Int32] 0xC000042F) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_BEYOND_VDL', [Int32] 0xC0000432) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_ENCOUNTERED_WRITE_IN_PROGRESS', [Int32] 0xC0000433) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_PTE_CHANGED', [Int32] 0xC0000434) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_PURGE_FAILED', [Int32] 0xC0000435) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_CRED_REQUIRES_CONFIRMATION', [Int32] 0xC0000440) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_CS_ENCRYPTION_INVALID_SERVER_RESPONSE', [Int32] 0xC0000441) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_CS_ENCRYPTION_UNSUPPORTED_SERVER', [Int32] 0xC0000442) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_CS_ENCRYPTION_EXISTING_ENCRYPTED_FILE', [Int32] 0xC0000443) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_CS_ENCRYPTION_NEW_ENCRYPTED_FILE', [Int32] 0xC0000444) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_CS_ENCRYPTION_FILE_NOT_CSE', [Int32] 0xC0000445) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_INVALID_LABEL', [Int32] 0xC0000446) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_DRIVER_PROCESS_TERMINATED', [Int32] 0xC0000450) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_AMBIGUOUS_SYSTEM_DEVICE', [Int32] 0xC0000451) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_SYSTEM_DEVICE_NOT_FOUND', [Int32] 0xC0000452) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_RESTART_BOOT_APPLICATION', [Int32] 0xC0000453) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_INSUFFICIENT_NVRAM_RESOURCES', [Int32] 0xC0000454) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_INVALID_SESSION', [Int32] 0xC0000455) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_THREAD_ALREADY_IN_SESSION', [Int32] 0xC0000456) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_THREAD_NOT_IN_SESSION', [Int32] 0xC0000457) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_INVALID_WEIGHT', [Int32] 0xC0000458) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_REQUEST_PAUSED', [Int32] 0xC0000459) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_NO_RANGES_PROCESSED', [Int32] 0xC0000460) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_DISK_RESOURCES_EXHAUSTED', [Int32] 0xC0000461) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_NEEDS_REMEDIATION', [Int32] 0xC0000462) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_DEVICE_FEATURE_NOT_SUPPORTED', [Int32] 0xC0000463) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_DEVICE_UNREACHABLE', [Int32] 0xC0000464) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_INVALID_TOKEN', [Int32] 0xC0000465) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_SERVER_UNAVAILABLE', [Int32] 0xC0000466) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FILE_NOT_AVAILABLE', [Int32] 0xC0000467) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_DEVICE_INSUFFICIENT_RESOURCES', [Int32] 0xC0000468) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_PACKAGE_UPDATING', [Int32] 0xC0000469) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_NOT_READ_FROM_COPY', [Int32] 0xC000046A) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FT_WRITE_FAILURE', [Int32] 0xC000046B) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FT_DI_SCAN_REQUIRED', [Int32] 0xC000046C) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_DATA_CHECKSUM_ERROR', [Int32] 0xC0000470) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_INTERMIXED_KERNEL_EA_OPERATION', [Int32] 0xC0000471) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_TRIM_READ_ZERO_NOT_SUPPORTED', [Int32] 0xC0000472) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_TOO_MANY_SEGMENT_DESCRIPTORS', [Int32] 0xC0000473) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_INVALID_OFFSET_ALIGNMENT', [Int32] 0xC0000474) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_INVALID_FIELD_IN_PARAMETER_LIST', [Int32] 0xC0000475) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_OPERATION_IN_PROGRESS', [Int32] 0xC0000476) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_INVALID_INITIATOR_TARGET_PATH', [Int32] 0xC0000477) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_SCRUB_DATA_DISABLED', [Int32] 0xC0000478) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_NOT_REDUNDANT_STORAGE', [Int32] 0xC0000479) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_RESIDENT_FILE_NOT_SUPPORTED', [Int32] 0xC000047A) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_COMPRESSED_FILE_NOT_SUPPORTED', [Int32] 0xC000047B) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_DIRECTORY_NOT_SUPPORTED', [Int32] 0xC000047C) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_IO_OPERATION_TIMEOUT', [Int32] 0xC000047D) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_SYSTEM_NEEDS_REMEDIATION', [Int32] 0xC000047E) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_APPX_INTEGRITY_FAILURE_CLR_NGEN', [Int32] 0xC000047F) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_SHARE_UNAVAILABLE', [Int32] 0xC0000480) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_INVALID_TASK_NAME', [Int32] 0xC0000500) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_INVALID_TASK_INDEX', [Int32] 0xC0000501) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_THREAD_ALREADY_IN_TASK', [Int32] 0xC0000502) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_CALLBACK_BYPASS', [Int32] 0xC0000503) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_UNDEFINED_SCOPE', [Int32] 0xC0000504) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_INVALID_CAP', [Int32] 0xC0000505) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_NOT_GUI_PROCESS', [Int32] 0xC0000506) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FAIL_FAST_EXCEPTION', [Int32] 0xC0000602) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_IMAGE_CERT_REVOKED', [Int32] 0xC0000603) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_PORT_CLOSED', [Int32] 0xC0000700) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_MESSAGE_LOST', [Int32] 0xC0000701) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_INVALID_MESSAGE', [Int32] 0xC0000702) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_REQUEST_CANCELED', [Int32] 0xC0000703) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_RECURSIVE_DISPATCH', [Int32] 0xC0000704) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_LPC_RECEIVE_BUFFER_EXPECTED', [Int32] 0xC0000705) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_LPC_INVALID_CONNECTION_USAGE', [Int32] 0xC0000706) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_LPC_REQUESTS_NOT_ALLOWED', [Int32] 0xC0000707) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_RESOURCE_IN_USE', [Int32] 0xC0000708) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_HARDWARE_MEMORY_ERROR', [Int32] 0xC0000709) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_THREADPOOL_HANDLE_EXCEPTION', [Int32] 0xC000070A) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_THREADPOOL_SET_EVENT_ON_COMPLETION_FAILED', [Int32] 0xC000070B) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_THREADPOOL_RELEASE_SEMAPHORE_ON_COMPLETION_FAILED', [Int32] 0xC000070C) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_THREADPOOL_RELEASE_MUTEX_ON_COMPLETION_FAILED', [Int32] 0xC000070D) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_THREADPOOL_FREE_LIBRARY_ON_COMPLETION_FAILED', [Int32] 0xC000070E) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_THREADPOOL_RELEASED_DURING_OPERATION', [Int32] 0xC000070F) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_CALLBACK_RETURNED_WHILE_IMPERSONATING', [Int32] 0xC0000710) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_APC_RETURNED_WHILE_IMPERSONATING', [Int32] 0xC0000711) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_PROCESS_IS_PROTECTED', [Int32] 0xC0000712) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_MCA_EXCEPTION', [Int32] 0xC0000713) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_CERTIFICATE_MAPPING_NOT_UNIQUE', [Int32] 0xC0000714) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_SYMLINK_CLASS_DISABLED', [Int32] 0xC0000715) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_INVALID_IDN_NORMALIZATION', [Int32] 0xC0000716) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_NO_UNICODE_TRANSLATION', [Int32] 0xC0000717) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_ALREADY_REGISTERED', [Int32] 0xC0000718) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_CONTEXT_MISMATCH', [Int32] 0xC0000719) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_PORT_ALREADY_HAS_COMPLETION_LIST', [Int32] 0xC000071A) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_CALLBACK_RETURNED_THREAD_PRIORITY', [Int32] 0xC000071B) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_INVALID_THREAD', [Int32] 0xC000071C) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_CALLBACK_RETURNED_TRANSACTION', [Int32] 0xC000071D) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_CALLBACK_RETURNED_LDR_LOCK', [Int32] 0xC000071E) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_CALLBACK_RETURNED_LANG', [Int32] 0xC000071F) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_CALLBACK_RETURNED_PRI_BACK', [Int32] 0xC0000720) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_CALLBACK_RETURNED_THREAD_AFFINITY', [Int32] 0xC0000721) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_DISK_REPAIR_DISABLED', [Int32] 0xC0000800) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_DS_DOMAIN_RENAME_IN_PROGRESS', [Int32] 0xC0000801) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_DISK_QUOTA_EXCEEDED', [Int32] 0xC0000802) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_DATA_LOST_REPAIR', [Int32] 0x80000803) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_CONTENT_BLOCKED', [Int32] 0xC0000804) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_BAD_CLUSTERS', [Int32] 0xC0000805) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_VOLUME_DIRTY', [Int32] 0xC0000806) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_DISK_REPAIR_REDIRECTED', [Int32] 0x40000807) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_DISK_REPAIR_UNSUCCESSFUL', [Int32] 0xC0000808) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_CORRUPT_LOG_OVERFULL', [Int32] 0xC0000809) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_CORRUPT_LOG_CORRUPTED', [Int32] 0xC000080A) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_CORRUPT_LOG_UNAVAILABLE', [Int32] 0xC000080B) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_CORRUPT_LOG_DELETED_FULL', [Int32] 0xC000080C) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_CORRUPT_LOG_CLEARED', [Int32] 0xC000080D) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_ORPHAN_NAME_EXHAUSTED', [Int32] 0xC000080E) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_PROACTIVE_SCAN_IN_PROGRESS', [Int32] 0xC000080F) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FILE_CHECKED_OUT', [Int32] 0xC0000901) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_CHECKOUT_REQUIRED', [Int32] 0xC0000902) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_BAD_FILE_TYPE', [Int32] 0xC0000903) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FILE_TOO_LARGE', [Int32] 0xC0000904) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FORMS_AUTH_REQUIRED', [Int32] 0xC0000905) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_VIRUS_INFECTED', [Int32] 0xC0000906) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_VIRUS_DELETED', [Int32] 0xC0000907) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_BAD_MCFG_TABLE', [Int32] 0xC0000908) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_CANNOT_BREAK_OPLOCK', [Int32] 0xC0000909) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_BAD_KEY', [Int32] 0xC000090A) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_BAD_DATA', [Int32] 0xC000090B) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_NO_KEY', [Int32] 0xC000090C) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FILE_HANDLE_REVOKED', [Int32] 0xC0000910) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_WOW_ASSERTION', [Int32] 0xC0009898) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_INVALID_SIGNATURE', [Int32] 0xC000A000) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_HMAC_NOT_SUPPORTED', [Int32] 0xC000A001) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_AUTH_TAG_MISMATCH', [Int32] 0xC000A002) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_INVALID_STATE_TRANSITION', [Int32] 0xC000A003) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_INVALID_KERNEL_INFO_VERSION', [Int32] 0xC000A004) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_INVALID_PEP_INFO_VERSION', [Int32] 0xC000A005) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_IPSEC_QUEUE_OVERFLOW', [Int32] 0xC000A010) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_ND_QUEUE_OVERFLOW', [Int32] 0xC000A011) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_HOPLIMIT_EXCEEDED', [Int32] 0xC000A012) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_PROTOCOL_NOT_SUPPORTED', [Int32] 0xC000A013) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FASTPATH_REJECTED', [Int32] 0xC000A014) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_LOST_WRITEBEHIND_DATA_NETWORK_DISCONNECTED', [Int32] 0xC000A080) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_LOST_WRITEBEHIND_DATA_NETWORK_SERVER_ERROR', [Int32] 0xC000A081) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_LOST_WRITEBEHIND_DATA_LOCAL_DISK_ERROR', [Int32] 0xC000A082) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_XML_PARSE_ERROR', [Int32] 0xC000A083) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_XMLDSIG_ERROR', [Int32] 0xC000A084) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_WRONG_COMPARTMENT', [Int32] 0xC000A085) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_AUTHIP_FAILURE', [Int32] 0xC000A086) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_DS_OID_MAPPED_GROUP_CANT_HAVE_MEMBERS', [Int32] 0xC000A087) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_DS_OID_NOT_FOUND', [Int32] 0xC000A088) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_INCORRECT_ACCOUNT_TYPE', [Int32] 0xC000A089) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_HASH_NOT_SUPPORTED', [Int32] 0xC000A100) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_HASH_NOT_PRESENT', [Int32] 0xC000A101) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_SECONDARY_IC_PROVIDER_NOT_REGISTERED', [Int32] 0xC000A121) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_GPIO_CLIENT_INFORMATION_INVALID', [Int32] 0xC000A122) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_GPIO_VERSION_NOT_SUPPORTED', [Int32] 0xC000A123) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_GPIO_INVALID_REGISTRATION_PACKET', [Int32] 0xC000A124) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_GPIO_OPERATION_DENIED', [Int32] 0xC000A125) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_GPIO_INCOMPATIBLE_CONNECT_MODE', [Int32] 0xC000A126) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_GPIO_INTERRUPT_ALREADY_UNMASKED', [Int32] 0x8000A127) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_CANNOT_SWITCH_RUNLEVEL', [Int32] 0xC000A141) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_INVALID_RUNLEVEL_SETTING', [Int32] 0xC000A142) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_RUNLEVEL_SWITCH_TIMEOUT', [Int32] 0xC000A143) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_SERVICES_FAILED_AUTOSTART', [Int32] 0x4000A144) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_RUNLEVEL_SWITCH_AGENT_TIMEOUT', [Int32] 0xC000A145) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_RUNLEVEL_SWITCH_IN_PROGRESS', [Int32] 0xC000A146) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_NOT_APPCONTAINER', [Int32] 0xC000A200) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_NOT_SUPPORTED_IN_APPCONTAINER', [Int32] 0xC000A201) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_INVALID_PACKAGE_SID_LENGTH', [Int32] 0xC000A202) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_APP_DATA_NOT_FOUND', [Int32] 0xC000A281) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_APP_DATA_EXPIRED', [Int32] 0xC000A282) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_APP_DATA_CORRUPT', [Int32] 0xC000A283) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_APP_DATA_LIMIT_EXCEEDED', [Int32] 0xC000A284) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_APP_DATA_REBOOT_REQUIRED', [Int32] 0xC000A285) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_OFFLOAD_READ_FLT_NOT_SUPPORTED', [Int32] 0xC000A2A1) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_OFFLOAD_WRITE_FLT_NOT_SUPPORTED', [Int32] 0xC000A2A2) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_OFFLOAD_READ_FILE_NOT_SUPPORTED', [Int32] 0xC000A2A3) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_OFFLOAD_WRITE_FILE_NOT_SUPPORTED', [Int32] 0xC000A2A4) | Out-Null
        $EnumBuilder.DefineLiteral('DBG_NO_STATE_CHANGE', [Int32] 0xC0010001) | Out-Null
        $EnumBuilder.DefineLiteral('DBG_APP_NOT_IDLE', [Int32] 0xC0010002) | Out-Null
        $EnumBuilder.DefineLiteral('RPC_NT_INVALID_STRING_BINDING', [Int32] 0xC0020001) | Out-Null
        $EnumBuilder.DefineLiteral('RPC_NT_WRONG_KIND_OF_BINDING', [Int32] 0xC0020002) | Out-Null
        $EnumBuilder.DefineLiteral('RPC_NT_INVALID_BINDING', [Int32] 0xC0020003) | Out-Null
        $EnumBuilder.DefineLiteral('RPC_NT_PROTSEQ_NOT_SUPPORTED', [Int32] 0xC0020004) | Out-Null
        $EnumBuilder.DefineLiteral('RPC_NT_INVALID_RPC_PROTSEQ', [Int32] 0xC0020005) | Out-Null
        $EnumBuilder.DefineLiteral('RPC_NT_INVALID_STRING_UUID', [Int32] 0xC0020006) | Out-Null
        $EnumBuilder.DefineLiteral('RPC_NT_INVALID_ENDPOINT_FORMAT', [Int32] 0xC0020007) | Out-Null
        $EnumBuilder.DefineLiteral('RPC_NT_INVALID_NET_ADDR', [Int32] 0xC0020008) | Out-Null
        $EnumBuilder.DefineLiteral('RPC_NT_NO_ENDPOINT_FOUND', [Int32] 0xC0020009) | Out-Null
        $EnumBuilder.DefineLiteral('RPC_NT_INVALID_TIMEOUT', [Int32] 0xC002000A) | Out-Null
        $EnumBuilder.DefineLiteral('RPC_NT_OBJECT_NOT_FOUND', [Int32] 0xC002000B) | Out-Null
        $EnumBuilder.DefineLiteral('RPC_NT_ALREADY_REGISTERED', [Int32] 0xC002000C) | Out-Null
        $EnumBuilder.DefineLiteral('RPC_NT_TYPE_ALREADY_REGISTERED', [Int32] 0xC002000D) | Out-Null
        $EnumBuilder.DefineLiteral('RPC_NT_ALREADY_LISTENING', [Int32] 0xC002000E) | Out-Null
        $EnumBuilder.DefineLiteral('RPC_NT_NO_PROTSEQS_REGISTERED', [Int32] 0xC002000F) | Out-Null
        $EnumBuilder.DefineLiteral('RPC_NT_NOT_LISTENING', [Int32] 0xC0020010) | Out-Null
        $EnumBuilder.DefineLiteral('RPC_NT_UNKNOWN_MGR_TYPE', [Int32] 0xC0020011) | Out-Null
        $EnumBuilder.DefineLiteral('RPC_NT_UNKNOWN_IF', [Int32] 0xC0020012) | Out-Null
        $EnumBuilder.DefineLiteral('RPC_NT_NO_BINDINGS', [Int32] 0xC0020013) | Out-Null
        $EnumBuilder.DefineLiteral('RPC_NT_NO_PROTSEQS', [Int32] 0xC0020014) | Out-Null
        $EnumBuilder.DefineLiteral('RPC_NT_CANT_CREATE_ENDPOINT', [Int32] 0xC0020015) | Out-Null
        $EnumBuilder.DefineLiteral('RPC_NT_OUT_OF_RESOURCES', [Int32] 0xC0020016) | Out-Null
        $EnumBuilder.DefineLiteral('RPC_NT_SERVER_UNAVAILABLE', [Int32] 0xC0020017) | Out-Null
        $EnumBuilder.DefineLiteral('RPC_NT_SERVER_TOO_BUSY', [Int32] 0xC0020018) | Out-Null
        $EnumBuilder.DefineLiteral('RPC_NT_INVALID_NETWORK_OPTIONS', [Int32] 0xC0020019) | Out-Null
        $EnumBuilder.DefineLiteral('RPC_NT_NO_CALL_ACTIVE', [Int32] 0xC002001A) | Out-Null
        $EnumBuilder.DefineLiteral('RPC_NT_CALL_FAILED', [Int32] 0xC002001B) | Out-Null
        $EnumBuilder.DefineLiteral('RPC_NT_CALL_FAILED_DNE', [Int32] 0xC002001C) | Out-Null
        $EnumBuilder.DefineLiteral('RPC_NT_PROTOCOL_ERROR', [Int32] 0xC002001D) | Out-Null
        $EnumBuilder.DefineLiteral('RPC_NT_UNSUPPORTED_TRANS_SYN', [Int32] 0xC002001F) | Out-Null
        $EnumBuilder.DefineLiteral('RPC_NT_UNSUPPORTED_TYPE', [Int32] 0xC0020021) | Out-Null
        $EnumBuilder.DefineLiteral('RPC_NT_INVALID_TAG', [Int32] 0xC0020022) | Out-Null
        $EnumBuilder.DefineLiteral('RPC_NT_INVALID_BOUND', [Int32] 0xC0020023) | Out-Null
        $EnumBuilder.DefineLiteral('RPC_NT_NO_ENTRY_NAME', [Int32] 0xC0020024) | Out-Null
        $EnumBuilder.DefineLiteral('RPC_NT_INVALID_NAME_SYNTAX', [Int32] 0xC0020025) | Out-Null
        $EnumBuilder.DefineLiteral('RPC_NT_UNSUPPORTED_NAME_SYNTAX', [Int32] 0xC0020026) | Out-Null
        $EnumBuilder.DefineLiteral('RPC_NT_UUID_NO_ADDRESS', [Int32] 0xC0020028) | Out-Null
        $EnumBuilder.DefineLiteral('RPC_NT_DUPLICATE_ENDPOINT', [Int32] 0xC0020029) | Out-Null
        $EnumBuilder.DefineLiteral('RPC_NT_UNKNOWN_AUTHN_TYPE', [Int32] 0xC002002A) | Out-Null
        $EnumBuilder.DefineLiteral('RPC_NT_MAX_CALLS_TOO_SMALL', [Int32] 0xC002002B) | Out-Null
        $EnumBuilder.DefineLiteral('RPC_NT_STRING_TOO_LONG', [Int32] 0xC002002C) | Out-Null
        $EnumBuilder.DefineLiteral('RPC_NT_PROTSEQ_NOT_FOUND', [Int32] 0xC002002D) | Out-Null
        $EnumBuilder.DefineLiteral('RPC_NT_PROCNUM_OUT_OF_RANGE', [Int32] 0xC002002E) | Out-Null
        $EnumBuilder.DefineLiteral('RPC_NT_BINDING_HAS_NO_AUTH', [Int32] 0xC002002F) | Out-Null
        $EnumBuilder.DefineLiteral('RPC_NT_UNKNOWN_AUTHN_SERVICE', [Int32] 0xC0020030) | Out-Null
        $EnumBuilder.DefineLiteral('RPC_NT_UNKNOWN_AUTHN_LEVEL', [Int32] 0xC0020031) | Out-Null
        $EnumBuilder.DefineLiteral('RPC_NT_INVALID_AUTH_IDENTITY', [Int32] 0xC0020032) | Out-Null
        $EnumBuilder.DefineLiteral('RPC_NT_UNKNOWN_AUTHZ_SERVICE', [Int32] 0xC0020033) | Out-Null
        $EnumBuilder.DefineLiteral('EPT_NT_INVALID_ENTRY', [Int32] 0xC0020034) | Out-Null
        $EnumBuilder.DefineLiteral('EPT_NT_CANT_PERFORM_OP', [Int32] 0xC0020035) | Out-Null
        $EnumBuilder.DefineLiteral('EPT_NT_NOT_REGISTERED', [Int32] 0xC0020036) | Out-Null
        $EnumBuilder.DefineLiteral('RPC_NT_NOTHING_TO_EXPORT', [Int32] 0xC0020037) | Out-Null
        $EnumBuilder.DefineLiteral('RPC_NT_INCOMPLETE_NAME', [Int32] 0xC0020038) | Out-Null
        $EnumBuilder.DefineLiteral('RPC_NT_INVALID_VERS_OPTION', [Int32] 0xC0020039) | Out-Null
        $EnumBuilder.DefineLiteral('RPC_NT_NO_MORE_MEMBERS', [Int32] 0xC002003A) | Out-Null
        $EnumBuilder.DefineLiteral('RPC_NT_NOT_ALL_OBJS_UNEXPORTED', [Int32] 0xC002003B) | Out-Null
        $EnumBuilder.DefineLiteral('RPC_NT_INTERFACE_NOT_FOUND', [Int32] 0xC002003C) | Out-Null
        $EnumBuilder.DefineLiteral('RPC_NT_ENTRY_ALREADY_EXISTS', [Int32] 0xC002003D) | Out-Null
        $EnumBuilder.DefineLiteral('RPC_NT_ENTRY_NOT_FOUND', [Int32] 0xC002003E) | Out-Null
        $EnumBuilder.DefineLiteral('RPC_NT_NAME_SERVICE_UNAVAILABLE', [Int32] 0xC002003F) | Out-Null
        $EnumBuilder.DefineLiteral('RPC_NT_INVALID_NAF_ID', [Int32] 0xC0020040) | Out-Null
        $EnumBuilder.DefineLiteral('RPC_NT_CANNOT_SUPPORT', [Int32] 0xC0020041) | Out-Null
        $EnumBuilder.DefineLiteral('RPC_NT_NO_CONTEXT_AVAILABLE', [Int32] 0xC0020042) | Out-Null
        $EnumBuilder.DefineLiteral('RPC_NT_INTERNAL_ERROR', [Int32] 0xC0020043) | Out-Null
        $EnumBuilder.DefineLiteral('RPC_NT_ZERO_DIVIDE', [Int32] 0xC0020044) | Out-Null
        $EnumBuilder.DefineLiteral('RPC_NT_ADDRESS_ERROR', [Int32] 0xC0020045) | Out-Null
        $EnumBuilder.DefineLiteral('RPC_NT_FP_DIV_ZERO', [Int32] 0xC0020046) | Out-Null
        $EnumBuilder.DefineLiteral('RPC_NT_FP_UNDERFLOW', [Int32] 0xC0020047) | Out-Null
        $EnumBuilder.DefineLiteral('RPC_NT_FP_OVERFLOW', [Int32] 0xC0020048) | Out-Null
        $EnumBuilder.DefineLiteral('RPC_NT_NO_MORE_ENTRIES', [Int32] 0xC0030001) | Out-Null
        $EnumBuilder.DefineLiteral('RPC_NT_SS_CHAR_TRANS_OPEN_FAIL', [Int32] 0xC0030002) | Out-Null
        $EnumBuilder.DefineLiteral('RPC_NT_SS_CHAR_TRANS_SHORT_FILE', [Int32] 0xC0030003) | Out-Null
        $EnumBuilder.DefineLiteral('RPC_NT_SS_IN_NULL_CONTEXT', [Int32] 0xC0030004) | Out-Null
        $EnumBuilder.DefineLiteral('RPC_NT_SS_CONTEXT_MISMATCH', [Int32] 0xC0030005) | Out-Null
        $EnumBuilder.DefineLiteral('RPC_NT_SS_CONTEXT_DAMAGED', [Int32] 0xC0030006) | Out-Null
        $EnumBuilder.DefineLiteral('RPC_NT_SS_HANDLES_MISMATCH', [Int32] 0xC0030007) | Out-Null
        $EnumBuilder.DefineLiteral('RPC_NT_SS_CANNOT_GET_CALL_HANDLE', [Int32] 0xC0030008) | Out-Null
        $EnumBuilder.DefineLiteral('RPC_NT_NULL_REF_POINTER', [Int32] 0xC0030009) | Out-Null
        $EnumBuilder.DefineLiteral('RPC_NT_ENUM_VALUE_OUT_OF_RANGE', [Int32] 0xC003000A) | Out-Null
        $EnumBuilder.DefineLiteral('RPC_NT_BYTE_COUNT_TOO_SMALL', [Int32] 0xC003000B) | Out-Null
        $EnumBuilder.DefineLiteral('RPC_NT_BAD_STUB_DATA', [Int32] 0xC003000C) | Out-Null
        $EnumBuilder.DefineLiteral('RPC_NT_CALL_IN_PROGRESS', [Int32] 0xC0020049) | Out-Null
        $EnumBuilder.DefineLiteral('RPC_NT_NO_MORE_BINDINGS', [Int32] 0xC002004A) | Out-Null
        $EnumBuilder.DefineLiteral('RPC_NT_GROUP_MEMBER_NOT_FOUND', [Int32] 0xC002004B) | Out-Null
        $EnumBuilder.DefineLiteral('EPT_NT_CANT_CREATE', [Int32] 0xC002004C) | Out-Null
        $EnumBuilder.DefineLiteral('RPC_NT_INVALID_OBJECT', [Int32] 0xC002004D) | Out-Null
        $EnumBuilder.DefineLiteral('RPC_NT_NO_INTERFACES', [Int32] 0xC002004F) | Out-Null
        $EnumBuilder.DefineLiteral('RPC_NT_CALL_CANCELLED', [Int32] 0xC0020050) | Out-Null
        $EnumBuilder.DefineLiteral('RPC_NT_BINDING_INCOMPLETE', [Int32] 0xC0020051) | Out-Null
        $EnumBuilder.DefineLiteral('RPC_NT_COMM_FAILURE', [Int32] 0xC0020052) | Out-Null
        $EnumBuilder.DefineLiteral('RPC_NT_UNSUPPORTED_AUTHN_LEVEL', [Int32] 0xC0020053) | Out-Null
        $EnumBuilder.DefineLiteral('RPC_NT_NO_PRINC_NAME', [Int32] 0xC0020054) | Out-Null
        $EnumBuilder.DefineLiteral('RPC_NT_NOT_RPC_ERROR', [Int32] 0xC0020055) | Out-Null
        $EnumBuilder.DefineLiteral('RPC_NT_UUID_LOCAL_ONLY', [Int32] 0x40020056) | Out-Null
        $EnumBuilder.DefineLiteral('RPC_NT_SEC_PKG_ERROR', [Int32] 0xC0020057) | Out-Null
        $EnumBuilder.DefineLiteral('RPC_NT_NOT_CANCELLED', [Int32] 0xC0020058) | Out-Null
        $EnumBuilder.DefineLiteral('RPC_NT_INVALID_ES_ACTION', [Int32] 0xC0030059) | Out-Null
        $EnumBuilder.DefineLiteral('RPC_NT_WRONG_ES_VERSION', [Int32] 0xC003005A) | Out-Null
        $EnumBuilder.DefineLiteral('RPC_NT_WRONG_STUB_VERSION', [Int32] 0xC003005B) | Out-Null
        $EnumBuilder.DefineLiteral('RPC_NT_INVALID_PIPE_OBJECT', [Int32] 0xC003005C) | Out-Null
        $EnumBuilder.DefineLiteral('RPC_NT_INVALID_PIPE_OPERATION', [Int32] 0xC003005D) | Out-Null
        $EnumBuilder.DefineLiteral('RPC_NT_WRONG_PIPE_VERSION', [Int32] 0xC003005E) | Out-Null
        $EnumBuilder.DefineLiteral('RPC_NT_PIPE_CLOSED', [Int32] 0xC003005F) | Out-Null
        $EnumBuilder.DefineLiteral('RPC_NT_PIPE_DISCIPLINE_ERROR', [Int32] 0xC0030060) | Out-Null
        $EnumBuilder.DefineLiteral('RPC_NT_PIPE_EMPTY', [Int32] 0xC0030061) | Out-Null
        $EnumBuilder.DefineLiteral('RPC_NT_INVALID_ASYNC_HANDLE', [Int32] 0xC0020062) | Out-Null
        $EnumBuilder.DefineLiteral('RPC_NT_INVALID_ASYNC_CALL', [Int32] 0xC0020063) | Out-Null
        $EnumBuilder.DefineLiteral('RPC_NT_PROXY_ACCESS_DENIED', [Int32] 0xC0020064) | Out-Null
        $EnumBuilder.DefineLiteral('RPC_NT_COOKIE_AUTH_FAILED', [Int32] 0xC0020065) | Out-Null
        $EnumBuilder.DefineLiteral('RPC_NT_SEND_INCOMPLETE', [Int32] 0x400200AF) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_ACPI_INVALID_OPCODE', [Int32] 0xC0140001) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_ACPI_STACK_OVERFLOW', [Int32] 0xC0140002) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_ACPI_ASSERT_FAILED', [Int32] 0xC0140003) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_ACPI_INVALID_INDEX', [Int32] 0xC0140004) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_ACPI_INVALID_ARGUMENT', [Int32] 0xC0140005) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_ACPI_FATAL', [Int32] 0xC0140006) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_ACPI_INVALID_SUPERNAME', [Int32] 0xC0140007) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_ACPI_INVALID_ARGTYPE', [Int32] 0xC0140008) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_ACPI_INVALID_OBJTYPE', [Int32] 0xC0140009) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_ACPI_INVALID_TARGETTYPE', [Int32] 0xC014000A) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_ACPI_INCORRECT_ARGUMENT_COUNT', [Int32] 0xC014000B) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_ACPI_ADDRESS_NOT_MAPPED', [Int32] 0xC014000C) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_ACPI_INVALID_EVENTTYPE', [Int32] 0xC014000D) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_ACPI_HANDLER_COLLISION', [Int32] 0xC014000E) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_ACPI_INVALID_DATA', [Int32] 0xC014000F) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_ACPI_INVALID_REGION', [Int32] 0xC0140010) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_ACPI_INVALID_ACCESS_SIZE', [Int32] 0xC0140011) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_ACPI_ACQUIRE_GLOBAL_LOCK', [Int32] 0xC0140012) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_ACPI_ALREADY_INITIALIZED', [Int32] 0xC0140013) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_ACPI_NOT_INITIALIZED', [Int32] 0xC0140014) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_ACPI_INVALID_MUTEX_LEVEL', [Int32] 0xC0140015) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_ACPI_MUTEX_NOT_OWNED', [Int32] 0xC0140016) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_ACPI_MUTEX_NOT_OWNER', [Int32] 0xC0140017) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_ACPI_RS_ACCESS', [Int32] 0xC0140018) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_ACPI_INVALID_TABLE', [Int32] 0xC0140019) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_ACPI_REG_HANDLER_FAILED', [Int32] 0xC0140020) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_ACPI_POWER_REQUEST_FAILED', [Int32] 0xC0140021) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_CTX_WINSTATION_NAME_INVALID', [Int32] 0xC00A0001) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_CTX_INVALID_PD', [Int32] 0xC00A0002) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_CTX_PD_NOT_FOUND', [Int32] 0xC00A0003) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_CTX_CDM_CONNECT', [Int32] 0x400A0004) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_CTX_CDM_DISCONNECT', [Int32] 0x400A0005) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_CTX_CLOSE_PENDING', [Int32] 0xC00A0006) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_CTX_NO_OUTBUF', [Int32] 0xC00A0007) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_CTX_MODEM_INF_NOT_FOUND', [Int32] 0xC00A0008) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_CTX_INVALID_MODEMNAME', [Int32] 0xC00A0009) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_CTX_RESPONSE_ERROR', [Int32] 0xC00A000A) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_CTX_MODEM_RESPONSE_TIMEOUT', [Int32] 0xC00A000B) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_CTX_MODEM_RESPONSE_NO_CARRIER', [Int32] 0xC00A000C) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_CTX_MODEM_RESPONSE_NO_DIALTONE', [Int32] 0xC00A000D) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_CTX_MODEM_RESPONSE_BUSY', [Int32] 0xC00A000E) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_CTX_MODEM_RESPONSE_VOICE', [Int32] 0xC00A000F) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_CTX_TD_ERROR', [Int32] 0xC00A0010) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_CTX_LICENSE_CLIENT_INVALID', [Int32] 0xC00A0012) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_CTX_LICENSE_NOT_AVAILABLE', [Int32] 0xC00A0013) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_CTX_LICENSE_EXPIRED', [Int32] 0xC00A0014) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_CTX_WINSTATION_NOT_FOUND', [Int32] 0xC00A0015) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_CTX_WINSTATION_NAME_COLLISION', [Int32] 0xC00A0016) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_CTX_WINSTATION_BUSY', [Int32] 0xC00A0017) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_CTX_BAD_VIDEO_MODE', [Int32] 0xC00A0018) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_CTX_GRAPHICS_INVALID', [Int32] 0xC00A0022) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_CTX_NOT_CONSOLE', [Int32] 0xC00A0024) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_CTX_CLIENT_QUERY_TIMEOUT', [Int32] 0xC00A0026) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_CTX_CONSOLE_DISCONNECT', [Int32] 0xC00A0027) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_CTX_CONSOLE_CONNECT', [Int32] 0xC00A0028) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_CTX_SHADOW_DENIED', [Int32] 0xC00A002A) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_CTX_WINSTATION_ACCESS_DENIED', [Int32] 0xC00A002B) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_CTX_INVALID_WD', [Int32] 0xC00A002E) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_CTX_WD_NOT_FOUND', [Int32] 0xC00A002F) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_CTX_SHADOW_INVALID', [Int32] 0xC00A0030) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_CTX_SHADOW_DISABLED', [Int32] 0xC00A0031) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_RDP_PROTOCOL_ERROR', [Int32] 0xC00A0032) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_CTX_CLIENT_LICENSE_NOT_SET', [Int32] 0xC00A0033) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_CTX_CLIENT_LICENSE_IN_USE', [Int32] 0xC00A0034) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_CTX_SHADOW_ENDED_BY_MODE_CHANGE', [Int32] 0xC00A0035) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_CTX_SHADOW_NOT_RUNNING', [Int32] 0xC00A0036) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_CTX_LOGON_DISABLED', [Int32] 0xC00A0037) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_CTX_SECURITY_LAYER_ERROR', [Int32] 0xC00A0038) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_TS_INCOMPATIBLE_SESSIONS', [Int32] 0xC00A0039) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_TS_VIDEO_SUBSYSTEM_ERROR', [Int32] 0xC00A003A) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_PNP_BAD_MPS_TABLE', [Int32] 0xC0040035) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_PNP_TRANSLATION_FAILED', [Int32] 0xC0040036) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_PNP_IRQ_TRANSLATION_FAILED', [Int32] 0xC0040037) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_PNP_INVALID_ID', [Int32] 0xC0040038) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_IO_REISSUE_AS_CACHED', [Int32] 0xC0040039) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_MUI_FILE_NOT_FOUND', [Int32] 0xC00B0001) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_MUI_INVALID_FILE', [Int32] 0xC00B0002) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_MUI_INVALID_RC_CONFIG', [Int32] 0xC00B0003) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_MUI_INVALID_LOCALE_NAME', [Int32] 0xC00B0004) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_MUI_INVALID_ULTIMATEFALLBACK_NAME', [Int32] 0xC00B0005) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_MUI_FILE_NOT_LOADED', [Int32] 0xC00B0006) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_RESOURCE_ENUM_USER_STOP', [Int32] 0xC00B0007) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FLT_NO_HANDLER_DEFINED', [Int32] 0xC01C0001) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FLT_CONTEXT_ALREADY_DEFINED', [Int32] 0xC01C0002) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FLT_INVALID_ASYNCHRONOUS_REQUEST', [Int32] 0xC01C0003) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FLT_DISALLOW_FAST_IO', [Int32] 0xC01C0004) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FLT_INVALID_NAME_REQUEST', [Int32] 0xC01C0005) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FLT_NOT_SAFE_TO_POST_OPERATION', [Int32] 0xC01C0006) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FLT_NOT_INITIALIZED', [Int32] 0xC01C0007) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FLT_FILTER_NOT_READY', [Int32] 0xC01C0008) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FLT_POST_OPERATION_CLEANUP', [Int32] 0xC01C0009) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FLT_INTERNAL_ERROR', [Int32] 0xC01C000A) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FLT_DELETING_OBJECT', [Int32] 0xC01C000B) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FLT_MUST_BE_NONPAGED_POOL', [Int32] 0xC01C000C) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FLT_DUPLICATE_ENTRY', [Int32] 0xC01C000D) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FLT_CBDQ_DISABLED', [Int32] 0xC01C000E) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FLT_DO_NOT_ATTACH', [Int32] 0xC01C000F) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FLT_DO_NOT_DETACH', [Int32] 0xC01C0010) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FLT_INSTANCE_ALTITUDE_COLLISION', [Int32] 0xC01C0011) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FLT_INSTANCE_NAME_COLLISION', [Int32] 0xC01C0012) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FLT_FILTER_NOT_FOUND', [Int32] 0xC01C0013) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FLT_VOLUME_NOT_FOUND', [Int32] 0xC01C0014) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FLT_INSTANCE_NOT_FOUND', [Int32] 0xC01C0015) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FLT_CONTEXT_ALLOCATION_NOT_FOUND', [Int32] 0xC01C0016) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FLT_INVALID_CONTEXT_REGISTRATION', [Int32] 0xC01C0017) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FLT_NAME_CACHE_MISS', [Int32] 0xC01C0018) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FLT_NO_DEVICE_OBJECT', [Int32] 0xC01C0019) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FLT_VOLUME_ALREADY_MOUNTED', [Int32] 0xC01C001A) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FLT_ALREADY_ENLISTED', [Int32] 0xC01C001B) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FLT_CONTEXT_ALREADY_LINKED', [Int32] 0xC01C001C) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FLT_NO_WAITER_FOR_REPLY', [Int32] 0xC01C0020) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FLT_REGISTRATION_BUSY', [Int32] 0xC01C0023) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_SXS_SECTION_NOT_FOUND', [Int32] 0xC0150001) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_SXS_CANT_GEN_ACTCTX', [Int32] 0xC0150002) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_SXS_INVALID_ACTCTXDATA_FORMAT', [Int32] 0xC0150003) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_SXS_ASSEMBLY_NOT_FOUND', [Int32] 0xC0150004) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_SXS_MANIFEST_FORMAT_ERROR', [Int32] 0xC0150005) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_SXS_MANIFEST_PARSE_ERROR', [Int32] 0xC0150006) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_SXS_ACTIVATION_CONTEXT_DISABLED', [Int32] 0xC0150007) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_SXS_KEY_NOT_FOUND', [Int32] 0xC0150008) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_SXS_VERSION_CONFLICT', [Int32] 0xC0150009) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_SXS_WRONG_SECTION_TYPE', [Int32] 0xC015000A) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_SXS_THREAD_QUERIES_DISABLED', [Int32] 0xC015000B) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_SXS_ASSEMBLY_MISSING', [Int32] 0xC015000C) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_SXS_RELEASE_ACTIVATION_CONTEXT', [Int32] 0x4015000D) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_SXS_PROCESS_DEFAULT_ALREADY_SET', [Int32] 0xC015000E) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_SXS_EARLY_DEACTIVATION', [Int32] 0xC015000F) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_SXS_INVALID_DEACTIVATION', [Int32] 0xC0150010) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_SXS_MULTIPLE_DEACTIVATION', [Int32] 0xC0150011) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_SXS_SYSTEM_DEFAULT_ACTIVATION_CONTEXT_EMPTY', [Int32] 0xC0150012) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_SXS_PROCESS_TERMINATION_REQUESTED', [Int32] 0xC0150013) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_SXS_CORRUPT_ACTIVATION_STACK', [Int32] 0xC0150014) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_SXS_CORRUPTION', [Int32] 0xC0150015) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_SXS_INVALID_IDENTITY_ATTRIBUTE_VALUE', [Int32] 0xC0150016) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_SXS_INVALID_IDENTITY_ATTRIBUTE_NAME', [Int32] 0xC0150017) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_SXS_IDENTITY_DUPLICATE_ATTRIBUTE', [Int32] 0xC0150018) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_SXS_IDENTITY_PARSE_ERROR', [Int32] 0xC0150019) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_SXS_COMPONENT_STORE_CORRUPT', [Int32] 0xC015001A) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_SXS_FILE_HASH_MISMATCH', [Int32] 0xC015001B) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_SXS_MANIFEST_IDENTITY_SAME_BUT_CONTENTS_DIFFERENT', [Int32] 0xC015001C) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_SXS_IDENTITIES_DIFFERENT', [Int32] 0xC015001D) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_SXS_ASSEMBLY_IS_NOT_A_DEPLOYMENT', [Int32] 0xC015001E) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_SXS_FILE_NOT_PART_OF_ASSEMBLY', [Int32] 0xC015001F) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_ADVANCED_INSTALLER_FAILED', [Int32] 0xC0150020) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_XML_ENCODING_MISMATCH', [Int32] 0xC0150021) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_SXS_MANIFEST_TOO_BIG', [Int32] 0xC0150022) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_SXS_SETTING_NOT_REGISTERED', [Int32] 0xC0150023) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_SXS_TRANSACTION_CLOSURE_INCOMPLETE', [Int32] 0xC0150024) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_SMI_PRIMITIVE_INSTALLER_FAILED', [Int32] 0xC0150025) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_GENERIC_COMMAND_FAILED', [Int32] 0xC0150026) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_SXS_FILE_HASH_MISSING', [Int32] 0xC0150027) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_CLUSTER_INVALID_NODE', [Int32] 0xC0130001) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_CLUSTER_NODE_EXISTS', [Int32] 0xC0130002) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_CLUSTER_JOIN_IN_PROGRESS', [Int32] 0xC0130003) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_CLUSTER_NODE_NOT_FOUND', [Int32] 0xC0130004) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_CLUSTER_LOCAL_NODE_NOT_FOUND', [Int32] 0xC0130005) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_CLUSTER_NETWORK_EXISTS', [Int32] 0xC0130006) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_CLUSTER_NETWORK_NOT_FOUND', [Int32] 0xC0130007) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_CLUSTER_NETINTERFACE_EXISTS', [Int32] 0xC0130008) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_CLUSTER_NETINTERFACE_NOT_FOUND', [Int32] 0xC0130009) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_CLUSTER_INVALID_REQUEST', [Int32] 0xC013000A) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_CLUSTER_INVALID_NETWORK_PROVIDER', [Int32] 0xC013000B) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_CLUSTER_NODE_DOWN', [Int32] 0xC013000C) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_CLUSTER_NODE_UNREACHABLE', [Int32] 0xC013000D) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_CLUSTER_NODE_NOT_MEMBER', [Int32] 0xC013000E) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_CLUSTER_JOIN_NOT_IN_PROGRESS', [Int32] 0xC013000F) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_CLUSTER_INVALID_NETWORK', [Int32] 0xC0130010) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_CLUSTER_NO_NET_ADAPTERS', [Int32] 0xC0130011) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_CLUSTER_NODE_UP', [Int32] 0xC0130012) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_CLUSTER_NODE_PAUSED', [Int32] 0xC0130013) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_CLUSTER_NODE_NOT_PAUSED', [Int32] 0xC0130014) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_CLUSTER_NO_SECURITY_CONTEXT', [Int32] 0xC0130015) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_CLUSTER_NETWORK_NOT_INTERNAL', [Int32] 0xC0130016) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_CLUSTER_POISONED', [Int32] 0xC0130017) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_CLUSTER_NON_CSV_PATH', [Int32] 0xC0130018) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_CLUSTER_CSV_VOLUME_NOT_LOCAL', [Int32] 0xC0130019) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_CLUSTER_CSV_READ_OPLOCK_BREAK_IN_PROGRESS', [Int32] 0xC0130020) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_CLUSTER_CSV_AUTO_PAUSE_ERROR', [Int32] 0xC0130021) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_CLUSTER_CSV_REDIRECTED', [Int32] 0xC0130022) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_CLUSTER_CSV_NOT_REDIRECTED', [Int32] 0xC0130023) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_CLUSTER_CSV_VOLUME_DRAINING', [Int32] 0xC0130024) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_TRANSACTIONAL_CONFLICT', [Int32] 0xC0190001) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_INVALID_TRANSACTION', [Int32] 0xC0190002) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_TRANSACTION_NOT_ACTIVE', [Int32] 0xC0190003) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_TM_INITIALIZATION_FAILED', [Int32] 0xC0190004) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_RM_NOT_ACTIVE', [Int32] 0xC0190005) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_RM_METADATA_CORRUPT', [Int32] 0xC0190006) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_TRANSACTION_NOT_JOINED', [Int32] 0xC0190007) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_DIRECTORY_NOT_RM', [Int32] 0xC0190008) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_COULD_NOT_RESIZE_LOG', [Int32] 0x80190009) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_TRANSACTIONS_UNSUPPORTED_REMOTE', [Int32] 0xC019000A) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_LOG_RESIZE_INVALID_SIZE', [Int32] 0xC019000B) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_REMOTE_FILE_VERSION_MISMATCH', [Int32] 0xC019000C) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_CRM_PROTOCOL_ALREADY_EXISTS', [Int32] 0xC019000F) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_TRANSACTION_PROPAGATION_FAILED', [Int32] 0xC0190010) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_CRM_PROTOCOL_NOT_FOUND', [Int32] 0xC0190011) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_TRANSACTION_SUPERIOR_EXISTS', [Int32] 0xC0190012) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_TRANSACTION_REQUEST_NOT_VALID', [Int32] 0xC0190013) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_TRANSACTION_NOT_REQUESTED', [Int32] 0xC0190014) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_TRANSACTION_ALREADY_ABORTED', [Int32] 0xC0190015) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_TRANSACTION_ALREADY_COMMITTED', [Int32] 0xC0190016) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_TRANSACTION_INVALID_MARSHALL_BUFFER', [Int32] 0xC0190017) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_CURRENT_TRANSACTION_NOT_VALID', [Int32] 0xC0190018) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_LOG_GROWTH_FAILED', [Int32] 0xC0190019) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_OBJECT_NO_LONGER_EXISTS', [Int32] 0xC0190021) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_STREAM_MINIVERSION_NOT_FOUND', [Int32] 0xC0190022) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_STREAM_MINIVERSION_NOT_VALID', [Int32] 0xC0190023) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_MINIVERSION_INACCESSIBLE_FROM_SPECIFIED_TRANSACTION', [Int32] 0xC0190024) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_CANT_OPEN_MINIVERSION_WITH_MODIFY_INTENT', [Int32] 0xC0190025) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_CANT_CREATE_MORE_STREAM_MINIVERSIONS', [Int32] 0xC0190026) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_HANDLE_NO_LONGER_VALID', [Int32] 0xC0190028) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_NO_TXF_METADATA', [Int32] 0x80190029) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_LOG_CORRUPTION_DETECTED', [Int32] 0xC0190030) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_CANT_RECOVER_WITH_HANDLE_OPEN', [Int32] 0x80190031) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_RM_DISCONNECTED', [Int32] 0xC0190032) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_ENLISTMENT_NOT_SUPERIOR', [Int32] 0xC0190033) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_RECOVERY_NOT_NEEDED', [Int32] 0x40190034) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_RM_ALREADY_STARTED', [Int32] 0x40190035) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FILE_IDENTITY_NOT_PERSISTENT', [Int32] 0xC0190036) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_CANT_BREAK_TRANSACTIONAL_DEPENDENCY', [Int32] 0xC0190037) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_CANT_CROSS_RM_BOUNDARY', [Int32] 0xC0190038) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_TXF_DIR_NOT_EMPTY', [Int32] 0xC0190039) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_INDOUBT_TRANSACTIONS_EXIST', [Int32] 0xC019003A) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_TM_VOLATILE', [Int32] 0xC019003B) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_ROLLBACK_TIMER_EXPIRED', [Int32] 0xC019003C) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_TXF_ATTRIBUTE_CORRUPT', [Int32] 0xC019003D) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_EFS_NOT_ALLOWED_IN_TRANSACTION', [Int32] 0xC019003E) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_TRANSACTIONAL_OPEN_NOT_ALLOWED', [Int32] 0xC019003F) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_TRANSACTED_MAPPING_UNSUPPORTED_REMOTE', [Int32] 0xC0190040) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_TXF_METADATA_ALREADY_PRESENT', [Int32] 0x80190041) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_TRANSACTION_SCOPE_CALLBACKS_NOT_SET', [Int32] 0x80190042) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_TRANSACTION_REQUIRED_PROMOTION', [Int32] 0xC0190043) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_CANNOT_EXECUTE_FILE_IN_TRANSACTION', [Int32] 0xC0190044) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_TRANSACTIONS_NOT_FROZEN', [Int32] 0xC0190045) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_TRANSACTION_FREEZE_IN_PROGRESS', [Int32] 0xC0190046) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_NOT_SNAPSHOT_VOLUME', [Int32] 0xC0190047) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_NO_SAVEPOINT_WITH_OPEN_FILES', [Int32] 0xC0190048) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_SPARSE_NOT_ALLOWED_IN_TRANSACTION', [Int32] 0xC0190049) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_TM_IDENTITY_MISMATCH', [Int32] 0xC019004A) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FLOATED_SECTION', [Int32] 0xC019004B) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_CANNOT_ACCEPT_TRANSACTED_WORK', [Int32] 0xC019004C) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_CANNOT_ABORT_TRANSACTIONS', [Int32] 0xC019004D) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_TRANSACTION_NOT_FOUND', [Int32] 0xC019004E) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_RESOURCEMANAGER_NOT_FOUND', [Int32] 0xC019004F) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_ENLISTMENT_NOT_FOUND', [Int32] 0xC0190050) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_TRANSACTIONMANAGER_NOT_FOUND', [Int32] 0xC0190051) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_TRANSACTIONMANAGER_NOT_ONLINE', [Int32] 0xC0190052) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_TRANSACTIONMANAGER_RECOVERY_NAME_COLLISION', [Int32] 0xC0190053) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_TRANSACTION_NOT_ROOT', [Int32] 0xC0190054) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_TRANSACTION_OBJECT_EXPIRED', [Int32] 0xC0190055) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_COMPRESSION_NOT_ALLOWED_IN_TRANSACTION', [Int32] 0xC0190056) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_TRANSACTION_RESPONSE_NOT_ENLISTED', [Int32] 0xC0190057) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_TRANSACTION_RECORD_TOO_LONG', [Int32] 0xC0190058) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_NO_LINK_TRACKING_IN_TRANSACTION', [Int32] 0xC0190059) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_OPERATION_NOT_SUPPORTED_IN_TRANSACTION', [Int32] 0xC019005A) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_TRANSACTION_INTEGRITY_VIOLATED', [Int32] 0xC019005B) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_TRANSACTIONMANAGER_IDENTITY_MISMATCH', [Int32] 0xC019005C) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_RM_CANNOT_BE_FROZEN_FOR_SNAPSHOT', [Int32] 0xC019005D) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_TRANSACTION_MUST_WRITETHROUGH', [Int32] 0xC019005E) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_TRANSACTION_NO_SUPERIOR', [Int32] 0xC019005F) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_EXPIRED_HANDLE', [Int32] 0xC0190060) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_TRANSACTION_NOT_ENLISTED', [Int32] 0xC0190061) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_LOG_SECTOR_INVALID', [Int32] 0xC01A0001) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_LOG_SECTOR_PARITY_INVALID', [Int32] 0xC01A0002) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_LOG_SECTOR_REMAPPED', [Int32] 0xC01A0003) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_LOG_BLOCK_INCOMPLETE', [Int32] 0xC01A0004) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_LOG_INVALID_RANGE', [Int32] 0xC01A0005) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_LOG_BLOCKS_EXHAUSTED', [Int32] 0xC01A0006) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_LOG_READ_CONTEXT_INVALID', [Int32] 0xC01A0007) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_LOG_RESTART_INVALID', [Int32] 0xC01A0008) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_LOG_BLOCK_VERSION', [Int32] 0xC01A0009) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_LOG_BLOCK_INVALID', [Int32] 0xC01A000A) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_LOG_READ_MODE_INVALID', [Int32] 0xC01A000B) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_LOG_NO_RESTART', [Int32] 0x401A000C) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_LOG_METADATA_CORRUPT', [Int32] 0xC01A000D) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_LOG_METADATA_INVALID', [Int32] 0xC01A000E) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_LOG_METADATA_INCONSISTENT', [Int32] 0xC01A000F) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_LOG_RESERVATION_INVALID', [Int32] 0xC01A0010) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_LOG_CANT_DELETE', [Int32] 0xC01A0011) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_LOG_CONTAINER_LIMIT_EXCEEDED', [Int32] 0xC01A0012) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_LOG_START_OF_LOG', [Int32] 0xC01A0013) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_LOG_POLICY_ALREADY_INSTALLED', [Int32] 0xC01A0014) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_LOG_POLICY_NOT_INSTALLED', [Int32] 0xC01A0015) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_LOG_POLICY_INVALID', [Int32] 0xC01A0016) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_LOG_POLICY_CONFLICT', [Int32] 0xC01A0017) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_LOG_PINNED_ARCHIVE_TAIL', [Int32] 0xC01A0018) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_LOG_RECORD_NONEXISTENT', [Int32] 0xC01A0019) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_LOG_RECORDS_RESERVED_INVALID', [Int32] 0xC01A001A) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_LOG_SPACE_RESERVED_INVALID', [Int32] 0xC01A001B) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_LOG_TAIL_INVALID', [Int32] 0xC01A001C) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_LOG_FULL', [Int32] 0xC01A001D) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_LOG_MULTIPLEXED', [Int32] 0xC01A001E) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_LOG_DEDICATED', [Int32] 0xC01A001F) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_LOG_ARCHIVE_NOT_IN_PROGRESS', [Int32] 0xC01A0020) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_LOG_ARCHIVE_IN_PROGRESS', [Int32] 0xC01A0021) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_LOG_EPHEMERAL', [Int32] 0xC01A0022) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_LOG_NOT_ENOUGH_CONTAINERS', [Int32] 0xC01A0023) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_LOG_CLIENT_ALREADY_REGISTERED', [Int32] 0xC01A0024) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_LOG_CLIENT_NOT_REGISTERED', [Int32] 0xC01A0025) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_LOG_FULL_HANDLER_IN_PROGRESS', [Int32] 0xC01A0026) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_LOG_CONTAINER_READ_FAILED', [Int32] 0xC01A0027) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_LOG_CONTAINER_WRITE_FAILED', [Int32] 0xC01A0028) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_LOG_CONTAINER_OPEN_FAILED', [Int32] 0xC01A0029) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_LOG_CONTAINER_STATE_INVALID', [Int32] 0xC01A002A) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_LOG_STATE_INVALID', [Int32] 0xC01A002B) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_LOG_PINNED', [Int32] 0xC01A002C) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_LOG_METADATA_FLUSH_FAILED', [Int32] 0xC01A002D) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_LOG_INCONSISTENT_SECURITY', [Int32] 0xC01A002E) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_LOG_APPENDED_FLUSH_FAILED', [Int32] 0xC01A002F) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_LOG_PINNED_RESERVATION', [Int32] 0xC01A0030) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_VIDEO_HUNG_DISPLAY_DRIVER_THREAD', [Int32] 0xC01B00EA) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_VIDEO_HUNG_DISPLAY_DRIVER_THREAD_RECOVERED', [Int32] 0x801B00EB) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_VIDEO_DRIVER_DEBUG_REPORT_REQUEST', [Int32] 0x401B00EC) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_MONITOR_NO_DESCRIPTOR', [Int32] 0xC01D0001) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_MONITOR_UNKNOWN_DESCRIPTOR_FORMAT', [Int32] 0xC01D0002) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_MONITOR_INVALID_DESCRIPTOR_CHECKSUM', [Int32] 0xC01D0003) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_MONITOR_INVALID_STANDARD_TIMING_BLOCK', [Int32] 0xC01D0004) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_MONITOR_WMI_DATABLOCK_REGISTRATION_FAILED', [Int32] 0xC01D0005) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_MONITOR_INVALID_SERIAL_NUMBER_MONDSC_BLOCK', [Int32] 0xC01D0006) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_MONITOR_INVALID_USER_FRIENDLY_MONDSC_BLOCK', [Int32] 0xC01D0007) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_MONITOR_NO_MORE_DESCRIPTOR_DATA', [Int32] 0xC01D0008) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_MONITOR_INVALID_DETAILED_TIMING_BLOCK', [Int32] 0xC01D0009) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_MONITOR_INVALID_MANUFACTURE_DATE', [Int32] 0xC01D000A) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_GRAPHICS_NOT_EXCLUSIVE_MODE_OWNER', [Int32] 0xC01E0000) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_GRAPHICS_INSUFFICIENT_DMA_BUFFER', [Int32] 0xC01E0001) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_GRAPHICS_INVALID_DISPLAY_ADAPTER', [Int32] 0xC01E0002) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_GRAPHICS_ADAPTER_WAS_RESET', [Int32] 0xC01E0003) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_GRAPHICS_INVALID_DRIVER_MODEL', [Int32] 0xC01E0004) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_GRAPHICS_PRESENT_MODE_CHANGED', [Int32] 0xC01E0005) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_GRAPHICS_PRESENT_OCCLUDED', [Int32] 0xC01E0006) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_GRAPHICS_PRESENT_DENIED', [Int32] 0xC01E0007) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_GRAPHICS_CANNOTCOLORCONVERT', [Int32] 0xC01E0008) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_GRAPHICS_DRIVER_MISMATCH', [Int32] 0xC01E0009) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_GRAPHICS_PARTIAL_DATA_POPULATED', [Int32] 0x401E000A) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_GRAPHICS_PRESENT_REDIRECTION_DISABLED', [Int32] 0xC01E000B) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_GRAPHICS_PRESENT_UNOCCLUDED', [Int32] 0xC01E000C) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_GRAPHICS_WINDOWDC_NOT_AVAILABLE', [Int32] 0xC01E000D) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_GRAPHICS_WINDOWLESS_PRESENT_DISABLED', [Int32] 0xC01E000E) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_GRAPHICS_NO_VIDEO_MEMORY', [Int32] 0xC01E0100) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_GRAPHICS_CANT_LOCK_MEMORY', [Int32] 0xC01E0101) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_GRAPHICS_ALLOCATION_BUSY', [Int32] 0xC01E0102) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_GRAPHICS_TOO_MANY_REFERENCES', [Int32] 0xC01E0103) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_GRAPHICS_TRY_AGAIN_LATER', [Int32] 0xC01E0104) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_GRAPHICS_TRY_AGAIN_NOW', [Int32] 0xC01E0105) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_GRAPHICS_ALLOCATION_INVALID', [Int32] 0xC01E0106) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_GRAPHICS_UNSWIZZLING_APERTURE_UNAVAILABLE', [Int32] 0xC01E0107) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_GRAPHICS_UNSWIZZLING_APERTURE_UNSUPPORTED', [Int32] 0xC01E0108) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_GRAPHICS_CANT_EVICT_PINNED_ALLOCATION', [Int32] 0xC01E0109) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_GRAPHICS_INVALID_ALLOCATION_USAGE', [Int32] 0xC01E0110) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_GRAPHICS_CANT_RENDER_LOCKED_ALLOCATION', [Int32] 0xC01E0111) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_GRAPHICS_ALLOCATION_CLOSED', [Int32] 0xC01E0112) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_GRAPHICS_INVALID_ALLOCATION_INSTANCE', [Int32] 0xC01E0113) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_GRAPHICS_INVALID_ALLOCATION_HANDLE', [Int32] 0xC01E0114) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_GRAPHICS_WRONG_ALLOCATION_DEVICE', [Int32] 0xC01E0115) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_GRAPHICS_ALLOCATION_CONTENT_LOST', [Int32] 0xC01E0116) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_GRAPHICS_GPU_EXCEPTION_ON_DEVICE', [Int32] 0xC01E0200) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_GRAPHICS_SKIP_ALLOCATION_PREPARATION', [Int32] 0x401E0201) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_GRAPHICS_INVALID_VIDPN_TOPOLOGY', [Int32] 0xC01E0300) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_GRAPHICS_VIDPN_TOPOLOGY_NOT_SUPPORTED', [Int32] 0xC01E0301) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_GRAPHICS_VIDPN_TOPOLOGY_CURRENTLY_NOT_SUPPORTED', [Int32] 0xC01E0302) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_GRAPHICS_INVALID_VIDPN', [Int32] 0xC01E0303) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_GRAPHICS_INVALID_VIDEO_PRESENT_SOURCE', [Int32] 0xC01E0304) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_GRAPHICS_INVALID_VIDEO_PRESENT_TARGET', [Int32] 0xC01E0305) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_GRAPHICS_VIDPN_MODALITY_NOT_SUPPORTED', [Int32] 0xC01E0306) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_GRAPHICS_MODE_NOT_PINNED', [Int32] 0x401E0307) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_GRAPHICS_INVALID_VIDPN_SOURCEMODESET', [Int32] 0xC01E0308) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_GRAPHICS_INVALID_VIDPN_TARGETMODESET', [Int32] 0xC01E0309) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_GRAPHICS_INVALID_FREQUENCY', [Int32] 0xC01E030A) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_GRAPHICS_INVALID_ACTIVE_REGION', [Int32] 0xC01E030B) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_GRAPHICS_INVALID_TOTAL_REGION', [Int32] 0xC01E030C) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_GRAPHICS_INVALID_VIDEO_PRESENT_SOURCE_MODE', [Int32] 0xC01E0310) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_GRAPHICS_INVALID_VIDEO_PRESENT_TARGET_MODE', [Int32] 0xC01E0311) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_GRAPHICS_PINNED_MODE_MUST_REMAIN_IN_SET', [Int32] 0xC01E0312) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_GRAPHICS_PATH_ALREADY_IN_TOPOLOGY', [Int32] 0xC01E0313) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_GRAPHICS_MODE_ALREADY_IN_MODESET', [Int32] 0xC01E0314) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_GRAPHICS_INVALID_VIDEOPRESENTSOURCESET', [Int32] 0xC01E0315) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_GRAPHICS_INVALID_VIDEOPRESENTTARGETSET', [Int32] 0xC01E0316) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_GRAPHICS_SOURCE_ALREADY_IN_SET', [Int32] 0xC01E0317) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_GRAPHICS_TARGET_ALREADY_IN_SET', [Int32] 0xC01E0318) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_GRAPHICS_INVALID_VIDPN_PRESENT_PATH', [Int32] 0xC01E0319) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_GRAPHICS_NO_RECOMMENDED_VIDPN_TOPOLOGY', [Int32] 0xC01E031A) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_GRAPHICS_INVALID_MONITOR_FREQUENCYRANGESET', [Int32] 0xC01E031B) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_GRAPHICS_INVALID_MONITOR_FREQUENCYRANGE', [Int32] 0xC01E031C) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_GRAPHICS_FREQUENCYRANGE_NOT_IN_SET', [Int32] 0xC01E031D) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_GRAPHICS_NO_PREFERRED_MODE', [Int32] 0x401E031E) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_GRAPHICS_FREQUENCYRANGE_ALREADY_IN_SET', [Int32] 0xC01E031F) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_GRAPHICS_STALE_MODESET', [Int32] 0xC01E0320) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_GRAPHICS_INVALID_MONITOR_SOURCEMODESET', [Int32] 0xC01E0321) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_GRAPHICS_INVALID_MONITOR_SOURCE_MODE', [Int32] 0xC01E0322) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_GRAPHICS_NO_RECOMMENDED_FUNCTIONAL_VIDPN', [Int32] 0xC01E0323) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_GRAPHICS_MODE_ID_MUST_BE_UNIQUE', [Int32] 0xC01E0324) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_GRAPHICS_EMPTY_ADAPTER_MONITOR_MODE_SUPPORT_INTERSECTION', [Int32] 0xC01E0325) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_GRAPHICS_VIDEO_PRESENT_TARGETS_LESS_THAN_SOURCES', [Int32] 0xC01E0326) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_GRAPHICS_PATH_NOT_IN_TOPOLOGY', [Int32] 0xC01E0327) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_GRAPHICS_ADAPTER_MUST_HAVE_AT_LEAST_ONE_SOURCE', [Int32] 0xC01E0328) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_GRAPHICS_ADAPTER_MUST_HAVE_AT_LEAST_ONE_TARGET', [Int32] 0xC01E0329) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_GRAPHICS_INVALID_MONITORDESCRIPTORSET', [Int32] 0xC01E032A) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_GRAPHICS_INVALID_MONITORDESCRIPTOR', [Int32] 0xC01E032B) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_GRAPHICS_MONITORDESCRIPTOR_NOT_IN_SET', [Int32] 0xC01E032C) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_GRAPHICS_MONITORDESCRIPTOR_ALREADY_IN_SET', [Int32] 0xC01E032D) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_GRAPHICS_MONITORDESCRIPTOR_ID_MUST_BE_UNIQUE', [Int32] 0xC01E032E) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_GRAPHICS_INVALID_VIDPN_TARGET_SUBSET_TYPE', [Int32] 0xC01E032F) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_GRAPHICS_RESOURCES_NOT_RELATED', [Int32] 0xC01E0330) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_GRAPHICS_SOURCE_ID_MUST_BE_UNIQUE', [Int32] 0xC01E0331) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_GRAPHICS_TARGET_ID_MUST_BE_UNIQUE', [Int32] 0xC01E0332) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_GRAPHICS_NO_AVAILABLE_VIDPN_TARGET', [Int32] 0xC01E0333) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_GRAPHICS_MONITOR_COULD_NOT_BE_ASSOCIATED_WITH_ADAPTER', [Int32] 0xC01E0334) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_GRAPHICS_NO_VIDPNMGR', [Int32] 0xC01E0335) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_GRAPHICS_NO_ACTIVE_VIDPN', [Int32] 0xC01E0336) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_GRAPHICS_STALE_VIDPN_TOPOLOGY', [Int32] 0xC01E0337) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_GRAPHICS_MONITOR_NOT_CONNECTED', [Int32] 0xC01E0338) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_GRAPHICS_SOURCE_NOT_IN_TOPOLOGY', [Int32] 0xC01E0339) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_GRAPHICS_INVALID_PRIMARYSURFACE_SIZE', [Int32] 0xC01E033A) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_GRAPHICS_INVALID_VISIBLEREGION_SIZE', [Int32] 0xC01E033B) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_GRAPHICS_INVALID_STRIDE', [Int32] 0xC01E033C) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_GRAPHICS_INVALID_PIXELFORMAT', [Int32] 0xC01E033D) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_GRAPHICS_INVALID_COLORBASIS', [Int32] 0xC01E033E) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_GRAPHICS_INVALID_PIXELVALUEACCESSMODE', [Int32] 0xC01E033F) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_GRAPHICS_TARGET_NOT_IN_TOPOLOGY', [Int32] 0xC01E0340) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_GRAPHICS_NO_DISPLAY_MODE_MANAGEMENT_SUPPORT', [Int32] 0xC01E0341) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_GRAPHICS_VIDPN_SOURCE_IN_USE', [Int32] 0xC01E0342) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_GRAPHICS_CANT_ACCESS_ACTIVE_VIDPN', [Int32] 0xC01E0343) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_GRAPHICS_INVALID_PATH_IMPORTANCE_ORDINAL', [Int32] 0xC01E0344) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_GRAPHICS_INVALID_PATH_CONTENT_GEOMETRY_TRANSFORMATION', [Int32] 0xC01E0345) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_GRAPHICS_PATH_CONTENT_GEOMETRY_TRANSFORMATION_NOT_SUPPORTED', [Int32] 0xC01E0346) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_GRAPHICS_INVALID_GAMMA_RAMP', [Int32] 0xC01E0347) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_GRAPHICS_GAMMA_RAMP_NOT_SUPPORTED', [Int32] 0xC01E0348) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_GRAPHICS_MULTISAMPLING_NOT_SUPPORTED', [Int32] 0xC01E0349) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_GRAPHICS_MODE_NOT_IN_MODESET', [Int32] 0xC01E034A) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_GRAPHICS_DATASET_IS_EMPTY', [Int32] 0x401E034B) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_GRAPHICS_NO_MORE_ELEMENTS_IN_DATASET', [Int32] 0x401E034C) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_GRAPHICS_INVALID_VIDPN_TOPOLOGY_RECOMMENDATION_REASON', [Int32] 0xC01E034D) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_GRAPHICS_INVALID_PATH_CONTENT_TYPE', [Int32] 0xC01E034E) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_GRAPHICS_INVALID_COPYPROTECTION_TYPE', [Int32] 0xC01E034F) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_GRAPHICS_UNASSIGNED_MODESET_ALREADY_EXISTS', [Int32] 0xC01E0350) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_GRAPHICS_PATH_CONTENT_GEOMETRY_TRANSFORMATION_NOT_PINNED', [Int32] 0x401E0351) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_GRAPHICS_INVALID_SCANLINE_ORDERING', [Int32] 0xC01E0352) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_GRAPHICS_TOPOLOGY_CHANGES_NOT_ALLOWED', [Int32] 0xC01E0353) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_GRAPHICS_NO_AVAILABLE_IMPORTANCE_ORDINALS', [Int32] 0xC01E0354) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_GRAPHICS_INCOMPATIBLE_PRIVATE_FORMAT', [Int32] 0xC01E0355) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_GRAPHICS_INVALID_MODE_PRUNING_ALGORITHM', [Int32] 0xC01E0356) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_GRAPHICS_INVALID_MONITOR_CAPABILITY_ORIGIN', [Int32] 0xC01E0357) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_GRAPHICS_INVALID_MONITOR_FREQUENCYRANGE_CONSTRAINT', [Int32] 0xC01E0358) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_GRAPHICS_MAX_NUM_PATHS_REACHED', [Int32] 0xC01E0359) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_GRAPHICS_CANCEL_VIDPN_TOPOLOGY_AUGMENTATION', [Int32] 0xC01E035A) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_GRAPHICS_INVALID_CLIENT_TYPE', [Int32] 0xC01E035B) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_GRAPHICS_CLIENTVIDPN_NOT_SET', [Int32] 0xC01E035C) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_GRAPHICS_SPECIFIED_CHILD_ALREADY_CONNECTED', [Int32] 0xC01E0400) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_GRAPHICS_CHILD_DESCRIPTOR_NOT_SUPPORTED', [Int32] 0xC01E0401) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_GRAPHICS_UNKNOWN_CHILD_STATUS', [Int32] 0x401E042F) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_GRAPHICS_NOT_A_LINKED_ADAPTER', [Int32] 0xC01E0430) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_GRAPHICS_LEADLINK_NOT_ENUMERATED', [Int32] 0xC01E0431) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_GRAPHICS_CHAINLINKS_NOT_ENUMERATED', [Int32] 0xC01E0432) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_GRAPHICS_ADAPTER_CHAIN_NOT_READY', [Int32] 0xC01E0433) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_GRAPHICS_CHAINLINKS_NOT_STARTED', [Int32] 0xC01E0434) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_GRAPHICS_CHAINLINKS_NOT_POWERED_ON', [Int32] 0xC01E0435) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_GRAPHICS_INCONSISTENT_DEVICE_LINK_STATE', [Int32] 0xC01E0436) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_GRAPHICS_LEADLINK_START_DEFERRED', [Int32] 0x401E0437) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_GRAPHICS_NOT_POST_DEVICE_DRIVER', [Int32] 0xC01E0438) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_GRAPHICS_POLLING_TOO_FREQUENTLY', [Int32] 0x401E0439) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_GRAPHICS_START_DEFERRED', [Int32] 0x401E043A) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_GRAPHICS_ADAPTER_ACCESS_NOT_EXCLUDED', [Int32] 0xC01E043B) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_GRAPHICS_OPM_NOT_SUPPORTED', [Int32] 0xC01E0500) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_GRAPHICS_COPP_NOT_SUPPORTED', [Int32] 0xC01E0501) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_GRAPHICS_UAB_NOT_SUPPORTED', [Int32] 0xC01E0502) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_GRAPHICS_OPM_INVALID_ENCRYPTED_PARAMETERS', [Int32] 0xC01E0503) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_GRAPHICS_OPM_NO_PROTECTED_OUTPUTS_EXIST', [Int32] 0xC01E0505) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_GRAPHICS_OPM_INTERNAL_ERROR', [Int32] 0xC01E050B) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_GRAPHICS_OPM_INVALID_HANDLE', [Int32] 0xC01E050C) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_GRAPHICS_PVP_INVALID_CERTIFICATE_LENGTH', [Int32] 0xC01E050E) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_GRAPHICS_OPM_SPANNING_MODE_ENABLED', [Int32] 0xC01E050F) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_GRAPHICS_OPM_THEATER_MODE_ENABLED', [Int32] 0xC01E0510) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_GRAPHICS_PVP_HFS_FAILED', [Int32] 0xC01E0511) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_GRAPHICS_OPM_INVALID_SRM', [Int32] 0xC01E0512) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_GRAPHICS_OPM_OUTPUT_DOES_NOT_SUPPORT_HDCP', [Int32] 0xC01E0513) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_GRAPHICS_OPM_OUTPUT_DOES_NOT_SUPPORT_ACP', [Int32] 0xC01E0514) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_GRAPHICS_OPM_OUTPUT_DOES_NOT_SUPPORT_CGMSA', [Int32] 0xC01E0515) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_GRAPHICS_OPM_HDCP_SRM_NEVER_SET', [Int32] 0xC01E0516) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_GRAPHICS_OPM_RESOLUTION_TOO_HIGH', [Int32] 0xC01E0517) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_GRAPHICS_OPM_ALL_HDCP_HARDWARE_ALREADY_IN_USE', [Int32] 0xC01E0518) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_GRAPHICS_OPM_PROTECTED_OUTPUT_NO_LONGER_EXISTS', [Int32] 0xC01E051A) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_GRAPHICS_OPM_PROTECTED_OUTPUT_DOES_NOT_HAVE_COPP_SEMANTICS', [Int32] 0xC01E051C) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_GRAPHICS_OPM_INVALID_INFORMATION_REQUEST', [Int32] 0xC01E051D) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_GRAPHICS_OPM_DRIVER_INTERNAL_ERROR', [Int32] 0xC01E051E) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_GRAPHICS_OPM_PROTECTED_OUTPUT_DOES_NOT_HAVE_OPM_SEMANTICS', [Int32] 0xC01E051F) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_GRAPHICS_OPM_SIGNALING_NOT_SUPPORTED', [Int32] 0xC01E0520) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_GRAPHICS_OPM_INVALID_CONFIGURATION_REQUEST', [Int32] 0xC01E0521) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_GRAPHICS_I2C_NOT_SUPPORTED', [Int32] 0xC01E0580) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_GRAPHICS_I2C_DEVICE_DOES_NOT_EXIST', [Int32] 0xC01E0581) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_GRAPHICS_I2C_ERROR_TRANSMITTING_DATA', [Int32] 0xC01E0582) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_GRAPHICS_I2C_ERROR_RECEIVING_DATA', [Int32] 0xC01E0583) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_GRAPHICS_DDCCI_VCP_NOT_SUPPORTED', [Int32] 0xC01E0584) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_GRAPHICS_DDCCI_INVALID_DATA', [Int32] 0xC01E0585) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_GRAPHICS_DDCCI_MONITOR_RETURNED_INVALID_TIMING_STATUS_BYTE', [Int32] 0xC01E0586) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_GRAPHICS_DDCCI_INVALID_CAPABILITIES_STRING', [Int32] 0xC01E0587) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_GRAPHICS_MCA_INTERNAL_ERROR', [Int32] 0xC01E0588) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_GRAPHICS_DDCCI_INVALID_MESSAGE_COMMAND', [Int32] 0xC01E0589) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_GRAPHICS_DDCCI_INVALID_MESSAGE_LENGTH', [Int32] 0xC01E058A) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_GRAPHICS_DDCCI_INVALID_MESSAGE_CHECKSUM', [Int32] 0xC01E058B) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_GRAPHICS_INVALID_PHYSICAL_MONITOR_HANDLE', [Int32] 0xC01E058C) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_GRAPHICS_MONITOR_NO_LONGER_EXISTS', [Int32] 0xC01E058D) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_GRAPHICS_ONLY_CONSOLE_SESSION_SUPPORTED', [Int32] 0xC01E05E0) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_GRAPHICS_NO_DISPLAY_DEVICE_CORRESPONDS_TO_NAME', [Int32] 0xC01E05E1) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_GRAPHICS_DISPLAY_DEVICE_NOT_ATTACHED_TO_DESKTOP', [Int32] 0xC01E05E2) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_GRAPHICS_MIRRORING_DEVICES_NOT_SUPPORTED', [Int32] 0xC01E05E3) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_GRAPHICS_INVALID_POINTER', [Int32] 0xC01E05E4) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_GRAPHICS_NO_MONITORS_CORRESPOND_TO_DISPLAY_DEVICE', [Int32] 0xC01E05E5) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_GRAPHICS_PARAMETER_ARRAY_TOO_SMALL', [Int32] 0xC01E05E6) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_GRAPHICS_INTERNAL_ERROR', [Int32] 0xC01E05E7) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_GRAPHICS_SESSION_TYPE_CHANGE_IN_PROGRESS', [Int32] 0xC01E05E8) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FVE_LOCKED_VOLUME', [Int32] 0xC0210000) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FVE_NOT_ENCRYPTED', [Int32] 0xC0210001) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FVE_BAD_INFORMATION', [Int32] 0xC0210002) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FVE_TOO_SMALL', [Int32] 0xC0210003) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FVE_FAILED_WRONG_FS', [Int32] 0xC0210004) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FVE_BAD_PARTITION_SIZE', [Int32] 0xC0210005) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FVE_FS_NOT_EXTENDED', [Int32] 0xC0210006) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FVE_FS_MOUNTED', [Int32] 0xC0210007) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FVE_NO_LICENSE', [Int32] 0xC0210008) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FVE_ACTION_NOT_ALLOWED', [Int32] 0xC0210009) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FVE_BAD_DATA', [Int32] 0xC021000A) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FVE_VOLUME_NOT_BOUND', [Int32] 0xC021000B) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FVE_NOT_DATA_VOLUME', [Int32] 0xC021000C) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FVE_CONV_READ_ERROR', [Int32] 0xC021000D) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FVE_CONV_WRITE_ERROR', [Int32] 0xC021000E) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FVE_OVERLAPPED_UPDATE', [Int32] 0xC021000F) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FVE_FAILED_SECTOR_SIZE', [Int32] 0xC0210010) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FVE_FAILED_AUTHENTICATION', [Int32] 0xC0210011) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FVE_NOT_OS_VOLUME', [Int32] 0xC0210012) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FVE_KEYFILE_NOT_FOUND', [Int32] 0xC0210013) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FVE_KEYFILE_INVALID', [Int32] 0xC0210014) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FVE_KEYFILE_NO_VMK', [Int32] 0xC0210015) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FVE_TPM_DISABLED', [Int32] 0xC0210016) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FVE_TPM_SRK_AUTH_NOT_ZERO', [Int32] 0xC0210017) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FVE_TPM_INVALID_PCR', [Int32] 0xC0210018) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FVE_TPM_NO_VMK', [Int32] 0xC0210019) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FVE_PIN_INVALID', [Int32] 0xC021001A) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FVE_AUTH_INVALID_APPLICATION', [Int32] 0xC021001B) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FVE_AUTH_INVALID_CONFIG', [Int32] 0xC021001C) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FVE_DEBUGGER_ENABLED', [Int32] 0xC021001D) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FVE_DRY_RUN_FAILED', [Int32] 0xC021001E) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FVE_BAD_METADATA_POINTER', [Int32] 0xC021001F) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FVE_OLD_METADATA_COPY', [Int32] 0xC0210020) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FVE_REBOOT_REQUIRED', [Int32] 0xC0210021) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FVE_RAW_ACCESS', [Int32] 0xC0210022) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FVE_RAW_BLOCKED', [Int32] 0xC0210023) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FVE_NO_AUTOUNLOCK_MASTER_KEY', [Int32] 0xC0210024) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FVE_MOR_FAILED', [Int32] 0xC0210025) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FVE_NO_FEATURE_LICENSE', [Int32] 0xC0210026) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FVE_POLICY_USER_DISABLE_RDV_NOT_ALLOWED', [Int32] 0xC0210027) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FVE_CONV_RECOVERY_FAILED', [Int32] 0xC0210028) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FVE_VIRTUALIZED_SPACE_TOO_BIG', [Int32] 0xC0210029) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FVE_INVALID_DATUM_TYPE', [Int32] 0xC021002A) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FVE_VOLUME_TOO_SMALL', [Int32] 0xC0210030) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FVE_ENH_PIN_INVALID', [Int32] 0xC0210031) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FVE_FULL_ENCRYPTION_NOT_ALLOWED_ON_TP_STORAGE', [Int32] 0xC0210032) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FVE_WIPE_NOT_ALLOWED_ON_TP_STORAGE', [Int32] 0xC0210033) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FVE_NOT_ALLOWED_ON_CSV_STACK', [Int32] 0xC0210034) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FVE_NOT_ALLOWED_ON_CLUSTER', [Int32] 0xC0210035) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FVE_NOT_ALLOWED_TO_UPGRADE_WHILE_CONVERTING', [Int32] 0xC0210036) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FVE_WIPE_CANCEL_NOT_APPLICABLE', [Int32] 0xC0210037) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FVE_EDRIVE_DRY_RUN_FAILED', [Int32] 0xC0210038) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FVE_SECUREBOOT_DISABLED', [Int32] 0xC0210039) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FVE_SECUREBOOT_CONFIG_CHANGE', [Int32] 0xC021003A) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FVE_DEVICE_LOCKEDOUT', [Int32] 0xC021003B) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FWP_CALLOUT_NOT_FOUND', [Int32] 0xC0220001) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FWP_CONDITION_NOT_FOUND', [Int32] 0xC0220002) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FWP_FILTER_NOT_FOUND', [Int32] 0xC0220003) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FWP_LAYER_NOT_FOUND', [Int32] 0xC0220004) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FWP_PROVIDER_NOT_FOUND', [Int32] 0xC0220005) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FWP_PROVIDER_CONTEXT_NOT_FOUND', [Int32] 0xC0220006) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FWP_SUBLAYER_NOT_FOUND', [Int32] 0xC0220007) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FWP_NOT_FOUND', [Int32] 0xC0220008) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FWP_ALREADY_EXISTS', [Int32] 0xC0220009) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FWP_IN_USE', [Int32] 0xC022000A) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FWP_DYNAMIC_SESSION_IN_PROGRESS', [Int32] 0xC022000B) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FWP_WRONG_SESSION', [Int32] 0xC022000C) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FWP_NO_TXN_IN_PROGRESS', [Int32] 0xC022000D) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FWP_TXN_IN_PROGRESS', [Int32] 0xC022000E) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FWP_TXN_ABORTED', [Int32] 0xC022000F) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FWP_SESSION_ABORTED', [Int32] 0xC0220010) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FWP_INCOMPATIBLE_TXN', [Int32] 0xC0220011) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FWP_TIMEOUT', [Int32] 0xC0220012) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FWP_NET_EVENTS_DISABLED', [Int32] 0xC0220013) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FWP_INCOMPATIBLE_LAYER', [Int32] 0xC0220014) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FWP_KM_CLIENTS_ONLY', [Int32] 0xC0220015) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FWP_LIFETIME_MISMATCH', [Int32] 0xC0220016) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FWP_BUILTIN_OBJECT', [Int32] 0xC0220017) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FWP_TOO_MANY_CALLOUTS', [Int32] 0xC0220018) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FWP_NOTIFICATION_DROPPED', [Int32] 0xC0220019) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FWP_TRAFFIC_MISMATCH', [Int32] 0xC022001A) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FWP_INCOMPATIBLE_SA_STATE', [Int32] 0xC022001B) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FWP_NULL_POINTER', [Int32] 0xC022001C) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FWP_INVALID_ENUMERATOR', [Int32] 0xC022001D) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FWP_INVALID_FLAGS', [Int32] 0xC022001E) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FWP_INVALID_NET_MASK', [Int32] 0xC022001F) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FWP_INVALID_RANGE', [Int32] 0xC0220020) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FWP_INVALID_INTERVAL', [Int32] 0xC0220021) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FWP_ZERO_LENGTH_ARRAY', [Int32] 0xC0220022) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FWP_NULL_DISPLAY_NAME', [Int32] 0xC0220023) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FWP_INVALID_ACTION_TYPE', [Int32] 0xC0220024) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FWP_INVALID_WEIGHT', [Int32] 0xC0220025) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FWP_MATCH_TYPE_MISMATCH', [Int32] 0xC0220026) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FWP_TYPE_MISMATCH', [Int32] 0xC0220027) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FWP_OUT_OF_BOUNDS', [Int32] 0xC0220028) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FWP_RESERVED', [Int32] 0xC0220029) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FWP_DUPLICATE_CONDITION', [Int32] 0xC022002A) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FWP_DUPLICATE_KEYMOD', [Int32] 0xC022002B) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FWP_ACTION_INCOMPATIBLE_WITH_LAYER', [Int32] 0xC022002C) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FWP_ACTION_INCOMPATIBLE_WITH_SUBLAYER', [Int32] 0xC022002D) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FWP_CONTEXT_INCOMPATIBLE_WITH_LAYER', [Int32] 0xC022002E) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FWP_CONTEXT_INCOMPATIBLE_WITH_CALLOUT', [Int32] 0xC022002F) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FWP_INCOMPATIBLE_AUTH_METHOD', [Int32] 0xC0220030) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FWP_INCOMPATIBLE_DH_GROUP', [Int32] 0xC0220031) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FWP_EM_NOT_SUPPORTED', [Int32] 0xC0220032) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FWP_NEVER_MATCH', [Int32] 0xC0220033) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FWP_PROVIDER_CONTEXT_MISMATCH', [Int32] 0xC0220034) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FWP_INVALID_PARAMETER', [Int32] 0xC0220035) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FWP_TOO_MANY_SUBLAYERS', [Int32] 0xC0220036) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FWP_CALLOUT_NOTIFICATION_FAILED', [Int32] 0xC0220037) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FWP_INVALID_AUTH_TRANSFORM', [Int32] 0xC0220038) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FWP_INVALID_CIPHER_TRANSFORM', [Int32] 0xC0220039) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FWP_INCOMPATIBLE_CIPHER_TRANSFORM', [Int32] 0xC022003A) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FWP_INVALID_TRANSFORM_COMBINATION', [Int32] 0xC022003B) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FWP_DUPLICATE_AUTH_METHOD', [Int32] 0xC022003C) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FWP_INVALID_TUNNEL_ENDPOINT', [Int32] 0xC022003D) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FWP_L2_DRIVER_NOT_READY', [Int32] 0xC022003E) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FWP_KEY_DICTATOR_ALREADY_REGISTERED', [Int32] 0xC022003F) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FWP_KEY_DICTATION_INVALID_KEYING_MATERIAL', [Int32] 0xC0220040) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FWP_CONNECTIONS_DISABLED', [Int32] 0xC0220041) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FWP_INVALID_DNS_NAME', [Int32] 0xC0220042) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FWP_STILL_ON', [Int32] 0xC0220043) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FWP_IKEEXT_NOT_RUNNING', [Int32] 0xC0220044) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FWP_TCPIP_NOT_READY', [Int32] 0xC0220100) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FWP_INJECT_HANDLE_CLOSING', [Int32] 0xC0220101) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FWP_INJECT_HANDLE_STALE', [Int32] 0xC0220102) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FWP_CANNOT_PEND', [Int32] 0xC0220103) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_FWP_DROP_NOICMP', [Int32] 0xC0220104) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_NDIS_CLOSING', [Int32] 0xC0230002) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_NDIS_BAD_VERSION', [Int32] 0xC0230004) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_NDIS_BAD_CHARACTERISTICS', [Int32] 0xC0230005) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_NDIS_ADAPTER_NOT_FOUND', [Int32] 0xC0230006) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_NDIS_OPEN_FAILED', [Int32] 0xC0230007) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_NDIS_DEVICE_FAILED', [Int32] 0xC0230008) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_NDIS_MULTICAST_FULL', [Int32] 0xC0230009) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_NDIS_MULTICAST_EXISTS', [Int32] 0xC023000A) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_NDIS_MULTICAST_NOT_FOUND', [Int32] 0xC023000B) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_NDIS_REQUEST_ABORTED', [Int32] 0xC023000C) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_NDIS_RESET_IN_PROGRESS', [Int32] 0xC023000D) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_NDIS_NOT_SUPPORTED', [Int32] 0xC02300BB) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_NDIS_INVALID_PACKET', [Int32] 0xC023000F) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_NDIS_ADAPTER_NOT_READY', [Int32] 0xC0230011) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_NDIS_INVALID_LENGTH', [Int32] 0xC0230014) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_NDIS_INVALID_DATA', [Int32] 0xC0230015) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_NDIS_BUFFER_TOO_SHORT', [Int32] 0xC0230016) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_NDIS_INVALID_OID', [Int32] 0xC0230017) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_NDIS_ADAPTER_REMOVED', [Int32] 0xC0230018) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_NDIS_UNSUPPORTED_MEDIA', [Int32] 0xC0230019) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_NDIS_GROUP_ADDRESS_IN_USE', [Int32] 0xC023001A) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_NDIS_FILE_NOT_FOUND', [Int32] 0xC023001B) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_NDIS_ERROR_READING_FILE', [Int32] 0xC023001C) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_NDIS_ALREADY_MAPPED', [Int32] 0xC023001D) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_NDIS_RESOURCE_CONFLICT', [Int32] 0xC023001E) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_NDIS_MEDIA_DISCONNECTED', [Int32] 0xC023001F) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_NDIS_INVALID_ADDRESS', [Int32] 0xC0230022) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_NDIS_INVALID_DEVICE_REQUEST', [Int32] 0xC0230010) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_NDIS_PAUSED', [Int32] 0xC023002A) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_NDIS_INTERFACE_NOT_FOUND', [Int32] 0xC023002B) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_NDIS_UNSUPPORTED_REVISION', [Int32] 0xC023002C) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_NDIS_INVALID_PORT', [Int32] 0xC023002D) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_NDIS_INVALID_PORT_STATE', [Int32] 0xC023002E) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_NDIS_LOW_POWER_STATE', [Int32] 0xC023002F) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_NDIS_REINIT_REQUIRED', [Int32] 0xC0230030) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_NDIS_DOT11_AUTO_CONFIG_ENABLED', [Int32] 0xC0232000) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_NDIS_DOT11_MEDIA_IN_USE', [Int32] 0xC0232001) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_NDIS_DOT11_POWER_STATE_INVALID', [Int32] 0xC0232002) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_NDIS_PM_WOL_PATTERN_LIST_FULL', [Int32] 0xC0232003) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_NDIS_PM_PROTOCOL_OFFLOAD_LIST_FULL', [Int32] 0xC0232004) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_NDIS_INDICATION_REQUIRED', [Int32] 0x40230001) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_NDIS_OFFLOAD_POLICY', [Int32] 0xC023100F) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_NDIS_OFFLOAD_CONNECTION_REJECTED', [Int32] 0xC0231012) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_NDIS_OFFLOAD_PATH_REJECTED', [Int32] 0xC0231013) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_TPM_ERROR_MASK', [Int32] 0xC0290000) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_TPM_AUTHFAIL', [Int32] 0xC0290001) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_TPM_BADINDEX', [Int32] 0xC0290002) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_TPM_BAD_PARAMETER', [Int32] 0xC0290003) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_TPM_AUDITFAILURE', [Int32] 0xC0290004) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_TPM_CLEAR_DISABLED', [Int32] 0xC0290005) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_TPM_DEACTIVATED', [Int32] 0xC0290006) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_TPM_DISABLED', [Int32] 0xC0290007) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_TPM_DISABLED_CMD', [Int32] 0xC0290008) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_TPM_FAIL', [Int32] 0xC0290009) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_TPM_BAD_ORDINAL', [Int32] 0xC029000A) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_TPM_INSTALL_DISABLED', [Int32] 0xC029000B) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_TPM_INVALID_KEYHANDLE', [Int32] 0xC029000C) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_TPM_KEYNOTFOUND', [Int32] 0xC029000D) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_TPM_INAPPROPRIATE_ENC', [Int32] 0xC029000E) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_TPM_MIGRATEFAIL', [Int32] 0xC029000F) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_TPM_INVALID_PCR_INFO', [Int32] 0xC0290010) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_TPM_NOSPACE', [Int32] 0xC0290011) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_TPM_NOSRK', [Int32] 0xC0290012) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_TPM_NOTSEALED_BLOB', [Int32] 0xC0290013) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_TPM_OWNER_SET', [Int32] 0xC0290014) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_TPM_RESOURCES', [Int32] 0xC0290015) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_TPM_SHORTRANDOM', [Int32] 0xC0290016) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_TPM_SIZE', [Int32] 0xC0290017) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_TPM_WRONGPCRVAL', [Int32] 0xC0290018) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_TPM_BAD_PARAM_SIZE', [Int32] 0xC0290019) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_TPM_SHA_THREAD', [Int32] 0xC029001A) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_TPM_SHA_ERROR', [Int32] 0xC029001B) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_TPM_FAILEDSELFTEST', [Int32] 0xC029001C) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_TPM_AUTH2FAIL', [Int32] 0xC029001D) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_TPM_BADTAG', [Int32] 0xC029001E) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_TPM_IOERROR', [Int32] 0xC029001F) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_TPM_ENCRYPT_ERROR', [Int32] 0xC0290020) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_TPM_DECRYPT_ERROR', [Int32] 0xC0290021) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_TPM_INVALID_AUTHHANDLE', [Int32] 0xC0290022) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_TPM_NO_ENDORSEMENT', [Int32] 0xC0290023) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_TPM_INVALID_KEYUSAGE', [Int32] 0xC0290024) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_TPM_WRONG_ENTITYTYPE', [Int32] 0xC0290025) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_TPM_INVALID_POSTINIT', [Int32] 0xC0290026) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_TPM_INAPPROPRIATE_SIG', [Int32] 0xC0290027) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_TPM_BAD_KEY_PROPERTY', [Int32] 0xC0290028) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_TPM_BAD_MIGRATION', [Int32] 0xC0290029) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_TPM_BAD_SCHEME', [Int32] 0xC029002A) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_TPM_BAD_DATASIZE', [Int32] 0xC029002B) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_TPM_BAD_MODE', [Int32] 0xC029002C) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_TPM_BAD_PRESENCE', [Int32] 0xC029002D) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_TPM_BAD_VERSION', [Int32] 0xC029002E) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_TPM_NO_WRAP_TRANSPORT', [Int32] 0xC029002F) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_TPM_AUDITFAIL_UNSUCCESSFUL', [Int32] 0xC0290030) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_TPM_AUDITFAIL_SUCCESSFUL', [Int32] 0xC0290031) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_TPM_NOTRESETABLE', [Int32] 0xC0290032) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_TPM_NOTLOCAL', [Int32] 0xC0290033) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_TPM_BAD_TYPE', [Int32] 0xC0290034) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_TPM_INVALID_RESOURCE', [Int32] 0xC0290035) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_TPM_NOTFIPS', [Int32] 0xC0290036) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_TPM_INVALID_FAMILY', [Int32] 0xC0290037) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_TPM_NO_NV_PERMISSION', [Int32] 0xC0290038) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_TPM_REQUIRES_SIGN', [Int32] 0xC0290039) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_TPM_KEY_NOTSUPPORTED', [Int32] 0xC029003A) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_TPM_AUTH_CONFLICT', [Int32] 0xC029003B) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_TPM_AREA_LOCKED', [Int32] 0xC029003C) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_TPM_BAD_LOCALITY', [Int32] 0xC029003D) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_TPM_READ_ONLY', [Int32] 0xC029003E) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_TPM_PER_NOWRITE', [Int32] 0xC029003F) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_TPM_FAMILYCOUNT', [Int32] 0xC0290040) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_TPM_WRITE_LOCKED', [Int32] 0xC0290041) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_TPM_BAD_ATTRIBUTES', [Int32] 0xC0290042) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_TPM_INVALID_STRUCTURE', [Int32] 0xC0290043) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_TPM_KEY_OWNER_CONTROL', [Int32] 0xC0290044) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_TPM_BAD_COUNTER', [Int32] 0xC0290045) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_TPM_NOT_FULLWRITE', [Int32] 0xC0290046) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_TPM_CONTEXT_GAP', [Int32] 0xC0290047) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_TPM_MAXNVWRITES', [Int32] 0xC0290048) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_TPM_NOOPERATOR', [Int32] 0xC0290049) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_TPM_RESOURCEMISSING', [Int32] 0xC029004A) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_TPM_DELEGATE_LOCK', [Int32] 0xC029004B) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_TPM_DELEGATE_FAMILY', [Int32] 0xC029004C) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_TPM_DELEGATE_ADMIN', [Int32] 0xC029004D) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_TPM_TRANSPORT_NOTEXCLUSIVE', [Int32] 0xC029004E) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_TPM_OWNER_CONTROL', [Int32] 0xC029004F) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_TPM_DAA_RESOURCES', [Int32] 0xC0290050) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_TPM_DAA_INPUT_DATA0', [Int32] 0xC0290051) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_TPM_DAA_INPUT_DATA1', [Int32] 0xC0290052) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_TPM_DAA_ISSUER_SETTINGS', [Int32] 0xC0290053) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_TPM_DAA_TPM_SETTINGS', [Int32] 0xC0290054) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_TPM_DAA_STAGE', [Int32] 0xC0290055) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_TPM_DAA_ISSUER_VALIDITY', [Int32] 0xC0290056) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_TPM_DAA_WRONG_W', [Int32] 0xC0290057) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_TPM_BAD_HANDLE', [Int32] 0xC0290058) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_TPM_BAD_DELEGATE', [Int32] 0xC0290059) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_TPM_BADCONTEXT', [Int32] 0xC029005A) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_TPM_TOOMANYCONTEXTS', [Int32] 0xC029005B) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_TPM_MA_TICKET_SIGNATURE', [Int32] 0xC029005C) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_TPM_MA_DESTINATION', [Int32] 0xC029005D) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_TPM_MA_SOURCE', [Int32] 0xC029005E) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_TPM_MA_AUTHORITY', [Int32] 0xC029005F) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_TPM_PERMANENTEK', [Int32] 0xC0290061) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_TPM_BAD_SIGNATURE', [Int32] 0xC0290062) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_TPM_NOCONTEXTSPACE', [Int32] 0xC0290063) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_TPM_COMMAND_BLOCKED', [Int32] 0xC0290400) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_TPM_INVALID_HANDLE', [Int32] 0xC0290401) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_TPM_DUPLICATE_VHANDLE', [Int32] 0xC0290402) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_TPM_EMBEDDED_COMMAND_BLOCKED', [Int32] 0xC0290403) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_TPM_EMBEDDED_COMMAND_UNSUPPORTED', [Int32] 0xC0290404) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_TPM_RETRY', [Int32] 0xC0290800) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_TPM_NEEDS_SELFTEST', [Int32] 0xC0290801) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_TPM_DOING_SELFTEST', [Int32] 0xC0290802) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_TPM_DEFEND_LOCK_RUNNING', [Int32] 0xC0290803) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_TPM_COMMAND_CANCELED', [Int32] 0xC0291001) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_TPM_TOO_MANY_CONTEXTS', [Int32] 0xC0291002) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_TPM_NOT_FOUND', [Int32] 0xC0291003) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_TPM_ACCESS_DENIED', [Int32] 0xC0291004) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_TPM_INSUFFICIENT_BUFFER', [Int32] 0xC0291005) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_TPM_PPI_FUNCTION_UNSUPPORTED', [Int32] 0xC0291006) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_PCP_ERROR_MASK', [Int32] 0xC0292000) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_PCP_DEVICE_NOT_READY', [Int32] 0xC0292001) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_PCP_INVALID_HANDLE', [Int32] 0xC0292002) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_PCP_INVALID_PARAMETER', [Int32] 0xC0292003) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_PCP_FLAG_NOT_SUPPORTED', [Int32] 0xC0292004) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_PCP_NOT_SUPPORTED', [Int32] 0xC0292005) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_PCP_BUFFER_TOO_SMALL', [Int32] 0xC0292006) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_PCP_INTERNAL_ERROR', [Int32] 0xC0292007) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_PCP_AUTHENTICATION_FAILED', [Int32] 0xC0292008) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_PCP_AUTHENTICATION_IGNORED', [Int32] 0xC0292009) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_PCP_POLICY_NOT_FOUND', [Int32] 0xC029200A) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_PCP_PROFILE_NOT_FOUND', [Int32] 0xC029200B) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_PCP_VALIDATION_FAILED', [Int32] 0xC029200C) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_HV_INVALID_HYPERCALL_CODE', [Int32] 0xC0350002) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_HV_INVALID_HYPERCALL_INPUT', [Int32] 0xC0350003) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_HV_INVALID_ALIGNMENT', [Int32] 0xC0350004) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_HV_INVALID_PARAMETER', [Int32] 0xC0350005) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_HV_ACCESS_DENIED', [Int32] 0xC0350006) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_HV_INVALID_PARTITION_STATE', [Int32] 0xC0350007) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_HV_OPERATION_DENIED', [Int32] 0xC0350008) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_HV_UNKNOWN_PROPERTY', [Int32] 0xC0350009) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_HV_PROPERTY_VALUE_OUT_OF_RANGE', [Int32] 0xC035000A) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_HV_INSUFFICIENT_MEMORY', [Int32] 0xC035000B) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_HV_PARTITION_TOO_DEEP', [Int32] 0xC035000C) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_HV_INVALID_PARTITION_ID', [Int32] 0xC035000D) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_HV_INVALID_VP_INDEX', [Int32] 0xC035000E) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_HV_INVALID_PORT_ID', [Int32] 0xC0350011) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_HV_INVALID_CONNECTION_ID', [Int32] 0xC0350012) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_HV_INSUFFICIENT_BUFFERS', [Int32] 0xC0350013) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_HV_NOT_ACKNOWLEDGED', [Int32] 0xC0350014) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_HV_ACKNOWLEDGED', [Int32] 0xC0350016) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_HV_INVALID_SAVE_RESTORE_STATE', [Int32] 0xC0350017) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_HV_INVALID_SYNIC_STATE', [Int32] 0xC0350018) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_HV_OBJECT_IN_USE', [Int32] 0xC0350019) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_HV_INVALID_PROXIMITY_DOMAIN_INFO', [Int32] 0xC035001A) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_HV_NO_DATA', [Int32] 0xC035001B) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_HV_INACTIVE', [Int32] 0xC035001C) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_HV_NO_RESOURCES', [Int32] 0xC035001D) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_HV_FEATURE_UNAVAILABLE', [Int32] 0xC035001E) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_HV_INSUFFICIENT_DEVICE_DOMAINS', [Int32] 0xC0350038) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_HV_INVALID_LP_INDEX', [Int32] 0xC0350041) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_HV_NOT_PRESENT', [Int32] 0xC0351000) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_VID_DUPLICATE_HANDLER', [Int32] 0xC0370001) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_VID_TOO_MANY_HANDLERS', [Int32] 0xC0370002) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_VID_QUEUE_FULL', [Int32] 0xC0370003) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_VID_HANDLER_NOT_PRESENT', [Int32] 0xC0370004) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_VID_INVALID_OBJECT_NAME', [Int32] 0xC0370005) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_VID_PARTITION_NAME_TOO_LONG', [Int32] 0xC0370006) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_VID_MESSAGE_QUEUE_NAME_TOO_LONG', [Int32] 0xC0370007) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_VID_PARTITION_ALREADY_EXISTS', [Int32] 0xC0370008) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_VID_PARTITION_DOES_NOT_EXIST', [Int32] 0xC0370009) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_VID_PARTITION_NAME_NOT_FOUND', [Int32] 0xC037000A) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_VID_MESSAGE_QUEUE_ALREADY_EXISTS', [Int32] 0xC037000B) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_VID_EXCEEDED_MBP_ENTRY_MAP_LIMIT', [Int32] 0xC037000C) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_VID_MB_STILL_REFERENCED', [Int32] 0xC037000D) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_VID_CHILD_GPA_PAGE_SET_CORRUPTED', [Int32] 0xC037000E) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_VID_INVALID_NUMA_SETTINGS', [Int32] 0xC037000F) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_VID_INVALID_NUMA_NODE_INDEX', [Int32] 0xC0370010) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_VID_NOTIFICATION_QUEUE_ALREADY_ASSOCIATED', [Int32] 0xC0370011) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_VID_INVALID_MEMORY_BLOCK_HANDLE', [Int32] 0xC0370012) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_VID_PAGE_RANGE_OVERFLOW', [Int32] 0xC0370013) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_VID_INVALID_MESSAGE_QUEUE_HANDLE', [Int32] 0xC0370014) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_VID_INVALID_GPA_RANGE_HANDLE', [Int32] 0xC0370015) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_VID_NO_MEMORY_BLOCK_NOTIFICATION_QUEUE', [Int32] 0xC0370016) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_VID_MEMORY_BLOCK_LOCK_COUNT_EXCEEDED', [Int32] 0xC0370017) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_VID_INVALID_PPM_HANDLE', [Int32] 0xC0370018) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_VID_MBPS_ARE_LOCKED', [Int32] 0xC0370019) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_VID_MESSAGE_QUEUE_CLOSED', [Int32] 0xC037001A) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_VID_VIRTUAL_PROCESSOR_LIMIT_EXCEEDED', [Int32] 0xC037001B) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_VID_STOP_PENDING', [Int32] 0xC037001C) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_VID_INVALID_PROCESSOR_STATE', [Int32] 0xC037001D) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_VID_EXCEEDED_KM_CONTEXT_COUNT_LIMIT', [Int32] 0xC037001E) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_VID_KM_INTERFACE_ALREADY_INITIALIZED', [Int32] 0xC037001F) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_VID_MB_PROPERTY_ALREADY_SET_RESET', [Int32] 0xC0370020) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_VID_MMIO_RANGE_DESTROYED', [Int32] 0xC0370021) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_VID_INVALID_CHILD_GPA_PAGE_SET', [Int32] 0xC0370022) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_VID_RESERVE_PAGE_SET_IS_BEING_USED', [Int32] 0xC0370023) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_VID_RESERVE_PAGE_SET_TOO_SMALL', [Int32] 0xC0370024) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_VID_MBP_ALREADY_LOCKED_USING_RESERVED_PAGE', [Int32] 0xC0370025) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_VID_MBP_COUNT_EXCEEDED_LIMIT', [Int32] 0xC0370026) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_VID_SAVED_STATE_CORRUPT', [Int32] 0xC0370027) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_VID_SAVED_STATE_UNRECOGNIZED_ITEM', [Int32] 0xC0370028) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_VID_SAVED_STATE_INCOMPATIBLE', [Int32] 0xC0370029) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_VID_REMOTE_NODE_PARENT_GPA_PAGES_USED', [Int32] 0x80370001) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_IPSEC_BAD_SPI', [Int32] 0xC0360001) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_IPSEC_SA_LIFETIME_EXPIRED', [Int32] 0xC0360002) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_IPSEC_WRONG_SA', [Int32] 0xC0360003) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_IPSEC_REPLAY_CHECK_FAILED', [Int32] 0xC0360004) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_IPSEC_INVALID_PACKET', [Int32] 0xC0360005) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_IPSEC_INTEGRITY_CHECK_FAILED', [Int32] 0xC0360006) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_IPSEC_CLEAR_TEXT_DROP', [Int32] 0xC0360007) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_IPSEC_AUTH_FIREWALL_DROP', [Int32] 0xC0360008) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_IPSEC_THROTTLE_DROP', [Int32] 0xC0360009) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_IPSEC_DOSP_BLOCK', [Int32] 0xC0368000) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_IPSEC_DOSP_RECEIVED_MULTICAST', [Int32] 0xC0368001) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_IPSEC_DOSP_INVALID_PACKET', [Int32] 0xC0368002) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_IPSEC_DOSP_STATE_LOOKUP_FAILED', [Int32] 0xC0368003) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_IPSEC_DOSP_MAX_ENTRIES', [Int32] 0xC0368004) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_IPSEC_DOSP_KEYMOD_NOT_ALLOWED', [Int32] 0xC0368005) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_IPSEC_DOSP_MAX_PER_IP_RATELIMIT_QUEUES', [Int32] 0xC0368006) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_VOLMGR_INCOMPLETE_REGENERATION', [Int32] 0x80380001) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_VOLMGR_INCOMPLETE_DISK_MIGRATION', [Int32] 0x80380002) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_VOLMGR_DATABASE_FULL', [Int32] 0xC0380001) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_VOLMGR_DISK_CONFIGURATION_CORRUPTED', [Int32] 0xC0380002) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_VOLMGR_DISK_CONFIGURATION_NOT_IN_SYNC', [Int32] 0xC0380003) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_VOLMGR_PACK_CONFIG_UPDATE_FAILED', [Int32] 0xC0380004) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_VOLMGR_DISK_CONTAINS_NON_SIMPLE_VOLUME', [Int32] 0xC0380005) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_VOLMGR_DISK_DUPLICATE', [Int32] 0xC0380006) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_VOLMGR_DISK_DYNAMIC', [Int32] 0xC0380007) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_VOLMGR_DISK_ID_INVALID', [Int32] 0xC0380008) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_VOLMGR_DISK_INVALID', [Int32] 0xC0380009) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_VOLMGR_DISK_LAST_VOTER', [Int32] 0xC038000A) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_VOLMGR_DISK_LAYOUT_INVALID', [Int32] 0xC038000B) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_VOLMGR_DISK_LAYOUT_NON_BASIC_BETWEEN_BASIC_PARTITIONS', [Int32] 0xC038000C) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_VOLMGR_DISK_LAYOUT_NOT_CYLINDER_ALIGNED', [Int32] 0xC038000D) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_VOLMGR_DISK_LAYOUT_PARTITIONS_TOO_SMALL', [Int32] 0xC038000E) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_VOLMGR_DISK_LAYOUT_PRIMARY_BETWEEN_LOGICAL_PARTITIONS', [Int32] 0xC038000F) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_VOLMGR_DISK_LAYOUT_TOO_MANY_PARTITIONS', [Int32] 0xC0380010) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_VOLMGR_DISK_MISSING', [Int32] 0xC0380011) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_VOLMGR_DISK_NOT_EMPTY', [Int32] 0xC0380012) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_VOLMGR_DISK_NOT_ENOUGH_SPACE', [Int32] 0xC0380013) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_VOLMGR_DISK_REVECTORING_FAILED', [Int32] 0xC0380014) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_VOLMGR_DISK_SECTOR_SIZE_INVALID', [Int32] 0xC0380015) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_VOLMGR_DISK_SET_NOT_CONTAINED', [Int32] 0xC0380016) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_VOLMGR_DISK_USED_BY_MULTIPLE_MEMBERS', [Int32] 0xC0380017) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_VOLMGR_DISK_USED_BY_MULTIPLE_PLEXES', [Int32] 0xC0380018) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_VOLMGR_DYNAMIC_DISK_NOT_SUPPORTED', [Int32] 0xC0380019) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_VOLMGR_EXTENT_ALREADY_USED', [Int32] 0xC038001A) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_VOLMGR_EXTENT_NOT_CONTIGUOUS', [Int32] 0xC038001B) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_VOLMGR_EXTENT_NOT_IN_PUBLIC_REGION', [Int32] 0xC038001C) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_VOLMGR_EXTENT_NOT_SECTOR_ALIGNED', [Int32] 0xC038001D) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_VOLMGR_EXTENT_OVERLAPS_EBR_PARTITION', [Int32] 0xC038001E) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_VOLMGR_EXTENT_VOLUME_LENGTHS_DO_NOT_MATCH', [Int32] 0xC038001F) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_VOLMGR_FAULT_TOLERANT_NOT_SUPPORTED', [Int32] 0xC0380020) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_VOLMGR_INTERLEAVE_LENGTH_INVALID', [Int32] 0xC0380021) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_VOLMGR_MAXIMUM_REGISTERED_USERS', [Int32] 0xC0380022) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_VOLMGR_MEMBER_IN_SYNC', [Int32] 0xC0380023) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_VOLMGR_MEMBER_INDEX_DUPLICATE', [Int32] 0xC0380024) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_VOLMGR_MEMBER_INDEX_INVALID', [Int32] 0xC0380025) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_VOLMGR_MEMBER_MISSING', [Int32] 0xC0380026) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_VOLMGR_MEMBER_NOT_DETACHED', [Int32] 0xC0380027) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_VOLMGR_MEMBER_REGENERATING', [Int32] 0xC0380028) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_VOLMGR_ALL_DISKS_FAILED', [Int32] 0xC0380029) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_VOLMGR_NO_REGISTERED_USERS', [Int32] 0xC038002A) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_VOLMGR_NO_SUCH_USER', [Int32] 0xC038002B) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_VOLMGR_NOTIFICATION_RESET', [Int32] 0xC038002C) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_VOLMGR_NUMBER_OF_MEMBERS_INVALID', [Int32] 0xC038002D) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_VOLMGR_NUMBER_OF_PLEXES_INVALID', [Int32] 0xC038002E) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_VOLMGR_PACK_DUPLICATE', [Int32] 0xC038002F) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_VOLMGR_PACK_ID_INVALID', [Int32] 0xC0380030) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_VOLMGR_PACK_INVALID', [Int32] 0xC0380031) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_VOLMGR_PACK_NAME_INVALID', [Int32] 0xC0380032) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_VOLMGR_PACK_OFFLINE', [Int32] 0xC0380033) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_VOLMGR_PACK_HAS_QUORUM', [Int32] 0xC0380034) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_VOLMGR_PACK_WITHOUT_QUORUM', [Int32] 0xC0380035) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_VOLMGR_PARTITION_STYLE_INVALID', [Int32] 0xC0380036) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_VOLMGR_PARTITION_UPDATE_FAILED', [Int32] 0xC0380037) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_VOLMGR_PLEX_IN_SYNC', [Int32] 0xC0380038) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_VOLMGR_PLEX_INDEX_DUPLICATE', [Int32] 0xC0380039) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_VOLMGR_PLEX_INDEX_INVALID', [Int32] 0xC038003A) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_VOLMGR_PLEX_LAST_ACTIVE', [Int32] 0xC038003B) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_VOLMGR_PLEX_MISSING', [Int32] 0xC038003C) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_VOLMGR_PLEX_REGENERATING', [Int32] 0xC038003D) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_VOLMGR_PLEX_TYPE_INVALID', [Int32] 0xC038003E) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_VOLMGR_PLEX_NOT_RAID5', [Int32] 0xC038003F) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_VOLMGR_PLEX_NOT_SIMPLE', [Int32] 0xC0380040) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_VOLMGR_STRUCTURE_SIZE_INVALID', [Int32] 0xC0380041) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_VOLMGR_TOO_MANY_NOTIFICATION_REQUESTS', [Int32] 0xC0380042) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_VOLMGR_TRANSACTION_IN_PROGRESS', [Int32] 0xC0380043) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_VOLMGR_UNEXPECTED_DISK_LAYOUT_CHANGE', [Int32] 0xC0380044) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_VOLMGR_VOLUME_CONTAINS_MISSING_DISK', [Int32] 0xC0380045) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_VOLMGR_VOLUME_ID_INVALID', [Int32] 0xC0380046) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_VOLMGR_VOLUME_LENGTH_INVALID', [Int32] 0xC0380047) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_VOLMGR_VOLUME_LENGTH_NOT_SECTOR_SIZE_MULTIPLE', [Int32] 0xC0380048) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_VOLMGR_VOLUME_NOT_MIRRORED', [Int32] 0xC0380049) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_VOLMGR_VOLUME_NOT_RETAINED', [Int32] 0xC038004A) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_VOLMGR_VOLUME_OFFLINE', [Int32] 0xC038004B) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_VOLMGR_VOLUME_RETAINED', [Int32] 0xC038004C) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_VOLMGR_NUMBER_OF_EXTENTS_INVALID', [Int32] 0xC038004D) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_VOLMGR_DIFFERENT_SECTOR_SIZE', [Int32] 0xC038004E) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_VOLMGR_BAD_BOOT_DISK', [Int32] 0xC038004F) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_VOLMGR_PACK_CONFIG_OFFLINE', [Int32] 0xC0380050) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_VOLMGR_PACK_CONFIG_ONLINE', [Int32] 0xC0380051) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_VOLMGR_NOT_PRIMARY_PACK', [Int32] 0xC0380052) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_VOLMGR_PACK_LOG_UPDATE_FAILED', [Int32] 0xC0380053) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_VOLMGR_NUMBER_OF_DISKS_IN_PLEX_INVALID', [Int32] 0xC0380054) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_VOLMGR_NUMBER_OF_DISKS_IN_MEMBER_INVALID', [Int32] 0xC0380055) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_VOLMGR_VOLUME_MIRRORED', [Int32] 0xC0380056) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_VOLMGR_PLEX_NOT_SIMPLE_SPANNED', [Int32] 0xC0380057) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_VOLMGR_NO_VALID_LOG_COPIES', [Int32] 0xC0380058) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_VOLMGR_PRIMARY_PACK_PRESENT', [Int32] 0xC0380059) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_VOLMGR_NUMBER_OF_DISKS_INVALID', [Int32] 0xC038005A) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_VOLMGR_MIRROR_NOT_SUPPORTED', [Int32] 0xC038005B) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_VOLMGR_RAID5_NOT_SUPPORTED', [Int32] 0xC038005C) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_BCD_NOT_ALL_ENTRIES_IMPORTED', [Int32] 0x80390001) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_BCD_TOO_MANY_ELEMENTS', [Int32] 0xC0390002) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_BCD_NOT_ALL_ENTRIES_SYNCHRONIZED', [Int32] 0x80390003) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_VHD_DRIVE_FOOTER_MISSING', [Int32] 0xC03A0001) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_VHD_DRIVE_FOOTER_CHECKSUM_MISMATCH', [Int32] 0xC03A0002) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_VHD_DRIVE_FOOTER_CORRUPT', [Int32] 0xC03A0003) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_VHD_FORMAT_UNKNOWN', [Int32] 0xC03A0004) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_VHD_FORMAT_UNSUPPORTED_VERSION', [Int32] 0xC03A0005) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_VHD_SPARSE_HEADER_CHECKSUM_MISMATCH', [Int32] 0xC03A0006) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_VHD_SPARSE_HEADER_UNSUPPORTED_VERSION', [Int32] 0xC03A0007) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_VHD_SPARSE_HEADER_CORRUPT', [Int32] 0xC03A0008) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_VHD_BLOCK_ALLOCATION_FAILURE', [Int32] 0xC03A0009) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_VHD_BLOCK_ALLOCATION_TABLE_CORRUPT', [Int32] 0xC03A000A) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_VHD_INVALID_BLOCK_SIZE', [Int32] 0xC03A000B) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_VHD_BITMAP_MISMATCH', [Int32] 0xC03A000C) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_VHD_PARENT_VHD_NOT_FOUND', [Int32] 0xC03A000D) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_VHD_CHILD_PARENT_ID_MISMATCH', [Int32] 0xC03A000E) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_VHD_CHILD_PARENT_TIMESTAMP_MISMATCH', [Int32] 0xC03A000F) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_VHD_METADATA_READ_FAILURE', [Int32] 0xC03A0010) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_VHD_METADATA_WRITE_FAILURE', [Int32] 0xC03A0011) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_VHD_INVALID_SIZE', [Int32] 0xC03A0012) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_VHD_INVALID_FILE_SIZE', [Int32] 0xC03A0013) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_VIRTDISK_PROVIDER_NOT_FOUND', [Int32] 0xC03A0014) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_VIRTDISK_NOT_VIRTUAL_DISK', [Int32] 0xC03A0015) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_VHD_PARENT_VHD_ACCESS_DENIED', [Int32] 0xC03A0016) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_VHD_CHILD_PARENT_SIZE_MISMATCH', [Int32] 0xC03A0017) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_VHD_DIFFERENCING_CHAIN_CYCLE_DETECTED', [Int32] 0xC03A0018) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_VHD_DIFFERENCING_CHAIN_ERROR_IN_PARENT', [Int32] 0xC03A0019) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_VIRTUAL_DISK_LIMITATION', [Int32] 0xC03A001A) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_VHD_INVALID_TYPE', [Int32] 0xC03A001B) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_VHD_INVALID_STATE', [Int32] 0xC03A001C) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_VIRTDISK_UNSUPPORTED_DISK_SECTOR_SIZE', [Int32] 0xC03A001D) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_VIRTDISK_DISK_ALREADY_OWNED', [Int32] 0xC03A001E) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_VIRTDISK_DISK_ONLINE_AND_WRITABLE', [Int32] 0xC03A001F) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_CTLOG_TRACKING_NOT_INITIALIZED', [Int32] 0xC03A0020) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_CTLOG_LOGFILE_SIZE_EXCEEDED_MAXSIZE', [Int32] 0xC03A0021) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_CTLOG_VHD_CHANGED_OFFLINE', [Int32] 0xC03A0022) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_CTLOG_INVALID_TRACKING_STATE', [Int32] 0xC03A0023) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_CTLOG_INCONSISTENT_TRACKING_FILE', [Int32] 0xC03A0024) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_VHD_METADATA_FULL', [Int32] 0xC03A0028) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_QUERY_STORAGE_ERROR', [Int32] 0x803A0001) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_DIS_NOT_PRESENT', [Int32] 0xC03C0001) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_DIS_ATTRIBUTE_NOT_FOUND', [Int32] 0xC03C0002) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_DIS_UNRECOGNIZED_ATTRIBUTE', [Int32] 0xC03C0003) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_DIS_PARTIAL_DATA', [Int32] 0xC03C0004) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_RKF_KEY_NOT_FOUND', [Int32] 0xC0400001) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_RKF_DUPLICATE_KEY', [Int32] 0xC0400002) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_RKF_BLOB_FULL', [Int32] 0xC0400003) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_RKF_STORE_FULL', [Int32] 0xC0400004) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_RKF_FILE_BLOCKED', [Int32] 0xC0400005) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_RKF_ACTIVE_KEY', [Int32] 0xC0400006) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_RDBSS_RESTART_OPERATION', [Int32] 0xC0410001) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_RDBSS_CONTINUE_OPERATION', [Int32] 0xC0410002) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_RDBSS_POST_OPERATION', [Int32] 0xC0410003) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_BTH_ATT_INVALID_HANDLE', [Int32] 0xC0420001) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_BTH_ATT_READ_NOT_PERMITTED', [Int32] 0xC0420002) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_BTH_ATT_WRITE_NOT_PERMITTED', [Int32] 0xC0420003) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_BTH_ATT_INVALID_PDU', [Int32] 0xC0420004) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_BTH_ATT_INSUFFICIENT_AUTHENTICATION', [Int32] 0xC0420005) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_BTH_ATT_REQUEST_NOT_SUPPORTED', [Int32] 0xC0420006) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_BTH_ATT_INVALID_OFFSET', [Int32] 0xC0420007) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_BTH_ATT_INSUFFICIENT_AUTHORIZATION', [Int32] 0xC0420008) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_BTH_ATT_PREPARE_QUEUE_FULL', [Int32] 0xC0420009) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_BTH_ATT_ATTRIBUTE_NOT_FOUND', [Int32] 0xC042000A) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_BTH_ATT_ATTRIBUTE_NOT_LONG', [Int32] 0xC042000B) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_BTH_ATT_INSUFFICIENT_ENCRYPTION_KEY_SIZE', [Int32] 0xC042000C) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_BTH_ATT_INVALID_ATTRIBUTE_VALUE_LENGTH', [Int32] 0xC042000D) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_BTH_ATT_UNLIKELY', [Int32] 0xC042000E) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_BTH_ATT_INSUFFICIENT_ENCRYPTION', [Int32] 0xC042000F) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_BTH_ATT_UNSUPPORTED_GROUP_TYPE', [Int32] 0xC0420010) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_BTH_ATT_INSUFFICIENT_RESOURCES', [Int32] 0xC0420011) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_BTH_ATT_UNKNOWN_ERROR', [Int32] 0xC0421000) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_SECUREBOOT_ROLLBACK_DETECTED', [Int32] 0xC0430001) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_SECUREBOOT_POLICY_VIOLATION', [Int32] 0xC0430002) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_SECUREBOOT_INVALID_POLICY', [Int32] 0xC0430003) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_SECUREBOOT_POLICY_PUBLISHER_NOT_FOUND', [Int32] 0xC0430004) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_SECUREBOOT_POLICY_NOT_SIGNED', [Int32] 0xC0430005) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_SECUREBOOT_NOT_ENABLED', [Int32] 0x80430006) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_SECUREBOOT_FILE_REPLACED', [Int32] 0xC0430007) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_AUDIO_ENGINE_NODE_NOT_FOUND', [Int32] 0xC0440001) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_HDAUDIO_EMPTY_CONNECTION_LIST', [Int32] 0xC0440002) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_HDAUDIO_CONNECTION_LIST_NOT_SUPPORTED', [Int32] 0xC0440003) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_HDAUDIO_NO_LOGICAL_DEVICES_CREATED', [Int32] 0xC0440004) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_HDAUDIO_NULL_LINKED_LIST_ENTRY', [Int32] 0xC0440005) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_SPACES_RESILIENCY_TYPE_INVALID', [Int32] 0xC0E70003) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_SPACES_DRIVE_SECTOR_SIZE_INVALID', [Int32] 0xC0E70004) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_SPACES_INTERLEAVE_LENGTH_INVALID', [Int32] 0xC0E70009) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_SPACES_NUMBER_OF_COLUMNS_INVALID', [Int32] 0xC0E7000A) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_SPACES_NOT_ENOUGH_DRIVES', [Int32] 0xC0E7000B) | Out-Null
        $EnumBuilder.DefineLiteral('STATUS_VOLSNAP_BOOTFILE_NOT_VALID', [Int32] 0xC0500003) | Out-Null
        $NtStatus = $EnumBuilder.CreateType()
    }

    try { $PoolType = [POOL_TYPE] } catch [Management.Automation.RuntimeException] # Only build the assembly if it hasn't already been defined
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

    try { $HandleFlags = [HANDLE_FLAGS] } catch [Management.Automation.RuntimeException] # Only build the assembly if it hasn't already been defined
    {
        $EnumBuilder = $ModuleBuilder.DefineEnum('HANDLE_FLAGS', 'Public', [Byte])
        $EnumBuilder.DefineLiteral('PROTECT_FROM_CLOSE', [Byte] 1) | Out-Null
        $EnumBuilder.DefineLiteral('INHERIT', [Byte] 2) | Out-Null
        $EnumBuilder.SetCustomAttribute($FlagsCustomAttribute)
        $HandleFlags = $EnumBuilder.CreateType()
    }

    try { $ObjectAttributes = [OBJECT_ATTRIBUTES] } catch [Management.Automation.RuntimeException] # Only build the assembly if it hasn't already been defined
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

    try { $ObjectFlags = [OBJECT_FLAGS] } catch [Management.Automation.RuntimeException] # Only build the assembly if it hasn't already been defined
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

    try { $AccessMask = [ACCESS_MASK] } catch [Management.Automation.RuntimeException] # Only build the assembly if it hasn't already been defined
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

    try { $GFlagsEnum = [GLOBAL_FLAGS] } catch [Management.Automation.RuntimeException] # Only build the assembly if it hasn't already been defined
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
    }
    else
    {
        $Size_SYSTEM_MODULE = 284
        $Size_SYSTEM_POOL_TAG_INFORMATION = 28
        $Size_SYSTEM_HANDLE_INFORMATION = 16
        $Size_SYSTEM_OBJECTTYPE_INFORMATION = 56
        $Size_SYSTEM_OBJECT_INFORMATION = 48
    }

    try { $UnicodeStringClass = [_UNICODE_STRING] } catch [Management.Automation.RuntimeException] # Only build the assembly if it hasn't already been defined
    {
        $MarshalAsCustomAttribute = New-Object Reflection.Emit.CustomAttributeBuilder($MarshalAsConstructor, @([Runtime.InteropServices.UnmanagedType]::LPWStr))

        if ([IntPtr]::Size -eq 8)
        {
            $TypeBuilder = $ModuleBuilder.DefineType('_UNICODE_STRING', $StructAttributes, [System.ValueType], 2, 16)
            $TypeBuilder.SetCustomAttribute($StructLayoutCustomAttribute)

            $TypeBuilder.DefineField('Length', [UInt16], 'Public').SetCustomAttribute((New-Object Reflection.Emit.CustomAttributeBuilder($FieldOffsetConstructor, @(0))))
            $TypeBuilder.DefineField('MaximumLength', [UInt16], 'Public').SetCustomAttribute((New-Object Reflection.Emit.CustomAttributeBuilder($FieldOffsetConstructor, @(2))))
            $BufferField = $TypeBuilder.DefineField('Buffer', [String], 'Public, HasFieldMarshal')
            $BufferField.SetCustomAttribute($MarshalAsCustomAttribute)
            $BufferField.SetCustomAttribute((New-Object Reflection.Emit.CustomAttributeBuilder($FieldOffsetConstructor, @(8))))
        }
        else
        {
            $TypeBuilder = $ModuleBuilder.DefineType('_UNICODE_STRING', $StructAttributes, [System.ValueType], 2, 8)
            $TypeBuilder.SetCustomAttribute($StructLayoutCustomAttribute)

            $TypeBuilder.DefineField('Length', [UInt16], 'Public').SetCustomAttribute((New-Object Reflection.Emit.CustomAttributeBuilder($FieldOffsetConstructor, @(0))))
            $TypeBuilder.DefineField('MaximumLength', [UInt16], 'Public').SetCustomAttribute((New-Object Reflection.Emit.CustomAttributeBuilder($FieldOffsetConstructor, @(2))))
            $BufferField = $TypeBuilder.DefineField('Buffer', [String], 'Public, HasFieldMarshal')
            $BufferField.SetCustomAttribute($MarshalAsCustomAttribute)
            $BufferField.SetCustomAttribute((New-Object Reflection.Emit.CustomAttributeBuilder($FieldOffsetConstructor, @(4))))
        }

        $UnicodeStringClass = $TypeBuilder.CreateType()
    }

    try { $GenericMappingClass = [_GENERIC_MAPPING] } catch [Management.Automation.RuntimeException] # Only build the assembly if it hasn't already been defined
    {
        $TypeBuilder = $ModuleBuilder.DefineType('_GENERIC_MAPPING', $StructAttributes, [System.ValueType], 4, 16)

        $TypeBuilder.DefineField('GenericRead', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('GenericWrite', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('GenericExecute', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('GenericAll', [UInt32], 'Public') | Out-Null

        $GenericMappingClass = $TypeBuilder.CreateType()
    }

    try { $HandleInfoClass = [_SYSTEM_HANDLE_INFORMATION] } catch [Management.Automation.RuntimeException] # Only build the assembly if it hasn't already been defined
    {
        $TypeBuilder = $ModuleBuilder.DefineType('_SYSTEM_HANDLE_INFORMATION', $StructAttributes, [System.ValueType], 1, $Size_SYSTEM_HANDLE_INFORMATION)

        $TypeBuilder.DefineField('UniqueProcessId', [UInt16], 'Public') | Out-Null
        $TypeBuilder.DefineField('CreatorBackTraceIndex', [UInt16], 'Public') | Out-Null
        $TypeBuilder.DefineField('ObjectTypeIndex', [Byte], 'Public') | Out-Null
        $TypeBuilder.DefineField('HandleAttribute', [Byte], 'Public') | Out-Null
        $TypeBuilder.DefineField('HandleValue', [UInt16], 'Public') | Out-Null
        $TypeBuilder.DefineField('Object', [IntPtr], 'Public') | Out-Null
        $TypeBuilder.DefineField('GrantedAccess', [UInt32], 'Public') | Out-Null

        $HandleInfoClass = $TypeBuilder.CreateType()
    }

    try { $ModuleInfoClass = [_SYSTEM_MODULE] } catch [Management.Automation.RuntimeException] # Only build the assembly if it hasn't already been defined
    {
        $MarshalAsCustomAttribute = New-Object Reflection.Emit.CustomAttributeBuilder($MarshalAsConstructor, @([Runtime.InteropServices.UnmanagedType]::ByValTStr), [Reflection.FieldInfo[]]@($SizeConst), @(256))

        if ([IntPtr]::Size -eq 8)
        {
            $TypeBuilder = $ModuleBuilder.DefineType('_SYSTEM_MODULE', $StructAttributes, [System.ValueType], 1, $Size_SYSTEM_MODULE)

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
            $TypeBuilder = $ModuleBuilder.DefineType('_SYSTEM_MODULE', $StructAttributes, [System.ValueType], 1, $Size_SYSTEM_MODULE)

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

    try { $PoolTagInfoClass = [_SYSTEM_POOL_TAG_INFORMATION] } catch [Management.Automation.RuntimeException] # Only build the assembly if it hasn't already been defined
    {
        $TypeBuilder = $ModuleBuilder.DefineType('_SYSTEM_POOL_TAG_INFORMATION', $StructAttributes, [System.ValueType], 4, $Size_SYSTEM_POOL_TAG_INFORMATION)
        $TypeBuilder.SetCustomAttribute($StructLayoutCustomAttribute)

        if ([IntPtr]::Size -eq 8)
        {
            $TypeBuilder.DefineField('TagValue', [UInt32], 'Public, HasFieldMarshal').SetCustomAttribute((New-Object Reflection.Emit.CustomAttributeBuilder($FieldOffsetConstructor, @(0))))
            $TypeBuilder.DefineField('PagedPoolAllocs', [UInt32], 'Public').SetCustomAttribute((New-Object Reflection.Emit.CustomAttributeBuilder($FieldOffsetConstructor, @(4))))
            $TypeBuilder.DefineField('PagedPoolFrees', [UInt32], 'Public').SetCustomAttribute((New-Object Reflection.Emit.CustomAttributeBuilder($FieldOffsetConstructor, @(8))))
            $TypeBuilder.DefineField('PagedPoolUsage', [UInt32], 'Public').SetCustomAttribute((New-Object Reflection.Emit.CustomAttributeBuilder($FieldOffsetConstructor, @(16))))
            $TypeBuilder.DefineField('NonPagedPoolAllocs', [UInt32], 'Public').SetCustomAttribute((New-Object Reflection.Emit.CustomAttributeBuilder($FieldOffsetConstructor, @(24))))
            $TypeBuilder.DefineField('NonPagedPoolFrees', [UInt32], 'Public').SetCustomAttribute((New-Object Reflection.Emit.CustomAttributeBuilder($FieldOffsetConstructor, @(28))))
            $TypeBuilder.DefineField('NonPagedPoolUsage', [UInt32], 'Public').SetCustomAttribute((New-Object Reflection.Emit.CustomAttributeBuilder($FieldOffsetConstructor, @(32))))
        }
        else
        {
            $TypeBuilder.DefineField('TagValue', [UInt32], 'Public, HasFieldMarshal').SetCustomAttribute((New-Object Reflection.Emit.CustomAttributeBuilder($FieldOffsetConstructor, @(0))))
            $TypeBuilder.DefineField('PagedPoolAllocs', [UInt32], 'Public').SetCustomAttribute((New-Object Reflection.Emit.CustomAttributeBuilder($FieldOffsetConstructor, @(4))))
            $TypeBuilder.DefineField('PagedPoolFrees', [UInt32], 'Public').SetCustomAttribute((New-Object Reflection.Emit.CustomAttributeBuilder($FieldOffsetConstructor, @(8))))
            $TypeBuilder.DefineField('PagedPoolUsage', [UInt32], 'Public').SetCustomAttribute((New-Object Reflection.Emit.CustomAttributeBuilder($FieldOffsetConstructor, @(12))))
            $TypeBuilder.DefineField('NonPagedPoolAllocs', [UInt32], 'Public').SetCustomAttribute((New-Object Reflection.Emit.CustomAttributeBuilder($FieldOffsetConstructor, @(16))))
            $TypeBuilder.DefineField('NonPagedPoolFrees', [UInt32], 'Public').SetCustomAttribute((New-Object Reflection.Emit.CustomAttributeBuilder($FieldOffsetConstructor, @(20))))
            $TypeBuilder.DefineField('NonPagedPoolUsage', [UInt32], 'Public').SetCustomAttribute((New-Object Reflection.Emit.CustomAttributeBuilder($FieldOffsetConstructor, @(24))))
        }

        $PoolTagInfoClass = $TypeBuilder.CreateType()
    }

    try { $HandleInfoClass = [_SYSTEM_HANDLE_INFORMATION] } catch [Management.Automation.RuntimeException] # Only build the assembly if it hasn't already been defined
    {
        $TypeBuilder = $ModuleBuilder.DefineType('_SYSTEM_HANDLE_INFORMATION', $StructAttributes, [System.ValueType], 1, $Size_SYSTEM_HANDLE_INFORMATION)

        $TypeBuilder.DefineField('UniqueProcessId', [UInt16], 'Public') | Out-Null
        $TypeBuilder.DefineField('CreatorBackTraceIndex', [UInt16], 'Public') | Out-Null
        $TypeBuilder.DefineField('ObjectTypeIndex', [Byte], 'Public') | Out-Null
        $TypeBuilder.DefineField('HandleAttribute', [Byte], 'Public') | Out-Null
        $TypeBuilder.DefineField('HandleValue', [UInt16], 'Public') | Out-Null
        $TypeBuilder.DefineField('Object', [IntPtr], 'Public') | Out-Null
        $TypeBuilder.DefineField('GrantedAccess', [UInt32], 'Public') | Out-Null

        $HandleInfoClass = $TypeBuilder.CreateType()
    }

    try { $ObjectTypeClass = [_SYSTEM_OBJECTTYPE_INFORMATION] } catch [Management.Automation.RuntimeException] # Only build the assembly if it hasn't already been defined
    {
        $TypeBuilder = $ModuleBuilder.DefineType('_SYSTEM_OBJECTTYPE_INFORMATION', $StructAttributes, [System.ValueType], 1, $Size_SYSTEM_OBJECTTYPE_INFORMATION)
        $TypeBuilder.SetCustomAttribute($StructLayoutCustomAttribute)

        $TypeBuilder.DefineField('NextEntryOffset', [UInt32], 'Public').SetCustomAttribute((New-Object Reflection.Emit.CustomAttributeBuilder($FieldOffsetConstructor, @(0x00))))
        $TypeBuilder.DefineField('NumberOfObjects', [UInt32], 'Public').SetCustomAttribute((New-Object Reflection.Emit.CustomAttributeBuilder($FieldOffsetConstructor, @(0x04))))
        $TypeBuilder.DefineField('NumberOfHandles', [UInt32], 'Public').SetCustomAttribute((New-Object Reflection.Emit.CustomAttributeBuilder($FieldOffsetConstructor, @(0x08))))
        $TypeBuilder.DefineField('TypeIndex', [UInt32], 'Public').SetCustomAttribute((New-Object Reflection.Emit.CustomAttributeBuilder($FieldOffsetConstructor, @(0x0C))))
        $TypeBuilder.DefineField('InvalidAttributes', [UInt32], 'Public').SetCustomAttribute((New-Object Reflection.Emit.CustomAttributeBuilder($FieldOffsetConstructor, @(0x10))))
        $TypeBuilder.DefineField('GenericMapping', $GenericMappingClass, 'Public').SetCustomAttribute((New-Object Reflection.Emit.CustomAttributeBuilder($FieldOffsetConstructor, @(0x14))))
        $TypeBuilder.DefineField('ValidAccessMask', [UInt32], 'Public').SetCustomAttribute((New-Object Reflection.Emit.CustomAttributeBuilder($FieldOffsetConstructor, @(0x24))))
        $TypeBuilder.DefineField('PoolType', $PoolType, 'Public').SetCustomAttribute((New-Object Reflection.Emit.CustomAttributeBuilder($FieldOffsetConstructor, @(0x28))))
        $TypeBuilder.DefineField('SecurityRequired', [Byte], 'Public').SetCustomAttribute((New-Object Reflection.Emit.CustomAttributeBuilder($FieldOffsetConstructor, @(0x2C))))
        $TypeBuilder.DefineField('WaitableObject', [Byte], 'Public').SetCustomAttribute((New-Object Reflection.Emit.CustomAttributeBuilder($FieldOffsetConstructor, @(0x2D))))
        $TypeBuilder.DefineField('TypeName', $UnicodeStringClass, 'Public').SetCustomAttribute((New-Object Reflection.Emit.CustomAttributeBuilder($FieldOffsetConstructor, @(0x30))))

        $ObjectTypeClass = $TypeBuilder.CreateType()
    }

    try { $ObjectTypeClass = [_SYSTEM_OBJECT_INFORMATION] } catch [Management.Automation.RuntimeException] # Only build the assembly if it hasn't already been defined
    {
        $TypeBuilder = $ModuleBuilder.DefineType('_SYSTEM_OBJECT_INFORMATION', $StructAttributes, [System.ValueType], 1, $Size_SYSTEM_OBJECT_INFORMATION)
        $TypeBuilder.SetCustomAttribute($StructLayoutCustomAttribute)

        if ([IntPtr]::Size -eq 8)
        {
            $TypeBuilder.DefineField('NextEntryOffset', [UInt32], 'Public').SetCustomAttribute((New-Object Reflection.Emit.CustomAttributeBuilder($FieldOffsetConstructor, @(0x00))))
            $TypeBuilder.DefineField('Object', [IntPtr], 'Public').SetCustomAttribute((New-Object Reflection.Emit.CustomAttributeBuilder($FieldOffsetConstructor, @(0x08))))
            $TypeBuilder.DefineField('CreatorUniqueProcess', [IntPtr], 'Public').SetCustomAttribute((New-Object Reflection.Emit.CustomAttributeBuilder($FieldOffsetConstructor, @(0x10))))
            $TypeBuilder.DefineField('CreatorBackTraceIndex', [UInt16], 'Public').SetCustomAttribute((New-Object Reflection.Emit.CustomAttributeBuilder($FieldOffsetConstructor, @(0x018))))
            $TypeBuilder.DefineField('Flags', [UInt16], 'Public').SetCustomAttribute((New-Object Reflection.Emit.CustomAttributeBuilder($FieldOffsetConstructor, @(0x1A))))
            $TypeBuilder.DefineField('PointerCount', [Int32], 'Public').SetCustomAttribute((New-Object Reflection.Emit.CustomAttributeBuilder($FieldOffsetConstructor, @(0x1C))))
            $TypeBuilder.DefineField('HandleCount', [Int32], 'Public').SetCustomAttribute((New-Object Reflection.Emit.CustomAttributeBuilder($FieldOffsetConstructor, @(0x20))))
            $TypeBuilder.DefineField('PagedPoolCharge', [UInt32], 'Public').SetCustomAttribute((New-Object Reflection.Emit.CustomAttributeBuilder($FieldOffsetConstructor, @(0x24))))
            $TypeBuilder.DefineField('NonPagedPoolCharge', [UInt32], 'Public').SetCustomAttribute((New-Object Reflection.Emit.CustomAttributeBuilder($FieldOffsetConstructor, @(0x28))))
            $TypeBuilder.DefineField('ExclusiveProcessId', [IntPtr], 'Public').SetCustomAttribute((New-Object Reflection.Emit.CustomAttributeBuilder($FieldOffsetConstructor, @(0x30))))
            $TypeBuilder.DefineField('SecurityDescriptor', [IntPtr], 'Public').SetCustomAttribute((New-Object Reflection.Emit.CustomAttributeBuilder($FieldOffsetConstructor, @(0x38))))
            $TypeBuilder.DefineField('NameInfo', $UnicodeStringClass, 'Public').SetCustomAttribute((New-Object Reflection.Emit.CustomAttributeBuilder($FieldOffsetConstructor, @(0x40))))
        }
        else
        {
            $TypeBuilder.DefineField('NextEntryOffset', [UInt32], 'Public').SetCustomAttribute((New-Object Reflection.Emit.CustomAttributeBuilder($FieldOffsetConstructor, @(0x00))))
            $TypeBuilder.DefineField('Object', [IntPtr], 'Public').SetCustomAttribute((New-Object Reflection.Emit.CustomAttributeBuilder($FieldOffsetConstructor, @(0x04))))
            $TypeBuilder.DefineField('CreatorUniqueProcess', [IntPtr], 'Public').SetCustomAttribute((New-Object Reflection.Emit.CustomAttributeBuilder($FieldOffsetConstructor, @(0x08))))
            $TypeBuilder.DefineField('CreatorBackTraceIndex', [UInt16], 'Public').SetCustomAttribute((New-Object Reflection.Emit.CustomAttributeBuilder($FieldOffsetConstructor, @(0x0C))))
            $TypeBuilder.DefineField('Flags', [UInt16], 'Public').SetCustomAttribute((New-Object Reflection.Emit.CustomAttributeBuilder($FieldOffsetConstructor, @(0x0E))))
            $TypeBuilder.DefineField('PointerCount', [Int32], 'Public').SetCustomAttribute((New-Object Reflection.Emit.CustomAttributeBuilder($FieldOffsetConstructor, @(0x10))))
            $TypeBuilder.DefineField('HandleCount', [Int32], 'Public').SetCustomAttribute((New-Object Reflection.Emit.CustomAttributeBuilder($FieldOffsetConstructor, @(0x14))))
            $TypeBuilder.DefineField('PagedPoolCharge', [UInt32], 'Public').SetCustomAttribute((New-Object Reflection.Emit.CustomAttributeBuilder($FieldOffsetConstructor, @(0x18))))
            $TypeBuilder.DefineField('NonPagedPoolCharge', [UInt32], 'Public').SetCustomAttribute((New-Object Reflection.Emit.CustomAttributeBuilder($FieldOffsetConstructor, @(0x1C))))
            $TypeBuilder.DefineField('ExclusiveProcessId', [IntPtr], 'Public').SetCustomAttribute((New-Object Reflection.Emit.CustomAttributeBuilder($FieldOffsetConstructor, @(0x20))))
            $TypeBuilder.DefineField('SecurityDescriptor', [IntPtr], 'Public').SetCustomAttribute((New-Object Reflection.Emit.CustomAttributeBuilder($FieldOffsetConstructor, @(0x24))))
            $TypeBuilder.DefineField('NameInfo', $UnicodeStringClass, 'Public').SetCustomAttribute((New-Object Reflection.Emit.CustomAttributeBuilder($FieldOffsetConstructor, @(0x28))))
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

        $Output = New-Object Byte[]($ReturnedLength)
        [Runtime.InteropServices.Marshal]::Copy($PtrData2, $Output, 0, $ReturnedLength)

        foreach ($i in 0..($Count-1))
        {
            [Runtime.InteropServices.Marshal]::PtrToStructure($StructAddress, $StructType)
            $StructAddress = ([IntPtr]($StructAddress.ToInt64() + $StructSize))
        }

        [Runtime.InteropServices.Marshal]::FreeHGlobal($PtrData2)    
    }

#region Main program logic
    switch ($PsCmdlet.ParameterSetName)
    {
        'ModuleInformation' {

            Get-Struct -InformationClass $SystemInformationClass::SystemModuleInformation `
                   -StructType $ModuleInfoClass `
                   -X86Size 284 `
                   -X64Size 296 `
                   -OffsetMultiplier 2 `
                   -ErrorText 'system module'

        }

        'PoolTagInformation' {
        
            Get-Struct -InformationClass $SystemInformationClass::SystemPoolTagInformation `
                   -StructType $PoolTagInfoClass `
                   -X86Size 28 `
                   -X64Size 40 `
                   -OffsetMultiplier 1 `
                   -ErrorText 'system pool tag' | % {
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
            Get-Struct -InformationClass $SystemInformationClass::SystemHandleInformation `
                   -StructType $HandleInfoClass `
                   -X86Size 16 `
                   -X64Size 24 `
                   -OffsetMultiplier 1 `
                   -ErrorText 'system handle' | % {
                           $Handle = $_.HandleAttribute -as $HandleFlags
                           if ($Handle -eq 0) {$HandleValue = $null} else {$HandleValue = $Handle}

                           $Access = ( ($_.GrantedAccess -band 0xFFFF0000) -as $AccessMask )
                           if ($Access -eq 0) {$AccessValue = $null} else {$AccessValue = $Access}

                           $Result = @{
                               UniqueProcessId = $_.UniqueProcessId
                               CreatorBackTraceIndex = $_.CreatorBackTraceIndex
                               ObjectTypeIndex = $_.ObjectTypeIndex
                               HandleAttribute = $HandleValue
                               HandleValue = $_.HandleValue
                               Object = $_.Object
                               GrantedAccess = $AccessValue
                           }

                           $Handle = New-Object PSObject -Property $Result
                           $Handle.PSObject.TypeNames.Insert(0, '_SYSTEM_HANDLE_INFORMATION')

                           Write-Output $Handle
                       }
        }

        'ObjectInformation' {
            # Get system global flags first to ensure the correct flags are set
            $Flags = Get-NtSystemInformation -GlobalFlags

            $RequiredFlags = [GLOBAL_FLAGS] 'FLG_MAINTAIN_OBJECT_TYPELIST, FLG_ENABLE_HANDLE_TYPE_TAGGING'

            if (($Flags -band $RequiredFlags) -ne $RequiredFlags)
            {
                throw 'Global flags FLG_MAINTAIN_OBJECT_TYPELIST and FLG_ENABLE_HANDLE_TYPE_TAGGING have not been set. They must be set in gflags.exe (i.e. `gflags.exe -r +otl +eot`) or in the registry.'
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

                $Result = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ObjectTypeAbsoluteAddress, $ObjectTypeClass)

                if ($Result.NumberOfObjects -gt 0)
                {
                    # Calculate the offset to the first _SYSTEM_OBJECT_INFORMATION structure
                    $NextObjectOffset = $Size_SYSTEM_OBJECTTYPE_INFORMATION + $Result.TypeName.MaximumLength
                    $ObjectBaseAddr = $ObjectTypeAbsoluteAddress

                    $ObjectArray = @()

                    do
                    {
                        $ObjectResult = [System.Runtime.InteropServices.Marshal]::PtrToStructure(( [IntPtr]($ObjectBaseAddr.ToInt64() + $NextObjectOffset) ), $ObjectClass)

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
                    ValidAccessMask = $Access
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

        'GlobalFlags' {
            $TotalLength = 0
            $ReturnedLength = 0

            if ((($ntdll::NtQuerySystemInformation($SystemInformationClass::SystemGlobalFlag, [IntPtr]::Zero, 0, [Ref] $TotalLength) -as [NTSTATUS]) -ne [NTSTATUS]::STATUS_INFO_LENGTH_MISMATCH) -and ($TotalLength -gt 0))
            {
                Write-Error "Unable to obtain global flags information information."
            }
            else
            {
                $PtrData = [Runtime.InteropServices.Marshal]::AllocHGlobal($TotalLength)
                $ntdll::NtQuerySystemInformation($SystemInformationClass::SystemGlobalFlag, $PtrData, $TotalLength, [Ref] $ReturnedLength) | Out-Null
                [Runtime.InteropServices.Marshal]::ReadInt32($PtrData) -as $GFlagsEnum
            }

            [Runtime.InteropServices.Marshal]::FreeHGlobal($PtrData)
        }

        default { return }
    }
}
#endregion
