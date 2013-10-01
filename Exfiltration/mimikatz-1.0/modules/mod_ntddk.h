/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : http://creativecommons.org/licenses/by/3.0/fr/
*/
#pragma once
#include <windows.h>
#include <ntsecapi.h>

typedef LONG KPRIORITY;
typedef void** PPVOID;

typedef enum _SYSTEM_INFORMATION_CLASS {
	SystemBasicInformation,
	SystemProcessorInformation,
	SystemPerformanceInformation,
	SystemTimeOfDayInformation,
	SystemPathInformation,
	SystemProcessInformation,
	SystemCallCountInformation,
	SystemDeviceInformation,
	SystemProcessorPerformanceInformation,
	SystemFlagsInformation,
	SystemCallTimeInformation,
	SystemModuleInformation,
	SystemLocksInformation,
	SystemStackTraceInformation,
	SystemPagedPoolInformation,
	SystemNonPagedPoolInformation,
	SystemHandleInformation,
	SystemObjectInformation,
	SystemPageFileInformation,
	SystemVdmInstemulInformation,
	SystemVdmBopInformation,
	SystemFileCacheInformation,
	SystemPoolTagInformation,
	SystemInterruptInformation,
	SystemDpcBehaviorInformation,
	SystemFullMemoryInformation,
	SystemLoadGdiDriverInformation,
	SystemUnloadGdiDriverInformation,
	SystemTimeAdjustmentInformation,
	SystemSummaryMemoryInformation,
	SystemNextEventIdInformation,
	SystemEventIdsInformation,
	SystemCrashDumpInformation,
	SystemExceptionInformation,
	SystemCrashDumpStateInformation,
	SystemKernelDebuggerInformation,
	SystemContextSwitchInformation,
	SystemRegistryQuotaInformation,
	SystemExtendServiceTableInformation,
	SystemPrioritySeperation,
	SystemPlugPlayBusInformation,
	SystemDockInformation,
	KIWI_SystemPowerInformation,
	SystemProcessorSpeedInformation,
	SystemCurrentTimeZoneInformation,
	SystemLookasideInformation,
	KIWI_SystemMmSystemRangeStart = 50
} SYSTEM_INFORMATION_CLASS, *PSYSTEM_INFORMATION_CLASS;

typedef enum _OBJECT_INFORMATION_CLASS {
	ObjectBasicInformation,
	ObjectNameInformation,
	ObjectTypeInformation,
	ObjectAllInformation,
	ObjectDataInformation
} OBJECT_INFORMATION_CLASS, *POBJECT_INFORMATION_CLASS;


typedef enum _PROCESSINFOCLASS {
	ProcessBasicInformation,
	ProcessQuotaLimits,
	ProcessIoCounters,
	ProcessVmCounters,
	ProcessTimes,
	ProcessBasePriority,
	ProcessRaisePriority,
	ProcessDebugPort,
	ProcessExceptionPort,
	ProcessAccessToken,
	ProcessLdtInformation,
	ProcessLdtSize,
	ProcessDefaultHardErrorMode,
	ProcessIoPortHandlers,          // Note: this is kernel mode only
	ProcessPooledUsageAndLimits,
	ProcessWorkingSetWatch,
	ProcessUserModeIOPL,
	ProcessEnableAlignmentFaultFixup,
	ProcessPriorityClass,
	ProcessWx86Information,
	ProcessHandleCount,
	ProcessAffinityMask,
	ProcessPriorityBoost,
	ProcessDeviceMap,
	ProcessSessionInformation,
	ProcessForegroundInformation,
	ProcessWow64Information,
	ProcessImageFileName,
	ProcessLUIDDeviceMapsEnabled,
	ProcessBreakOnTermination,
	ProcessDebugObjectHandle,
	ProcessDebugFlags,
	ProcessHandleTracing,
	ProcessIoPriority,
	ProcessExecuteFlags,
	ProcessTlsInformation,
	ProcessCookie,
	ProcessImageInformation,
	ProcessCycleTime,
	ProcessPagePriority,
	ProcessInstrumentationCallback,
	ProcessThreadStackAllocation,
	ProcessWorkingSetWatchEx,
	ProcessImageFileNameWin32,
	ProcessImageFileMapping,
	ProcessAffinityUpdateMode,
	ProcessMemoryAllocationMode,
	ProcessGroupInformation,
	ProcessTokenVirtualizationEnabled,
	ProcessConsoleHostProcess,
	ProcessWindowInformation,
	MaxProcessInfoClass             // MaxProcessInfoClass should always be the last enum
} PROCESSINFOCLASS;

typedef enum _POOL_TYPE
{
    NonPagedPool,
    PagedPool,
    NonPagedPoolMustSucceed,
    DontUseThisType,
    NonPagedPoolCacheAligned,
    PagedPoolCacheAligned,
    NonPagedPoolCacheAlignedMustS
} POOL_TYPE, *PPOOL_TYPE;

typedef struct _PROCESS_SESSION_INFORMATION {
    ULONG   SessionId;
} PROCESS_SESSION_INFORMATION, *PPROCESS_SESSION_INFORMATION;

typedef struct _PROCESS_ACCESS_TOKEN {
	HANDLE Token;
	HANDLE Thread;
} PROCESS_ACCESS_TOKEN, *PPROCESS_ACCESS_TOKEN;

typedef struct _OBJECT_TYPE_INFORMATION
{
    UNICODE_STRING Name;
    ULONG TotalNumberOfObjects;
    ULONG TotalNumberOfHandles;
    ULONG TotalPagedPoolUsage;
    ULONG TotalNonPagedPoolUsage;
    ULONG TotalNamePoolUsage;
    ULONG TotalHandleTableUsage;
    ULONG HighWaterNumberOfObjects;
    ULONG HighWaterNumberOfHandles;
    ULONG HighWaterPagedPoolUsage;
    ULONG HighWaterNonPagedPoolUsage;
    ULONG HighWaterNamePoolUsage;
    ULONG HighWaterHandleTableUsage;
    ULONG InvalidAttributes;
    GENERIC_MAPPING GenericMapping;
    ULONG ValidAccess;
    BOOLEAN SecurityRequired;
    BOOLEAN MaintainHandleCount;
    USHORT MaintainTypeList;
    POOL_TYPE PoolType;
    ULONG PagedPoolUsage;
    ULONG NonPagedPoolUsage;
} OBJECT_TYPE_INFORMATION, *POBJECT_TYPE_INFORMATION;

typedef struct _LDR_DATA_TABLE_ENTRY
{
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderLinks;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;
	WORD LoadCount;
	WORD TlsIndex;
	union
	{
		LIST_ENTRY HashLinks;
		struct
		{
			PVOID SectionPointer;
			ULONG CheckSum;
		};
	};
	union
	{
		ULONG TimeDateStamp;
		PVOID LoadedImports;
	};
	DWORD EntryPointActivationContext; //_ACTIVATION_CONTEXT * EntryPointActivationContext;
	PVOID PatchInformation;
	LIST_ENTRY ForwarderLinks;
	LIST_ENTRY ServiceTagLinks;
	LIST_ENTRY StaticLinks;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;


typedef struct _PEB_LDR_DATA {
	ULONG Length; 
	BOOLEAN Initialized; 
	PVOID SsHandle; 
	LIST_ENTRY InLoadOrderModulevector; 
	LIST_ENTRY InMemoryOrderModulevector; 
	LIST_ENTRY InInitializationOrderModulevector;
} PEB_LDR_DATA, *PPEB_LDR_DATA;


typedef struct _PEB
{
	BOOLEAN InheritedAddressSpace; 
	BOOLEAN ReadImageFileExecOptions; 
	BOOLEAN BeingDebugged; 
	BOOLEAN Spare; 
	HANDLE Mutant; 
	PVOID ImageBaseAddress; 
	PPEB_LDR_DATA LoaderData; 
	PVOID ProcessParameters; //PRTL_USER_PROCESS_PARAMETERS ProcessParameters; 
	PVOID SubSystemData; 
	PVOID ProcessHeap; 
	PVOID FastPebLock; 
	PVOID FastPebLockRoutine; //PPEBLOCKROUTINE FastPebLockRoutine; 
	PVOID FastPebUnlockRoutine; //PPEBLOCKROUTINE FastPebUnlockRoutine; 
	ULONG EnvironmentUpdateCount; 
	PPVOID KernelCallbackTable; 
	PVOID EventLogSection; 
	PVOID EventLog; 
	DWORD Freevector; //PPEB_FREE_BLOCK Freevector; 
	ULONG TlsExpansionCounter; 
	PVOID TlsBitmap; 
	ULONG TlsBitmapBits[0x2]; 
	PVOID ReadOnlySharedMemoryBase; 
	PVOID ReadOnlySharedMemoryHeap; 
	PPVOID ReadOnlyStaticServerData; 
	PVOID AnsiCodePageData; 
	PVOID OemCodePageData; 
	PVOID UnicodeCaseTableData; 
	ULONG NumberOfProcessors; 
	ULONG NtGlobalFlag; 
	BYTE Spare2[0x4]; 
	LARGE_INTEGER CriticalSectionTimeout; 
	ULONG HeapSegmentReserve; 
	ULONG HeapSegmentCommit; 
	ULONG HeapDeCommitTotalFreeThreshold; 
	ULONG HeapDeCommitFreeBlockThreshold; 
	ULONG NumberOfHeaps; 
	ULONG MaximumNumberOfHeaps; 
	PPVOID *ProcessHeaps; 
	PVOID GdiSharedHandleTable; 
	PVOID ProcessStarterHelper; 
	PVOID GdiDCAttributevector; 
	PVOID LoaderLock; 
	ULONG OSMajorVersion; 
	ULONG OSMinorVersion; 
	ULONG OSBuildNumber; 
	ULONG OSPlatformId; 
	ULONG ImageSubSystem; 
	ULONG ImageSubSystemMajorVersion; 
	ULONG ImageSubSystemMinorVersion; 
	ULONG GdiHandleBuffer[0x22]; 
	ULONG PostProcessInitRoutine; 
	ULONG TlsExpansionBitmap; 
	BYTE TlsExpansionBitmapBits[0x80]; 
	ULONG SessionId;
} PEB, *PPEB;

typedef struct _PROCESS_BASIC_INFORMATION {
	NTSTATUS ExitStatus;
	PPEB PebBaseAddress;
	ULONG_PTR AffinityMask;
	KPRIORITY BasePriority;
	ULONG_PTR UniqueProcessId;
	ULONG_PTR InheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION,*PPROCESS_BASIC_INFORMATION;

typedef struct _PROCESS_EXTENDED_BASIC_INFORMATION {
	SIZE_T Size;    // Must be set to structure size on input
	PROCESS_BASIC_INFORMATION BasicInfo;
	union {
		ULONG Flags;
		struct {
			ULONG IsProtectedProcess : 1;
			ULONG IsWow64Process : 1;
			ULONG IsProcessDeleting : 1;
			ULONG IsCrossSessionCreate : 1;
			ULONG SpareBits : 28;
		} DUMMYSTRUCTNAME;
	} DUMMYUNIONNAME;
} PROCESS_EXTENDED_BASIC_INFORMATION, *PPROCESS_EXTENDED_BASIC_INFORMATION;

typedef struct _SYSTEM_HANDLE
{
    DWORD ProcessId;
    BYTE ObjectTypeNumber;
    BYTE Flags;
    USHORT Handle;
    PVOID Object;
    ACCESS_MASK GrantedAccess;
} SYSTEM_HANDLE, *PSYSTEM_HANDLE;

typedef struct _SYSTEM_HANDLE_INFORMATION
{
    DWORD HandleCount;
    SYSTEM_HANDLE Handles[1];
} SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION;

typedef NTSTATUS (WINAPI * PNT_QUERY_INFORMATION_PROCESS)	(__in HANDLE ProcessHandle, __in PROCESSINFOCLASS ProcessInformationClass, __out PVOID ProcessInformation, __in ULONG ProcessInformationLength, __out_opt  PULONG ReturnLength);
typedef NTSTATUS (WINAPI * PNT_SET_INFORMATION_PROCESS)		(__in HANDLE ProcessHandle, __in PROCESSINFOCLASS ProcessInformationClass, __in PVOID ProcessInformation, __in ULONG ProcessInformationLength); 
typedef NTSTATUS (WINAPI * PNT_SUSPEND_PROCESS)				(__in HANDLE ProcessHandle);
typedef NTSTATUS (WINAPI * PNT_RESUME_PROCESS)				(__in HANDLE ProcessHandle);
typedef NTSTATUS (WINAPI * PNT_QUERY_SYSTEM_INFORMATION)	(__in SYSTEM_INFORMATION_CLASS SystemInformationClass, __inout PVOID SystemInformation, __in ULONG SystemInformationLength, __out_opt PULONG ReturnLength);
typedef NTSTATUS (WINAPI * PNT_QUERY_OBJECT)				(__in_opt HANDLE Handle, __in OBJECT_INFORMATION_CLASS ObjectInformationClass, __out_opt PVOID ObjectInformation, __in ULONG ObjectInformationLength, __out_opt PULONG ReturnLength);
typedef NTSTATUS (WINAPI * PNT_FILTER_TOKEN)				(__in HANDLE ExistingTokenHandle, __in ULONG Flags, __in PTOKEN_GROUPS SidsToDisable, __in PTOKEN_PRIVILEGES PrivilegeToDelete, __in PTOKEN_GROUPS SidsToRestricted, __out PHANDLE NewTokenHandle);