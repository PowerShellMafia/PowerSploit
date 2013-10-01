/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : http://creativecommons.org/licenses/by/3.0/fr/
*/
#pragma once
#pragma warning(disable:4530)
#include <stdio.h>
#include <windows.h>
#include <ntsecapi.h>
#include <string>
#include <vector>
using namespace std;

#define SECURITY_WIN32
#define PAGE_SIZE			0x1000
#define MAX_DOMAIN_LEN		24
#define MAX_USERNAME_LEN	24

#define MIMIKATZ L"mimikatz"
#ifdef _M_X64
	#define MIMIKATZ_FULL L"mimikatz 1.0 x64 (RC)"
#else ifdef
	#define MIMIKATZ_FULL L"mimikatz 1.0 x86 (RC)"
#endif

#define NT_SUCCESS(Status)			(((NTSTATUS)(Status)) >= 0)
#define NT_INFORMATION(Status)		((((ULONG)(Status)) >> 30) == 1)
#define NT_WARNING(Status)			((((ULONG)(Status)) >> 30) == 2)
#define NT_ERROR(Status)			((((ULONG)(Status)) >> 30) == 3)

#define STATUS_SUCCESS				((NTSTATUS)0x00000000L)
#define STATUS_INFO_LENGTH_MISMATCH	((NTSTATUS)0xc0000004L)
#define STATUS_MORE_ENTRIES			((NTSTATUS)0x00000105L)

#define S_SWAP(a, b) {BYTE t = S[a]; S[a] = S[b]; S[b] = t;}

typedef bool (* PKIWI_LOCAL_COMMAND) (vector<wstring> * arguments);

typedef struct _KIWI_MIMIKATZ_LOCAL_MODULE_COMMAND {
	PKIWI_LOCAL_COMMAND ptrCommand;
	wstring commandName;
	wstring commandHelp;
	_KIWI_MIMIKATZ_LOCAL_MODULE_COMMAND(PKIWI_LOCAL_COMMAND command, wstring name, wstring help) : ptrCommand(command), commandName(name), commandHelp(help) {}
	_KIWI_MIMIKATZ_LOCAL_MODULE_COMMAND(PKIWI_LOCAL_COMMAND command, wstring name) : ptrCommand(command), commandName(name), commandHelp() {}
} KIWI_MIMIKATZ_LOCAL_MODULE_COMMAND, *PKIWI_MIMIKATZ_LOCAL_MODULE_COMMAND;

typedef struct _KIWI_MIMIKATZ_LOCAL_MODULE {
	wstring module;
	wstring description;
	vector<KIWI_MIMIKATZ_LOCAL_MODULE_COMMAND> commandes;
	_KIWI_MIMIKATZ_LOCAL_MODULE(wstring leModule, wstring laDescription, vector<KIWI_MIMIKATZ_LOCAL_MODULE_COMMAND> lesCommandes) : module(leModule), description(laDescription), commandes(lesCommandes) {}
} KIWI_MIMIKATZ_LOCAL_MODULE, *PKIWI_MIMIKATZ_LOCAL_MODULE;

typedef struct _CLIENT_ID {
	PVOID UniqueProcess;
	PVOID UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

typedef const ULONG CLONG;
typedef const UNICODE_STRING *PCUNICODE_STRING;
typedef STRING OEM_STRING;
typedef PSTRING POEM_STRING;
typedef CONST STRING* PCOEM_STRING;

/* System* */
typedef NTSTATUS		(WINAPI * PSYSTEM_FUNCTION_006) (LPCSTR string, BYTE hash[16]);
typedef NTSTATUS		(WINAPI * PSYSTEM_FUNCTION_007) (PUNICODE_STRING string, BYTE hash[16]);
typedef NTSTATUS		(WINAPI * PSYSTEM_FUNCTION_025) (BYTE[16], DWORD *, BYTE[16]);
typedef NTSTATUS		(WINAPI * PSYSTEM_FUNCTION_027) (BYTE[16], DWORD *, BYTE[16]);
/* CNG */
typedef SECURITY_STATUS	(WINAPI * PNCRYPT_OPEN_STORAGE_PROVIDER)	(__out NCRYPT_PROV_HANDLE *phProvider, __in_opt LPCWSTR pszProviderName, __in    DWORD   dwFlags);
typedef SECURITY_STATUS	(WINAPI * PNCRYPT_ENUM_KEYS)				(__in NCRYPT_PROV_HANDLE hProvider, __in_opt LPCWSTR pszScope, __deref_out NCryptKeyName **ppKeyName, __inout PVOID * ppEnumState, __in    DWORD   dwFlags);
typedef	SECURITY_STATUS	(WINAPI * PNCRYPT_OPEN_KEY)					(__in NCRYPT_PROV_HANDLE hProvider, __out NCRYPT_KEY_HANDLE *phKey, __in   LPCWSTR pszKeyName, __in   DWORD dwLegacyKeySpec, __in   DWORD dwFlags);
typedef SECURITY_STATUS	(WINAPI * PNCRYPT_EXPORT_KEY)				(__in NCRYPT_KEY_HANDLE hKey, __in_opt NCRYPT_KEY_HANDLE hExportKey, __in       LPCWSTR pszBlobType, __in_opt   NCryptBufferDesc *pParameterList, __out_opt  PBYTE pbOutput, __in       DWORD cbOutput, __out      DWORD *pcbResult, __in       DWORD dwFlags);
typedef SECURITY_STATUS	(WINAPI * PNCRYPT_GET_PROPERTY)				(__in NCRYPT_HANDLE hObject, __in LPCWSTR pszProperty, __out_bcount_part_opt(cbOutput, *pcbResult) PBYTE pbOutput, __in    DWORD   cbOutput, __out   DWORD * pcbResult, __in    DWORD   dwFlags);
typedef SECURITY_STATUS	(WINAPI * PNCRYPT_FREE_BUFFER)				(__deref PVOID pvInput);
typedef SECURITY_STATUS	(WINAPI * PNCRYPT_FREE_OBJECT)				(__in NCRYPT_HANDLE hObject);
typedef NTSTATUS		(WINAPI * PBCRYPT_ENUM_REGISTERED_PROVIDERS)(__inout ULONG* pcbBuffer, __deref_opt_inout_bcount_part_opt(*pcbBuffer, *pcbBuffer) PCRYPT_PROVIDERS *ppBuffer);
typedef VOID			(WINAPI * PBCRYPT_FREE_BUFFER)				(__in PVOID pvBuffer);

typedef NTSTATUS		(WINAPI * PBCRYPT_OPEN_ALGORITHM_PROVIDER)	(__out BCRYPT_ALG_HANDLE  *phAlgorithm, __in LPCWSTR pszAlgId, __in_opt LPCWSTR pszImplementation, __in ULONG dwFlags);
typedef NTSTATUS		(WINAPI * PBCRYPT_SET_PROPERTY)				(__inout BCRYPT_HANDLE hObject, __in LPCWSTR pszProperty, __in_bcount(cbInput) PUCHAR pbInput, __in ULONG cbInput, __in ULONG dwFlags);
typedef NTSTATUS		(WINAPI * PBCRYPT_GET_PROPERTY)				(__in BCRYPT_HANDLE hObject, __in LPCWSTR pszProperty, __out_bcount_part_opt(cbOutput, *pcbResult) PUCHAR pbOutput, __in ULONG cbOutput, __out ULONG *pcbResult, __in ULONG dwFlags);
typedef NTSTATUS		(WINAPI * PBCRYPT_GENERATE_SYMMETRIC_KEY)	(__inout BCRYPT_ALG_HANDLE hAlgorithm, __out BCRYPT_KEY_HANDLE *phKey, __out_bcount_full_opt(cbKeyObject) PUCHAR pbKeyObject, __in ULONG cbKeyObject, __in_bcount(cbSecret) PUCHAR pbSecret, __in ULONG cbSecret, __in ULONG dwFlags);
typedef NTSTATUS		(WINAPI * PBCRYTP_DESTROY_KEY)				(__inout BCRYPT_KEY_HANDLE hKey);
typedef NTSTATUS		(WINAPI * PBCRYTP_CLOSE_ALGORITHM_PROVIDER)	(__inout BCRYPT_ALG_HANDLE hAlgorithm, __in ULONG dwFlags);

/* Rtl* */
#define RtlEqualLuid(L1, L2) (((L1)->LowPart == (L2)->LowPart) && ((L1)->HighPart == (L2)->HighPart))
typedef NTSTATUS		(WINAPI * PRTL_CREATE_USER_THREAD)						(__in HANDLE Process, __in_opt PSECURITY_DESCRIPTOR ThreadSecurityDescriptor, __in char Flags, __in_opt ULONG ZeroBits, __in_opt SIZE_T MaximumStackSize, __in_opt SIZE_T CommittedStackSize, __in PTHREAD_START_ROUTINE StartAddress, __in_opt PVOID Parameter, __out_opt PHANDLE Thread, __out_opt PCLIENT_ID ClientId);
typedef VOID			(WINAPI * PRTL_INIT_STRING)								(PSTRING DestinationString, PCSTR SourceString);
typedef VOID			(WINAPI * PRTL_INIT_UNICODESTRING)						(PUNICODE_STRING DestinationString, PCWSTR SourceString);
typedef NTSTATUS		(WINAPI * PRTL_UPCASE_UNICODE_STRING_TO_OEM_STRING)		(POEM_STRING DestinationString, PCUNICODE_STRING SourceString, BOOLEAN AllocateDestinationString);
typedef VOID			(WINAPI * PRTL_FREE_OEM_STRING)							(POEM_STRING OemString);
typedef PVOID			(WINAPI * PRTL_LOOKUP_ELEMENT_GENERIC_TABLE_AV)			(__in struct _RTL_AVL_TABLE *Table, __in PVOID Buffer);
typedef enum _RTL_GENERIC_COMPARE_RESULTS	(WINAPI * PRTL_AVL_COMPARE_ROUTINE)	(__in struct _RTL_AVL_TABLE *Table, __in PVOID FirstStruct, __in PVOID SecondStruct);
typedef PVOID			(WINAPI * PRTL_AVL_ALLOCATE_ROUTINE)					(__in struct _RTL_AVL_TABLE *Table, __in CLONG ByteSize);
typedef VOID			(WINAPI * PRTL_AVL_FREE_ROUTINE)						(__in struct _RTL_AVL_TABLE *Table, __in PVOID Buffer);

typedef struct _RTL_BALANCED_LINKS {
	struct _RTL_BALANCED_LINKS *Parent;
	struct _RTL_BALANCED_LINKS *LeftChild;
	struct _RTL_BALANCED_LINKS *RightChild;
	CHAR Balance;
	UCHAR Reserved[3];
} RTL_BALANCED_LINKS;
typedef RTL_BALANCED_LINKS *PRTL_BALANCED_LINKS;

typedef enum _RTL_GENERIC_COMPARE_RESULTS {
	GenericLessThan,
	GenericGreaterThan,
	GenericEqual
} RTL_GENERIC_COMPARE_RESULTS;

typedef struct _RTL_AVL_TABLE {
	RTL_BALANCED_LINKS BalancedRoot;
	PVOID OrderedPointer;
	ULONG WhichOrderedElement;
	ULONG NumberGenericTableElements;
	ULONG DepthOfTree;
	PRTL_BALANCED_LINKS RestartKey;
	ULONG DeleteCount;
	PRTL_AVL_COMPARE_ROUTINE CompareRoutine;
	PRTL_AVL_ALLOCATE_ROUTINE AllocateRoutine;
	PRTL_AVL_FREE_ROUTINE FreeRoutine;
	PVOID TableContext;
} RTL_AVL_TABLE, *PRTL_AVL_TABLE;
