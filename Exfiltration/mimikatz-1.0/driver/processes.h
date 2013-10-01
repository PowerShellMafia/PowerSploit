#pragma once
#include <ntifs.h>
#include "k_types.h"

#define	INDEX_EPROCESS_NEXT			0
#define	INDEX_EPROCESS_FLAGS2		1
#define	INDEX_TOKEN_PRIVS			2
#define MAX_EPROCESS_LEN			3

#define TOKEN_FROZEN_MASK	0x00008000

typedef struct _KIWI_NT6_PRIVILEGES
{
	UCHAR Present[8];
	UCHAR Enabled[8];
	UCHAR EnabledByDefault[8];
} KIWI_NT6_PRIVILEGES, *PKIWI_NT6_PRIVILEGES;

typedef enum _KIWI_EPROCESS_ACTION
{
	ListProcesses,
	ExchangeToken,
	FullPrivilegeNT6
} KIWI_EPROCESS_ACTION;

extern char* PsGetProcessImageFileName(PEPROCESS monProcess);
extern NTSYSAPI NTSTATUS NTAPI ZwSetInformationProcess (__in HANDLE ProcessHandle, __in PROCESSINFOCLASS ProcessInformationClass, __in_bcount(ProcessInformationLength) PVOID ProcessInformation, __in ULONG ProcessInformationLength);

NTSTATUS listProcesses(LPWSTR pszDest, size_t cbDest, LPWSTR *ppszDestEnd, size_t *pcbRemaining);
NTSTATUS sysToken(LPWSTR pszDest, size_t cbDest, LPWSTR *ppszDestEnd, size_t *pcbRemaining);
NTSTATUS privProcesses(LPWSTR pszDest, size_t cbDest, LPWSTR *ppszDestEnd, size_t *pcbRemaining);

NTSTATUS listProcessesOrSysToken(LPWSTR pszDest, size_t cbDest, LPWSTR *ppszDestEnd, size_t *pcbRemaining, KIWI_EPROCESS_ACTION action);