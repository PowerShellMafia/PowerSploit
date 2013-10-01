#pragma once
#include <ntddk.h>
#include <ntstrsafe.h>

#define MIN(a, b)  (((a) < (b)) ? (a) : (b))
#define MAX(a, b)  (((a) > (b)) ? (a) : (b))

#ifndef KIWI_NameToFunc
#define KIWI_NameToFunc(Name, Function)	 if(taillFunc == sizeof(Name) - sizeof(WCHAR)) if(RtlCompareMemory(Name, buffer, taillFunc) == taillFunc) {*destFunc = Function; return STATUS_SUCCESS;}
#endif

#ifndef KIWI_mask3bits
#define KIWI_mask3bits(addr)	 (((ULONG_PTR) (addr)) & ~7)
#endif

#define POOL_TAG	'iwik'

#define INDEX_UNK	0
#define INDEX_XP	1
#define INDEX_2K3	2
#define INDEX_VISTA	3
#define INDEX_2K8	4
#define INDEX_7		5
#define INDEX_2K8R2	6
#define INDEX_8		7
#define MAX_OS_LEN	8

#ifdef _M_IX86
#define EX_FAST_REF_MASK	0x07
#else
#define EX_FAST_REF_MASK	0x0f
#endif

typedef NTSTATUS (* ptrLocalFunction)	(LPWSTR pszDest, size_t cbDest, LPWSTR *ppszDestEnd, size_t *pcbRemaining);

ULONG INDEX_OS;

PDRIVER_OBJECT moi;

typedef struct _SERVICE_DESCRIPTOR_TABLE {
#ifdef _M_IX86
	PVOID	*ServiceTable;
#else
	LONG	*OffsetToService;
#endif
	PULONG	CounterTable;
	ULONG	TableSize;
	PUCHAR	ArgumentTable;
} SERVICE_DESCRIPTOR_TABLE, *PSERVICE_DESCRIPTOR_TABLE;
