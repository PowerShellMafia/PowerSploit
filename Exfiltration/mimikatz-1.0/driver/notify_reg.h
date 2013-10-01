#pragma once
#include "notify.h"

ULONG * CmpCallBackCount;
PVOID * CmpCallBackVector;
PLIST_ENTRY CallbackListHead;

typedef struct _KIWI_REGISTRY6_CALLBACK
{
	LARGE_INTEGER cookie;
	PVOID context;
	PVOID callback;
	UNICODE_STRING altitude;
} KIWI_REGISTRY6_CALLBACK, *PKIWI_REGISTRY6_CALLBACK;

NTSTATUS getNotifyRegistryRoutine();
NTSTATUS kListNotifyRegistry(LPWSTR pszDest, size_t cbDest, LPWSTR *ppszDestEnd, size_t *pcbRemaining);
