#pragma once
#include "notify.h"

#define OBJECT_HASH_TABLE_SIZE 37

typedef struct _OBJECT_DIRECTORY_ENTRY {
	struct	_OBJECT_DIRECTORY_ENTRY *NextEntry;
	PVOID	Object;
	ULONG	HashValue;	// pas en NT5
} OBJECT_DIRECTORY_ENTRY, *POBJECT_DIRECTORY_ENTRY;

typedef struct _OBJECT_DIRECTORY {
	POBJECT_DIRECTORY_ENTRY	HashBuckets[OBJECT_HASH_TABLE_SIZE];
	EX_PUSH_LOCK			Lock;
	PVOID					DeviceMap;
	ULONG					SessionId;
	PVOID					NamespaceEntry; // a partir de là, différent en NT5, mais pas utilisé...
	ULONG					Flags;
} OBJECT_DIRECTORY, *POBJECT_DIRECTORY;

typedef struct _OBJECT_TYPE_INITIALIZER	// NT6, décaler ULONG en NT5x86 (compensé par l'alignement en x64)
{
	SHORT Length;
	UCHAR ObjectTypeFlags;
	ULONG ObjectTypeCode;
	ULONG InvalidAttributes;
	GENERIC_MAPPING GenericMapping;
	ACCESS_MASK ValidAccessMask;
	ULONG RetainAccess;
	POOL_TYPE PoolType;
	ULONG DefaultPagedPoolCharge;
	ULONG DefaultNonPagedPoolCharge;
	PVOID DumpProcedure;
	PVOID OpenProcedure;
	PVOID CloseProcedure;
	PVOID DeleteProcedure;
	PVOID ParseProcedure;
	PVOID SecurityProcedure;
	PVOID QueryNameProcedure;
	PVOID OkayToCloseProcedure;
} OBJECT_TYPE_INITIALIZER, *POBJECT_TYPE_INITIALIZER;

typedef struct _OBJECT_TYPE {
	LIST_ENTRY				TypeList;
	UNICODE_STRING			Name;
	PVOID					DefaultObject;
	UCHAR					Index;
	ULONG					TotalNumberOfObjects;
	ULONG					TotalNumberOfHandles;
	ULONG					HighWaterNumberOfObjects;
	ULONG					HighWaterNumberOfHandles;
	OBJECT_TYPE_INITIALIZER	TypeInfo;
	EX_PUSH_LOCK			TypeLock;
	ULONG					Key;
	LIST_ENTRY				CallbackList;
} OBJECT_TYPE, *POBJECT_TYPE;

typedef struct _OBJECT_CALLBACK_ENTRY {
	LIST_ENTRY CallbackList;
	OB_OPERATION Operations;
	ULONG Active;
	/*OB_HANDLE*/ PVOID Handle;
	POBJECT_TYPE ObjectType;
	POB_PRE_OPERATION_CALLBACK  PreOperation;
	POB_POST_OPERATION_CALLBACK PostOperation;
} OBJECT_CALLBACK_ENTRY, *POBJECT_CALLBACK_ENTRY;

typedef enum _KIWI_NOTIF_OBJECT_ACTION
{
	ListNotif,
	ClearNotif
} KIWI_NOTIF_OBJECT_ACTION;

POBJECT_DIRECTORY * ObpTypeDirectoryObject;

NTSTATUS getObpTypeDirectoryObject();
NTSTATUS kListNotifyObjects(LPWSTR pszDest, size_t cbDest, LPWSTR *ppszDestEnd, size_t *pcbRemaining);
NTSTATUS kClearNotifyObjects(LPWSTR pszDest, size_t cbDest, LPWSTR *ppszDestEnd, size_t *pcbRemaining);
NTSTATUS listNotifyOrClearObjects(LPWSTR pszDest, size_t cbDest, LPWSTR *ppszDestEnd, size_t *pcbRemaining, KIWI_NOTIF_OBJECT_ACTION action);
