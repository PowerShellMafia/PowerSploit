#include "notify_object.h"

POBJECT_DIRECTORY * ObpTypeDirectoryObject		= NULL;

const WCHAR *procCallToName[] = {
	L"Dump       ",
	L"Open       ",
	L"Close      ",
	L"Delete     ",
	L"Parse      ",
	L"Security   ",
	L"QueryName  ",
	L"OkayToClose",
};

NTSTATUS kListNotifyObjects(LPWSTR pszDest, size_t cbDest, LPWSTR *ppszDestEnd, size_t *pcbRemaining)
{
	return listNotifyOrClearObjects(pszDest, cbDest, ppszDestEnd, pcbRemaining, ListNotif);	
}

NTSTATUS kClearNotifyObjects(LPWSTR pszDest, size_t cbDest, LPWSTR *ppszDestEnd, size_t *pcbRemaining)
{
	return listNotifyOrClearObjects(pszDest, cbDest, ppszDestEnd, pcbRemaining, ClearNotif);	
}

NTSTATUS listNotifyOrClearObjects(LPWSTR pszDest, size_t cbDest, LPWSTR *ppszDestEnd, size_t *pcbRemaining, KIWI_NOTIF_OBJECT_ACTION action)
{
	NTSTATUS status;
	ULONG i, j;
	POBJECT_DIRECTORY_ENTRY monEntree;
	POBJECT_TYPE monType, monTypeDecal;
	PVOID * miniProc;
	POBJECT_CALLBACK_ENTRY pStruct;

	*ppszDestEnd = pszDest; *pcbRemaining= cbDest;
	status = RtlStringCbPrintfExW(*ppszDestEnd, *pcbRemaining, ppszDestEnd, pcbRemaining, STRSAFE_NO_TRUNCATION, L"kListNotifyObjects\n\n");
	
	if(NT_SUCCESS(status))
	{
		status = getObpTypeDirectoryObject();
		if(NT_SUCCESS(status))
		{
			for(i = 0; (i < OBJECT_HASH_TABLE_SIZE) && NT_SUCCESS(status); i++)
			{
				if((*ObpTypeDirectoryObject)->HashBuckets[i])
				{
					for(monEntree = (*ObpTypeDirectoryObject)->HashBuckets[i]; monEntree && NT_SUCCESS(status); monEntree = monEntree->NextEntry)
					{
						if(monType = monEntree->Object)
						{
							if(INDEX_OS < INDEX_VISTA)
								monType = (POBJECT_TYPE) ((ULONG_PTR) (monType) + sizeof(ERESOURCE));
							
							if(action == ListNotif)
							{
								status = RtlStringCbPrintfExW(*ppszDestEnd, *pcbRemaining, ppszDestEnd, pcbRemaining, STRSAFE_NO_TRUNCATION, L"\n%wZ\n", &(monType->Name));
								for(j = 0; (j < 8) && NT_SUCCESS(status); j++)
								{
									miniProc = (PVOID *) (((ULONG_PTR) &(monType->TypeInfo)) + FIELD_OFFSET(OBJECT_TYPE_INITIALIZER, DumpProcedure) + sizeof(PVOID)*j
									#ifdef _M_IX86
										- ((INDEX_OS < INDEX_VISTA) ? sizeof(ULONG) : 0)
									#endif
									);
									if(*miniProc)
									{
										status = RtlStringCbPrintfExW(*ppszDestEnd, *pcbRemaining, ppszDestEnd, pcbRemaining, STRSAFE_NO_TRUNCATION, L" - %ws : ", procCallToName[j]);
										if(NT_SUCCESS(status))
										{
											status = getModuleFromAddr((ULONG_PTR) *miniProc, *ppszDestEnd, *pcbRemaining, ppszDestEnd, pcbRemaining);
											if(NT_SUCCESS(status) || status == STATUS_NOT_FOUND)
											{
												status = RtlStringCbPrintfExW(*ppszDestEnd, *pcbRemaining, ppszDestEnd, pcbRemaining, STRSAFE_NO_TRUNCATION, L"\n");
											}
										}
									}
								}
							}
							if(INDEX_OS >= INDEX_VISTA)
							{
								if(INDEX_OS < INDEX_7)
									monType = (POBJECT_TYPE) ((ULONG_PTR) (monType) + sizeof(ERESOURCE) + 32*sizeof(EX_PUSH_LOCK));
								else if (INDEX_OS > INDEX_7)
									monType = (POBJECT_TYPE) ((ULONG_PTR) (monType) + sizeof(ULONG) + 2*sizeof(USHORT)); // W8 : nouveaux champs avant les callbacks
									
								for(pStruct = (POBJECT_CALLBACK_ENTRY) (monType->CallbackList.Flink) ; (pStruct != (POBJECT_CALLBACK_ENTRY) &(monType->CallbackList)) && NT_SUCCESS(status) ; pStruct = (POBJECT_CALLBACK_ENTRY) pStruct->CallbackList.Flink)
								{
									if(pStruct->PreOperation || pStruct->PostOperation)
									{
										status = RtlStringCbPrintfExW(*ppszDestEnd, *pcbRemaining, ppszDestEnd, pcbRemaining, STRSAFE_NO_TRUNCATION, L" * Callback %u  : ", pStruct->Operations, pStruct->PreOperation);;
										if(NT_SUCCESS(status))
										{
											status = getModuleFromAddr((ULONG_PTR) pStruct->PreOperation, *ppszDestEnd, *pcbRemaining, ppszDestEnd, pcbRemaining);
											if(NT_SUCCESS(status) || status == STATUS_NOT_FOUND)
											{
												status = RtlStringCbPrintfExW(*ppszDestEnd, *pcbRemaining, ppszDestEnd, pcbRemaining, STRSAFE_NO_TRUNCATION, L" / ");
												if(NT_SUCCESS(status))
												{
													status = getModuleFromAddr((ULONG_PTR) pStruct->PostOperation, *ppszDestEnd, *pcbRemaining, ppszDestEnd, pcbRemaining);
													if(NT_SUCCESS(status) || status == STATUS_NOT_FOUND)
													{
														status = RtlStringCbPrintfExW(*ppszDestEnd, *pcbRemaining, ppszDestEnd, pcbRemaining, STRSAFE_NO_TRUNCATION, L"\n");
													}
												}
											}
										}
										
										if(action == ClearNotif)
										{
											pStruct->PreOperation = NULL;
											pStruct->PostOperation = NULL;
											status = RtlStringCbPrintfExW(*ppszDestEnd, *pcbRemaining, ppszDestEnd, pcbRemaining, STRSAFE_NO_TRUNCATION, L" -> NULL !\n");
										}
									}
								}
							}
						}
					}
				}
			}
		}
	}
	return status;
}

NTSTATUS getObpTypeDirectoryObject()
{
	NTSTATUS retour = STATUS_NOT_FOUND;
	#ifdef _M_X64
		UCHAR PTRN_WALL_Object[]	= {0x66, 0x83, 0xf8, 0x5c, 0x0f, 0x84};
		LONG OFFS_WNT5_Object		= sizeof(PTRN_WALL_Object) + 4 + 2 + 2 + 8 + 8 + 8 + 3;
		LONG OFFS_WNO8_Object		= sizeof(PTRN_WALL_Object) + 4 + 3 + 2 + 3;
		LONG OFFS_WIN8_Object		= sizeof(PTRN_WALL_Object) + 4 + 2 + 2 + 3;
	#elif defined _M_IX86
		UCHAR PTRN_WALL_Object[]	= {0x5c, 0x0f, 0x84};
		LONG OFFS_WNT5_Object		= sizeof(PTRN_WALL_Object) + 4 + 2 + 2 + 2;
		LONG OFFS_WNO8_Object		= sizeof(PTRN_WALL_Object) + 4 + 2 + 2 + 1;
		LONG OFFS_WIN8_Object		= sizeof(PTRN_WALL_Object) + 4 + 2 + 2 + 2;
	#endif
	
	PUCHAR refDebut = NULL, refFin = NULL; LONG offsetTo = 0;
	UNICODE_STRING maRoutine;

	if(ObpTypeDirectoryObject)
	{
		retour = STATUS_SUCCESS;
	}
	else
	{
		RtlInitUnicodeString(&maRoutine, L"ObCreateObjectType");
		if(refDebut = (PUCHAR) MmGetSystemRoutineAddress(&maRoutine))
		{
			refFin = refDebut + PAGE_SIZE;
			
			if(INDEX_OS < INDEX_8)
			{
				if(INDEX_OS < INDEX_VISTA)
					offsetTo = OFFS_WNT5_Object;
				else
				{
					offsetTo = OFFS_WNO8_Object;
					#ifdef _M_X64
						refFin = refDebut - PAGE_SIZE;
					#endif
				}
			}
			else
				offsetTo = OFFS_WIN8_Object;
				
			retour = genericPointerSearch((PUCHAR *) &ObpTypeDirectoryObject, refDebut, refFin, PTRN_WALL_Object, sizeof(PTRN_WALL_Object), offsetTo);
		}
	}
	return retour;
}