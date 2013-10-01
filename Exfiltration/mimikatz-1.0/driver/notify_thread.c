#include "notify_thread.h"

ULONG * PspCreateThreadNotifyRoutineCount		= NULL;
PVOID * PspCreateThreadNotifyRoutine			= NULL;

NTSTATUS kListNotifyThreads(LPWSTR pszDest, size_t cbDest, LPWSTR *ppszDestEnd, size_t *pcbRemaining)
{
	NTSTATUS status;
	ULONG i;
	PKIWI_CALLBACK monCallBack;

	*ppszDestEnd = pszDest; *pcbRemaining= cbDest;
	status = RtlStringCbPrintfExW(*ppszDestEnd, *pcbRemaining, ppszDestEnd, pcbRemaining, STRSAFE_NO_TRUNCATION, L"kListNotifyThreads\n\n");
	if(NT_SUCCESS(status))
	{
		status = getPspCreateThreadNotifyRoutine();
		if(NT_SUCCESS(status))
		{
			for(i = 0; (i < *PspCreateThreadNotifyRoutineCount) && NT_SUCCESS(status) ; i++)
			{
				monCallBack = (PKIWI_CALLBACK) KIWI_mask3bits(PspCreateThreadNotifyRoutine[i]);
				if(monCallBack != NULL)
				{
					status = RtlStringCbPrintfExW(*ppszDestEnd, *pcbRemaining, ppszDestEnd, pcbRemaining, STRSAFE_NO_TRUNCATION, L"[%.2u] ", i);
					if(NT_SUCCESS(status))
					{
						status = getModuleFromAddr((ULONG_PTR) monCallBack->callback, *ppszDestEnd, *pcbRemaining, ppszDestEnd, pcbRemaining);
						if(NT_SUCCESS(status) || status == STATUS_NOT_FOUND)
						{
							status = RtlStringCbPrintfExW(*ppszDestEnd, *pcbRemaining, ppszDestEnd, pcbRemaining, STRSAFE_NO_TRUNCATION, L"\n");
						}
					}
				}
			}
		}
	}
	return status;
}

NTSTATUS getPspCreateThreadNotifyRoutine()
{
	NTSTATUS retour = STATUS_NOT_FOUND;
	#ifdef _M_X64
		UCHAR PTRN_WNT5_Thread[]	= {0x48, 0x8d, 0x35};
		LONG OFFS_WNT5_Thread		= sizeof(PTRN_WNT5_Thread);
		UCHAR PTRN_WNT6_Thread[]	= {0x48, 0x8d, 0x0d};
		LONG OFFS_WNT6_Thread		= sizeof(PTRN_WNT6_Thread);
	#elif defined _M_IX86
		UCHAR PTRN_WNO8_Thread[]	= {0x56, 0xbe};
		LONG OFFS_WNO8_Thread		= sizeof(PTRN_WNO8_Thread);
		UCHAR PTRN_WIN8_Thread[]	= {0x53, 0xbb};
		LONG OFFS_WIN8_Thread		= sizeof(PTRN_WIN8_Thread);
	#endif
	LONG OFFS_WNT5_Count		= sizeof(PVOID) * MAX_NT5_PspCreateProcessNotifyRoutine;
	LONG OFFS_WNT6_Count		= sizeof(PVOID) * MAX_NT6_PspCreateThreadNotifyRoutine;

	PUCHAR pointeur = NULL, pattern = NULL, refDebut = (PUCHAR) PsSetCreateThreadNotifyRoutine, refFin = refDebut + PAGE_SIZE; SIZE_T taille = 0; LONG offsetTo = 0;
	LONG offsetToCount = 0;

	if(PspCreateThreadNotifyRoutine && PspCreateThreadNotifyRoutineCount)
	{
		retour = STATUS_SUCCESS;
	}
	else
	{
		if(INDEX_OS < INDEX_VISTA)
		{
			#ifdef _M_X64
				pattern		= PTRN_WNT5_Thread;
				taille		= sizeof(PTRN_WNT5_Thread);
				offsetTo	= OFFS_WNT5_Thread;
			#endif
			offsetToCount	= OFFS_WNT5_Count;
		}
		else
		{
			#ifdef _M_X64
				pattern		= PTRN_WNT6_Thread;
				taille		= sizeof(PTRN_WNT6_Thread);
				offsetTo	= OFFS_WNT6_Thread;
			#endif
			offsetToCount	= OFFS_WNT6_Count;
		}
		
		#if defined _M_IX86
			if(INDEX_OS < INDEX_8)
			{
				pattern		= PTRN_WNO8_Thread;
				taille		= sizeof(PTRN_WNO8_Thread);
				offsetTo	= OFFS_WNO8_Thread;
			}
			else
			{
				pattern		= PTRN_WIN8_Thread;
				taille		= sizeof(PTRN_WIN8_Thread);
				offsetTo	= OFFS_WIN8_Thread;
			}
		#endif
		
		retour = genericPointerSearch(&pointeur, refDebut, refFin, pattern, taille, offsetTo);
		if(NT_SUCCESS(retour))
		{
			PspCreateThreadNotifyRoutine			= (PVOID)	(pointeur);
			PspCreateThreadNotifyRoutineCount		= (PULONG)	(pointeur + offsetToCount);

			if(PspCreateThreadNotifyRoutine && PspCreateThreadNotifyRoutineCount)
				retour = STATUS_SUCCESS;
		}
	}
	return retour;
}
