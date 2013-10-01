#include "notify_image.h"

ULONG * PspLoadImageNotifyRoutineCount			= NULL;
PVOID * PspLoadImageNotifyRoutine				= NULL;

NTSTATUS kListNotifyImages(LPWSTR pszDest, size_t cbDest, LPWSTR *ppszDestEnd, size_t *pcbRemaining)
{
	NTSTATUS status;
	ULONG i;
	PKIWI_CALLBACK monCallBack;

	*ppszDestEnd = pszDest; *pcbRemaining= cbDest;
	status = RtlStringCbPrintfExW(*ppszDestEnd, *pcbRemaining, ppszDestEnd, pcbRemaining, STRSAFE_NO_TRUNCATION, L"kListNotifyImages\n\n");
	if(NT_SUCCESS(status))
	{
		status = getPspLoadImageNotifyRoutine();
		if(NT_SUCCESS(status))
		{
			for(i = 0; (i < *PspLoadImageNotifyRoutineCount) && NT_SUCCESS(status); i++)
			{
				monCallBack = (PKIWI_CALLBACK) KIWI_mask3bits(PspLoadImageNotifyRoutine[i]);
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

NTSTATUS getPspLoadImageNotifyRoutine()
{
	NTSTATUS retour = STATUS_NOT_FOUND;
	#ifdef _M_X64
		UCHAR PTRN_WNT5_Image[]	= {0x48, 0x8d, 0x35};
		LONG OFFS_WNT5_Image	= sizeof(PTRN_WNT5_Image);
		UCHAR PTRN_WNT6_Image[]	= {0x48, 0x8d, 0x0d};
		LONG OFFS_WNT6_Image	= sizeof(PTRN_WNT6_Image);

		LONG OFFS_WNT5_Count	= - 0x0c;
		LONG OFFS_WNT6_Count	= sizeof(PVOID) * MAX_NT_PspLoadImageNotifyRoutine;
	#elif defined _M_IX86
		UCHAR PTRN_WNT5_Image[]	= {0x6a, 0x00, 0x53, 0x56};
		UCHAR PTRN_WNO8_Image[]	= {0x6a, 0x00, 0x8b, 0xcb, 0x8b, 0xc6};
		UCHAR PTRN_WIN8_Image[]	= {0x33, 0xff, 0x6a, 0x00, 0x53, 0x8b, 0xc6};
		LONG OFFS_WALL_Image	= -(LONG) sizeof(PVOID);

		LONG OFFS_WNT5_Count	= - 0x18;
		LONG OFFS_WNO8_Count	= sizeof(PVOID) * MAX_NT_PspLoadImageNotifyRoutine;
		LONG OFFS_WIN8_Count	= - 0x20;
	#endif
	
	PUCHAR pointeur = NULL, pattern = NULL, refDebut = (PUCHAR) PsSetLoadImageNotifyRoutine, refFin = refDebut + PAGE_SIZE; SIZE_T taille = 0; LONG offsetTo = 0;
	LONG offsetToCountEx = 0, offsetToCount = 0;
	
	if(PspLoadImageNotifyRoutine && PspLoadImageNotifyRoutineCount)
	{
		retour = STATUS_SUCCESS;
	}
	else
	{
		if(INDEX_OS < INDEX_VISTA)
		{
			pattern			= PTRN_WNT5_Image;
			taille			= sizeof(PTRN_WNT5_Image);
			#ifdef _M_X64
				offsetTo		= OFFS_WNT5_Image;
			#endif
			offsetToCount	= OFFS_WNT5_Count;
		}
		else
		{
			#ifdef _M_X64
				pattern			= PTRN_WNT6_Image;
				taille			= sizeof(PTRN_WNT6_Image);
				offsetTo		= OFFS_WNT6_Image;
				offsetToCount	= OFFS_WNT6_Count;
			#elif defined _M_IX86
				if(INDEX_OS < INDEX_8)
				{
					pattern			= PTRN_WNO8_Image;
					taille			= sizeof(PTRN_WNO8_Image);
					offsetToCount	= OFFS_WNO8_Count;
				}
				else
				{
					pattern			= PTRN_WIN8_Image;
					taille			= sizeof(PTRN_WIN8_Image);
					offsetToCount	= OFFS_WIN8_Count;
				}
			#endif
		}
		#ifdef _M_IX86
			offsetTo		= OFFS_WALL_Image;
		#endif
		
		retour = genericPointerSearch(&pointeur, refDebut, refFin, pattern, taille, offsetTo);
		if(NT_SUCCESS(retour))
		{
			PspLoadImageNotifyRoutine		= (PVOID)	(pointeur);
			PspLoadImageNotifyRoutineCount	= (PULONG)	(pointeur + offsetToCount);

			if(PspLoadImageNotifyRoutine && PspLoadImageNotifyRoutineCount)
				retour = STATUS_SUCCESS;
		}
	}
	return retour;
}
