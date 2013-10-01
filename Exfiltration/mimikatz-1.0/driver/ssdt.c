#include "ssdt.h"

#ifdef _M_X64
PSERVICE_DESCRIPTOR_TABLE	KeServiceDescriptorTable = NULL;
#endif

NTSTATUS kSSDT(LPWSTR pszDest, size_t cbDest, LPWSTR *ppszDestEnd, size_t *pcbRemaining)
{
	NTSTATUS status;
	USHORT idxFunction;
	ULONG_PTR funcAddr;

	#ifdef _M_X64
	status = getKeServiceDescriptorTable();
	if(NT_SUCCESS(status))
	{
	#endif
		*ppszDestEnd = pszDest; *pcbRemaining= cbDest;
		status = RtlStringCbPrintfExW(*ppszDestEnd, *pcbRemaining, ppszDestEnd, pcbRemaining, STRSAFE_NO_TRUNCATION , L"kSSDT - KeServiceDescriptorTable\t: %p\nkSSDT - KeServiceDescriptorTable.TableSize\t: %u\n", KeServiceDescriptorTable, KeServiceDescriptorTable->TableSize);
		for(idxFunction = 0; (idxFunction < KeServiceDescriptorTable->TableSize) && NT_SUCCESS(status) ; idxFunction++)
		{
			#ifdef _M_IX86
				funcAddr = (ULONG_PTR) KeServiceDescriptorTable->ServiceTable[idxFunction];
			#else
				funcAddr = (ULONG_PTR) KeServiceDescriptorTable->OffsetToService;
				if(INDEX_OS < INDEX_VISTA)
				{
					funcAddr += KeServiceDescriptorTable->OffsetToService[idxFunction] & ~EX_FAST_REF_MASK;
				}
				else
				{
					funcAddr += KeServiceDescriptorTable->OffsetToService[idxFunction] >> 4;
				}		
			#endif
			
			status = RtlStringCbPrintfExW(*ppszDestEnd, *pcbRemaining, ppszDestEnd, pcbRemaining, STRSAFE_NO_TRUNCATION, L"[%4u]\t: ", idxFunction);
			if(NT_SUCCESS(status))
			{
				status = getModuleFromAddr(funcAddr, *ppszDestEnd, *pcbRemaining, ppszDestEnd, pcbRemaining);
				if(NT_SUCCESS(status) || status == STATUS_NOT_FOUND)
				{
					status = RtlStringCbPrintfExW(*ppszDestEnd, *pcbRemaining, ppszDestEnd, pcbRemaining, STRSAFE_NO_TRUNCATION, L"\n");
				}
			}
		}
	#ifdef _M_X64
	}
	#endif
	return status;
}

#ifdef _M_X64
NTSTATUS getKeServiceDescriptorTable()
{
	NTSTATUS retour = STATUS_NOT_FOUND;
	
	UCHAR PTRN_WALL_Ke[]	= {0x00, 0x00, 0x4d, 0x0f, 0x45, 0xd3, 0x42, 0x3b, 0x44, 0x17, 0x10, 0x0f, 0x83};
	LONG OFFS_WNO8_Ke		= -19;
	LONG OFFS_WIN8_Ke		= -16;
	
	PUCHAR refDebut = NULL, refFin = NULL; LONG offsetTo = 0;
	UNICODE_STRING maRoutine;
	PUCHAR baseSearch = NULL;
		
	if(KeServiceDescriptorTable)
	{
		retour = STATUS_SUCCESS;
	}
	else
	{	
		RtlInitUnicodeString(&maRoutine, L"ZwUnloadKey");
		if(baseSearch = (PUCHAR) MmGetSystemRoutineAddress(&maRoutine))
		{
			refDebut= baseSearch - 21*PAGE_SIZE;
			refFin	= baseSearch + 16*PAGE_SIZE;
			offsetTo = (INDEX_OS < INDEX_8) ? OFFS_WNO8_Ke : OFFS_WIN8_Ke;

			retour = genericPointerSearch((PUCHAR *) &KeServiceDescriptorTable, refDebut, refFin, PTRN_WALL_Ke, sizeof(PTRN_WALL_Ke), offsetTo);
		}
	}
	return retour;
}
#endif