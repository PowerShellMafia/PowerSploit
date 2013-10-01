#include "mod_memory.h"

NTSTATUS searchMemory(const PUCHAR adresseBase, const PUCHAR adresseMaxMin, const PUCHAR pattern, PUCHAR *addressePattern, SIZE_T longueur)
{
	for(*addressePattern = adresseBase; (adresseMaxMin > adresseBase) ? (*addressePattern <= adresseMaxMin) : (*addressePattern >= adresseMaxMin); *addressePattern += (adresseMaxMin > adresseBase) ? 1 : -1)
	{
		if(RtlCompareMemory(pattern, *addressePattern, longueur) == longueur)
		{
			return STATUS_SUCCESS;
		}
	}
	*addressePattern = NULL;
	return STATUS_NOT_FOUND;
}

NTSTATUS genericPointerSearch(PUCHAR *addressePointeur, const PUCHAR adresseBase, const PUCHAR adresseMaxMin, const PUCHAR pattern, SIZE_T longueur, LONG offsetTo)
{
	NTSTATUS status = searchMemory(adresseBase, adresseMaxMin, pattern, addressePointeur, longueur);
	if(NT_SUCCESS(status))
	{
		*addressePointeur += offsetTo;
		#ifdef _M_X64
			*addressePointeur += sizeof(LONG) + *(PLONG)(*addressePointeur);
		#elif defined _M_IX86
			*addressePointeur = *(PUCHAR *)(*addressePointeur);
		#endif
		
		if(!*addressePointeur)
			status = STATUS_INVALID_HANDLE;
	}
	return status;
}
