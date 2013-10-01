#include "fsfilters.h"

NTSTATUS kFiltersList(LPWSTR pszDest, size_t cbDest, LPWSTR *ppszDestEnd, size_t *pcbRemaining)
{
	NTSTATUS status;
	ULONG ActualNumberDriverObjects = 0;
	PDRIVER_OBJECT * DriverObjectList = NULL;

	ULONG i;

	*ppszDestEnd = pszDest;
	*pcbRemaining= cbDest;
	
	IoEnumerateRegisteredFiltersList(NULL, 0, &ActualNumberDriverObjects);
	status = RtlStringCbPrintfExW(*ppszDestEnd, *pcbRemaining, ppszDestEnd, pcbRemaining, STRSAFE_NO_TRUNCATION, L"kFiltersList - ActualNumberDriverObjects : %u\n\n", ActualNumberDriverObjects);
	if(NT_SUCCESS(status))
	{
		if(ActualNumberDriverObjects > 0)
		{
			DriverObjectList = ExAllocatePoolWithTag(NonPagedPool, sizeof(PDRIVER_OBJECT) * ActualNumberDriverObjects, POOL_TAG);
			if(DriverObjectList != NULL)
			{
				IoEnumerateRegisteredFiltersList(DriverObjectList, sizeof(PDRIVER_OBJECT) * ActualNumberDriverObjects, &ActualNumberDriverObjects);
				for(i = 0; (i < ActualNumberDriverObjects) && NT_SUCCESS(status); i++)
				{
					status = RtlStringCbPrintfExW(*ppszDestEnd, *pcbRemaining, ppszDestEnd, pcbRemaining, STRSAFE_NO_TRUNCATION, L"[%.2u] %wZ\n",i , &(DriverObjectList[i]->DriverName));
					//DbgPrint("[%.2u] %wZ\n",i , &(DriverObjectList[i]->DriverName));
					ObDereferenceObject(DriverObjectList[i]);
				}
				ExFreePoolWithTag(DriverObjectList, POOL_TAG);
			}
		}
	}
	return status;
}