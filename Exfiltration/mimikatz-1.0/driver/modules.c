#include "modules.h"

NTSTATUS kModulesList(LPWSTR pszDest, size_t cbDest, LPWSTR *ppszDestEnd, size_t *pcbRemaining)
{
	NTSTATUS status = STATUS_SUCCESS;
	ULONG i;
	ULONG modulesSize;
	AUX_MODULE_EXTENDED_INFO*  modules;
	ULONG  numberOfModules;
	
	*ppszDestEnd = pszDest;
	*pcbRemaining= cbDest;

	status = AuxKlibInitialize();
	if(NT_SUCCESS(status))
	{
		status = AuxKlibQueryModuleInformation(&modulesSize, sizeof(AUX_MODULE_EXTENDED_INFO), NULL);		
		if (NT_SUCCESS(status))
		{
			if(modulesSize > 0)
			{
				numberOfModules = modulesSize / sizeof(AUX_MODULE_EXTENDED_INFO);
				modules = (AUX_MODULE_EXTENDED_INFO*) ExAllocatePoolWithTag(PagedPool, modulesSize, POOL_TAG);
				
				if(modules != NULL)
				{
					status = AuxKlibQueryModuleInformation(&modulesSize, sizeof(AUX_MODULE_EXTENDED_INFO), modules);
					if (NT_SUCCESS(status))
					{
						for(i = 0; i < numberOfModules; i++)
						{
							status = RtlStringCbPrintfExW(*ppszDestEnd, *pcbRemaining, ppszDestEnd, pcbRemaining, STRSAFE_NO_TRUNCATION,
								L"%p - %.8u [%S] %S\n",
									modules[i].BasicInfo.ImageBase,
									modules[i].ImageSize,
									modules[i].FullPathName + modules[i].FileNameOffset,
									modules[i].FullPathName
								);
						}
					}
					ExFreePoolWithTag(modules, POOL_TAG);
				}
			}
		}
	}

	return status;	
}

NTSTATUS getModuleFromAddr(ULONG_PTR theAddr, LPWSTR pszDest, size_t cbDest, LPWSTR *ppszDestEnd, size_t *pcbRemaining)
{
	NTSTATUS status = STATUS_SUCCESS;
	ULONG i;
	ULONG modulesSize;
	AUX_MODULE_EXTENDED_INFO*  modules;
	ULONG  numberOfModules;
	
	*ppszDestEnd = pszDest;
	*pcbRemaining= cbDest;

	status = AuxKlibInitialize();
	if(NT_SUCCESS(status))
	{
		status = AuxKlibQueryModuleInformation(&modulesSize, sizeof(AUX_MODULE_EXTENDED_INFO), NULL);		
		if (NT_SUCCESS(status))
		{
			if(modulesSize > 0)
			{
				numberOfModules = modulesSize / sizeof(AUX_MODULE_EXTENDED_INFO);
				modules = (AUX_MODULE_EXTENDED_INFO*) ExAllocatePoolWithTag(PagedPool, modulesSize, POOL_TAG);
				
				if(modules != NULL)
				{
					status = AuxKlibQueryModuleInformation(&modulesSize, sizeof(AUX_MODULE_EXTENDED_INFO), modules);
					if (NT_SUCCESS(status))
					{
						for(i = 0; i < numberOfModules; i++)
						{
							status = STATUS_NOT_FOUND;
							if(theAddr >= (ULONG_PTR) modules[i].BasicInfo.ImageBase && theAddr < ((ULONG_PTR) modules[i].BasicInfo.ImageBase + modules[i].ImageSize))
							{
								status = RtlStringCbPrintfExW(*ppszDestEnd, *pcbRemaining, ppszDestEnd, pcbRemaining, STRSAFE_NO_TRUNCATION,
								L"%p [%S+%u]", 
									theAddr,
									modules[i].FullPathName + modules[i].FileNameOffset,
									theAddr - (ULONG_PTR) modules[i].BasicInfo.ImageBase
								);	
								break;
							}
							

						}
						
						if(status == STATUS_NOT_FOUND)
						{
							status = RtlStringCbPrintfExW(*ppszDestEnd, *pcbRemaining, ppszDestEnd, pcbRemaining, STRSAFE_NO_TRUNCATION, L"%p [?]", theAddr);
							if (NT_SUCCESS(status)) status = STATUS_NOT_FOUND;
						}
					}
					ExFreePoolWithTag(modules, POOL_TAG);
				}
			}
		}
	}

	return status;	
}



