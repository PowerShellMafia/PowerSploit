#include "minifilters.h"

const ULONG MF_OffSetTable[MAX_OS_LEN][MAX_MF_LEN] =
{
				/* INDEX_MF_CALLBACK_OFF, INDEX_MF_CALLBACK_PRE_OFF, INDEX_MF_CALLBACK_POST_OFF, INDEX_MF_VOLUME_NAME_OFF */
#ifdef _M_IX86
/* INDEX_UNK	*/	{0x0000, 0x0000, 0x0000, 0x0000},
/* INDEX_XP		*/	{0x007c, 0x000c, 0x0010, 0x002c},
/* INDEX_2K3	*/	{0x007c, 0x000c, 0x0010, 0x002c},
/* INDEX_VISTA	*/	{0x004c, 0x000c, 0x0010, 0x0030},
/* INDEX_2K8	*/	{0x004c, 0x000c, 0x0010, 0x0030},
/* INDEX_7		*/	{0x004c, 0x000c, 0x0010, 0x0030},
/* INDEX_2K8R2	*/	{0x0000, 0x0000, 0x0000, 0x0000},/* n'existe pas !*/
/* INDEX_8		*/	{0x004c, 0x000c, 0x0010, 0x0030}
#else
/* INDEX_UNK	*/	{0x0000, 0x0000, 0x0000, 0x0000},
/* INDEX_XP		*/	{0x0000, 0x0000, 0x0000, 0x0000},/* n'existe pas, XP x64 est 2003 x64 */
/* INDEX_2K3	*/	{0x00e8, 0x0018, 0x0020, 0x0048},
/* INDEX_VISTA	*/	{0x0090, 0x0018, 0x0020, 0x0050},
/* INDEX_2K8	*/	{0x0090, 0x0018, 0x0020, 0x0050},
/* INDEX_7		*/	{0x0090, 0x0018, 0x0020, 0x0050},
/* INDEX_2K8R2	*/	{0x0090, 0x0018, 0x0020, 0x0050},
/* INDEX_8		*/	{0x0090, 0x0018, 0x0020, 0x0050}
#endif
};

const WCHAR *irpToName[] = {
	L"CREATE",
	L"CREATE_NAMED_PIPE",
	L"CLOSE",
	L"READ",
	L"WRITE",
	L"QUERY_INFORMATION",
	L"SET_INFORMATION",
	L"QUERY_EA",
	L"SET_EA",
	L"FLUSH_BUFFERS",
	L"QUERY_VOLUME_INFORMATION",
	L"SET_VOLUME_INFORMATION",
	L"DIRECTORY_CONTROL",
	L"FILE_SYSTEM_CONTROL",
	L"DEVICE_CONTROL",
	L"INTERNAL_DEVICE_CONTROL",
	L"SHUTDOWN",
	L"LOCK_CONTROL",
	L"CLEANUP",
	L"CREATE_MAILSLOT",
	L"QUERY_SECURITY",
	L"SET_SECURITY",
	L"POWER",
	L"SYSTEM_CONTROL",
	L"DEVICE_CHANGE",
	L"QUERY_QUOTA",
	L"SET_QUOTA",
	L"PNP",
};

NTSTATUS kMiniFiltersList(LPWSTR pszDest, size_t cbDest, LPWSTR *ppszDestEnd, size_t *pcbRemaining)
{
	NTSTATUS status;

	ULONG i, j, k;
	
	ULONG NumberFiltersReturned = 0;
	PFLT_FILTER *FilterList = NULL;
	
	ULONG BytesReturned = 0;
	PFILTER_FULL_INFORMATION myFilterFullInformation = NULL;
	
	PFLT_INSTANCE *InstanceList = NULL;
	ULONG NumberInstancesReturned = 0;

	PFLT_VOLUME RetVolume = NULL;
	
	PVOID monCallBack, preCallBack, postCallBack;

	*ppszDestEnd = pszDest;
	*pcbRemaining= cbDest;
	
	status = RtlStringCbPrintfExW(*ppszDestEnd, *pcbRemaining, ppszDestEnd, pcbRemaining, STRSAFE_NO_TRUNCATION, L"kMiniFiltersList\n\n");
	if(NT_SUCCESS(status))
	{
		status = FltEnumerateFilters(NULL, 0, &NumberFiltersReturned); 
		if((status == STATUS_BUFFER_TOO_SMALL) && (NumberFiltersReturned > 0))
		{
			FilterList = ExAllocatePoolWithTag(NonPagedPool, sizeof(PFLT_FILTER) * NumberFiltersReturned, POOL_TAG);
			if(FilterList != NULL)
			{
				status = FltEnumerateFilters(FilterList, sizeof(PFLT_FILTER) * NumberFiltersReturned, &NumberFiltersReturned); 
				for(i = 0; (i < NumberFiltersReturned) && NT_SUCCESS(status); i++)
				{
					status = FltGetFilterInformation(FilterList[i], FilterFullInformation, NULL, 0, &BytesReturned);
					if((status == STATUS_BUFFER_TOO_SMALL) && (BytesReturned > 0))
					{
						myFilterFullInformation = ExAllocatePoolWithTag(NonPagedPool, BytesReturned, POOL_TAG);
						if(myFilterFullInformation != NULL)
						{
							status = FltGetFilterInformation(FilterList[i], FilterFullInformation, myFilterFullInformation, BytesReturned, &BytesReturned);
							if(NT_SUCCESS(status))
							{
								status = RtlStringCbPrintfExW(*ppszDestEnd, *pcbRemaining, ppszDestEnd, pcbRemaining, STRSAFE_NO_TRUNCATION,
								L"%*.*ws\n",
								myFilterFullInformation->FilterNameLength/sizeof(WCHAR), myFilterFullInformation->FilterNameLength/sizeof(WCHAR),
								myFilterFullInformation->FilterNameBuffer
								);
								
								if(NT_SUCCESS(status))
								{
									status = FltEnumerateInstances(NULL, FilterList[i], NULL, 0, &NumberInstancesReturned);
									if((status == STATUS_BUFFER_TOO_SMALL) && (NumberInstancesReturned > 0))
									{
										InstanceList = ExAllocatePoolWithTag(NonPagedPool, sizeof(PFLT_INSTANCE) * NumberInstancesReturned, POOL_TAG);
										if(InstanceList != NULL)
										{
											status = FltEnumerateInstances(NULL, FilterList[i], InstanceList, NumberInstancesReturned, &NumberInstancesReturned);
											for(j = 0; (j < NumberInstancesReturned) && NT_SUCCESS(status); j++)
											{
												/*
												http://msdn.microsoft.com/en-us/library/windows/hardware/ff541499%28v=VS.85%29.aspx
													* InstanceName
													* Altitude
													* VolumeName
													- FilterName
												*/
												
												if(NT_SUCCESS(FltGetVolumeFromInstance(InstanceList[j], &RetVolume)))
												{
													status = RtlStringCbPrintfExW(*ppszDestEnd, *pcbRemaining, ppszDestEnd, pcbRemaining, STRSAFE_NO_TRUNCATION,
													L" Instance %u @ %wZ\n",
													j,
													(PUNICODE_STRING) (((ULONG_PTR) RetVolume) + MF_OffSetTable[INDEX_OS][INDEX_MF_VOLUME_NAME_OFF])
													);
													FltObjectDereference (RetVolume);
												}
												else
												{
													status = RtlStringCbPrintfExW(*ppszDestEnd, *pcbRemaining, ppszDestEnd, pcbRemaining, STRSAFE_NO_TRUNCATION,
													L" Instance %u\n",
													j
													);
												}
												
												for(k = 0x16; (k < 0x32) && NT_SUCCESS(status); k++)
												{
													monCallBack = (PVOID) *(PULONG_PTR) (( ((ULONG_PTR) InstanceList[j] )+ MF_OffSetTable[INDEX_OS][INDEX_MF_CALLBACK_OFF]) + sizeof(PVOID)*k);
													if(monCallBack != NULL)
													{
														preCallBack = (PVOID) *(PULONG_PTR) (((ULONG_PTR) monCallBack) + MF_OffSetTable[INDEX_OS][INDEX_MF_CALLBACK_PRE_OFF]);
														postCallBack = (PVOID) *(PULONG_PTR) (((ULONG_PTR) monCallBack) + MF_OffSetTable[INDEX_OS][INDEX_MF_CALLBACK_POST_OFF]);
														
														status = RtlStringCbPrintfExW(*ppszDestEnd, *pcbRemaining, ppszDestEnd, pcbRemaining, STRSAFE_NO_TRUNCATION,
														L"  [0x%2x %-24ws] ",
														k,
														irpToName[k - 0x16]
														);
														
														if(NT_SUCCESS(status))
														{
															status = getModuleFromAddr((ULONG_PTR) preCallBack, *ppszDestEnd, *pcbRemaining, ppszDestEnd, pcbRemaining);
															if(NT_SUCCESS(status) || status == STATUS_NOT_FOUND)
															{
																status = RtlStringCbPrintfExW(*ppszDestEnd, *pcbRemaining, ppszDestEnd, pcbRemaining, STRSAFE_NO_TRUNCATION, L" / ");
																if(NT_SUCCESS(status))
																{
																	status = getModuleFromAddr((ULONG_PTR) postCallBack, *ppszDestEnd, *pcbRemaining, ppszDestEnd, pcbRemaining);
																	if(NT_SUCCESS(status) || status == STATUS_NOT_FOUND)
																	{
																		status = RtlStringCbPrintfExW(*ppszDestEnd, *pcbRemaining, ppszDestEnd, pcbRemaining, STRSAFE_NO_TRUNCATION, L"\n");
																	}
																}
															}
															
														}
													}
												}
												FltObjectDereference (InstanceList[j]);
											}
											ExFreePoolWithTag(InstanceList, POOL_TAG);
										}
									}
								}
							}
							ExFreePoolWithTag(myFilterFullInformation, POOL_TAG);
						}
					}
					FltObjectDereference (FilterList[i]);
				}
				ExFreePoolWithTag(FilterList, POOL_TAG);
			}
		}
	}
	return status;
}
