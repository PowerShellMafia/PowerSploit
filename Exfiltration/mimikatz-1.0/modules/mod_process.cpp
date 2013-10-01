/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : http://creativecommons.org/licenses/by/3.0/fr/
*/
#include "mod_process.h"

bool mod_process::getList(vector<KIWI_PROCESSENTRY32> * maProcessesvector, wstring * processName)
{
	HANDLE hProcessesSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if(hProcessesSnapshot != INVALID_HANDLE_VALUE)
	{
		PROCESSENTRY32 monProcessus;
		monProcessus.dwSize = sizeof(PROCESSENTRY32);

		if(Process32First(hProcessesSnapshot, &monProcessus))
		{
			do
			{
				if(!processName || (_wcsicmp(processName->c_str(), monProcessus.szExeFile) == 0))
				{
					KIWI_PROCESSENTRY32 monProcessK = {
						monProcessus.dwSize,
						monProcessus.cntUsage,
						monProcessus.th32ProcessID,
						monProcessus.th32DefaultHeapID,
						monProcessus.th32ModuleID,
						monProcessus.cntThreads,
						monProcessus.th32ParentProcessID,
						monProcessus.pcPriClassBase,
						monProcessus.dwFlags,
						monProcessus.szExeFile
					};

					maProcessesvector->push_back(monProcessK);
				}
			} while(Process32Next(hProcessesSnapshot, &monProcessus));
		}
		CloseHandle(hProcessesSnapshot);
		return true;
	}
	else
	{
		return false;
	}
}

bool mod_process::getUniqueForName(KIWI_PROCESSENTRY32 * monProcess, wstring * processName)
{
	bool reussite = false;

	vector<KIWI_PROCESSENTRY32> * mesProcesses = new vector<KIWI_PROCESSENTRY32>();

	if(getList(mesProcesses, processName))
	{
		if(reussite = (mesProcesses->size() == 1))
		{
			*monProcess = mesProcesses->front();
		}
	}
	delete mesProcesses;
	return reussite;
}

bool mod_process::getUniqueModuleForName(KIWI_MODULEENTRY32 * monModule, wstring * moduleName, DWORD * processId)
{
	bool reussite = false;

	vector<KIWI_MODULEENTRY32> * monVecteurDeModule = new vector<KIWI_MODULEENTRY32>();
	if(mod_process::getModulesListForProcessId(monVecteurDeModule, processId))
	{
		if(!moduleName)
		{
			*monModule = *(monVecteurDeModule->begin());
			reussite = true;
		}
		else
		{
			for(vector<KIWI_MODULEENTRY32>::iterator leModule = monVecteurDeModule->begin(); leModule != monVecteurDeModule->end(); leModule++)
			{
				if(_wcsicmp(leModule->szModule.c_str(), moduleName->c_str()) == 0)
				{
					*monModule = *leModule;
					reussite = true;
					break;
				}
			}
		}
	}
	delete monVecteurDeModule;
	
	return reussite;
}

bool mod_process::getModulesListForProcessId(vector<KIWI_MODULEENTRY32> * maModulevector, DWORD * processId)
{
	HANDLE hModuleSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, (processId ? *processId : 0));
	
	if(hModuleSnapshot != INVALID_HANDLE_VALUE)
	{
		MODULEENTRY32 monModule;
		monModule.dwSize = sizeof(MODULEENTRY32);

		if(Module32First(hModuleSnapshot, &monModule))
		{
			do
			{
				KIWI_MODULEENTRY32 monModuleK = {
					monModule.dwSize,
					monModule.th32ModuleID,
					monModule.th32ProcessID,
					monModule.GlblcntUsage,
					monModule.ProccntUsage,
					monModule.modBaseAddr,
					monModule.modBaseSize,
					monModule.hModule,
					monModule.szModule,
					monModule.szExePath
				};
				maModulevector->push_back(monModuleK);
			} while(Module32Next(hModuleSnapshot, &monModule));
		}
		CloseHandle(hModuleSnapshot);
		return true;
	}
	else
	{
		return false;
	}
}

bool mod_process::start(wstring * maCommandLine, PROCESS_INFORMATION * mesInfosProcess, bool paused, bool aUsurper, HANDLE leToken)
{
	bool reussite = false;
	RtlZeroMemory(mesInfosProcess, sizeof(PROCESS_INFORMATION));
	STARTUPINFO mesInfosDemarrer;
	RtlZeroMemory(&mesInfosDemarrer, sizeof(STARTUPINFO));
	mesInfosDemarrer.cb = sizeof(STARTUPINFO);
	
	wchar_t * commandLine = new wchar_t[maCommandLine->size() + 1];
	maCommandLine->_Copy_s(commandLine, maCommandLine->size(), maCommandLine->size());
	commandLine[maCommandLine->size()] = L'\0';

	DWORD creationFlag = CREATE_NEW_CONSOLE | (paused ? CREATE_SUSPENDED : NULL);

	if(leToken)
		reussite = CreateProcessAsUser(leToken, NULL, commandLine, NULL, NULL, FALSE, creationFlag, NULL, NULL, &mesInfosDemarrer, mesInfosProcess) != 0;
	else if(aUsurper)
		reussite = CreateProcessWithLogonW(L"mimikatzU", L"mimikatzD", L"mimikatzP", LOGON_NETCREDENTIALS_ONLY, NULL, commandLine, creationFlag, NULL, NULL, &mesInfosDemarrer, mesInfosProcess) != 0;
	else
		reussite = CreateProcess(NULL, commandLine, NULL, NULL, FALSE, creationFlag, NULL, NULL, &mesInfosDemarrer, mesInfosProcess) != 0;
	
	delete[] commandLine;
	return reussite;
}

bool mod_process::suspend(DWORD & processId)
{
	bool reussite = false;
	
	if(PNT_SUSPEND_PROCESS NtSuspendProcess = reinterpret_cast<PNT_SUSPEND_PROCESS>(GetProcAddress(GetModuleHandle(L"ntdll"), "NtSuspendProcess")))
	{
		HANDLE monHandle = OpenProcess(PROCESS_SUSPEND_RESUME, false, processId);
		if(reussite = (monHandle && monHandle != INVALID_HANDLE_VALUE))
		{
			reussite = NT_SUCCESS(NtSuspendProcess(monHandle));
			CloseHandle(monHandle);
		}
	}
	return reussite;
}

bool mod_process::resume(DWORD & processId)
{
	bool reussite = false;
	
	if(PNT_RESUME_PROCESS NtResumeProcess = reinterpret_cast<PNT_RESUME_PROCESS>(GetProcAddress(GetModuleHandle(L"ntdll"), "NtResumeProcess")))
	{
		HANDLE monHandle = OpenProcess(PROCESS_SUSPEND_RESUME, false, processId);
		if(reussite = (monHandle && monHandle != INVALID_HANDLE_VALUE))
		{
			reussite = NT_SUCCESS(NtResumeProcess(monHandle));
			CloseHandle(monHandle);
		}
	}
	return reussite;
}

bool mod_process::stop(DWORD & processId, DWORD exitCode)
{
	bool reussite = false;
	
	HANDLE monHandle = OpenProcess(PROCESS_TERMINATE, false, processId);
	if(reussite = (monHandle && monHandle != INVALID_HANDLE_VALUE))
	{
		reussite = (TerminateProcess(monHandle, exitCode) != 0);
		CloseHandle(monHandle);
	}
	return reussite;
}

bool mod_process::debug(DWORD & processId)
{
	return (DebugActiveProcess(processId) != 0);
}

bool mod_process::getProcessBasicInformation(PROCESS_BASIC_INFORMATION * mesInfos, HANDLE processHandle)
{
	bool reussite = false;

	if(processHandle == INVALID_HANDLE_VALUE)
		processHandle = GetCurrentProcess();

	if(PNT_QUERY_INFORMATION_PROCESS NtQueryInformationProcess = reinterpret_cast<PNT_QUERY_INFORMATION_PROCESS>(GetProcAddress(GetModuleHandle(L"ntdll"), "NtQueryInformationProcess")))
	{
		ULONG sizeReturn;
		reussite = NT_SUCCESS(NtQueryInformationProcess(processHandle, ProcessBasicInformation, mesInfos, sizeof(PROCESS_BASIC_INFORMATION), &sizeReturn)) && (sizeReturn == sizeof(PROCESS_BASIC_INFORMATION));
	}
	return reussite;
}

bool mod_process::getAuthentificationIdFromProcessId(DWORD & processId, LUID & AuthentificationId)
{
	bool reussite = false;

	HANDLE handleProcess = OpenProcess(PROCESS_QUERY_INFORMATION , false, processId);
	if(handleProcess && handleProcess != INVALID_HANDLE_VALUE)
	{
		HANDLE handleProc;
		if(OpenProcessToken(handleProcess, TOKEN_READ, &handleProc) != 0)
		{
			DWORD ddNeededSize;
			TOKEN_STATISTICS tokenStats;

			if(reussite = (GetTokenInformation(handleProc, TokenStatistics, &tokenStats, sizeof(tokenStats), &ddNeededSize) != 0))
			{
				AuthentificationId = tokenStats.AuthenticationId;
			}
			CloseHandle(handleProc);
		}
		CloseHandle(handleProcess);
	}

	return reussite;
}

bool mod_process::getPeb(PEB * peb, HANDLE processHandle)
{
	bool reussite = false;
	PROCESS_BASIC_INFORMATION * mesInfos = new PROCESS_BASIC_INFORMATION();
	if(getProcessBasicInformation(mesInfos, processHandle))
	{
		reussite = mod_memory::readMemory(mesInfos->PebBaseAddress, peb, sizeof(PEB), processHandle);
	}
	delete mesInfos;
	return reussite;
}

bool mod_process::getIAT(PBYTE ptrBaseAddr, vector<pair<string, vector<KIWI_IAT_MODULE>>> * monIAT, HANDLE handleProcess)
{
	bool reussite = false;

	BYTE * baseAddr = ptrBaseAddr;

	BYTE * ayIMAGE_DOS_HEADER = new BYTE[sizeof(IMAGE_DOS_HEADER)];
	if(mod_memory::readMemory(baseAddr, ayIMAGE_DOS_HEADER, sizeof(IMAGE_DOS_HEADER), handleProcess))
	{
		PIMAGE_DOS_HEADER structDOSHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(ayIMAGE_DOS_HEADER);
		if(!IsBadReadPtr(structDOSHeader, sizeof(IMAGE_DOS_HEADER)) && structDOSHeader->e_magic == IMAGE_DOS_SIGNATURE)
		{
			BYTE * ayIMAGE_NT_HEADERS = new BYTE[sizeof(IMAGE_NT_HEADERS)];
			if(mod_memory::readMemory(baseAddr + structDOSHeader->e_lfanew, ayIMAGE_NT_HEADERS, sizeof(IMAGE_NT_HEADERS), handleProcess))
			{
				PIMAGE_NT_HEADERS structPEHeader = reinterpret_cast<PIMAGE_NT_HEADERS>(ayIMAGE_NT_HEADERS);
				if(!IsBadReadPtr(structPEHeader, sizeof(IMAGE_NT_HEADERS)) && structPEHeader->Signature == IMAGE_NT_SIGNATURE)
				{
					if(structPEHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress != NULL && structPEHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size > 0)
					{
						BYTE * ayIMAGE_IMPORT_DESCRIPTOR = new BYTE[structPEHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size];
						if(mod_memory::readMemory(baseAddr + structPEHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress, ayIMAGE_IMPORT_DESCRIPTOR, structPEHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size, handleProcess))
						{
							PIMAGE_IMPORT_DESCRIPTOR structImportDesc = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(ayIMAGE_IMPORT_DESCRIPTOR);
							if(reussite = !IsBadReadPtr(structImportDesc, sizeof(IMAGE_IMPORT_DESCRIPTOR)))
							{
								while(structImportDesc->Characteristics)
								{
									DWORD i = 0;
									
									BYTE * ayIMAGE_THUNK_DATA_HintName = new BYTE[sizeof(IMAGE_THUNK_DATA)];
									BYTE * ayIMAGE_THUNK_DATA_IAT = new BYTE[sizeof(IMAGE_THUNK_DATA)];

									vector<KIWI_IAT_MODULE> mesImports;

									for(;;)
									{
										if(
											mod_memory::readMemory(baseAddr + structImportDesc->OriginalFirstThunk + i*sizeof(IMAGE_THUNK_DATA), ayIMAGE_THUNK_DATA_HintName, sizeof(IMAGE_THUNK_DATA), handleProcess)
											&&
											mod_memory::readMemory(baseAddr + structImportDesc->FirstThunk + i*sizeof(IMAGE_THUNK_DATA), ayIMAGE_THUNK_DATA_IAT, sizeof(IMAGE_THUNK_DATA), handleProcess)
											)
										{
											PIMAGE_THUNK_DATA HintNameArray = reinterpret_cast<PIMAGE_THUNK_DATA>(ayIMAGE_THUNK_DATA_HintName);
											PIMAGE_THUNK_DATA IATArray = reinterpret_cast<PIMAGE_THUNK_DATA>(ayIMAGE_THUNK_DATA_IAT);

											if(HintNameArray->u1.Function)
											{
												KIWI_IAT_MODULE imageIAT = {
													baseAddr + structImportDesc->FirstThunk + i*sizeof(IMAGE_THUNK_DATA) + FIELD_OFFSET(IMAGE_THUNK_DATA, u1.Function),
													reinterpret_cast<PVOID>(IATArray->u1.Function),
													0,
													string()
												};
												
												if(HintNameArray->u1.Ordinal & IMAGE_ORDINAL_FLAG)
												{
													imageIAT.Ordinal = IMAGE_ORDINAL(HintNameArray->u1.Ordinal);
												}
												else
												{
													BYTE monTab[] = {0};
													long offsetToNull;
													if(mod_memory::searchMemory(baseAddr + HintNameArray->u1.AddressOfData + FIELD_OFFSET(IMAGE_IMPORT_BY_NAME, Name), 255, monTab, &offsetToNull, sizeof(monTab), true, handleProcess))
													{
														BYTE * ayIMAGE_IMPORT_BY_NAME = new BYTE[sizeof(IMAGE_IMPORT_BY_NAME) + offsetToNull];
														if(mod_memory::readMemory(baseAddr + HintNameArray->u1.AddressOfData, ayIMAGE_IMPORT_BY_NAME, sizeof(IMAGE_IMPORT_BY_NAME) + offsetToNull, handleProcess))
														{
															PIMAGE_IMPORT_BY_NAME nameImg = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(ayIMAGE_IMPORT_BY_NAME);
															imageIAT.funcName = string(reinterpret_cast<char *>(nameImg->Name));
														}
														delete [] ayIMAGE_IMPORT_BY_NAME;
													}
												}

												mesImports.push_back(imageIAT);
												i++;
											}
											else break;
										}
										else break;
									}
									
									delete[] ayIMAGE_THUNK_DATA_IAT;
									delete[] ayIMAGE_THUNK_DATA_HintName;

									BYTE monTab[] = {0};
									long offsetToNull;
									
									if(mod_memory::searchMemory(baseAddr + structImportDesc->Name, 255, monTab, &offsetToNull, sizeof(monTab), true, handleProcess))
									{
										char * maLib = new char[offsetToNull+1];
										if(mod_memory::readMemory(baseAddr + structImportDesc->Name, maLib, offsetToNull+1, handleProcess))
										{
											monIAT->push_back(make_pair(string(maLib), mesImports));
										}
										delete [] maLib;
									}

									structImportDesc++;
								}
							}
						}
						delete[] ayIMAGE_IMPORT_DESCRIPTOR;
					}
				}
			}
			delete[] ayIMAGE_NT_HEADERS;
		}
	}
	delete[] ayIMAGE_DOS_HEADER;

	return reussite;
}

bool mod_process::getProcessEntryFromProcessId(DWORD processId, KIWI_PROCESSENTRY32 * processKiwi, vector<mod_process::KIWI_PROCESSENTRY32> * mesProcess)
{
	bool reussite = false;
	bool tabOk = false;

	vector<mod_process::KIWI_PROCESSENTRY32> * monTab;

	if(!mesProcess)
	{
		monTab = new vector<mod_process::KIWI_PROCESSENTRY32>();
		tabOk = mod_process::getList(monTab);
	}
	else
	{
		monTab = mesProcess;
	}

	if(mesProcess || tabOk)
	{
		for(vector<mod_process::KIWI_PROCESSENTRY32>::iterator monProcess = monTab->begin(); monProcess != monTab->end(); monProcess++)
		{
			if(reussite = (monProcess->th32ProcessID == processId))
			{
				*processKiwi = *monProcess;
				break;
			}
		}
	}

	if(!mesProcess)
	{
		delete monTab;
	}

	return reussite;
}

bool mod_process::getVeryBasicModulesListForProcess(vector<KIWI_VERY_BASIC_MODULEENTRY> * monModuleVector, HANDLE processHandle)
{
	bool reussite = false;
	PEB * monPeb = new PEB();
	if(getPeb(monPeb, processHandle))
	{
		PEB_LDR_DATA * monLoader = new PEB_LDR_DATA();
		if(mod_memory::readMemory(monPeb->LoaderData, monLoader, sizeof(PEB_LDR_DATA), processHandle))
		{
			PBYTE aLire, fin;
			LDR_DATA_TABLE_ENTRY monEntry;
			for(
				aLire = PBYTE(monLoader->InMemoryOrderModulevector.Flink) - FIELD_OFFSET(LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks),
				fin = (PBYTE) (monPeb->LoaderData) + FIELD_OFFSET(PEB_LDR_DATA, InLoadOrderModulevector);
			aLire != fin;
			aLire = (PBYTE) monEntry.InMemoryOrderLinks.Flink - FIELD_OFFSET(LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks)
				)
			{
				if(reussite = mod_memory::readMemory(aLire, &monEntry, sizeof(monEntry), processHandle))
				{
					KIWI_VERY_BASIC_MODULEENTRY monModule = {
						reinterpret_cast<PBYTE>(monEntry.DllBase),
						monEntry.SizeOfImage,
						getUnicodeStringOfProcess(&monEntry.BaseDllName, processHandle)
					};
					monModuleVector->push_back(monModule);
				}
			}
		}
		delete monLoader;
	}
	delete monPeb;
	return reussite;
}

wstring mod_process::getUnicodeStringOfProcess(UNICODE_STRING * ptrString, HANDLE process, PLSA_PROTECT_MEMORY unProtectFunction)
{
	wstring maChaine;
	BYTE * monBuffer = NULL;
	if(getUnicodeStringOfProcess(ptrString, &monBuffer, process, unProtectFunction))
	{
		maChaine.assign(mod_text::stringOrHex(monBuffer, ptrString->Length));
	}
	if(monBuffer)
		delete[] monBuffer;
	return maChaine;
}

bool mod_process::getUnicodeStringOfProcess(UNICODE_STRING * ptrString, BYTE ** monBuffer, HANDLE process, PLSA_PROTECT_MEMORY unProtectFunction)
{
	bool resultat = false;

	if(ptrString->Buffer && (ptrString->Length > 0))
	{
		*monBuffer = new BYTE[ptrString->MaximumLength];
		if(resultat = mod_memory::readMemory(ptrString->Buffer, *monBuffer, ptrString->MaximumLength, process))
		{
			if(unProtectFunction)
				unProtectFunction(*monBuffer, ptrString->MaximumLength);
		}
	}
	return resultat;
}