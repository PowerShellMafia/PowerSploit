/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : http://creativecommons.org/licenses/by/3.0/fr/
*/
#include "mod_inject.h"

bool mod_inject::injectLibraryInHandle(const HANDLE & handleProcess, wstring * fullLibraryPath)
{
	bool reussite = false;

	wstring maLibComplete = L"";
	if(mod_system::getAbsolutePathOf(*fullLibraryPath, &maLibComplete))
	{
		bool fileExist = false;
		if(mod_system::isFileExist(maLibComplete, &fileExist) && fileExist)
		{
			SIZE_T szFullLibraryPath = static_cast<SIZE_T>((maLibComplete.size() + 1) * sizeof(wchar_t));

			if(LPVOID remoteVm = VirtualAllocEx(handleProcess, NULL, szFullLibraryPath, MEM_COMMIT, PAGE_EXECUTE_READWRITE))
			{
				if(mod_memory::writeMemory(remoteVm, maLibComplete.c_str(), szFullLibraryPath, handleProcess))
				{
					PTHREAD_START_ROUTINE pThreadStart = reinterpret_cast<PTHREAD_START_ROUTINE>(GetProcAddress(GetModuleHandle(L"kernel32"), "LoadLibraryW"));
					HANDLE hRemoteThread = INVALID_HANDLE_VALUE;

					if(mod_system::GLOB_Version.dwMajorVersion > 5)
					{
						PRTL_CREATE_USER_THREAD RtlCreateUserThread = reinterpret_cast<PRTL_CREATE_USER_THREAD>(GetProcAddress(GetModuleHandle(L"ntdll"), "RtlCreateUserThread"));
						SetLastError(RtlCreateUserThread(handleProcess, NULL, 0, 0, 0, 0, pThreadStart, remoteVm, &hRemoteThread, NULL));
					}
					else
					{
						hRemoteThread = CreateRemoteThread(handleProcess, NULL, 0, pThreadStart, remoteVm, 0, NULL);
					}

					if(hRemoteThread && hRemoteThread != INVALID_HANDLE_VALUE)
					{
						WaitForSingleObject(hRemoteThread, INFINITE);
						reussite = true;
						CloseHandle(hRemoteThread);
					}
				}
				VirtualFreeEx(handleProcess, remoteVm, 0, MEM_RELEASE);
			}
		}
	}
	return reussite;
}

bool mod_inject::injectLibraryInPid(const DWORD & pid, wstring * fullLibraryPath)
{
	bool reussite = false;
	if(HANDLE processHandle = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, false, pid))
	{
		reussite = injectLibraryInHandle(processHandle, fullLibraryPath);
		CloseHandle(processHandle);
	}
	return reussite;
}

bool mod_inject::injectLibraryInSingleProcess(wstring & processName, wstring * fullLibraryPath)
{
	bool reussite = false;

	mod_process::KIWI_PROCESSENTRY32 monProcess;
	if(mod_process::getUniqueForName(&monProcess, &processName))
	{
		reussite = injectLibraryInPid(monProcess.th32ProcessID, fullLibraryPath);
	}
	return reussite;	
}