/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : http://creativecommons.org/licenses/by/3.0/fr/
*/
#include "kappfree.h"

extern __declspec(dllexport) void __cdecl startW(HWND hwnd, HINSTANCE hinst, LPWSTR lpszCmdLine, int nCmdShow)
{
	HANDLE monToken, monSuperToken;
	wchar_t * commandLine;
	PROCESS_INFORMATION mesInfosProcess;
	STARTUPINFO mesInfosDemarrer;

	if(OpenProcessToken(GetCurrentProcess(), TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_QUERY /*| TOKEN_IMPERSONATE*/, &monToken))
	{
		if(CreateRestrictedToken(monToken, SANDBOX_INERT, 0, NULL, 0, NULL, 0, NULL, &monSuperToken))
		{
			RtlZeroMemory(&mesInfosProcess, sizeof(PROCESS_INFORMATION));
			RtlZeroMemory(&mesInfosDemarrer, sizeof(STARTUPINFO));
			mesInfosDemarrer.cb = sizeof(STARTUPINFO);
			
			commandLine = _wcsdup(lpszCmdLine);
			if(CreateProcessAsUser(monSuperToken, NULL, commandLine, NULL, NULL, FALSE, CREATE_NEW_CONSOLE, NULL, NULL, &mesInfosDemarrer, &mesInfosProcess))
			{
				CloseHandle(mesInfosProcess.hThread);
				CloseHandle(mesInfosProcess.hProcess);
			}
			free(commandLine);
			CloseHandle(monSuperToken);
		}
		CloseHandle(monToken);
	}
}
