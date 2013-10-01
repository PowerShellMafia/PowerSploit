/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : http://creativecommons.org/licenses/by/3.0/fr/
*/
#pragma once
#include "globdefs.h"
#include "mod_system.h"
#include "mod_process.h"
#include <iostream>

class mod_mimikatz_process
{
private:
	static void printInfosFromPid(DWORD &PID, DWORD ThreadId);
	static void printIATFromModule(mod_process::KIWI_MODULEENTRY32 * monModule, HANDLE monHandle = INVALID_HANDLE_VALUE);

public:
	static vector<KIWI_MIMIKATZ_LOCAL_MODULE_COMMAND> getMimiKatzCommands();
	
	static bool list(vector<wstring> * arguments);
	
	static bool start(vector<wstring> * arguments);
	static bool suspend(vector<wstring> * arguments);
	static bool resume(vector<wstring> * arguments);
	static bool stop(vector<wstring> * arguments);


	static bool modules(vector<wstring> * arguments);
	static bool iat(vector<wstring> * arguments);
};

