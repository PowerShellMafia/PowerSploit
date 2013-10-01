/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : http://creativecommons.org/licenses/by/3.0/fr/
*/
#pragma once
#include "globdefs.h"
#include "mod_memory.h"
#include "mod_system.h"
#include "mod_process.h"

class mod_inject
{
public:
	static bool injectLibraryInHandle(const HANDLE & handleProcess, wstring * fullLibraryPath);
	static bool injectLibraryInPid(const DWORD & pid, wstring * fullLibraryPath);
	static bool injectLibraryInSingleProcess(wstring & processName, wstring * fullLibraryPath);
};

