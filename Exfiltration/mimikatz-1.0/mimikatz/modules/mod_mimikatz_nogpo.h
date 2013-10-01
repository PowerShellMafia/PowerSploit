/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : http://creativecommons.org/licenses/by/3.0/fr/
*/
#pragma once
#include "globdefs.h"
#include "mod_process.h"
#include "mod_memory.h"
#include "mod_patch.h"
#include <iostream>

class mod_mimikatz_nogpo
{
private:
	static bool disableSimple(wstring commandLine, wstring origKey, wstring kiwiKey, DWORD * monPID = NULL);
	static bool disableSimple(wstring commandLine, string origKey, string kiwiKey, DWORD * monPID = NULL);
	static bool disableSimple(wstring commandLine, SIZE_T taillePattern, PBYTE maCleDeDepart, const void * maCleFinale, DWORD * monPID = NULL);

	static bool getApplicationPathFromCLSID(wstring application, wstring * path);

public:
	static vector<KIWI_MIMIKATZ_LOCAL_MODULE_COMMAND> getMimiKatzCommands();

	static bool regedit(vector<wstring> * arguments);
	static bool cmd(vector<wstring> * arguments);
	static bool taskmgr(vector<wstring> * arguments);
	static bool olpst(vector<wstring> * arguments);
};

