/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : http://creativecommons.org/licenses/by/3.0/fr/
*/
#pragma once
#include "globdefs.h"
#include "mod_system.h"
#include "mod_process.h"
#include "mod_memory.h"
#include "mod_service.h"
#include <iostream>

class mod_patch
{
public:
	typedef struct _KIWI_OS_CHECK
	{
		DWORD majorVersion;
		DWORD minorVersion;
		DWORD build;
		bool isServer;
		bool is64;
	} KIWI_OS_CHECK, *PKIWI_OS_CHECK;

	enum OS
	{
		WINDOWS_2000_PRO_x86,
		WINDOWS_2000_SRV_x86,

		WINDOWS_XP_PRO___x86,
		WINDOWS_XP_PRO___x64,
		WINDOWS_2003_____x86,
		WINDOWS_2003_____x64,

		WINDOWS_VISTA____x86,
		WINDOWS_VISTA____x64,
		WINDOWS_2008_____x86,
		WINDOWS_2008_____x64,

		WINDOWS_SEVEN____x86,
		WINDOWS_SEVEN____x64,
		WINDOWS_2008r2___x64,

		WINDOWS_8________x86,
		WINDOWS_8________x64,
		WINDOWS_8_SERVER_x64
	};

	static bool getFullVersion(DWORD * majorVersion = NULL, DWORD * minorVersion = NULL, DWORD * build = NULL, bool * isServer = NULL, bool * is64 = NULL);
	static bool checkVersion(KIWI_OS_CHECK * monOsValide);	
	static bool checkVersion(OS monOsValide);
	static bool checkVersion(vector<OS> * vectorValid);

	static bool patchModuleOfService(wstring serviceName, wstring moduleName, BYTE * patternToSearch, SIZE_T szPatternToSearch, BYTE * patternToPlace, SIZE_T szPatternToPlace, long offsetForPlace = 0);
	static bool patchModuleOfPID(DWORD pid, wstring moduleName, BYTE * patternToSearch, SIZE_T szPatternToSearch, BYTE * patternToPlace, SIZE_T szPatternToPlace, long offsetForPlace = 0);
};
