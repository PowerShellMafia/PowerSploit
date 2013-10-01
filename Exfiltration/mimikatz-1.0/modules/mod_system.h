/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : http://creativecommons.org/licenses/by/3.0/fr/
*/
#pragma once
#include "globdefs.h"
#include "mod_ntddk.h"
#include <security.h>
#include <shlwapi.h>
#include <sstream>
#include <iomanip>

class mod_system
{
private:
	static bool getHandleInfo(HANDLE monHandle, PBYTE * buffer, OBJECT_INFORMATION_CLASS typeInfo);

public:
	static wstring getWinError(bool automatique = true, DWORD code = 0);

	static bool getUserName(wstring * monUserName);
	static bool getComputerName(wstring *monComputerName);
	static bool getVersion(OSVERSIONINFOEX * maVersion);

	static bool isFileExist(std::wstring &fichier, bool *resultat);
	static bool getCurrentDirectory(wstring * monRepertoire);
	static bool getAbsolutePathOf(wstring &thisData, wstring *reponse);
	static bool getSystemHandles(vector<SYSTEM_HANDLE> * mesHandles, DWORD * pid = NULL); // type ??
	static bool getHandleType(HANDLE monHandle, wstring * strType);
	static bool getHandleName(HANDLE monHandle, wstring * strName);

	static OSVERSIONINFOEX GLOB_Version;
};
