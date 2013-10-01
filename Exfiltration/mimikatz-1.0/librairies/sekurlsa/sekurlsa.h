/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence    : http://creativecommons.org/licenses/by/3.0/fr/
	Ce fichier : http://creativecommons.org/licenses/by/3.0/fr/
*/
#pragma once
#include "kmodel.h"
#include "secpkg.h"
#include "mod_memory.h"
#include "mod_system.h"
#include "mod_text.h"
#include "mod_process.h"

extern PLSA_SECPKG_FUNCTION_TABLE	SeckPkgFunctionTable;

bool searchLSAFuncs();
__kextdll bool __cdecl getDescription(wstring * maDescription);

typedef bool (WINAPI * PFN_ENUM_BY_LUID) (__in PLUID logId, __in mod_pipe * monPipe, __in bool justSecurity);
bool		getLogonData(mod_pipe * monPipe, vector<wstring> * mesArguments, vector<pair<PFN_ENUM_BY_LUID, wstring>> * mesProviders);

wstring		getPasswordFromProtectedUnicodeString(LSA_UNICODE_STRING * ptrPass);
