/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence    : http://creativecommons.org/licenses/by/3.0/fr/
	Ce fichier : http://creativecommons.org/licenses/by/3.0/fr/
*/
#pragma once
#include "../sekurlsa.h"
#include "msv1_0_helper.h"

bool searchMSVFuncs();
bool WINAPI getMSVLogonData(__in PLUID logId, __in mod_pipe * monPipe, __in bool justSecurity);

__kextdll bool __cdecl getLogonSessions(mod_pipe * monPipe, vector<wstring> * mesArguments);
__kextdll bool __cdecl delLogonSession(mod_pipe * monPipe, vector<wstring> * mesArguments);
__kextdll bool __cdecl addLogonSession(mod_pipe * monPipe, vector<wstring> * mesArguments);
