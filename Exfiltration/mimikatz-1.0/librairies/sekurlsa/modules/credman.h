/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence    : http://creativecommons.org/licenses/by/3.0/fr/
	Ce fichier : http://creativecommons.org/licenses/by/3.0/fr/
*/
#pragma once
#include "../sekurlsa.h"

bool searchCredmanFuncs();
__kextdll bool __cdecl getCredmanFunctions(mod_pipe * monPipe, vector<wstring> * mesArguments);
__kextdll bool __cdecl getCredman(mod_pipe * monPipe, vector<wstring> * mesArguments);
bool WINAPI getCredmanData(__in PLUID logId, __in mod_pipe * monPipe, __in bool justSecurity);

wstring descEncryptedCredential(PENCRYPTED_CREDENTIALW pEncryptedCredential, __in bool justSecurity, wstring prefix = L"");

typedef NTSTATUS (WINAPI * PCRED_I_ENUMERATE)	(IN PLUID pLUID, IN DWORD unk0,	IN LPCTSTR Filter, IN DWORD Flags, OUT DWORD *Count, OUT PCREDENTIAL **Credentials);
typedef NTSTATUS (WINAPI * PCRED_I_ENUMERATE62) (IN PLUID pLUID,				IN LPCTSTR Filter, IN DWORD Flags, OUT DWORD *Count, OUT PCREDENTIAL **Credentials);

