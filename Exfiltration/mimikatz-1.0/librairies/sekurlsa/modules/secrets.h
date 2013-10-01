/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence    : http://creativecommons.org/licenses/by/3.0/fr/
	Ce fichier : http://creativecommons.org/licenses/by/3.0/fr/
*/
#pragma once
#include "kmodel.h"
#include "mod_text.h"
#include <wincred.h>

bool searchSECFuncs();
__kextdll bool __cdecl getSECFunctions(mod_pipe * monPipe, vector<wstring> * mesArguments);
__kextdll bool __cdecl getSecrets(mod_pipe * monPipe, vector<wstring> * mesArguments);

#define	SECRET_SET_VALUE	0x00000001
#define	SECRET_QUERY_VALUE	0x00000002

typedef struct _LSA_SECRET
{
	DWORD		Length;
	DWORD		MaximumLength;
	wchar_t *	Buffer;
} LSA_SECRET, *PLSA_SECRET;

typedef NTSTATUS (WINAPI * PLSA_I_OPEN_POLICY_TRUSTED)	(LSA_HANDLE * pHPolicy);
typedef NTSTATUS (WINAPI * PLSA_R_OPEN_SECRET)			(LSA_HANDLE hPolicy, LSA_UNICODE_STRING *, DWORD dwAccess, LSA_HANDLE * hSecret);
typedef NTSTATUS (WINAPI * PLSA_R_QUERY_SECRET)			(LSA_HANDLE hSecret, PLSA_SECRET * ppSecret, PVOID pCurrentValueSetTime, PLSA_UNICODE_STRING * ppOldSecret, PVOID pOldValueSetTime);
typedef NTSTATUS (WINAPI * PLSA_R_CLOSE)				(LSA_HANDLE * pHandle);
