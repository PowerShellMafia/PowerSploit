/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence    : http://creativecommons.org/licenses/by/3.0/fr/
	Ce fichier : http://creativecommons.org/licenses/by/3.0/fr/
*/
#pragma once
#include "../mod_mimikatz_sekurlsa.h"

class mod_mimikatz_sekurlsa_ssp {

private:
	typedef struct _KIWI_SSP_CREDENTIAL_LIST_ENTRY {
		struct _KIWI_SSP_CREDENTIAL_LIST_ENTRY *Flink;
		struct _KIWI_SSP_CREDENTIAL_LIST_ENTRY *Blink;
		ULONG References;
		ULONG CredentialReferences;
		LUID LogonId;
		ULONG unk0;
		ULONG unk1;
		ULONG unk2;
		KIWI_GENERIC_PRIMARY_CREDENTIAL credentials;
	} KIWI_SSP_CREDENTIAL_LIST_ENTRY, *PKIWI_SSP_CREDENTIAL_LIST_ENTRY;

	static PKIWI_SSP_CREDENTIAL_LIST_ENTRY SspCredentialList;
	static bool searchSSPEntryList();

public:
	static mod_process::PKIWI_VERY_BASIC_MODULEENTRY pModMSV;
	static bool getSSP(vector<wstring> * arguments);
	static bool WINAPI getSSPLogonData(__in PLUID logId, __in bool justSecurity);
};
