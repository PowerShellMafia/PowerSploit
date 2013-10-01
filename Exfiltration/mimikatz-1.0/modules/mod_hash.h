/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : http://creativecommons.org/licenses/by/3.0/fr/
*/
#pragma once
#include "globdefs.h"
#include "mod_text.h"
#include "mod_crypto.h"

class mod_hash
{
private:
	static PSYSTEM_FUNCTION_006 SystemFunction006;
	static PSYSTEM_FUNCTION_007 SystemFunction007;
	static PRTL_UPCASE_UNICODE_STRING_TO_OEM_STRING RtlUpcaseUnicodeStringToOemString;
	static PRTL_INIT_UNICODESTRING RtlInitUnicodeString;
	static PRTL_FREE_OEM_STRING RtlFreeOemString;

public:
	typedef enum _KIWI_HASH_TYPE
	{
		LM,
		NTLM
	} KIWI_HASH_TYPE;

	typedef struct _SAM_ENTRY {
	DWORD offset;
	DWORD lenght;
	DWORD unk;
} SAM_ENTRY, *PSAM_SENTRY;

	typedef struct _OLD_LARGE_INTEGER {
		unsigned long LowPart;
		long HighPart;
	} OLD_LARGE_INTEGER, *POLD_LARGE_INTEGER;

	typedef struct _USER_F { // http://www.beginningtoseethelight.org/ntsecurity/index.php#D3BC3F5643A17823
		DWORD unk0_header;
		DWORD align;
		OLD_LARGE_INTEGER LastLogon;
		OLD_LARGE_INTEGER LastLogoff;
		OLD_LARGE_INTEGER PasswordLastSet;
		OLD_LARGE_INTEGER AccountExpires;
		OLD_LARGE_INTEGER PasswordMustChange;
		unsigned long UserId;
		unsigned long unk1;
		unsigned long UserAccountControl;
	} USER_F, *PUSER_F;

	typedef struct _USER_V {
		SAM_ENTRY unk0;
		SAM_ENTRY Username;
		SAM_ENTRY Fullname;
		SAM_ENTRY Comment;
		SAM_ENTRY UserComment;
		SAM_ENTRY unk1;
		SAM_ENTRY Homedir;
		SAM_ENTRY Homedirconnect;
		SAM_ENTRY Scriptpath;
		SAM_ENTRY Profilepath;
		SAM_ENTRY Workstations;
		SAM_ENTRY HoursAllowed;
		SAM_ENTRY unk2;
		SAM_ENTRY LM;
		SAM_ENTRY NTLM;
		SAM_ENTRY unk3;
		SAM_ENTRY unk4;
		BYTE datas;
	} USER_V, *PUSER_V;

	static bool lm(wstring * chaine, wstring * hash);
	static bool ntlm(wstring * chaine, wstring * hash);

	static void getBootKeyFromKey(BYTE bootkey[0x10], BYTE key[0x10]);
	static bool getHbootKeyFromBootKeyAndF(BYTE hBootKey[0x10], BYTE bootKey[0x10], BYTE * AccountsF);
	static bool decryptHash(wstring * hash, BYTE * hBootKey, USER_V * userV, SAM_ENTRY * encHash, DWORD rid, bool isNtlm);
	static void str_to_key(BYTE *str, BYTE *key);
	static void sid_to_key1(DWORD sid, BYTE deskey[8]);
	static void sid_to_key2(DWORD sid, BYTE deskey[8]);
};
