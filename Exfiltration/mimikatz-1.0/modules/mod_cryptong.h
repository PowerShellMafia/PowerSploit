/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : http://creativecommons.org/licenses/by/3.0/fr/
*/
#pragma once
#include "globdefs.h"
#include <bcrypt.h>
#include <sstream>

class mod_cryptong /* Ref : http://msdn.microsoft.com/en-us/library/aa376210.aspx */
{
public:
	static bool getVectorProviders(vector<wstring> * monVectorProviders);
	static bool getVectorContainers(vector<wstring> * monVectorContainers, bool isMachine = false);
	static bool getHKeyFromName(wstring keyName, NCRYPT_KEY_HANDLE * keyHandle, bool isMachine = false);
	static bool getKeySize(HCRYPTPROV_OR_NCRYPT_KEY_HANDLE * provOrCle, DWORD * keySize);
	static bool isKeyExportable(HCRYPTPROV_OR_NCRYPT_KEY_HANDLE * provOrCle, bool * isExportable);
	static bool getPrivateKey(NCRYPT_KEY_HANDLE maCle, PBYTE * monExport, DWORD * tailleExport, LPCWSTR pszBlobType = LEGACY_RSAPRIVATE_BLOB);
	static bool NCryptFreeObject(NCRYPT_HANDLE hObject);

	static bool isNcrypt;
	static bool justInitCNG(LPCWSTR pszProviderName = NULL);
};
