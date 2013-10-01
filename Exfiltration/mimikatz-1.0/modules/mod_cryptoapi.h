/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : http://creativecommons.org/licenses/by/3.0/fr/
*/
#pragma once
#include "globdefs.h"
#include <wincrypt.h>
#include <sstream>
#include <map>

class mod_cryptoapi /* Ref : http://msdn.microsoft.com/en-us/library/aa380255.aspx */
{
private:
	static HMODULE hRsaEng;
public:
	static bool getProviderString(wstring ProviderName, wstring * Provider);
	static bool getProviderTypeFromString(wstring ProviderTypeName, DWORD * ProviderType);
	
	static bool getVectorProviders(vector<wstring> * monVectorProviders);
	static bool getVectorContainers(vector<wstring> * monVectorContainers, bool isMachine = false, wstring provider = MS_ENHANCED_PROV, DWORD providerType = PROV_RSA_FULL);
	static bool getPrivateKey(HCRYPTKEY maCle, PBYTE * monExport, DWORD * tailleExport, DWORD dwBlobType = PRIVATEKEYBLOB);

	static bool loadRsaEnh();
	static bool unloadRsaEnh();
};
