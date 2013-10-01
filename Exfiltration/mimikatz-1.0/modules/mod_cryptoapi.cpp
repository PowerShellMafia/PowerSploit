/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : http://creativecommons.org/licenses/by/3.0/fr/
*/
#include "mod_cryptoapi.h"
HMODULE mod_cryptoapi::hRsaEng = NULL;

bool mod_cryptoapi::loadRsaEnh()
{
	if(!hRsaEng)
		hRsaEng = LoadLibrary(L"rsaenh");
	return (hRsaEng != NULL);
}

bool mod_cryptoapi::unloadRsaEnh()
{
	if(hRsaEng)
		FreeLibrary(hRsaEng);
	return true;
}

bool mod_cryptoapi::getProviderString(wstring ProviderName, wstring * Provider)
{
	map<wstring, wstring> mesProviders;
	mesProviders.insert(make_pair(L"MS_DEF_PROV",				MS_DEF_PROV));
	mesProviders.insert(make_pair(L"MS_ENHANCED_PROV",			MS_ENHANCED_PROV));
	mesProviders.insert(make_pair(L"MS_STRONG_PROV",			MS_STRONG_PROV));
	mesProviders.insert(make_pair(L"MS_DEF_RSA_SIG_PROV",		MS_DEF_RSA_SIG_PROV));
	mesProviders.insert(make_pair(L"MS_DEF_RSA_SCHANNEL_PROV",	MS_DEF_RSA_SCHANNEL_PROV));
	mesProviders.insert(make_pair(L"MS_DEF_DSS_PROV",			MS_DEF_DSS_PROV));
	mesProviders.insert(make_pair(L"MS_DEF_DSS_DH_PROV",		MS_DEF_DSS_DH_PROV));
	mesProviders.insert(make_pair(L"MS_ENH_DSS_DH_PROV",		MS_ENH_DSS_DH_PROV));
	mesProviders.insert(make_pair(L"MS_DEF_DH_SCHANNEL_PROV",	MS_DEF_DH_SCHANNEL_PROV));
	mesProviders.insert(make_pair(L"MS_SCARD_PROV",				MS_SCARD_PROV));
	mesProviders.insert(make_pair(L"MS_ENH_RSA_AES_PROV",		MS_ENH_RSA_AES_PROV));
	mesProviders.insert(make_pair(L"MS_ENH_RSA_AES_PROV_XP",	MS_ENH_RSA_AES_PROV_XP));
	
	map<wstring, wstring>::iterator monIterateur = mesProviders.find(ProviderName);
	*Provider = (monIterateur != mesProviders.end()) ? monIterateur->second : ProviderName;
	return true;
}

bool mod_cryptoapi::getProviderTypeFromString(wstring ProviderTypeName, DWORD * ProviderType)
{
	map<wstring, DWORD> mesTypes;
	mesTypes.insert(make_pair(L"PROV_RSA_FULL",		PROV_RSA_FULL));
	mesTypes.insert(make_pair(L"PROV_RSA_SIG",		PROV_RSA_SIG));
	mesTypes.insert(make_pair(L"PROV_DSS",			PROV_DSS));
	mesTypes.insert(make_pair(L"PROV_FORTEZZA",		PROV_FORTEZZA));
	mesTypes.insert(make_pair(L"PROV_MS_EXCHANGE",	PROV_MS_EXCHANGE));
	mesTypes.insert(make_pair(L"PROV_SSL",			PROV_SSL));
	mesTypes.insert(make_pair(L"PROV_RSA_SCHANNEL",	PROV_RSA_SCHANNEL));
	mesTypes.insert(make_pair(L"PROV_DSS_DH",		PROV_DSS_DH));
	mesTypes.insert(make_pair(L"PROV_EC_ECDSA_SIG",	PROV_EC_ECDSA_SIG));
	mesTypes.insert(make_pair(L"PROV_EC_ECNRA_SIG",	PROV_EC_ECNRA_SIG));
	mesTypes.insert(make_pair(L"PROV_EC_ECDSA_FULL",PROV_EC_ECDSA_FULL));
	mesTypes.insert(make_pair(L"PROV_EC_ECNRA_FULL",PROV_EC_ECNRA_FULL));
	mesTypes.insert(make_pair(L"PROV_DH_SCHANNEL",	PROV_DH_SCHANNEL));
	mesTypes.insert(make_pair(L"PROV_SPYRUS_LYNKS",	PROV_SPYRUS_LYNKS));
	mesTypes.insert(make_pair(L"PROV_RNG",			PROV_RNG));
	mesTypes.insert(make_pair(L"PROV_INTEL_SEC",	PROV_INTEL_SEC));
	mesTypes.insert(make_pair(L"PROV_REPLACE_OWF",	PROV_REPLACE_OWF));
	mesTypes.insert(make_pair(L"PROV_RSA_AES",		PROV_RSA_AES));

	map<wstring, DWORD>::iterator monIterateur = mesTypes.find(ProviderTypeName);
	if(monIterateur != mesTypes.end())
	{
		*ProviderType = monIterateur->second;
		return true;
	}
	else return false;
}

bool mod_cryptoapi::getVectorProviders(vector<wstring> * monVectorProviders)
{
	DWORD index = 0;
	DWORD provType;
	DWORD tailleRequise;

	while(CryptEnumProviders(index, NULL, 0, &provType, NULL, &tailleRequise))
	{
		wchar_t * monProvider = new wchar_t[tailleRequise];
		if(CryptEnumProviders(index, NULL, 0, &provType, monProvider, &tailleRequise))
		{
			monVectorProviders->push_back(monProvider);
		}
		delete[] monProvider;
		index++;
	}
	return (GetLastError() == ERROR_NO_MORE_ITEMS);
}

bool mod_cryptoapi::getVectorContainers(vector<wstring> * monVectorContainers, bool isMachine, wstring provider, DWORD providerType)
{
	bool reussite = false;

	HCRYPTPROV hCryptProv = NULL;
	if(CryptAcquireContext(&hCryptProv, NULL, provider.c_str(), providerType, CRYPT_VERIFYCONTEXT | (isMachine ? CRYPT_MACHINE_KEYSET : NULL)))
	{
		DWORD tailleRequise = 0;
		char * containerName = NULL;
		DWORD CRYPT_first_next = CRYPT_FIRST;
		bool success = false;

		success = (CryptGetProvParam(hCryptProv, PP_ENUMCONTAINERS, NULL, &tailleRequise, CRYPT_first_next) != 0);
		while(success)
		{
			containerName = new char[tailleRequise];
			if(success = (CryptGetProvParam(hCryptProv, PP_ENUMCONTAINERS, reinterpret_cast<BYTE *>(containerName), &tailleRequise, CRYPT_first_next) != 0))
			{
				wstringstream resultat;
				resultat << containerName;
				monVectorContainers->push_back(resultat.str());
			}
			delete[] containerName;
			CRYPT_first_next = CRYPT_NEXT;
		}
		reussite = (GetLastError() == ERROR_NO_MORE_ITEMS);
		CryptReleaseContext(hCryptProv, 0);
	}

	return reussite;
}

bool mod_cryptoapi::getPrivateKey(HCRYPTKEY maCle, PBYTE * monExport, DWORD * tailleExport, DWORD dwBlobType)
{
	bool reussite = false;

	if(CryptExportKey(maCle, NULL, dwBlobType, NULL, NULL, tailleExport))
	{
		*monExport = new BYTE[*tailleExport];
		if(!(reussite = (CryptExportKey(maCle, NULL, dwBlobType, NULL, *monExport, tailleExport) != 0)))
			delete[] monExport;

	}
	return reussite;
}