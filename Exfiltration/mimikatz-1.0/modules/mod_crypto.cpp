/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : http://creativecommons.org/licenses/by/3.0/fr/
*/
#include "mod_crypto.h"

bool mod_crypto::getSystemStoreFromString(wstring strSystemStore, DWORD * systemStore)
{
	map<wstring, DWORD> mesEmplacements;
	mesEmplacements.insert(make_pair(L"CERT_SYSTEM_STORE_CURRENT_USER",					CERT_SYSTEM_STORE_CURRENT_USER));
	mesEmplacements.insert(make_pair(L"CERT_SYSTEM_STORE_CURRENT_USER_GROUP_POLICY",	CERT_SYSTEM_STORE_CURRENT_USER_GROUP_POLICY));
	mesEmplacements.insert(make_pair(L"CERT_SYSTEM_STORE_LOCAL_MACHINE",				CERT_SYSTEM_STORE_LOCAL_MACHINE));
	mesEmplacements.insert(make_pair(L"CERT_SYSTEM_STORE_LOCAL_MACHINE_GROUP_POLICY",	CERT_SYSTEM_STORE_LOCAL_MACHINE_GROUP_POLICY));
	mesEmplacements.insert(make_pair(L"CERT_SYSTEM_STORE_LOCAL_MACHINE_ENTERPRISE",		CERT_SYSTEM_STORE_LOCAL_MACHINE_ENTERPRISE));
	mesEmplacements.insert(make_pair(L"CERT_SYSTEM_STORE_CURRENT_SERVICE",				CERT_SYSTEM_STORE_CURRENT_SERVICE));
	mesEmplacements.insert(make_pair(L"CERT_SYSTEM_STORE_USERS",						CERT_SYSTEM_STORE_USERS));
	mesEmplacements.insert(make_pair(L"CERT_SYSTEM_STORE_SERVICES",						CERT_SYSTEM_STORE_SERVICES));

	map<wstring, DWORD>::iterator monIterateur = mesEmplacements.find(strSystemStore);
	if(monIterateur != mesEmplacements.end())
	{
		*systemStore = monIterateur->second;
		return true;
	}
	else return false;
}

BOOL WINAPI mod_crypto::enumSysCallback(const void *pvSystemStore, DWORD dwFlags, PCERT_SYSTEM_STORE_INFO pStoreInfo, void *pvReserved, void *pvArg)
{
	reinterpret_cast<vector<wstring> *>(pvArg)->push_back(reinterpret_cast<const wchar_t *>(pvSystemStore));
	return TRUE;
}

bool mod_crypto::getVectorSystemStores(vector<wstring> * maSystemStoresvector, DWORD systemStore)
{
	return (CertEnumSystemStore(systemStore, NULL, maSystemStoresvector, enumSysCallback) != 0);
}

bool mod_crypto::getCertNameFromCertCTX(PCCERT_CONTEXT certCTX, wstring * certName)
{
	bool reussite = false;
	wchar_t * monBuffer = NULL;
	
	DWORD maRecherche[] = {CERT_NAME_FRIENDLY_DISPLAY_TYPE, CERT_NAME_DNS_TYPE, CERT_NAME_EMAIL_TYPE, CERT_NAME_UPN_TYPE, CERT_NAME_URL_TYPE};

	for(DWORD i = 0; !reussite && (i < (sizeof(maRecherche) / sizeof(DWORD))); i++)
	{
		DWORD tailleRequise = CertGetNameString(certCTX, maRecherche[i], 0, NULL, NULL, 0);
		if(tailleRequise > 1)
		{
			monBuffer = new wchar_t[tailleRequise];
			reussite = CertGetNameString(certCTX, maRecherche[i], 0, NULL, monBuffer, tailleRequise) > 1;
			certName->assign(monBuffer);
			delete[] monBuffer;
		}	
	}
	return reussite;
}

bool mod_crypto::getKiwiKeyProvInfo(PCCERT_CONTEXT certCTX, KIWI_KEY_PROV_INFO * keyProvInfo)
{
	bool reussite = false;
	DWORD taille = 0;
	if(CertGetCertificateContextProperty(certCTX, CERT_KEY_PROV_INFO_PROP_ID, NULL, &taille))
	{
		BYTE * monBuffer = new BYTE[taille];
		if(reussite = (CertGetCertificateContextProperty(certCTX, CERT_KEY_PROV_INFO_PROP_ID, monBuffer, &taille) != 0))
		{
			CRYPT_KEY_PROV_INFO * mesInfos = reinterpret_cast<CRYPT_KEY_PROV_INFO *>(monBuffer);
			keyProvInfo->pwszProvName.assign(mesInfos->pwszProvName ? mesInfos->pwszProvName : L"(null)");
			keyProvInfo->pwszContainerName.assign(mesInfos->pwszContainerName ? mesInfos->pwszContainerName : L"(null)");
			keyProvInfo->cProvParam = mesInfos->cProvParam;
			keyProvInfo->dwFlags = mesInfos->dwFlags;
			keyProvInfo->dwKeySpec = mesInfos->dwKeySpec;
			keyProvInfo->dwProvType = mesInfos->dwProvType;
		}
		delete[] monBuffer;
	}
	return reussite;
}

bool mod_crypto::CertCTXtoPFX(PCCERT_CONTEXT certCTX, wstring pfxFile, wstring password)
{
	bool retour = false;

	HCERTSTORE hTempStore = CertOpenStore(CERT_STORE_PROV_MEMORY, 0, NULL, CERT_STORE_CREATE_NEW_FLAG, NULL); 
	PCCERT_CONTEXT  pCertContextCopy = NULL;

	if(CertAddCertificateContextToStore(hTempStore, certCTX, CERT_STORE_ADD_NEW, &pCertContextCopy))
	{
		CRYPT_DATA_BLOB bDataBlob = {0, NULL};
		if(PFXExportCertStoreEx(hTempStore, &bDataBlob, password.c_str(), NULL, EXPORT_PRIVATE_KEYS | REPORT_NOT_ABLE_TO_EXPORT_PRIVATE_KEY))
		{
			bDataBlob.pbData = new BYTE[bDataBlob.cbData]; 
			if(PFXExportCertStoreEx(hTempStore, &bDataBlob, password.c_str(), NULL, EXPORT_PRIVATE_KEYS | REPORT_NOT_ABLE_TO_EXPORT_PRIVATE_KEY))
			{
				HANDLE hFile = CreateFile(pfxFile.c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
				if(hFile && hFile != INVALID_HANDLE_VALUE)
				{
					DWORD dwBytesWritten;
					if(WriteFile(hFile, bDataBlob.pbData, bDataBlob.cbData, &dwBytesWritten, NULL) && (bDataBlob.cbData == dwBytesWritten))
					{
						retour = FlushFileBuffers(hFile) != 0;
					}
					CloseHandle(hFile);
				}
			}
			delete[] bDataBlob.pbData;
		}
		CertFreeCertificateContext(pCertContextCopy);
	}
	CertCloseStore(hTempStore, CERT_CLOSE_STORE_FORCE_FLAG);

	return retour;
}

bool mod_crypto::CertCTXtoDER(PCCERT_CONTEXT certCTX, wstring DERFile)
{
	bool retour = false;

	HANDLE hFile = CreateFile(DERFile.c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
	if(hFile && hFile != INVALID_HANDLE_VALUE)
	{
		DWORD dwBytesWritten;
		if(WriteFile(hFile, certCTX->pbCertEncoded, certCTX->cbCertEncoded, &dwBytesWritten, NULL) && certCTX->cbCertEncoded == dwBytesWritten)
		{
			retour = FlushFileBuffers(hFile) != 0;
		}
		CloseHandle(hFile);
	}
	return retour;
}

wstring mod_crypto::KeyTypeToString(DWORD keyType)
{
	wostringstream keyTypeStr;
	switch (keyType)
	{
		case AT_KEYEXCHANGE:
			keyTypeStr << L"AT_KEYEXCHANGE";
			break;
		case AT_SIGNATURE:
			keyTypeStr << L"AT_SIGNATURE";
			break;
		default:
			keyTypeStr << L"? (" << hex << keyType << L")";
	}
	return keyTypeStr.str();
}


bool mod_crypto::PrivateKeyBlobToPVK(BYTE * monExport, DWORD tailleExport, wstring pvkFile, DWORD keySpec)
{
	bool retour = false;
	FILE_HDR monHeader = {PVK_MAGIC, PVK_FILE_VERSION_0, keySpec, PVK_NO_ENCRYPT, 0, tailleExport};

	HANDLE hFile = CreateFile(pvkFile.c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
	if(hFile && hFile != INVALID_HANDLE_VALUE)
	{
		DWORD dwBytesWritten;
		if(WriteFile(hFile, &monHeader, sizeof(monHeader), &dwBytesWritten, NULL) && (sizeof(monHeader) == dwBytesWritten))
		{
			if(WriteFile(hFile, monExport, tailleExport, &dwBytesWritten, NULL) && (tailleExport == dwBytesWritten))
			{
				retour = FlushFileBuffers(hFile) != 0;
			}
		}
		CloseHandle(hFile);
	}

	return retour;
}

bool mod_crypto::genericDecrypt(BYTE * data, SIZE_T dataSize, const BYTE * key, SIZE_T keySize, ALG_ID algorithme, BYTE * destBuffer, SIZE_T destBufferSize)
{
	bool retour = false;
	HCRYPTPROV hCryptProv = NULL; 
	HCRYPTKEY hKey = NULL;
	PBYTE buffer = data;
	DWORD dwWorkingBufferLength = dataSize;
	
	if(destBuffer && destBufferSize >= dataSize)
	{
		RtlCopyMemory(destBuffer, data, dataSize);
		buffer = destBuffer;
	}
	
	if((algorithme == CALG_RC4) && (keySize > 16))
	{
		fullRC4(buffer, dataSize, key, keySize);
		retour = true;
	}
	else
	{
		if(CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
		{
			GENERICKEY_BLOB myKeyHead = {{PLAINTEXTKEYBLOB, CUR_BLOB_VERSION, 0, algorithme}, keySize};
			BYTE * myKey = new BYTE[sizeof(GENERICKEY_BLOB) + keySize];
			RtlCopyMemory(myKey, &myKeyHead, sizeof(GENERICKEY_BLOB));
			RtlCopyMemory(myKey + sizeof(GENERICKEY_BLOB), key, keySize);

			if(CryptImportKey(hCryptProv, myKey, sizeof(GENERICKEY_BLOB) + keySize, 0, CRYPT_EXPORTABLE, &hKey))
			{
				if(CryptDecrypt(hKey, NULL, TRUE, 0, buffer, &dwWorkingBufferLength) || ((algorithme == CALG_DES) && (GetLastError() == NTE_BAD_DATA))) // évite les erreurs de parités http://support.microsoft.com/kb/331367/
					retour = (dwWorkingBufferLength == dataSize);
				CryptDestroyKey(hKey);
			}
			delete[] myKey;
			CryptReleaseContext(hCryptProv, 0);
		}
	}
	return retour;
}

void mod_crypto::fullRC4(BYTE * data, SIZE_T data_len, const BYTE * key, SIZE_T keylen) // pour les clés >= 128 bits (16 octets)
{
	ULONG i, j, k = 0, kpos = 0;
	BYTE S[256], *pos = data;

	for (i = 0; i < 256; i++)
		S[i] = static_cast<BYTE>(i);

	for (i = 0, j = 0; i < 256; i++)
	{
		j = (j + S[i] + key[kpos]) & 0xff;
		kpos++;
		if (kpos >= keylen)
			kpos = 0;
		S_SWAP(i, j);
	}

	for (i = 0, j = 0; k < data_len; k++)
	{
		i = (i + 1) & 0xff;
		j = (j + S[i]) & 0xff;
		S_SWAP(i, j);
		*pos++ ^= S[(S[i] + S[j]) & 0xff];
	}
}
