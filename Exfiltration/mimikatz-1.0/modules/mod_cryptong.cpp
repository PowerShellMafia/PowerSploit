/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : http://creativecommons.org/licenses/by/3.0/fr/
*/
#include "mod_cryptong.h"

HMODULE hNcrypt = LoadLibrary(L"ncrypt");

PNCRYPT_OPEN_STORAGE_PROVIDER K_NCryptOpenStorageProvider = reinterpret_cast<PNCRYPT_OPEN_STORAGE_PROVIDER>(GetProcAddress(hNcrypt, "NCryptOpenStorageProvider"));
PNCRYPT_ENUM_KEYS K_NCryptEnumKeys = reinterpret_cast<PNCRYPT_ENUM_KEYS>(GetProcAddress(hNcrypt, "NCryptEnumKeys"));
PNCRYPT_OPEN_KEY K_NCryptOpenKey = reinterpret_cast<PNCRYPT_OPEN_KEY>(GetProcAddress(hNcrypt, "NCryptOpenKey"));
PNCRYPT_EXPORT_KEY K_NCryptExportKey = reinterpret_cast<PNCRYPT_EXPORT_KEY>(GetProcAddress(hNcrypt, "NCryptExportKey"));
PNCRYPT_GET_PROPERTY K_NCryptGetProperty = reinterpret_cast<PNCRYPT_GET_PROPERTY>(GetProcAddress(hNcrypt, "NCryptGetProperty"));

PNCRYPT_FREE_BUFFER K_NCryptFreeBuffer = reinterpret_cast<PNCRYPT_FREE_BUFFER>(GetProcAddress(hNcrypt, "NCryptFreeBuffer"));
PNCRYPT_FREE_OBJECT K_NCryptFreeObject = reinterpret_cast<PNCRYPT_FREE_OBJECT>(GetProcAddress(hNcrypt, "NCryptFreeObject"));

PBCRYPT_ENUM_REGISTERED_PROVIDERS K_BCryptEnumRegisteredProviders = reinterpret_cast<PBCRYPT_ENUM_REGISTERED_PROVIDERS>(GetProcAddress(hNcrypt, "BCryptEnumRegisteredProviders"));
PBCRYPT_FREE_BUFFER K_BCryptFreeBuffer = reinterpret_cast<PBCRYPT_FREE_BUFFER>(GetProcAddress(hNcrypt, "BCryptFreeBuffer"));

bool mod_cryptong::isNcrypt = (
	hNcrypt &&
	K_NCryptOpenStorageProvider &&
	K_NCryptEnumKeys &&
	K_NCryptOpenKey &&
	K_NCryptExportKey &&
	K_NCryptGetProperty &&
	K_NCryptFreeBuffer &&
	K_NCryptFreeObject &&
	K_BCryptEnumRegisteredProviders &&
	K_BCryptFreeBuffer
);

bool mod_cryptong::justInitCNG(LPCWSTR pszProviderName)
{
	bool reussite = false;
	NCRYPT_PROV_HANDLE hProvider;

	if(K_NCryptOpenStorageProvider(&hProvider, pszProviderName, 0) == ERROR_SUCCESS)
		reussite = (K_NCryptFreeObject(hProvider) == 0);

	return reussite;
}


bool mod_cryptong::getVectorProviders(vector<wstring> * monVectorProviders)
{
	bool reussite = false;
	
	DWORD cbBuffer;
    PCRYPT_PROVIDERS pBuffer = NULL;

	if(reussite = (K_BCryptEnumRegisteredProviders(&cbBuffer, &pBuffer) == 0))
	{
		for(DWORD i = 0; i < pBuffer->cProviders; i++)
			monVectorProviders->push_back(pBuffer->rgpszProviders[i]);
		K_BCryptFreeBuffer(pBuffer);
	}

	return reussite;
}

bool mod_cryptong::getVectorContainers(vector<wstring> * monVectorContainers, bool isMachine)
{
	bool reussite = false;
	NCRYPT_PROV_HANDLE hProvider;
	NCryptKeyName * pKeyName;
	PVOID pEnumState = NULL;
	
	SECURITY_STATUS retour;
	if(K_NCryptOpenStorageProvider(&hProvider, /*MS_KEY_STORAGE_PROVIDER*/ NULL, 0) == ERROR_SUCCESS)
	{
		while((retour = K_NCryptEnumKeys(hProvider, NULL, &pKeyName, &pEnumState, (isMachine ? NCRYPT_MACHINE_KEY_FLAG : NULL))) == ERROR_SUCCESS)
		{
			monVectorContainers->push_back(pKeyName->pszName);
			K_NCryptFreeBuffer(pKeyName);
		}
		reussite = (retour == NTE_NO_MORE_ITEMS);

		if(pEnumState)
			K_NCryptFreeBuffer(pEnumState);
		K_NCryptFreeObject(hProvider);
	}

	return reussite;
}

bool mod_cryptong::getHKeyFromName(wstring keyName, NCRYPT_KEY_HANDLE * keyHandle, bool isMachine)
{
	bool reussite = false;
	NCRYPT_PROV_HANDLE hProvider;

	if(K_NCryptOpenStorageProvider(&hProvider, /*MS_KEY_STORAGE_PROVIDER*/ NULL, 0) == ERROR_SUCCESS)
	{
		reussite = K_NCryptOpenKey(hProvider, keyHandle, keyName.c_str(), 0, (isMachine ? NCRYPT_MACHINE_KEY_FLAG : NULL)) == ERROR_SUCCESS;
		K_NCryptFreeObject(hProvider);
	}
	
	return reussite;
}



bool mod_cryptong::getKeySize(HCRYPTPROV_OR_NCRYPT_KEY_HANDLE * provOrCle, DWORD * keySize)
{
	DWORD tailleEcrite = 0;
	return ((K_NCryptGetProperty(*provOrCle, NCRYPT_LENGTH_PROPERTY,  reinterpret_cast<BYTE *>(keySize), sizeof(DWORD), &tailleEcrite, 0) == 0) && tailleEcrite == sizeof(DWORD));
}


bool mod_cryptong::isKeyExportable(HCRYPTPROV_OR_NCRYPT_KEY_HANDLE * provOrCle, bool * isExportable)
{
	bool reussite = false;
	DWORD tailleEcrite = 0, exportability = 0;
	
	if(reussite = ((K_NCryptGetProperty(*provOrCle, NCRYPT_EXPORT_POLICY_PROPERTY,  reinterpret_cast<BYTE *>(&exportability), sizeof(DWORD), &tailleEcrite, 0) == 0) && tailleEcrite == sizeof(DWORD)))
	{
		*isExportable =(exportability & NCRYPT_ALLOW_EXPORT_FLAG) != 0;
	}	
	return reussite;
}

bool mod_cryptong::getPrivateKey(NCRYPT_KEY_HANDLE maCle, PBYTE * monExport, DWORD * tailleExport, LPCWSTR pszBlobType)
{
	SECURITY_STATUS monRetour = K_NCryptExportKey(maCle, NULL, pszBlobType, NULL, NULL, 0, tailleExport, 0);
	if(monRetour == ERROR_SUCCESS)
	{
		*monExport = new BYTE[*tailleExport];
		monRetour = K_NCryptExportKey(maCle, NULL, pszBlobType, NULL, *monExport, *tailleExport, tailleExport, 0);

		if(monRetour != ERROR_SUCCESS)
			delete[] monExport;
	}
	SetLastError(monRetour);
	return (monRetour == ERROR_SUCCESS);
}


bool mod_cryptong::NCryptFreeObject(NCRYPT_HANDLE hObject)
{
	return (K_NCryptFreeObject(hObject) == 0);
}