/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : http://creativecommons.org/licenses/by/3.0/fr/
*/
#pragma once
#include "globdefs.h"
#include <wincrypt.h>
#include <sstream>
#include <map>

#define PVK_FILE_VERSION_0				0
#define PVK_MAGIC						0xb0b5f11e // bob's file
#define PVK_NO_ENCRYPT					0
#define PVK_RC4_PASSWORD_ENCRYPT		1
#define PVK_RC2_CBC_PASSWORD_ENCRYPT	2

class mod_crypto
{
public:
	typedef struct _KIWI_KEY_PROV_INFO {
		std::wstring	pwszContainerName;
		std::wstring	pwszProvName;
		DWORD			dwProvType;
		DWORD			dwFlags;
		DWORD			cProvParam;
		DWORD			dwKeySpec;
	} KIWI_KEY_PROV_INFO, *PKIWI_KEY_PROV_INFO;

private:
	typedef struct _GENERICKEY_BLOB {
		BLOBHEADER BlobHeader;
		DWORD dwKeyLen;
	} GENERICKEY_BLOB, *PGENERICKEY_BLOB;

	typedef struct _FILE_HDR {
		DWORD	dwMagic;
		DWORD	dwVersion;
		DWORD	dwKeySpec;
		DWORD	dwEncryptType;
		DWORD	cbEncryptData;
		DWORD	cbPvk;
	} FILE_HDR, *PFILE_HDR;

	static BOOL WINAPI enumSysCallback(const void *pvSystemStore, DWORD dwFlags, PCERT_SYSTEM_STORE_INFO pStoreInfo, void *pvReserved, void *pvArg);
public:
	static bool getSystemStoreFromString(wstring strSystemStore, DWORD * systemStore);

	static bool getVectorSystemStores(vector<wstring> * maSystemStoresvector, DWORD systemStore = CERT_SYSTEM_STORE_CURRENT_USER);
	static bool getCertNameFromCertCTX(PCCERT_CONTEXT certCTX, wstring * certName);
	static bool getKiwiKeyProvInfo(PCCERT_CONTEXT certCTX, KIWI_KEY_PROV_INFO * keyProvInfo);
	
	static bool	PrivateKeyBlobToPVK(BYTE * monExport, DWORD tailleExport, wstring pvkFile, DWORD keySpec = AT_KEYEXCHANGE);
	static bool CertCTXtoPFX(PCCERT_CONTEXT certCTX, wstring pfxFile, wstring password);
	static bool CertCTXtoDER(PCCERT_CONTEXT certCTX, wstring DERFile);
	static wstring KeyTypeToString(DWORD keyType);

	static bool genericDecrypt(BYTE * data, SIZE_T data_len, const BYTE * key, SIZE_T keylen, ALG_ID algorithme, BYTE * destBuffer = NULL, SIZE_T destBufferSize = 0);
	static void fullRC4(BYTE * data, SIZE_T data_len, const BYTE * key, SIZE_T keylen); // keysize >= 128 bits (16 bytes)
};
