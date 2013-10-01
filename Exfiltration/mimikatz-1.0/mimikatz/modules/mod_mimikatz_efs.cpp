/*	Benjamin DELPY `gentilkiwi`
http://blog.gentilkiwi.com
benjamin@gentilkiwi.com
Licence : http://creativecommons.org/licenses/by/3.0/fr/
*/
#include "mod_mimikatz_efs.h"
#include "..\global.h"

vector<KIWI_MIMIKATZ_LOCAL_MODULE_COMMAND> mod_mimikatz_efs::getMimiKatzCommands()
{
	vector<KIWI_MIMIKATZ_LOCAL_MODULE_COMMAND> monVector;
	monVector.push_back(KIWI_MIMIKATZ_LOCAL_MODULE_COMMAND(infos,	L"infos",	L"Affiche des informations basiques sur un fichier chiffré"));
	monVector.push_back(KIWI_MIMIKATZ_LOCAL_MODULE_COMMAND(full,	L"full",	L"Affiche des informations très détaillées sur un fichier chiffré"));
	monVector.push_back(KIWI_MIMIKATZ_LOCAL_MODULE_COMMAND(toraw,	L"toraw",	L"Dump les données EFS d'un fichier chiffré vers un fichier brut"));
	//	monVector.push_back(KIWI_MIMIKATZ_LOCAL_MODULE_COMMAND(fromraw,	L"fromraw"));
	return monVector;
}

bool mod_mimikatz_efs::infos(vector<wstring> * arguments)
{
	if(!arguments->empty())
	{
		PENCRYPTION_CERTIFICATE_HASH_LIST pHashes = NULL;

		if(QueryUsersOnEncryptedFile(arguments->front().c_str(), &pHashes) == ERROR_SUCCESS)
		{
			(*outputStream) << L"Utilisateur(s) déclaré(s) : " << pHashes->nCert_Hash << endl;
			printInfos(pHashes);
			FreeEncryptionCertificateHashList(pHashes);
		}
		else (*outputStream) << L"Erreur QueryUsersOnEncryptedFile : " << mod_system::getWinError() << endl;

		if(QueryRecoveryAgentsOnEncryptedFile(arguments->front().c_str(), &pHashes) == ERROR_SUCCESS)
		{
			(*outputStream) << L"Agent(s) de recouvrement  : " << pHashes->nCert_Hash << endl;
			printInfos(pHashes);
			FreeEncryptionCertificateHashList(pHashes);
		}
		else (*outputStream) << L"Erreur QueryRecoveryAgentsOnEncryptedFile : " << mod_system::getWinError() << endl;

	}
	return true;
}

bool mod_mimikatz_efs::full(vector<wstring> * arguments)
{
	if(!arguments->empty())
	{
		PVOID pvContext = NULL;
		if(OpenEncryptedFileRaw(arguments->front().c_str(), 0, &pvContext) == ERROR_SUCCESS)
		{
			SIMPLE_BYTE_ARRAY sba = {0, reinterpret_cast<BYTE *>(malloc(0))};
			if(ReadEncryptedFileRaw(ExportToArrayCallback, &sba, pvContext) == ERROR_SUCCESS)
			{
				PEFS_FEK Fek = NULL;
				PEFS_STREAM_DATA_SEGMENT monDataSegment = NULL;
				for(
					PEFS_MARSHALED_STREAM monMarshaledStream = reinterpret_cast<PEFS_MARSHALED_STREAM>(sba.tableau + sizeof(EFS_RAW));
					reinterpret_cast<PBYTE>(monMarshaledStream) < (sba.tableau + sba.nbElements);
				monMarshaledStream = reinterpret_cast<PEFS_MARSHALED_STREAM>(monDataSegment)
					)
				{

					bool isEFSMetaData = (monMarshaledStream->NameLenght == 2) && (monMarshaledStream->StreamName[0] == 0x1910);

					(*outputStream) << endl <<
						L"Marshaled Stream :" << endl <<
						L" * Taille : " << monMarshaledStream->Length << endl <<
						L" * Flag   : " << monMarshaledStream->Flag << endl <<
						L" * Nom    : " << (isEFSMetaData ? wstring(L"(EFS Metadata stream)") : wstring(monMarshaledStream->StreamName, monMarshaledStream->NameLenght / sizeof(wchar_t))) << endl <<
						L" * Type   : " << (isEFSMetaData ? L"EFS Metadata" : L"DATA") << endl <<
						endl;

					for(
						monDataSegment = reinterpret_cast<PEFS_STREAM_DATA_SEGMENT>(reinterpret_cast<PBYTE>(monMarshaledStream) + monMarshaledStream->Length);
						(reinterpret_cast<PBYTE>(monDataSegment) < (sba.tableau + sba.nbElements)) && (monDataSegment->GURE0 == 0x00550047) && (monDataSegment->GURE1 == 0x00450052);
					monDataSegment = reinterpret_cast<PEFS_STREAM_DATA_SEGMENT>(reinterpret_cast<PBYTE>(monDataSegment) + monDataSegment->Length)
						)

					{
						(*outputStream) << L"DataSegment : " << endl;
						PBYTE StreamData = reinterpret_cast<PBYTE>(monDataSegment) + sizeof(EFS_STREAM_DATA_SEGMENT);

						if(isEFSMetaData)
						{
							(*outputStream) << L"  EFS Metadata :" << endl;

							PEFS_METADATA_1 mesAttr = reinterpret_cast<PEFS_METADATA_1>(StreamData);
							(*outputStream) << L"   * Version EFS : " << mesAttr->EFS_Version << endl;
							if(mesAttr->DDF_Offset)
							{
								(*outputStream) << L"   * Utilisateur(s) déclaré(s) :" << endl;
								fullInfosFromEFS_KEY_LIST(mesAttr, mesAttr->DDF_Offset, &Fek);
							}
							if(mesAttr->DRF_Offset)
							{
								(*outputStream) << L"   * Agent(s) de recouvrement  :" << endl;
								fullInfosFromEFS_KEY_LIST(mesAttr, mesAttr->DRF_Offset, &Fek);
							}
						}
						else
						{
							(*outputStream) << L"  DATA :" << endl;
							if(!monMarshaledStream->Flag)
							{
								(*outputStream) << L"  DATA Segment Encryption Header :" << endl;
								PEFS_STREAM_DATA_SEGMENT_ENCRYPTION_HEADER monSegEncHead = reinterpret_cast<PEFS_STREAM_DATA_SEGMENT_ENCRYPTION_HEADER>(StreamData);
								(*outputStream) <<
									L"   * Length                : " << monSegEncHead->Length << endl <<
									L"   * StartingFile_Offset   : " << monSegEncHead->StartingFile_Offset << endl <<
									L"   * BytesWithinStreamSize : " << monSegEncHead->BytesWithinStreamSize << endl <<
									L"   * BytesWithinVDL        : " << monSegEncHead->BytesWithinVDL << endl <<
									L"   * DataUnitShift         : " << monSegEncHead->DataUnitShift << endl <<
									L"   * ChunkShift            : " << monSegEncHead->ChunkShift << endl <<
									L"   * ClusterShift          : " << monSegEncHead->ClusterShift << endl <<
									L"   * NumberOfDataBlocks    : " << monSegEncHead->NumberOfDataBlocks << endl <<
									endl;

								PEFS_EXTENDED_HEADER monExtHeader = reinterpret_cast<PEFS_EXTENDED_HEADER>(reinterpret_cast<PBYTE>(monSegEncHead) + FIELD_OFFSET(EFS_STREAM_DATA_SEGMENT_ENCRYPTION_HEADER, DataBlockSizes) + (sizeof(DWORD) * monSegEncHead->NumberOfDataBlocks));
								if(monExtHeader->EXTD_Number == 'DTXE')
								{
									(*outputStream) << L"   * Extended Header Flag  : " << monExtHeader->Flags << endl;
								}

								for(DWORD block = 0; block < monSegEncHead->NumberOfDataBlocks; block++)
								{
									(*outputStream) << L"    -> Block " << block+1 << L" ; taille : " << monSegEncHead->DataBlockSizes[block] << endl;

									PBYTE mesDatas = reinterpret_cast<PBYTE>(StreamData) + monSegEncHead->Length;
									(*outputStream) << mod_text::stringOfHex(mesDatas, monSegEncHead->DataBlockSizes[block], 16) << endl;

									if(Fek);
								}
							}
							else
							{
								(*outputStream) << L"TODO Data" << endl;
							}
						}
					}
				}
			}
			else (*outputStream) << L"Erreur ReadEncryptedFileRaw : " << mod_system::getWinError() << endl;

			free(sba.tableau);
			CloseEncryptedFileRaw(pvContext);
		}
		else (*outputStream) << L"Erreur OpenEncryptedFileRaw : " << mod_system::getWinError() << endl;
	}
	return true;
}

bool mod_mimikatz_efs::toraw(vector<wstring> * arguments)
{
	if(arguments->size() == 2)
	{
		PVOID pvContext = NULL;
		(*outputStream) << L"Ouverture de : " << arguments->front() << endl;
		if(OpenEncryptedFileRaw(arguments->front().c_str(), 0, &pvContext) == ERROR_SUCCESS)
		{
			(*outputStream) << L"Vers         : " << arguments->back() << endl;
			HANDLE hFile = CreateFile(arguments->back().c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
			if(ReadEncryptedFileRaw(ExportToFileCallback, &hFile, pvContext) == ERROR_SUCCESS)
			{
				(*outputStream) << L" * Export OK" << endl;
			}
			else (*outputStream) << L"* Erreur ReadEncryptedFileRaw : " << mod_system::getWinError() << endl;
			CloseHandle(hFile);
			CloseEncryptedFileRaw(pvContext);
		}
		else (*outputStream) << L"Erreur OpenEncryptedFileRaw : " << mod_system::getWinError() << endl;
	}
	return true;
}

void mod_mimikatz_efs::printInfos(PENCRYPTION_CERTIFICATE_HASH_LIST hashList)
{
	for(DWORD i = 0; i < hashList->nCert_Hash; i++)
	{
		wstring user;
		mod_secacl::simpleSidToString(hashList->pUsers[i]->pUserSid, &user);

		(*outputStream) <<
			L" * Nom                : " << user << endl <<
			L" * Nom simple         : " << hashList->pUsers[i]->lpDisplayInformation << endl <<
			L" * Hash du certificat : " << mod_text::stringOfHex(hashList->pUsers[i]->pHash->pbData, hashList->pUsers[i]->pHash->cbData) << endl <<
			endl;
	}
}

DWORD WINAPI mod_mimikatz_efs::ExportToArrayCallback(PBYTE pbData, PVOID pvCallbackContext, DWORD ulLength)
{
	if(ulLength)
	{
		PSIMPLE_BYTE_ARRAY sba = reinterpret_cast<PSIMPLE_BYTE_ARRAY>(pvCallbackContext);
		sba->tableau = reinterpret_cast<PBYTE>(realloc(sba->tableau, sba->nbElements + ulLength));
		if(sba->tableau)
		{
			RtlCopyMemory(sba->tableau + sba->nbElements, pbData, ulLength);
			sba->nbElements += ulLength;
		}
		else
			return ERROR_NOT_ENOUGH_MEMORY;
	}
	return ERROR_SUCCESS;
}

DWORD WINAPI mod_mimikatz_efs::ExportToFileCallback(PBYTE pbData, PVOID pvCallbackContext, ULONG ulLength)
{
	if(ulLength)
	{
		(*outputStream) << L" - Lecture d\'un bloc de : " << ulLength << endl;
		DWORD dwBytesWritten = 0;
		if(WriteFile(*reinterpret_cast<PHANDLE>(pvCallbackContext), pbData, ulLength, &dwBytesWritten, NULL) && (ulLength == dwBytesWritten))
			return ERROR_SUCCESS;
		return GetLastError();
	}
	return ERROR_SUCCESS;
}

bool mod_mimikatz_efs::fullInfosFromEFS_KEY_LIST(PEFS_METADATA_1 header, LONG KeyList_offset, PEFS_FEK * pFek)
{
	*pFek = NULL;
	PEFS_KEY_LIST monHead = reinterpret_cast<PEFS_KEY_LIST>(reinterpret_cast<PBYTE>(header) + KeyList_offset);

	PEFS_KEY_LIST_ENTRY monHeader = reinterpret_cast<PEFS_KEY_LIST_ENTRY>(monHead);
	DWORD previousSize = sizeof(PEFS_KEY_LIST);
	for(DWORD i = 0; i < monHead->Length; i++)
	{
		(*outputStream) << endl << L"    Champ de données " << (i + 1) << L" :" << endl;
		monHeader = reinterpret_cast<PEFS_KEY_LIST_ENTRY>((PBYTE) monHeader + previousSize);

		PEFS_PUBLIC_KEY_INFORMATION monCredHeader = reinterpret_cast<PEFS_PUBLIC_KEY_INFORMATION>(reinterpret_cast<PBYTE>(monHeader) + monHeader->PKI_Offset);
		wstring user;
		if(monCredHeader->OwnerSID_offset)
			mod_secacl::simpleSidToString((reinterpret_cast<PBYTE>(monCredHeader) + monCredHeader->OwnerSID_offset), &user);
		else user.assign(L"(null)");

		(*outputStream) << L"     * Utilisateur : " << user << endl;
		fullInfosFromEFS_CERTIFICATE_DATA(monCredHeader, monCredHeader->Certificate_offset);

		PBYTE Encrypted_FEK = reinterpret_cast<PBYTE>(monHeader) + monHeader->Enc_FEK_Offset;
		(*outputStream) <<
			L"     * Flags          : " << monHeader->Flags << endl <<
			L"     * FEK (chiffrée) : " << endl <<
			L"      -> Taille  : " << monHeader->Enc_FEK_Length << endl <<
			L"      -> Données : " << endl << mod_text::stringOfHex(Encrypted_FEK, monHeader->Enc_FEK_Length, 16) << endl <<
			endl;

		/*HCRYPTPROV hCryptKeyProv;
		if(CryptAcquireContext(&hCryptKeyProv, L"", MS_STRONG_PROV, PROV_RSA_FULL, NULL ))
		{
			HCRYPTKEY maCle = NULL;
			if(CryptGetUserKey(hCryptKeyProv, AT_KEYEXCHANGE, &maCle))
			{
				DWORD taille = monHeader->Enc_FEK_Length;	
				if (CryptDecrypt(maCle, 0, TRUE, 0, Encrypted_FEK, &taille) )
				{
					*pFek = reinterpret_cast<PEFS_FEK>(Encrypted_FEK);
					(*outputStream) <<
						L"     * FEK (clair)    : " << endl <<
						L"      -> Taille     : " << (*pFek)->Key_Lenght << endl <<
						L"      -> Algorithme : " << (*pFek)->Algorithm << endl <<
						L"      -> Entropie   : " << (*pFek)->Entropy << endl <<
						L"      -> Données    : " << endl << mod_text::stringOfHex((*pFek)->Key, (*pFek)->Key_Lenght, 16) << endl <<
						endl;
				}
				else
					(*outputStream) << mod_system::getWinError() << endl;
			}
			CryptReleaseContext(hCryptKeyProv, 0);
		}*/

		previousSize = monHeader->Length;
	}

	return (*pFek != NULL);
}

void mod_mimikatz_efs::fullInfosFromEFS_CERTIFICATE_DATA(PEFS_PUBLIC_KEY_INFORMATION header, LONG Certificate_offset)
{
	PEFS_CERTIFICATE_DATA monThCertificate = reinterpret_cast<PEFS_CERTIFICATE_DATA>(reinterpret_cast<PBYTE>(header) + header->Certificate_offset);

	(*outputStream) << L"      -> Nom affiché : ";
	if(monThCertificate->DisplayName_Offset)
		(*outputStream) << reinterpret_cast<wchar_t *>(reinterpret_cast<PBYTE>(monThCertificate) + monThCertificate->DisplayName_Offset);
	(*outputStream) << endl;

	(*outputStream) << L"      -> Provider    : ";
	if(monThCertificate->ProviderName_Offset)
		(*outputStream) << reinterpret_cast<wchar_t *>(reinterpret_cast<PBYTE>(monThCertificate) + monThCertificate->ProviderName_Offset);
	(*outputStream) << endl;

	(*outputStream) << L"      -> Container   : ";
	if(monThCertificate->ContainerName_Offset)
		(*outputStream) << reinterpret_cast<wchar_t *>(reinterpret_cast<PBYTE>(monThCertificate) + monThCertificate->ContainerName_Offset);
	(*outputStream) << endl;

	(*outputStream) << L"      -> Empreinte   : " << mod_text::stringOfHex(reinterpret_cast<PBYTE>(monThCertificate) + monThCertificate->CertificateThumbprint, monThCertificate->CertificateThumbprint_Length) << endl;
}
