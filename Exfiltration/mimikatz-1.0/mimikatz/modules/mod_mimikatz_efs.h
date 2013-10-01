/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : http://creativecommons.org/licenses/by/3.0/fr/
*/
#pragma once
#include "globdefs.h"
#include <WinEFS.h>
#include <iostream>
#include "mod_text.h"
#include "mod_system.h"
#include "mod_secacl.h"
#include "mod_crypto.h"

class mod_mimikatz_efs
{
private:
	// http://msdn.microsoft.com/library/cc230447.aspx
	typedef struct _EFS_RAW {
		DWORD	Unknown0;
		DWORD	ROBS0;
		DWORD	ROBS1;
		BYTE	Reserved[8];
	} EFS_RAW, *PEFS_RAW;
	
	typedef struct _EFS_MARSHALED_STREAM {
		DWORD	Length;
		DWORD	NTFS0;
		DWORD	NTFS1;
		DWORD	Flag;
		BYTE	Reserved[8];
		DWORD	NameLenght;
		wchar_t StreamName[1];
	} EFS_MARSHALED_STREAM, *PEFS_MARSHALED_STREAM;

	typedef struct _EFS_STREAM_DATA_SEGMENT {
		DWORD	Length;
		DWORD	GURE0;
		DWORD	GURE1;
		DWORD	Reserved;
	} EFS_STREAM_DATA_SEGMENT, *PEFS_STREAM_DATA_SEGMENT;

	typedef struct _EFS_STREAM_DATA_SEGMENT_ENCRYPTION_HEADER {
		LONG64	StartingFile_Offset;
		DWORD	Length;
		DWORD	BytesWithinStreamSize;
		DWORD	BytesWithinVDL;
		USHORT	ReservedForAlignement0;
		BYTE	DataUnitShift;
		BYTE	ChunkShift;
		BYTE	ClusterShift;
		BYTE	ReservedForAlignement1;
		USHORT	NumberOfDataBlocks;
		DWORD	DataBlockSizes[1];
	} EFS_STREAM_DATA_SEGMENT_ENCRYPTION_HEADER, *PEFS_STREAM_DATA_SEGMENT_ENCRYPTION_HEADER;

	typedef struct _EFS_EXTENDED_HEADER {
		DWORD	EXTD_Number;
		DWORD	Length;
		DWORD	Flags;
		DWORD	Reserved;
	} EFS_EXTENDED_HEADER, *PEFS_EXTENDED_HEADER;
	
	typedef struct _EFS_METADATA_1 {
		DWORD	Length;
		DWORD	Reserved1;
		DWORD	EFS_Version;
		DWORD	Reserved2;
		BYTE	EFS_ID[16];
		BYTE	EFS_Hash[16];
		BYTE	Reserved3[16];
		LONG	DDF_Offset;
		LONG	DRF_Offset;
		BYTE	Reserved4[12];
	} EFS_METADATA_1, *PEFS_METADATA_1;

	typedef struct _EFS_KEY_LIST {
		DWORD	Length;
	} EFS_KEY_LIST, *PEFS_KEY_LIST;

	typedef struct _EFS_KEY_LIST_ENTRY {
		DWORD	Length;
		LONG	PKI_Offset;
		DWORD	Enc_FEK_Length;
		LONG	Enc_FEK_Offset;
		DWORD	Flags;
	} EFS_KEY_LIST_ENTRY, *PEFS_KEY_LIST_ENTRY;

	typedef struct _EFS_PUBLIC_KEY_INFORMATION {
		DWORD	Length;
		LONG	OwnerSID_offset;
		DWORD	Type;
		DWORD	Certificate_Length;
		LONG	Certificate_offset;
	} EFS_PUBLIC_KEY_INFORMATION, *PEFS_PUBLIC_KEY_INFORMATION;

	typedef struct _EFS_CERTIFICATE_DATA {
		LONG	CertificateThumbprint;
		DWORD	CertificateThumbprint_Length;
		LONG	ContainerName_Offset;
		LONG	ProviderName_Offset;;
		LONG	DisplayName_Offset;
	} EFS_CERTIFICATE_DATA, *PEFS_CERTIFICATE_DATA;

	typedef struct _EFS_FEK {
		DWORD Key_Lenght;
		DWORD Entropy;
		ALG_ID Algorithm;
		DWORD Reserverd;
		BYTE Key[1];
	} EFSFEK, *PEFS_FEK;

	typedef struct _SIMPLE_BYTE_ARRAY{
		SIZE_T nbElements;
		PBYTE tableau;
	} SIMPLE_BYTE_ARRAY, *PSIMPLE_BYTE_ARRAY;
	
	static DWORD WINAPI ExportToArrayCallback(PBYTE pbData, PVOID pvCallbackContext, DWORD ulLength);
	static DWORD WINAPI ExportToFileCallback(PBYTE pbData, PVOID pvCallbackContext, DWORD ulLength);
	static void printInfos(PENCRYPTION_CERTIFICATE_HASH_LIST hashList);

	static bool fullInfosFromEFS_KEY_LIST(PEFS_METADATA_1 header, LONG KeyList_offset, PEFS_FEK * Fek);
	static void fullInfosFromEFS_CERTIFICATE_DATA(PEFS_PUBLIC_KEY_INFORMATION header, LONG Certificate_offset);

public:
	static vector<KIWI_MIMIKATZ_LOCAL_MODULE_COMMAND> getMimiKatzCommands();
	
	static bool infos(vector<wstring> * arguments);
	static bool full(vector<wstring> * arguments);
	static bool toraw(vector<wstring> * arguments);
	static bool fromraw(vector<wstring> * arguments);
};

