/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence    : http://creativecommons.org/licenses/by/3.0/fr/
	Ce fichier : http://creativecommons.org/licenses/by/3.0/fr/
*/
#pragma once
#include "../sekurlsa.h"

#define MSV1_0_PRIMARY_KEY "Primary" 
extern DWORD MSV1_0_MspAuthenticationPackageId;

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

void NlpMakeRelativeOrAbsoluteString(PVOID BaseAddress, PLSA_UNICODE_STRING String, bool relative = true);

NTSTATUS NlpAddPrimaryCredential(PLUID LogonId, PMSV1_0_PRIMARY_CREDENTIAL Credential, unsigned short  CredentialSize);  
NTSTATUS NlpGetPrimaryCredential(PLUID LogonId, PMSV1_0_PRIMARY_CREDENTIAL *Credential, unsigned short *CredentialSize);
NTSTATUS NlpDeletePrimaryCredential(PLUID LogonId);
