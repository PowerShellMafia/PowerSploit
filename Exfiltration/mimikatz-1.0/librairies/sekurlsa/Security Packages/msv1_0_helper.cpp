/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence    : http://creativecommons.org/licenses/by/3.0/fr/
	Ce fichier : http://creativecommons.org/licenses/by/3.0/fr/
*/
#include "msv1_0_helper.h"
DWORD MSV1_0_MspAuthenticationPackageId = 0;

void NlpMakeRelativeOrAbsoluteString(PVOID BaseAddress, PLSA_UNICODE_STRING String, bool relative)
{
	if(String->Buffer)
		String->Buffer = reinterpret_cast<wchar_t *>(reinterpret_cast<ULONG_PTR>(String->Buffer) + ((relative ? -1 : 1) * reinterpret_cast<ULONG_PTR>(BaseAddress)));
}

NTSTATUS NlpAddPrimaryCredential(PLUID LogonId, PMSV1_0_PRIMARY_CREDENTIAL Credential, unsigned short CredentialSize)
{
	STRING PrimaryKeyValue, CredentialString;
	mod_text::RtlInitString(&PrimaryKeyValue, MSV1_0_PRIMARY_KEY);

	NlpMakeRelativeOrAbsoluteString(Credential, &Credential->UserName);
	NlpMakeRelativeOrAbsoluteString(Credential, &Credential->LogonDomainName);
	CredentialString.Buffer = reinterpret_cast<char *>(Credential);
	CredentialString.MaximumLength = CredentialString.Length = CredentialSize;
	SeckPkgFunctionTable->LsaProtectMemory(CredentialString.Buffer, CredentialString.Length);
	return SeckPkgFunctionTable->AddCredential(LogonId, MSV1_0_MspAuthenticationPackageId, &PrimaryKeyValue, &CredentialString );
}

NTSTATUS NlpGetPrimaryCredential(PLUID LogonId, PMSV1_0_PRIMARY_CREDENTIAL *Credential, unsigned short *CredentialSize)
{
	ULONG QueryContext = 0, PrimaryKeyLength;
	STRING PrimaryKeyValue, CredentialString;
	mod_text::RtlInitString(&PrimaryKeyValue, MSV1_0_PRIMARY_KEY);
			
	NTSTATUS retour = SeckPkgFunctionTable->GetCredentials(LogonId, MSV1_0_MspAuthenticationPackageId, &QueryContext, FALSE, &PrimaryKeyValue, &PrimaryKeyLength, &CredentialString);
	if(NT_SUCCESS(retour))
	{
		SeckPkgFunctionTable->LsaUnprotectMemory(CredentialString.Buffer, CredentialString.Length);
		*Credential = (PMSV1_0_PRIMARY_CREDENTIAL) CredentialString.Buffer;
		NlpMakeRelativeOrAbsoluteString(*Credential, &((*Credential)->UserName), false);
		NlpMakeRelativeOrAbsoluteString(*Credential, &((*Credential)->LogonDomainName), false);
		if (CredentialSize)
			*CredentialSize = CredentialString.Length;
	}
	return retour;
}

NTSTATUS NlpDeletePrimaryCredential(PLUID LogonId)
{
	STRING PrimaryKeyValue;
	mod_text::RtlInitString(&PrimaryKeyValue, MSV1_0_PRIMARY_KEY);
	return SeckPkgFunctionTable->DeleteCredential(LogonId, MSV1_0_MspAuthenticationPackageId, &PrimaryKeyValue);
}