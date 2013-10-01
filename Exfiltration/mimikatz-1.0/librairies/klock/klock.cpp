/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : http://creativecommons.org/licenses/by/3.0/fr/
*/
#include "klock.h"

__kextdll bool __cdecl getDescription(wstring * maDescription)
{
	maDescription->assign(L"kLock : librairie de manipulation des bureaux");
	return true;
}

bool getNameOfDesktop(HDESK desktop, wstring &bureau)
{
	bool resultat = false;
	
	wchar_t * monBuffer;
	DWORD tailleRequise = 0;
	
	if(!GetUserObjectInformation(desktop, UOI_NAME, NULL, 0, &tailleRequise) && (tailleRequise > 0))
	{
		monBuffer = new wchar_t[tailleRequise];
		if(resultat = (GetUserObjectInformation(desktop, UOI_NAME, monBuffer, tailleRequise, &tailleRequise) != 0))
		{
			bureau.assign(monBuffer);
		}
		delete[] monBuffer;
	}
	return resultat;
}

__kextdll bool __cdecl echange(mod_pipe * monPipe, vector<wstring> * mesArguments)
{
	wstringstream maReponse;
	wstring source, cible, monBureau;
	bool modeFullAuto = true;

	if(mesArguments->size() == 2)
	{
		modeFullAuto = false;
		source = mesArguments->front();
		cible = mesArguments->back();
	}
	
	if (HDESK hOriginalDesktop = OpenInputDesktop(0, FALSE, GENERIC_READ | DESKTOP_SWITCHDESKTOP))
	{
		if(getNameOfDesktop(hOriginalDesktop, monBureau))
		{
			maReponse << L"Bureau courant : " << monBureau << endl;
			
			if((_wcsicmp(monBureau.c_str(), source.c_str()) == 0) || modeFullAuto)
			{
				if(modeFullAuto)
					cible = _wcsicmp(monBureau.c_str(), L"Default") == 0 ? L"WinLogon" : L"Default";

				maReponse << L"Bureau cible   : " << cible << endl;

				if (HDESK hNewDesktop = OpenDesktop(cible.c_str(), 0, FALSE, DESKTOP_SWITCHDESKTOP))
				{
					if (SwitchDesktop(hNewDesktop))
						maReponse << L"Switch du bureau réussi !";
					else
						maReponse << L"Erreur : impossible de basculer le bureau ; SwitchDesktop : " << mod_system::getWinError();
					maReponse << endl;
					CloseDesktop(hNewDesktop);
				}
				else maReponse << "Erreur : impossible d\'ouvrir le bureau cible (" << cible << L") ; OpenDesktop : " << mod_system::getWinError();
			}
			else if(!modeFullAuto)
				maReponse << L"Erreur : le bureau courant (" << monBureau << L") ne correspond pas au bureau source indiqué (" << source << L")" << endl;
		}
		else maReponse << L"Erreur : impossible d\'obtenir le nom du bureau courant ; getNameOfDesktop : " << mod_system::getWinError() << endl;

		CloseDesktop(hOriginalDesktop);
	}
	else maReponse << L"Erreur : impossible d\'ouvrir le bureau courant ; OpenInputDesktop : " << mod_system::getWinError() << endl;

	return sendTo(monPipe, maReponse.str());
}

__kextdll bool __cdecl getDesktop(mod_pipe * monPipe, vector<wstring> * mesArguments)
{
	wstringstream maReponse;
	wstring monBureau;

	if (HDESK hDesktop = OpenInputDesktop(0, FALSE, GENERIC_READ))
	{
		if(getNameOfDesktop(hDesktop, monBureau))
			maReponse << L"Bureau courant : " << monBureau << endl;
		else
			maReponse << L"Erreur : impossible d\'obtenir le nom du bureau courant ; getNameOfDesktop : " << mod_system::getWinError() << endl;

		CloseDesktop(hDesktop);
	}
	return sendTo(monPipe, maReponse.str());
}