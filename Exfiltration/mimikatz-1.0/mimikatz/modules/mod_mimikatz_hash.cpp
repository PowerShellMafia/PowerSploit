/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : http://creativecommons.org/licenses/by/3.0/fr/
*/
#include "mod_mimikatz_hash.h"
#include "..\global.h"

vector<KIWI_MIMIKATZ_LOCAL_MODULE_COMMAND> mod_mimikatz_hash::getMimiKatzCommands()
{
	vector<KIWI_MIMIKATZ_LOCAL_MODULE_COMMAND> monVector;
	monVector.push_back(KIWI_MIMIKATZ_LOCAL_MODULE_COMMAND(lm,		L"lm",		L"Hash LanManager (LM) d\'une chaîne de caractères"));
	monVector.push_back(KIWI_MIMIKATZ_LOCAL_MODULE_COMMAND(ntlm,	L"ntlm",	L"Hash NT LanManger (NTLM) d\'une chaîne de caractères"));
	return monVector;
}

bool mod_mimikatz_hash::lm(vector<wstring> * arguments)
{
	wstring chaine, hash;

	if(!arguments->empty())
		chaine = arguments->front();

	if(mod_hash::lm(&chaine, &hash))
		(*outputStream) << L"LM(\'" << chaine << L"\') = " << hash << endl;
	else
		(*outputStream) << L"Erreur de calcul du hash LM" << endl;
	return true;
}

bool mod_mimikatz_hash::ntlm(vector<wstring> * arguments)
{
	wstring chaine, hash;

	if(!arguments->empty())
		chaine = arguments->front();

	if(mod_hash::ntlm(&chaine, &hash))
		(*outputStream) << L"NTLM(\'" << chaine << L"\') = " << hash << endl;
	else
		(*outputStream) << L"Erreur de calcul du hash NTLM" << endl;
	return true;
}
