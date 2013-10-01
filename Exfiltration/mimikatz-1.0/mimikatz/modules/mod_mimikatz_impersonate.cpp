/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : http://creativecommons.org/licenses/by/3.0/fr/
*/
#include "mod_mimikatz_impersonate.h"
#include "..\global.h"

vector<KIWI_MIMIKATZ_LOCAL_MODULE_COMMAND> mod_mimikatz_impersonate::getMimiKatzCommands()
{
	vector<KIWI_MIMIKATZ_LOCAL_MODULE_COMMAND> monVector;
	monVector.push_back(KIWI_MIMIKATZ_LOCAL_MODULE_COMMAND(revert,	L"revert",	L"RevertToSelf"));
	return monVector;
}
bool mod_mimikatz_impersonate::revert(vector<wstring> * arguments)
{
	(*outputStream) << L"RevertToSelf : ";
	if(RevertToSelf())
		(*outputStream) << L"ok";
	else
		(*outputStream) << L"ko ; " << mod_system::getWinError();
	(*outputStream) << endl;

	return true;
}
