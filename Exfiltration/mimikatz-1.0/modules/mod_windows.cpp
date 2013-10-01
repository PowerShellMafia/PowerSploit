/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : http://creativecommons.org/licenses/by/3.0/fr/
*/
#include "mod_windows.h"

BOOL WINAPI mod_windows::enumHWNDCallback(HWND hwnd,  pair<DWORD, vector<mod_windows::KIWI_HWND_ENTRY> *>  * mesHWNDS)
{
	DWORD processId = 0;
	if(DWORD threadId = GetWindowThreadProcessId(hwnd, &processId))
	{
		if((mesHWNDS->first == 0) || (processId == mesHWNDS->first))
		{
			KIWI_HWND_ENTRY monEntree = {hwnd, processId, threadId};
			mesHWNDS->second->push_back(monEntree);
		}
	}
	return TRUE;
}


bool mod_windows::getHWNDsFromProcessId(vector<mod_windows::KIWI_HWND_ENTRY> * mesHWNDS, DWORD processId)
{
	return (EnumWindows(reinterpret_cast<WNDENUMPROC>(enumHWNDCallback), reinterpret_cast<LPARAM>(&make_pair<DWORD, vector<mod_windows::KIWI_HWND_ENTRY> *>(processId, mesHWNDS))) != FALSE);
}