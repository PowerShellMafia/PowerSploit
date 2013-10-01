/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : http://creativecommons.org/licenses/by/3.0/fr/
*/
#pragma once
#include "globdefs.h"

class mod_windows
{
public:
	typedef struct _KIWI_HWND_ENTRY
	{
		HWND	monHandle;
		DWORD	pid;
		DWORD	threadId;
	} KIWI_HWND_ENTRY, *PKIWI_HWND_ENTRY;

	static bool getHWNDsFromProcessId(vector<mod_windows::KIWI_HWND_ENTRY> * mesHWNDS, DWORD processId = 0);
private:
	static BOOL WINAPI enumHWNDCallback(HWND hwnd,  pair<DWORD, vector<mod_windows::KIWI_HWND_ENTRY> *>  * mesHWNDS);
};
