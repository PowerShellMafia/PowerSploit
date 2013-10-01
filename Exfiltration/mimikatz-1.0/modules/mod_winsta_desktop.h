/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : http://creativecommons.org/licenses/by/3.0/fr/
*/
#pragma once
#include "globdefs.h"

class mod_winsta_desktop
{
private:
	static BOOL CALLBACK EnumWindowStationProc(_In_ LPTSTR lpszWindowStation, _In_ LPARAM lParam);
	static BOOL CALLBACK EnumDesktopProc(_In_ LPTSTR lpszDesktop, _In_ LPARAM lParam);

public:
	static bool getWinstas(vector<wstring> * mesWinstas);
	static bool getDesktops(vector<wstring> * mesDesktop); // !
};
