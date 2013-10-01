/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : http://creativecommons.org/licenses/by/3.0/fr/
*/
#include "mod_winsta_desktop.h"

BOOL CALLBACK mod_winsta_desktop::EnumWindowStationProc(_In_ LPTSTR lpszWindowStation, _In_ LPARAM lParam)
{
	reinterpret_cast<vector<wstring> *>(lParam)->push_back(reinterpret_cast<const wchar_t *>(lpszWindowStation));
	return TRUE;
}

BOOL CALLBACK mod_winsta_desktop::EnumDesktopProc(_In_ LPTSTR lpszDesktop, _In_ LPARAM lParam)
{
	reinterpret_cast<vector<wstring> *>(lParam)->push_back(reinterpret_cast<const wchar_t *>(lpszDesktop));
	return TRUE;
}


bool mod_winsta_desktop::getWinstas(vector<wstring> * mesWinstas)
{
	return (EnumWindowStations(EnumWindowStationProc, reinterpret_cast<LPARAM>(mesWinstas)) != 0);
}

bool mod_winsta_desktop::getDesktops(vector<wstring> * mesDesktop)
{
	return (EnumDesktops(NULL, EnumDesktopProc, reinterpret_cast<LPARAM>(mesDesktop)) != 0);
}
