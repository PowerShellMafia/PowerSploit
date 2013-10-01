/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : http://creativecommons.org/licenses/by/3.0/fr/
*/
#pragma once
#include "globdefs.h"
#include "mod_system.h"
#include "mod_privilege.h"
#include <iostream>

class mod_mimikatz_privilege
{
private:
	static bool multiplePrivs(vector<wstring> * privs, DWORD type);
	static bool simplePriv(wstring priv, vector<wstring> * arguments);
public:
	static vector<KIWI_MIMIKATZ_LOCAL_MODULE_COMMAND> getMimiKatzCommands();
		
	static bool list(vector<wstring> * arguments);
	static bool enable(vector<wstring> * arguments);
	static bool remove(vector<wstring> * arguments);
	static bool disable(vector<wstring> * arguments);

	static bool debug(vector<wstring> * arguments);
	static bool security(vector<wstring> * arguments);
	static bool tcb(vector<wstring> * arguments);
	static bool impersonate(vector<wstring> * arguments);
	static bool assign(vector<wstring> * arguments);
	static bool shutdown(vector<wstring> * arguments);
	static bool takeowner(vector<wstring> * arguments);

};
