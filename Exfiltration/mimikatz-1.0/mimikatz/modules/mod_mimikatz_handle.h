/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : http://creativecommons.org/licenses/by/3.0/fr/
*/
#pragma once
#include "globdefs.h"
#include "mod_system.h"
#include "mod_process.h"
#include "mod_secacl.h"
#include <iostream>
#include <algorithm>

class mod_mimikatz_handle
{
public:
	static vector<KIWI_MIMIKATZ_LOCAL_MODULE_COMMAND> getMimiKatzCommands();

	static bool list(vector<wstring> * arguments);
	static bool processStop(vector<wstring> * arguments);
	static bool tokenImpersonate(vector<wstring> * arguments);
	static bool nullAcl(vector<wstring> * arguments);
};
