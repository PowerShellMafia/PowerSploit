/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : http://creativecommons.org/licenses/by/3.0/fr/
*/
#pragma once
#include "globdefs.h"
#include "mod_process.h"
#include "mod_patch.h"
#include "mod_secacl.h"
#include "mod_text.h"
#include "mod_crypto.h"
#include <iostream>
#include <wincred.h>
#include "..\global.h"

class mod_mimikatz_divers
{
public:
	static vector<KIWI_MIMIKATZ_LOCAL_MODULE_COMMAND> getMimiKatzCommands();

	static bool cancelator(vector<wstring> * arguments);
	static bool noroutemon(vector<wstring> * arguments);
	static bool eventdrop(vector<wstring> * arguments);
	static bool secrets(vector<wstring> * arguments);
	static bool nodetour(vector<wstring> * arguments);
	static bool pitme(vector<wstring> * arguments);
};


