/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : http://creativecommons.org/licenses/by/3.0/fr/
*/
#pragma once
#include "globdefs.h"
#include "mod_hash.h"
#include <iostream>

class mod_mimikatz_hash
{
public:
	static vector<KIWI_MIMIKATZ_LOCAL_MODULE_COMMAND> getMimiKatzCommands();
	
	static bool lm(vector<wstring> * arguments);
	static bool ntlm(vector<wstring> * arguments);
};
