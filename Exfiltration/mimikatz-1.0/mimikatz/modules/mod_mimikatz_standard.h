/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : http://creativecommons.org/licenses/by/3.0/fr/
*/
#pragma once
#include "globdefs.h"
#include <iostream>
#include <sstream>

class mod_mimikatz_standard
{
public:
	static vector<KIWI_MIMIKATZ_LOCAL_MODULE_COMMAND> getMimiKatzCommands();

	static bool clearScreen(vector<wstring> * arguments);
	static bool exit(vector<wstring> * arguments);
	static bool cite(vector<wstring> * arguments);
	static bool reponse(vector<wstring> * arguments);
	static bool version(vector<wstring> * arguments);
	static bool sleep(vector<wstring> * arguments);
	static bool test(vector<wstring> * arguments);
};
