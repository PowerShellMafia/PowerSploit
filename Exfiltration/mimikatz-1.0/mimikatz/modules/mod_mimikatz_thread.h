/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : http://creativecommons.org/licenses/by/3.0/fr/
*/
#pragma once
#include "globdefs.h"
#include "mod_system.h"
#include "mod_thread.h"
#include <iostream>
#include <iomanip>

class mod_mimikatz_thread
{
private:
public:
	static vector<KIWI_MIMIKATZ_LOCAL_MODULE_COMMAND> getMimiKatzCommands();
		
	static bool list(vector<wstring> * arguments);
	//static bool start(vector<wstring> * arguments);
	static bool suspend(vector<wstring> * arguments);
	static bool resume(vector<wstring> * arguments);
	static bool stop(vector<wstring> * arguments);
	//static bool query(vector<wstring> * arguments);

	static bool quit(vector<wstring> * arguments);
};
