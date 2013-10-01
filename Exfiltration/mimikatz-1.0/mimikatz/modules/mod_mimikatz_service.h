/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : http://creativecommons.org/licenses/by/3.0/fr/
*/
#pragma once
#include "globdefs.h"
#include "mod_system.h"
#include "mod_service.h"
#include <iostream>

class mod_mimikatz_service
{
private:
	typedef bool (* PMOD_SERVICE_FUNC) (wstring * serviceName, wstring * machineName);
	static bool genericFunction(PMOD_SERVICE_FUNC function, vector<wstring> * arguments);
public:
	static vector<KIWI_MIMIKATZ_LOCAL_MODULE_COMMAND> getMimiKatzCommands();
		
	static bool list(vector<wstring> * arguments);
	
	static bool start(vector<wstring> * arguments);
	static bool suspend(vector<wstring> * arguments);
	static bool resume(vector<wstring> * arguments);
	static bool stop(vector<wstring> * arguments);

	static bool query(vector<wstring> * arguments);
	
	static bool add(vector<wstring> * arguments);
	static bool remove(vector<wstring> * arguments);
	static bool control(vector<wstring> * arguments);

	static bool mimikatz(vector<wstring> * arguments);
};
