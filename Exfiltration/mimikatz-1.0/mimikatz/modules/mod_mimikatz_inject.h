/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : http://creativecommons.org/licenses/by/3.0/fr/
*/
#pragma once
#include "globdefs.h"
#include "mod_inject.h"
#include "mod_system.h"
#include "mod_process.h"
#include "mod_service.h"
#include "mod_pipe.h"
#include <iostream>

class mod_mimikatz_inject
{
private:
	static bool injectInPid(DWORD & pid, wstring & libPath, bool isComm = true);
	static void startComm();

public:
	static mod_pipe * monCommunicator;
	static bool closeThisCommunicator();
	
	static vector<KIWI_MIMIKATZ_LOCAL_MODULE_COMMAND> getMimiKatzCommands();

	static bool pid(vector<wstring> * arguments);
	static bool process(vector<wstring> * arguments);
	static bool service(vector<wstring> * arguments);

	static bool injectlegacy(vector<wstring> * arguments);
	
};
