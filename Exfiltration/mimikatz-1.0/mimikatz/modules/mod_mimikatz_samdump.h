/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : http://creativecommons.org/licenses/by/3.0/fr/
*/
#pragma once
#include "globdefs.h"
#include "mod_hive.h"
#include "mod_hash.h"
#include "mod_system.h"
#include <iostream>
#include <sstream>

class mod_mimikatz_samdump
{
private:
	static bool getNControlSetFromHive(mod_hive::hive * theHive, string * rootKey, DWORD * nControlSet);
	static bool getComputerNameFromHive(mod_hive::hive * theHive, string * fullControlSet, wstring * computerName);
	
	static bool getBootKeyFromHive(mod_hive::hive * theHive, string * fullControlSet, unsigned char bootkey[0x10]);
	static bool getInfosFromHive(wstring systemHive, unsigned char bootkey[0x10]);
	static bool getUsersAndHashesFromHive(wstring samHive, unsigned char bootkey[0x10]);

	static bool getBootKeyFromReg(BYTE bootkey[0x10]);
	static bool getInfosFromReg(BYTE bootkey[0x10]);
	static bool getUsersAndHashesFromReg(BYTE bootkey[0x10]);

	static void infosFromUserAndKey(mod_hash::USER_F * userF, mod_hash::USER_V * userV, BYTE hBootKey[0x20]);
public:
	static vector<KIWI_MIMIKATZ_LOCAL_MODULE_COMMAND> getMimiKatzCommands();

	static bool bootkey(vector<wstring> * arguments);
	static bool full(vector<wstring> * arguments);
};
