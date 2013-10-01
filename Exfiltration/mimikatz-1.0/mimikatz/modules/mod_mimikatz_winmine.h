/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : http://creativecommons.org/licenses/by/3.0/fr/
*/
#pragma once
#include "globdefs.h"
#include "mod_process.h"
#include "mod_memory.h"
#include "mod_windows.h"
#include <iostream>

class mod_mimikatz_winmine
{
private:
	typedef struct structMonDemineur{
		DWORD32 nbMines;
		DWORD32 longueur;
		DWORD32 hauteur;
		DWORD32 alignOffset;
		BYTE tabMines[26][32];
	} structMonDemineur;
	
	typedef struct structHandleAndAddr{
		HANDLE hWinmine;
		DWORD pidWinmine;
		structMonDemineur * addrMonDemineur;
		PTHREAD_START_ROUTINE addrPause;
		PTHREAD_START_ROUTINE addrResume;
		PTHREAD_START_ROUTINE addrStart;
	} structHandleAndAddr;

	static bool giveHandleAndAddr(structHandleAndAddr * monHandleAndAddr);
	static bool startThreadAt(unsigned long structOffset);
	static bool infosOrCheat(vector<wstring> * arguments, bool cheat = false);

public:
	static vector<KIWI_MIMIKATZ_LOCAL_MODULE_COMMAND> getMimiKatzCommands();

	static bool infos(vector<wstring> * arguments);
	static bool start(vector<wstring> * arguments);
	static bool pause(vector<wstring> * arguments);
	static bool reprise(vector<wstring> * arguments);
	static bool cheat(vector<wstring> * arguments);
};
