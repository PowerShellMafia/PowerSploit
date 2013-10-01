/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : http://creativecommons.org/licenses/by/3.0/fr/
*/
#pragma once
#include "globdefs.h"
#include "mod_ts.h"
#include "mod_process.h"
#include "mod_memory.h"
#include "mod_patch.h"
#include <iostream>

class mod_mimikatz_terminalserver
{
public:
	static vector<KIWI_MIMIKATZ_LOCAL_MODULE_COMMAND> getMimiKatzCommands();

	static bool sessions(vector<wstring> * arguments);
	static bool processes(vector<wstring> * arguments);
	static bool viewshadow(vector<wstring> * arguments);
	static bool modifyshadow(vector<wstring> * arguments);
	static bool multirdp(vector<wstring> * arguments);
	
private:
	static bool listAndOrModifySession(DWORD * id = NULL, DWORD * newState = NULL);
	static wstring shadowToType(DWORD shadow);
	static wstring stateToType(DWORD state);

	enum KIWI_SHADOW_TYPE {
		SHADOW_DISABLE = 0,
		SHADOW_INTERACT = 1,
		SHADOW_INTERACT_NOASK = 2,
		SHADOW_VIEW = 3,
		SHADOW_VIEW_NOASK = 4
	};

	typedef struct _KIWI_TS_SESSION {
		PBYTE next;
		PBYTE prev;
		PBYTE unk1;
		PBYTE refLock;
		PBYTE unk2;
		BYTE  unk3[8];
		DWORD id;
		wchar_t name[32+1];
		BYTE unk4[7434];
		wchar_t sname[32+1];
		wchar_t type[32+1];
		BYTE unk5[1684];
		DWORD shadow;
	} KIWI_TS_SESSION, * PKIWI_TS_SESSION;

};

