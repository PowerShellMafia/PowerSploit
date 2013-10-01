/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : http://creativecommons.org/licenses/by/3.0/fr/
*/
#pragma once
#include "globdefs.h"
#include "mod_secacl.h"
#include "mod_system.h"
#include <wtsapi32.h>

class mod_ts
{
private:
	static bool openServer(HANDLE * phServer, wstring * server = NULL, bool testIt = true);
	static bool closeServer(HANDLE hServer);

public:
	typedef struct _KIWI_WTS_SESSION_INFO {
		DWORD id;
		DWORD state;
		wstring sessionName;
	} KIWI_WTS_SESSION_INFO, * PKIWI_WTS_SESSION_INFO;

	typedef struct _KIWI_WTS_PROCESS_INFO {
		DWORD sessionId;
		DWORD pid;
		wstring processName;
		wstring userSid;
	} KIWI_WTS_PROCESS_INFO, * PKIWI_WTS_PROCESS_INFO;	

	static bool getSessions(vector<KIWI_WTS_SESSION_INFO> * mesSessions, wstring * server = NULL);
	static bool getProcesses(vector<KIWI_WTS_PROCESS_INFO> * mesProcesses, wstring * server = NULL);
};

