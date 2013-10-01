/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : http://creativecommons.org/licenses/by/3.0/fr/
*/
#include "mod_ts.h"

bool mod_ts::openServer(HANDLE * phServer, wstring * server, bool testIt)
{
	bool reussite = false;

	if(reussite = !server)
	{
		*phServer = WTS_CURRENT_SERVER_HANDLE;
	}
	else
	{
		wchar_t * serverName = _wcsdup(server->c_str());
		*phServer = WTSOpenServer(serverName);
		delete[] serverName;
		reussite = *phServer != NULL;
	}
	return reussite;
}

bool mod_ts::closeServer(HANDLE hServer)
{
	if(hServer != WTS_CURRENT_SERVER_HANDLE)
		WTSCloseServer(hServer);

	return true;
}

bool mod_ts::getSessions(vector<KIWI_WTS_SESSION_INFO> * mesSessions, wstring * server)
{
	bool reussite = false;

	PWTS_SESSION_INFO tabSessions;
	DWORD nbSessions = 0;
	HANDLE hServer = NULL;

	if(openServer(&hServer, server))
	{
		if(reussite = WTSEnumerateSessions(hServer, 0, 1, &tabSessions, &nbSessions) != 0)
		{
			for(DWORD i = 0; i < nbSessions; i++)
			{
				KIWI_WTS_SESSION_INFO a = {tabSessions[i].SessionId, tabSessions[i].State, tabSessions[i].pWinStationName};
				mesSessions->push_back(a);
			}
			WTSFreeMemory(tabSessions);
		}
		closeServer(hServer);
	}
	
	return reussite;
}

bool mod_ts::getProcesses(vector<KIWI_WTS_PROCESS_INFO> * mesProcesses, wstring * server)
{
	bool reussite = false;

	PWTS_PROCESS_INFO tabProcess;
	DWORD nbProcess = 0;
	HANDLE hServer = NULL;

	if(openServer(&hServer, server))
	{
		if(reussite = WTSEnumerateProcesses(hServer, 0, 1, &tabProcess, &nbProcess) != 0)
		{
			for(DWORD i = 0; i < nbProcess; i++)
			{
				KIWI_WTS_PROCESS_INFO a = {
					tabProcess[i].SessionId,
					tabProcess[i].ProcessId,
					tabProcess[i].pProcessName
				};

				wstring user;
				wstring domain;
				if(mod_secacl::sidToName(tabProcess[i].pUserSid, &user, &domain, server))
				{
					a.userSid.assign(domain);
					a.userSid.push_back(L'\\');
					a.userSid.append(user);
				}
				else if(!mod_secacl::sidToStrSid(tabProcess[i].pUserSid, &a.userSid))
				{
					if(tabProcess[i].pUserSid)
					{
						a.userSid.assign(L"erreur SID ; ");
						a.userSid.append(mod_system::getWinError());
					}
					else
						a.userSid.assign(L"n.a.");
				}

				mesProcesses->push_back(a);
			}
			WTSFreeMemory(tabProcess);
		}
		closeServer(hServer);
	}
	
	return reussite;
}