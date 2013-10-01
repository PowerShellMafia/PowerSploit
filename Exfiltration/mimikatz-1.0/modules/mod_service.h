/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : http://creativecommons.org/licenses/by/3.0/fr/
*/
#pragma once
#include "globdefs.h"
#include "mod_secacl.h"

class mod_service
{
private:
	static bool genericControl(wstring * serviceName, DWORD dwDesiredAccess, DWORD dwControl, LPSERVICE_STATUS ptrServiceStatus, wstring * machineName = NULL);

public:
	typedef struct _KIWI_SERVICE_STATUS_PROCESS
	{
		wstring serviceName;
		wstring serviceDisplayName;
		SERVICE_STATUS_PROCESS ServiceStatusProcess;
	} KIWI_SERVICE_STATUS_PROCESS, *PKIWI_SERVICE_STATUS_PROCESS;
	
	static bool getList(vector<KIWI_SERVICE_STATUS_PROCESS> * monVectorService, wstring * machineName = NULL);
	static bool getUniqueForName(KIWI_SERVICE_STATUS_PROCESS * monService, wstring * serviceName, wstring * machineName = NULL);

	static bool start(wstring * serviceName, wstring * machineName = NULL);
	static bool suspend(wstring * serviceName, wstring * machineName = NULL);
	static bool resume(wstring * serviceName, wstring * machineName = NULL);
	static bool stop(wstring * serviceName, wstring * machineName = NULL);

	static bool query(wstring * serviceName, wstring * machineName = NULL); // a voir ?
	
	static bool add(wstring * binPath, vector<wstring> * arguments); // bla bla
	static bool remove(wstring * serviceName, wstring * machineName = NULL);
	static bool control(vector<wstring> * arguments);

};

