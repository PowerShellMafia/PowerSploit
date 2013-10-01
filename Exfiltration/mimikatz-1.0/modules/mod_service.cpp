/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : http://creativecommons.org/licenses/by/3.0/fr/
*/
#include "mod_service.h"

bool mod_service::getList(vector<KIWI_SERVICE_STATUS_PROCESS> * monVectorService, wstring * machineName) // machine non implémenté
{
	bool reussite = false;
	DWORD error = ERROR_SUCCESS;

	if(SC_HANDLE monManager = OpenSCManager(machineName ? machineName->c_str() : NULL, SERVICES_ACTIVE_DATABASE, SC_MANAGER_CONNECT | SC_MANAGER_ENUMERATE_SERVICE))
	{
		DWORD tailleRequise = 0;
		DWORD nbServices = 0;
		DWORD resumeHandle = 0;
		
		if(!(EnumServicesStatusEx(monManager, SC_ENUM_PROCESS_INFO, SERVICE_DRIVER | SERVICE_WIN32, SERVICE_STATE_ALL, NULL, 0, &tailleRequise, &nbServices, &resumeHandle, NULL) != 0) && GetLastError() == ERROR_MORE_DATA)
		{
			BYTE * servicesBuff = new BYTE[tailleRequise];
			ENUM_SERVICE_STATUS_PROCESS * mesServ = reinterpret_cast<ENUM_SERVICE_STATUS_PROCESS *>(servicesBuff);
			if(reussite = EnumServicesStatusEx(monManager, SC_ENUM_PROCESS_INFO, SERVICE_DRIVER | SERVICE_WIN32, SERVICE_STATE_ALL, servicesBuff, tailleRequise, &tailleRequise, &nbServices, &resumeHandle, NULL) != 0)
			{
				for(DWORD i = 0; i < nbServices; i++)
				{
					KIWI_SERVICE_STATUS_PROCESS monService = {mesServ[i].lpServiceName, mesServ[i].lpDisplayName, mesServ[i].ServiceStatusProcess};
					monVectorService->push_back(monService);
				}
			}
			delete[] servicesBuff;
			error = GetLastError();
		}

		CloseServiceHandle(monManager);
		SetLastError(error);
	}
	return reussite;
}


bool mod_service::getUniqueForName(KIWI_SERVICE_STATUS_PROCESS * monService, wstring * serviceName, wstring * machineName) // machine non implémenté
{
	bool reussite = false;

	vector<KIWI_SERVICE_STATUS_PROCESS> * vectorServices = new vector<KIWI_SERVICE_STATUS_PROCESS>();
	if(getList(vectorServices, machineName))
	{
		for(vector<KIWI_SERVICE_STATUS_PROCESS>::iterator monSvc = vectorServices->begin(); monSvc != vectorServices->end(); monSvc++)
		{
			if(reussite = (_wcsicmp(monSvc->serviceName.c_str(), serviceName->c_str()) == 0))
			{
				*monService = *monSvc;
				break;
			}
		}
	}
	delete vectorServices;

	return reussite;	
}

bool mod_service::start(wstring * serviceName, wstring * machineName)
{
	bool reussite = false;
	DWORD error = ERROR_SUCCESS;
	if(SC_HANDLE monManager = OpenSCManager(machineName ? machineName->c_str() : NULL, SERVICES_ACTIVE_DATABASE, SC_MANAGER_CONNECT))
	{
		if(SC_HANDLE monService = OpenService(monManager, serviceName->c_str(), SERVICE_START))
		{
			if(!(reussite = StartService(monService, 0, NULL) != 0))
				error = GetLastError();
			CloseServiceHandle(monService);
		}
		else
			error = GetLastError();
		CloseServiceHandle(monManager);
		SetLastError(error);
	}
	
	return reussite;
}

bool mod_service::remove(wstring * serviceName, wstring * machineName)
{
	bool reussite = false;
	DWORD error = ERROR_SUCCESS;
	if(SC_HANDLE monManager = OpenSCManager(machineName ? machineName->c_str() : NULL, SERVICES_ACTIVE_DATABASE, SC_MANAGER_CONNECT))
	{
		if(SC_HANDLE monService = OpenService(monManager, serviceName->c_str(), DELETE))
		{
			if(!(reussite = DeleteService(monService) != 0))
				error = GetLastError();
			CloseServiceHandle(monService);
		}
		else
			error = GetLastError();
		CloseServiceHandle(monManager);
		SetLastError(error);
	}
	return reussite;
}

bool mod_service::genericControl(wstring * serviceName, DWORD dwDesiredAccess, DWORD dwControl, LPSERVICE_STATUS ptrServiceStatus, wstring * machineName)
{
	bool reussite = false;
	DWORD error = ERROR_SUCCESS;
	if(SC_HANDLE monManager = OpenSCManager(machineName ? machineName->c_str() : NULL, SERVICES_ACTIVE_DATABASE, SC_MANAGER_CONNECT))
	{
		if(SC_HANDLE monService = OpenService(monManager, serviceName->c_str(), dwDesiredAccess))
		{
			if(!(reussite = ControlService(monService, dwControl, ptrServiceStatus) != 0))
				error = GetLastError();
			CloseServiceHandle(monService);
		}
		else
			error = GetLastError();
		CloseServiceHandle(monManager);
		SetLastError(error);
	}
	return reussite;
}


bool mod_service::stop(wstring * serviceName, wstring * machineName)
{
	SERVICE_STATUS serviceStatus;
	return(genericControl(serviceName, SERVICE_STOP, SERVICE_CONTROL_STOP, &serviceStatus, machineName));
}

bool mod_service::suspend(wstring * serviceName, wstring * machineName)
{
	SERVICE_STATUS serviceStatus;
	return(genericControl(serviceName, SERVICE_PAUSE_CONTINUE, SERVICE_CONTROL_PAUSE, &serviceStatus, machineName));
}

bool mod_service::resume(wstring * serviceName, wstring * machineName)
{
	SERVICE_STATUS serviceStatus;
	return(genericControl(serviceName, SERVICE_PAUSE_CONTINUE, SERVICE_CONTROL_CONTINUE, &serviceStatus, machineName));
}

