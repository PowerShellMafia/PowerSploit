/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : http://creativecommons.org/licenses/by/3.0/fr/
*/
#include "mod_mimikatz_service.h"
#include "..\global.h"

vector<KIWI_MIMIKATZ_LOCAL_MODULE_COMMAND> mod_mimikatz_service::getMimiKatzCommands()
{
	vector<KIWI_MIMIKATZ_LOCAL_MODULE_COMMAND> monVector;
	monVector.push_back(KIWI_MIMIKATZ_LOCAL_MODULE_COMMAND(list,		L"list",		L"Liste les services et pilotes"));
	monVector.push_back(KIWI_MIMIKATZ_LOCAL_MODULE_COMMAND(start,		L"start",		L"Démarre un service ou pilote"));
	monVector.push_back(KIWI_MIMIKATZ_LOCAL_MODULE_COMMAND(stop,		L"stop",		L"Arrête un service ou pilote"));
	monVector.push_back(KIWI_MIMIKATZ_LOCAL_MODULE_COMMAND(remove,		L"remove",		L"Supprime un service ou pilote"));
	monVector.push_back(KIWI_MIMIKATZ_LOCAL_MODULE_COMMAND(mimikatz,	L"mimikatz",	L"Installe et/ou démarre le pilote mimikatz"));
	return monVector;
}

bool mod_mimikatz_service::start(vector<wstring> * arguments)
{
	(*outputStream) << L"Démarrage de \'";
	return genericFunction(mod_service::start, arguments);
}

bool mod_mimikatz_service::stop(vector<wstring> * arguments)
{
	(*outputStream) << L"Arrêt de \'";
	return genericFunction(mod_service::stop, arguments);
}

bool mod_mimikatz_service::remove(vector<wstring> * arguments)
{
	(*outputStream) << L"Suppression de \'";
	return genericFunction(mod_service::remove, arguments);
}

bool mod_mimikatz_service::genericFunction(PMOD_SERVICE_FUNC function, vector<wstring> * arguments)
{
	if(!arguments->empty())
	{
		(*outputStream) << arguments->front() << L"\' : ";
		if(function(&arguments->front(), NULL))
			(*outputStream) << L"OK";
		else
			(*outputStream) << L"KO ; " << mod_system::getWinError();
		(*outputStream) << endl;
	}
	else (*outputStream) << L"(null)\' - KO ; Nom de service manquant" << endl;

	return true;
}


bool mod_mimikatz_service::list(vector<wstring> * arguments)
{
	bool services_fs_drivers = true;
	bool services = false;
	bool fs = false;
	bool drivers = false;

	bool allstate = true;
	bool running = false;
	bool stopped = false;
	
	vector<mod_service::KIWI_SERVICE_STATUS_PROCESS> * vectorServices = new vector<mod_service::KIWI_SERVICE_STATUS_PROCESS>();
	if(mod_service::getList(vectorServices, (arguments->empty() ? NULL : &arguments->front())))
	{
		for(vector<mod_service::KIWI_SERVICE_STATUS_PROCESS>::iterator monService = vectorServices->begin(); monService != vectorServices->end(); monService++)
		{
			if(
				(
					(services && (monService->ServiceStatusProcess.dwServiceType & (SERVICE_WIN32_OWN_PROCESS | SERVICE_WIN32_SHARE_PROCESS))) ||
					(fs && (monService->ServiceStatusProcess.dwServiceType & SERVICE_FILE_SYSTEM_DRIVER)) ||
					(drivers && (monService->ServiceStatusProcess.dwServiceType & SERVICE_KERNEL_DRIVER)) ||
					(services_fs_drivers)
				)
				&&
				(
					(running && monService->ServiceStatusProcess.dwCurrentState == SERVICE_RUNNING) ||
					(stopped && monService->ServiceStatusProcess.dwCurrentState == SERVICE_STOPPED) ||
					(allstate)
				)
			  )
			{			
				if(monService->ServiceStatusProcess.dwProcessId != 0)
					(*outputStream) << setw(5) << setfill(wchar_t(' ')) << monService->ServiceStatusProcess.dwProcessId;
				(*outputStream) << L'\t';
				
				if(monService->ServiceStatusProcess.dwServiceType & SERVICE_INTERACTIVE_PROCESS)
					(*outputStream) << L"INTERACTIVE_PROCESS" << L'\t';
				if(monService->ServiceStatusProcess.dwServiceType & SERVICE_FILE_SYSTEM_DRIVER)
					(*outputStream) << L"FILE_SYSTEM_DRIVER" << L'\t';
				if(monService->ServiceStatusProcess.dwServiceType & SERVICE_KERNEL_DRIVER)
					(*outputStream) << L"KERNEL_DRIVER" << L'\t';
				if(monService->ServiceStatusProcess.dwServiceType & SERVICE_WIN32_OWN_PROCESS)
					(*outputStream) << L"WIN32_OWN_PROCESS" << L'\t';
				if(monService->ServiceStatusProcess.dwServiceType & SERVICE_WIN32_SHARE_PROCESS)
					(*outputStream) << L"WIN32_SHARE_PROCESS" << L'\t';

				switch(monService->ServiceStatusProcess.dwCurrentState)
				{
					case SERVICE_CONTINUE_PENDING:
						(*outputStream) << L"CONTINUE_PENDING";
						break;
					case SERVICE_PAUSE_PENDING:
						(*outputStream) << L"PAUSE_PENDING";
						break;
					case SERVICE_PAUSED:
						(*outputStream) << L"PAUSED";
						break;
					case SERVICE_RUNNING:
						(*outputStream) << L"RUNNING";
						break;
					case SERVICE_START_PENDING:
						(*outputStream) << L"START_PENDING";
						break;
					case SERVICE_STOP_PENDING:
						(*outputStream) << L"STOP_PENDING";
						break;
					case SERVICE_STOPPED:
						(*outputStream) << L"STOPPED";
						break;
				}

				(*outputStream) << L'\t' <<
					monService->serviceName << L'\t' <<
					monService->serviceDisplayName <<
					endl;
			}
		}
	}
	else
		(*outputStream) << L"mod_service::getList ; " << mod_system::getWinError() << endl;
			
	delete vectorServices;
	return true;
}

bool mod_mimikatz_service::mimikatz(vector<wstring> * arguments)
{
	if(SC_HANDLE monManager = OpenSCManager(NULL, SERVICES_ACTIVE_DATABASE, SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE))
	{
		SC_HANDLE monService = NULL;
		if(!(monService = OpenService(monManager, L"mimikatz", SERVICE_START)))
		{
			if(GetLastError() == ERROR_SERVICE_DOES_NOT_EXIST)
			{
				(*outputStream) << L"[*] Pilote mimikatz non présent, installation." << endl;
				
				wstring monPilote = L"mimikatz.sys";
				wstring monPiloteComplet = L"";
				if(mod_system::getAbsolutePathOf(monPilote, &monPiloteComplet))
				{
					bool fileExist = false;
					if(mod_system::isFileExist(monPiloteComplet, &fileExist) && fileExist)
					{
						if(monService = CreateService(monManager, L"mimikatz", L"mimikatz driver", READ_CONTROL | WRITE_DAC | SERVICE_START, SERVICE_KERNEL_DRIVER, SERVICE_AUTO_START, SERVICE_ERROR_NORMAL, monPiloteComplet.c_str(), NULL, NULL, NULL, NULL, NULL))
						{
							(*outputStream) << L"[+] Création du pilote : OK" << endl;
							if(mod_secacl::addWorldToMimikatz(&monService))
								(*outputStream) << L"[+] Attribution des droits : OK";
							else
								(*outputStream) << L"[-] Attribution des droits : KO ; " << mod_system::getWinError();
							(*outputStream) << endl;
						}
						else (*outputStream) << L"[!] Impossible de créer le pilote ; " << mod_system::getWinError() << endl;
					}
					else (*outputStream) << L"[!] Le pilote ne semble pas exister ; " << mod_system::getWinError() << endl;
				}
				else (*outputStream) << L"[!] Impossible d\'obtenir le chemin absolu du pilote ; " << mod_system::getWinError() << endl;
			}
			else (*outputStream) << L"[!] Ouverture du pilote mimikatz : KO ; " << mod_system::getWinError() << endl;
		}
		else (*outputStream) << L"[*] Pilote mimikatz déjà présent" << endl;
		
		if(monService)
		{
			if(StartService(monService, 0, NULL) != 0)
				(*outputStream) << L"[+] Démarrage du pilote : OK";
			else
				(*outputStream) << L"[-] Démarrage du pilote : KO ; " << mod_system::getWinError();
			(*outputStream) << endl;
			CloseServiceHandle(monService);
		}
		
		CloseServiceHandle(monManager);
	}
	else (*outputStream) << L"[!] Impossible d\'ouvrir le gestionnaire de service pour création ; " << mod_system::getWinError() << endl;
	return true;
}