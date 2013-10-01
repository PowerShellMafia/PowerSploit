/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : http://creativecommons.org/licenses/by/3.0/fr/
*/
#include "mod_mimikatz_process.h"
#include "..\global.h"

vector<KIWI_MIMIKATZ_LOCAL_MODULE_COMMAND> mod_mimikatz_process::getMimiKatzCommands()
{
	vector<KIWI_MIMIKATZ_LOCAL_MODULE_COMMAND> monVector;
	monVector.push_back(KIWI_MIMIKATZ_LOCAL_MODULE_COMMAND(list,	L"list",	L"Liste les processus"));
	monVector.push_back(KIWI_MIMIKATZ_LOCAL_MODULE_COMMAND(start,	L"start",	L"Exécute un processus, /paused et/ou /sudo"));
	monVector.push_back(KIWI_MIMIKATZ_LOCAL_MODULE_COMMAND(suspend,	L"suspend",	L"Suspend l\'exécution d\'un processus"));
	monVector.push_back(KIWI_MIMIKATZ_LOCAL_MODULE_COMMAND(resume,	L"resume",	L"Reprend un processus"));
	monVector.push_back(KIWI_MIMIKATZ_LOCAL_MODULE_COMMAND(stop,	L"stop",	L"Stoppe un (ou plusieurs) processus"));
	monVector.push_back(KIWI_MIMIKATZ_LOCAL_MODULE_COMMAND(modules,	L"modules",	L"Liste les modules (pour le moment du PID courant)"));
	monVector.push_back(KIWI_MIMIKATZ_LOCAL_MODULE_COMMAND(iat,		L"iat",		L"Liste la table d\'adressage"));
	return monVector;
}

bool mod_mimikatz_process::start(vector<wstring> * arguments)
{
	if(!arguments->empty())
	{
		wstring commande = arguments->back();
		bool paused = false;
		bool sudo = false;

		(*outputStream) << L"Demande d\'exécution de : \'" << commande << L"'" << endl;
		PROCESS_INFORMATION pi = {INVALID_HANDLE_VALUE, INVALID_HANDLE_VALUE, 0, 0};

		switch(arguments->size())
		{
		case 2:
			if(_wcsicmp(arguments->front().c_str(), L"/paused") == 0)
				paused = true;
			else if(_wcsicmp(arguments->front().c_str(), L"/sudo") == 0)
				sudo = true;
			else
				goto doStartProcess_syntaxerror;

			break;
		case 3:
			if(_wcsicmp(arguments->front().c_str(), L"/paused") == 0)
				paused = true;
			else
				goto doStartProcess_syntaxerror;

			if(_wcsicmp(arguments->at(1).c_str(), L"/sudo") == 0)
				sudo = true;
			else
				goto doStartProcess_syntaxerror;
			
			break;
		}

		if(mod_process::start(&commande, &pi, paused, sudo))
		{
			if(paused)
				(*outputStream) << L" * Le Thread principal est suspendu ! Reprise avec : thread::resume " << pi.dwThreadId << endl;

			if(sudo)
				(*outputStream) << L" * Le processus est démarré avec de fausses données d\'identification" << endl;

			printInfosFromPid(pi.dwProcessId, pi.dwThreadId);
		}
		else (*outputStream) << L"mod_process::start ; " <<  mod_system::getWinError() << endl;
	}
	else
	{
doStartProcess_syntaxerror:
		(*outputStream) << L"Erreur de syntaxe ; " << L"process::start [/paused] [/sudo] commande" << endl;
	}
	
	return true;
}

bool mod_mimikatz_process::stop(vector<wstring> * arguments)
{
	for(vector<wstring>::iterator monProcessName = arguments->begin(); monProcessName != arguments->end(); monProcessName++)
	{
		mod_process::KIWI_PROCESSENTRY32 monProcess;
		wstring procName = *monProcessName;

		if(mod_process::getUniqueForName(&monProcess, &procName))
		{
			(*outputStream) << L"Fin de : " <<  procName << L'\t';
			if(mod_process::stop(monProcess.th32ProcessID))
				(*outputStream) << L"OK";
			else
				(*outputStream) << L"KO - mod_process::stop ; " << mod_system::getWinError();
			(*outputStream) << endl;
		}
		else (*outputStream) << L"mod_process::getUniqueForName ; " << mod_system::getWinError() << endl;
	}

	return true;
}


bool mod_mimikatz_process::suspend(vector<wstring> * arguments)
{
	for(vector<wstring>::iterator monProcessName = arguments->begin(); monProcessName != arguments->end(); monProcessName++)
	{
		mod_process::KIWI_PROCESSENTRY32 monProcess;
		wstring procName = *monProcessName;

		if(mod_process::getUniqueForName(&monProcess, &procName))
		{
			(*outputStream) << L"Suspension de : " <<  procName << L'\t';
			if(mod_process::suspend(monProcess.th32ProcessID))
				(*outputStream) << L"OK";
			else
				(*outputStream) << L"KO - mod_process::suspend ; " << mod_system::getWinError();
			(*outputStream) << endl;
		}
		else (*outputStream) << L"mod_process::getUniqueForName ; " << mod_system::getWinError() << endl;
	}

	return true;
}


bool mod_mimikatz_process::resume(vector<wstring> * arguments)
{
	for(vector<wstring>::iterator monProcessName = arguments->begin(); monProcessName != arguments->end(); monProcessName++)
	{
		mod_process::KIWI_PROCESSENTRY32 monProcess;
		wstring procName = *monProcessName;

		if(mod_process::getUniqueForName(&monProcess, &procName))
		{
			(*outputStream) << L"Reprise de : " <<  procName << L'\t';
			if(mod_process::resume(monProcess.th32ProcessID))
				(*outputStream) << L"OK";
			else
				(*outputStream) << L"KO - mod_process::resume ; " << mod_system::getWinError();
			(*outputStream) << endl;
		}
		else (*outputStream) << L"mod_process::getUniqueForName ; " << mod_system::getWinError() << endl;
	}

	return true;
}




bool mod_mimikatz_process::list(vector<wstring> * arguments)
{
	vector<mod_process::KIWI_PROCESSENTRY32> * vectorProcess = new vector<mod_process::KIWI_PROCESSENTRY32>();
	if(mod_process::getList(vectorProcess))
	{
		(*outputStream) << L"PID\tPPID\t#Ths\tpri\timage" << endl;
		for(vector<mod_process::KIWI_PROCESSENTRY32>::iterator monProcess = vectorProcess->begin(); monProcess != vectorProcess->end(); monProcess++)
		{
			(*outputStream) << 
				setw(5) << setfill(wchar_t(' ')) << monProcess->th32ProcessID << L'\t' <<
				setw(5) << setfill(wchar_t(' ')) << monProcess->th32ParentProcessID << L'\t' <<
				setw(5) << setfill(wchar_t(' ')) << monProcess->cntThreads << L'\t' <<
				setw(5) << setfill(wchar_t(' ')) << monProcess->pcPriClassBase << L'\t' <<
				monProcess->szExeFile <<
			endl;
		}
	}
	else (*outputStream) << L"mod_process::getList ; " << mod_system::getWinError() << endl;

	delete vectorProcess;
	return true;
}

bool mod_mimikatz_process::modules(vector<wstring> * arguments)
{
	DWORD processId = 0 ;

	if(!arguments->empty() && !(arguments->size() > 1))
	{
		wstringstream monBuffer;
		monBuffer << arguments->front();
		monBuffer >> processId;
	}

	vector<mod_process::KIWI_MODULEENTRY32> * vectorModules = new vector<mod_process::KIWI_MODULEENTRY32>();
	if(mod_process::getModulesListForProcessId(vectorModules, &processId))
	{
		(*outputStream) << L"@Base\tTaille\tModule\tPath" << endl;
		for(vector<mod_process::KIWI_MODULEENTRY32>::iterator monModule = vectorModules->begin(); monModule != vectorModules->end(); monModule++)
		{
			(*outputStream) << monModule->modBaseAddr << L'\t' << monModule->modBaseSize << '\t' << monModule->szModule << L'\t' << monModule->szExePath << endl;
		}
	}
	else
		(*outputStream) << L"mod_process::getModulesListForProcessId ; " << mod_system::getWinError() << endl;

	delete vectorModules;
	return true;
}

bool mod_mimikatz_process::iat(vector<wstring> * arguments)
{
	wstring process;
	wstring module;

	switch(arguments->size())
	{
	case 2:
		process = arguments->at(0);
		module = arguments->at(1);
		break;
	case 1:
		process = arguments->at(0);
		break;
	default:
		;
	}
	
	mod_process::KIWI_PROCESSENTRY32 monProcess;
	if(mod_process::getUniqueForName(&monProcess, &process))
	{
		if(HANDLE monHandle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, monProcess.th32ProcessID))
		{
			if(module.empty() || (module.front() != L'*'))
			{
				if(module.empty())
					module.assign(process);
				
				mod_process::KIWI_MODULEENTRY32 * monModule = new mod_process::KIWI_MODULEENTRY32();
				if(mod_process::getUniqueModuleForName(monModule, &module, &monProcess.th32ProcessID))
				{
					printIATFromModule(monModule, monHandle);
				}
				else (*outputStream) << L"mod_process::getUniqueModuleForName ; " << mod_system::getWinError() << endl;
				delete monModule;
			}
			else
			{
				vector<mod_process::KIWI_MODULEENTRY32> * vectorModules = new vector<mod_process::KIWI_MODULEENTRY32>();
				if(mod_process::getModulesListForProcessId(vectorModules, &monProcess.th32ProcessID))
				{
					for(vector<mod_process::KIWI_MODULEENTRY32>::iterator monModule = vectorModules->begin(); monModule != vectorModules->end(); monModule++)
						printIATFromModule(&*monModule, monHandle);
				}
				else (*outputStream) << L"mod_process::getModulesListForProcessId ; " << mod_system::getWinError() << endl;

				delete vectorModules;
			}
			
			CloseHandle(monHandle);
		}
	}
	else (*outputStream) << L"mod_process::getUniqueForName ; " << mod_system::getWinError() << endl;

	return true;
}

void mod_mimikatz_process::printInfosFromPid(DWORD &PID, DWORD ThreadId)
{
	(*outputStream) << L"PID      : " << PID << endl;

	if(ThreadId)
	{
		(*outputStream) << L"ThreadID : " << ThreadId << endl;
	}

	LUID monId = {0, 0};
	if(mod_process::getAuthentificationIdFromProcessId(PID, monId))
	{
		(*outputStream) << "AuthId_h : " << monId.HighPart << endl;
		(*outputStream) << "AuthId_l : " << monId.LowPart << endl;
	}
	else (*outputStream) << L"Erreur : " <<  mod_system::getWinError() << endl;
}

void mod_mimikatz_process::printIATFromModule(mod_process::KIWI_MODULEENTRY32 * monModule, HANDLE monHandle)
{
	(*outputStream) << monModule->szModule << L" -> " << monModule->szExePath << endl;
	PBYTE baseAddr = reinterpret_cast<PBYTE>(monModule->modBaseAddr);

	vector<pair<string, vector<mod_process::KIWI_IAT_MODULE>>> * monIAT = new vector<pair<string, vector<mod_process::KIWI_IAT_MODULE>>>();
	if(mod_process::getIAT(baseAddr, monIAT, monHandle))
	{
		for(vector<pair<string, vector<mod_process::KIWI_IAT_MODULE>>>::iterator monModuleImporte = monIAT->begin(); monModuleImporte != monIAT->end(); monModuleImporte++)
		{
			(*outputStream) << L" - Imports depuis : " << monModuleImporte->first.c_str() << endl;
			for(vector<mod_process::KIWI_IAT_MODULE>::iterator maFonctionImporte = monModuleImporte->second.begin(); maFonctionImporte != monModuleImporte->second.end(); maFonctionImporte++)
			{
				(*outputStream) << L"      " << maFonctionImporte->ptrToFunc << L" -> " << maFonctionImporte->ptrFunc << L' ';
				if(maFonctionImporte->Ordinal != 0)
					(*outputStream) << L"O# " << maFonctionImporte->Ordinal;
				else
					(*outputStream) << maFonctionImporte->funcName.c_str();
				(*outputStream) << endl;
			}
		}
	}
	delete monIAT;
}
