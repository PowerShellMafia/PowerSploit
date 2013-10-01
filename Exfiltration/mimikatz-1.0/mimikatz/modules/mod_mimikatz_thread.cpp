/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : http://creativecommons.org/licenses/by/3.0/fr/
*/
#include "mod_mimikatz_thread.h"
#include "..\global.h"

vector<KIWI_MIMIKATZ_LOCAL_MODULE_COMMAND> mod_mimikatz_thread::getMimiKatzCommands()
{
	vector<KIWI_MIMIKATZ_LOCAL_MODULE_COMMAND> monVector;
	monVector.push_back(KIWI_MIMIKATZ_LOCAL_MODULE_COMMAND(list,	L"list",	L"Liste les threads"));
	monVector.push_back(KIWI_MIMIKATZ_LOCAL_MODULE_COMMAND(suspend,	L"suspend",	L"Suspend un thread actif"));
	monVector.push_back(KIWI_MIMIKATZ_LOCAL_MODULE_COMMAND(resume,	L"resume",	L"Reprend un thread suspendu"));
	monVector.push_back(KIWI_MIMIKATZ_LOCAL_MODULE_COMMAND(stop,	L"stop",	L"Arrête un thread"));
	monVector.push_back(KIWI_MIMIKATZ_LOCAL_MODULE_COMMAND(quit,	L"quit",	L"Envoi un message de fermeture à un thread"));
	return monVector;
}

bool mod_mimikatz_thread::list(vector<wstring> * arguments)
{
	vector<THREADENTRY32> * vectorThreads = new vector<THREADENTRY32>();

	DWORD processId = arguments->empty() ? 0 : _wtoi(arguments->front().c_str());

	if(mod_thread::getList(vectorThreads, arguments->empty() ? NULL : &processId))
	{
		(*outputStream) << L"PID\tTID\tprTh" << endl;
		for(vector<THREADENTRY32>::iterator monThread = vectorThreads->begin(); monThread != vectorThreads->end(); monThread++)
			(*outputStream) << 
				setw(5) << setfill(wchar_t(' ')) << monThread->th32OwnerProcessID << L'\t' <<
				setw(5) << setfill(wchar_t(' ')) << monThread->th32ThreadID << L'\t' <<
				setw(5) << setfill(wchar_t(' ')) << monThread->tpBasePri <<
			endl;
	}
	else
		(*outputStream) << L"mod_thread::getList ; " << mod_system::getWinError() << endl;

	delete vectorThreads;
	return true;
}

bool mod_mimikatz_thread::resume(vector<wstring> * arguments)
{
	for(vector<wstring>::iterator monArgThread = arguments->begin(); monArgThread != arguments->end(); monArgThread++)
	{
		DWORD threadId = _wtoi(monArgThread->c_str());
		
		if(threadId != 0)
		{
			(*outputStream) << L"thread " << setw(5) << setfill(wchar_t(' ')) << threadId << L"\treprise ";
			
			if(mod_thread::resume(threadId))
				(*outputStream) << L"OK";
			else
				(*outputStream) << L"KO - mod_thread::resume ; " << mod_system::getWinError();
		}
		else
			(*outputStream) << L"argument \'" << *monArgThread << L"\' invalide";

		(*outputStream) << endl;
	}

	return true;
}

bool mod_mimikatz_thread::suspend(vector<wstring> * arguments)
{
	for(vector<wstring>::iterator monArgThread = arguments->begin(); monArgThread != arguments->end(); monArgThread++)
	{
		DWORD threadId = _wtoi(monArgThread->c_str());
		
		if(threadId != 0)
		{
			(*outputStream) << L"thread " << setw(5) << setfill(wchar_t(' ')) << threadId << L"\tsuspension ";
			
			if(mod_thread::suspend(threadId))
				(*outputStream) << L"OK";
			else
				(*outputStream) << L"KO - mod_thread::suspend ; " << mod_system::getWinError();
		}
		else
			(*outputStream) << L"argument \'" << *monArgThread << L"\' invalide";

		(*outputStream) << endl;
	}

	return true;
}

bool mod_mimikatz_thread::stop(vector<wstring> * arguments)
{
	for(vector<wstring>::iterator monArgThread = arguments->begin(); monArgThread != arguments->end(); monArgThread++)
	{
		DWORD threadId = _wtoi(monArgThread->c_str());
		
		if(threadId != 0)
		{
			(*outputStream) << L"thread " << setw(5) << setfill(wchar_t(' ')) << threadId << L"\tarrêt ";
			
			if(mod_thread::stop(threadId))
				(*outputStream) << L"OK";
			else
				(*outputStream) << L"KO - mod_thread::stop ; " << mod_system::getWinError();
		}
		else
			(*outputStream) << L"argument \'" << *monArgThread << L"\' invalide";

		(*outputStream) << endl;
	}

	return true;
}


bool mod_mimikatz_thread::quit(vector<wstring> * arguments)
{
	for(vector<wstring>::iterator monArgThread = arguments->begin(); monArgThread != arguments->end(); monArgThread++)
	{
		DWORD threadId = _wtoi(monArgThread->c_str());
		
		if(threadId != 0)
		{
			(*outputStream) << L"thread " << setw(5) << setfill(wchar_t(' ')) << threadId << L"\tmessage fermeture ";
			
			if(mod_thread::quit(threadId))
				(*outputStream) << L"OK";
			else
				(*outputStream) << L"KO - mod_thread::quit ; " << mod_system::getWinError();
		}
		else
			(*outputStream) << L"argument \'" << *monArgThread << L"\' invalide";

		(*outputStream) << endl;
	}

	return true;
}
