/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : http://creativecommons.org/licenses/by/3.0/fr/
*/
#include "mod_mimikatz_privilege.h"
#include "..\global.h"

vector<KIWI_MIMIKATZ_LOCAL_MODULE_COMMAND> mod_mimikatz_privilege::getMimiKatzCommands()
{
	vector<KIWI_MIMIKATZ_LOCAL_MODULE_COMMAND> monVector;
	monVector.push_back(KIWI_MIMIKATZ_LOCAL_MODULE_COMMAND(list,	L"list",	L"Liste les privilèges"));
	monVector.push_back(KIWI_MIMIKATZ_LOCAL_MODULE_COMMAND(enable,	L"enable",	L"Active un ou plusieurs privilèges"));
	monVector.push_back(KIWI_MIMIKATZ_LOCAL_MODULE_COMMAND(remove,	L"remove",	L"Retire un ou plusieurs privilèges"));
	monVector.push_back(KIWI_MIMIKATZ_LOCAL_MODULE_COMMAND(disable,	L"disable",	L"Désactive un ou plusieurs privilèges"));
	/* Raccourçis */
	monVector.push_back(KIWI_MIMIKATZ_LOCAL_MODULE_COMMAND(debug,		L"debug",		L"Demande (ou désactive) le privilège Debug"));
	monVector.push_back(KIWI_MIMIKATZ_LOCAL_MODULE_COMMAND(security,	L"security",	L"Demande (ou désactive) le privilège Security"));
	monVector.push_back(KIWI_MIMIKATZ_LOCAL_MODULE_COMMAND(tcb,			L"tcb",			L"Demande (ou désactive) le privilège Tcb"));
	monVector.push_back(KIWI_MIMIKATZ_LOCAL_MODULE_COMMAND(impersonate,	L"impersonate",	L"Demande (ou désactive) le privilège Impersonate"));
	monVector.push_back(KIWI_MIMIKATZ_LOCAL_MODULE_COMMAND(assign,		L"assign",		L"Demande (ou désactive) le privilège AssignPrimaryToken"));
	monVector.push_back(KIWI_MIMIKATZ_LOCAL_MODULE_COMMAND(shutdown,	L"shutdown",	L"Demande (ou désactive) le privilège Shutdown"));
	monVector.push_back(KIWI_MIMIKATZ_LOCAL_MODULE_COMMAND(takeowner,	L"takeowner",	L"Demande (ou désactive) le privilège TakeOwnership"));
	return monVector;
}

bool mod_mimikatz_privilege::enable(vector<wstring> * arguments)
{
	bool reussite = multiplePrivs(arguments, SE_PRIVILEGE_ENABLED);
	return true;
}

bool mod_mimikatz_privilege::remove(vector<wstring> * arguments)
{
	bool reussite = multiplePrivs(arguments, SE_PRIVILEGE_REMOVED);
	return true;
}

bool mod_mimikatz_privilege::disable(vector<wstring> * arguments)
{
	bool reussite = multiplePrivs(arguments, 0);
	return true;
}

bool mod_mimikatz_privilege::simplePriv(wstring priv, vector<wstring> * arguments)
{
	bool ajout = arguments->empty();
	
	(*outputStream) << L"Demande d" << (ajout ? L"\'ACTIVATION" : L"e RETRAIT") << L" du privilège : " << priv << L" : ";
	
	vector<pair<wstring, DWORD>> * mesPrivs = new vector<pair<wstring, DWORD>>;
	mesPrivs->push_back(make_pair(priv, ajout ? SE_PRIVILEGE_ENABLED : 0));
	
	bool reussite = mod_privilege::set(mesPrivs);//, INVALID_HANDLE_VALUE);
	delete mesPrivs;
	
	if(reussite)
		(*outputStream) << L"OK";
	else
		(*outputStream) << L"KO ; " << mod_system::getWinError();
	(*outputStream) << endl;
	
	return reussite;
}

bool mod_mimikatz_privilege::multiplePrivs(vector<wstring> * privs, DWORD type)
{
	bool reussite = false;	
	vector<pair<wstring, DWORD>> * mesPrivs = new vector<pair<wstring, DWORD>>;
	for(vector<wstring>::iterator monPrivilege = privs->begin(); monPrivilege != privs->end() ; monPrivilege++)
	{
		mesPrivs->push_back(make_pair(*monPrivilege, type));
	}
	reussite = mod_privilege::set(mesPrivs);
	delete mesPrivs;

	if(reussite)
		(*outputStream) << L"OK";
	else
		(*outputStream) << L"KO ; " << mod_system::getWinError();
	(*outputStream) << endl;

	return reussite;
}


bool mod_mimikatz_privilege::list(vector<wstring> * arguments)
{
	vector<pair<wstring, DWORD>> * mesPrivs = new vector<pair<wstring, DWORD>>;

	if(mod_privilege::get(mesPrivs))//, INVALID_HANDLE_VALUE))
	{
		for(vector<pair<wstring, DWORD>>::iterator monPrivilege = mesPrivs->begin(); (monPrivilege != mesPrivs->end()) ; monPrivilege++)
		{
			(*outputStream) << setw(35) << setfill(wchar_t(L' ')) << left << monPrivilege->first << right << L'\t';
			
			if(monPrivilege->second & SE_PRIVILEGE_VALID_ATTRIBUTES)
			{
				if(monPrivilege->second & SE_PRIVILEGE_ENABLED_BY_DEFAULT)
				{
					(*outputStream) << L"ENABLED_BY_DEFAULT ";
				}

				if(monPrivilege->second & SE_PRIVILEGE_ENABLED)
				{
					(*outputStream) << L"ENABLED ";
				}

				if(monPrivilege->second & SE_PRIVILEGE_REMOVED)
				{
					(*outputStream) << L"REMOVED ";
				}

				if(monPrivilege->second & SE_PRIVILEGE_USED_FOR_ACCESS)
				{
					(*outputStream) << L"USED_FOR_ACCESS ";
				}

				if(monPrivilege->second & SE_PRIVILEGE_REMOVED)
				{
					(*outputStream) << L"REMOVED";
				}
			}

			(*outputStream) << endl;
		}
	}
	else (*outputStream) << mod_system::getWinError() << endl;

	return true;
}


bool mod_mimikatz_privilege::debug(vector<wstring> * arguments)
{
	simplePriv(SE_DEBUG_NAME, arguments); return true;
}

bool mod_mimikatz_privilege::security(vector<wstring> * arguments)
{
	simplePriv(SE_SECURITY_NAME, arguments); return true;
}

bool mod_mimikatz_privilege::tcb(vector<wstring> * arguments)
{
	simplePriv(SE_TCB_NAME, arguments); return true;
}

bool mod_mimikatz_privilege::impersonate(vector<wstring> * arguments)
{
	simplePriv(SE_IMPERSONATE_NAME, arguments); return true;
}

bool mod_mimikatz_privilege::assign(vector<wstring> * arguments)
{
	simplePriv(SE_ASSIGNPRIMARYTOKEN_NAME, arguments); return true;
}

bool mod_mimikatz_privilege::shutdown(vector<wstring> * arguments)
{
	simplePriv(SE_SHUTDOWN_NAME, arguments); return true;
}

bool mod_mimikatz_privilege::takeowner(vector<wstring> * arguments)
{
	simplePriv(SE_TAKE_OWNERSHIP_NAME, arguments); return true;
}