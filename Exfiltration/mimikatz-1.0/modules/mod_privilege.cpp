/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : http://creativecommons.org/licenses/by/3.0/fr/
*/
#include "mod_privilege.h"

bool mod_privilege::getName(PLUID idPrivilege, wstring * privilegeName)
{
	bool reussite = false;
	DWORD tailleRequise = 0;

	if(!LookupPrivilegeName(NULL, idPrivilege, NULL, &tailleRequise)  && GetLastError() == ERROR_INSUFFICIENT_BUFFER)
	{
		wchar_t * monBuffer = new wchar_t[tailleRequise];
		if(reussite = (LookupPrivilegeName(NULL, idPrivilege, monBuffer, &tailleRequise) != 0))
		{
			privilegeName->assign(monBuffer);
		}
		delete[] monBuffer;
	}
	return reussite;
}

bool mod_privilege::getValue(wstring * privilegeName, PLUID idPrivilege)
{
	return (LookupPrivilegeValue(NULL, privilegeName->c_str(), idPrivilege) != 0);
}

bool mod_privilege::get(vector<pair<wstring, DWORD>> *maPrivilegesvector, HANDLE handleProcess)
{
	bool reussite = false;

	HANDLE hToken = INVALID_HANDLE_VALUE;
	if(OpenProcessToken((handleProcess == INVALID_HANDLE_VALUE ? GetCurrentProcess() : handleProcess), TOKEN_QUERY /*| STANDARD_RIGHTS_READ*/, &hToken))
	{
		DWORD tailleRequise = 0;
		BYTE * monBuffer;
		
		if(!GetTokenInformation(hToken, TokenPrivileges, NULL, 0, &tailleRequise) && GetLastError() == ERROR_INSUFFICIENT_BUFFER)
		{
			monBuffer = new BYTE[tailleRequise];
			if(reussite = (GetTokenInformation(hToken, TokenPrivileges, monBuffer, tailleRequise, &tailleRequise) != 0))
			{
				TOKEN_PRIVILEGES * mesPrivileges = reinterpret_cast<TOKEN_PRIVILEGES *>(monBuffer);
				for(DWORD i = 0; i < mesPrivileges->PrivilegeCount; i++)
				{
					wstring * monPrivilege = new wstring();
					if(getName(&(mesPrivileges->Privileges[i].Luid), monPrivilege))
					{
						maPrivilegesvector->push_back(make_pair(*monPrivilege, mesPrivileges->Privileges[i].Attributes));
					}
					delete monPrivilege;
				}
			}
			delete[] monBuffer;
		}
	}
	return reussite;
}

bool mod_privilege::set(vector<pair<wstring, DWORD>> *maPrivilegesvector, HANDLE handleProcess)
{
	bool reussite = false;

	BYTE * monBuffer = new BYTE[FIELD_OFFSET(TOKEN_PRIVILEGES, Privileges[maPrivilegesvector->size()])];
	TOKEN_PRIVILEGES * mesPrivileges = reinterpret_cast<TOKEN_PRIVILEGES *>(monBuffer);
	mesPrivileges->PrivilegeCount = static_cast<DWORD>(maPrivilegesvector->size());

	unsigned int i;
	vector<pair<wstring, DWORD>>::iterator monPrivilege;
	for(monPrivilege = maPrivilegesvector->begin(), i = 0; (monPrivilege != maPrivilegesvector->end()) && ( i < mesPrivileges->PrivilegeCount) ; monPrivilege++, i++)
	{
		if(reussite = getValue(&(monPrivilege->first), &(mesPrivileges->Privileges[i].Luid)))
		{
			mesPrivileges->Privileges[i].Attributes = monPrivilege->second;
		}
		else
		{
			break;
		}
	}

	if(reussite)
	{
		HANDLE hToken = INVALID_HANDLE_VALUE;
		if(reussite = (OpenProcessToken((handleProcess == INVALID_HANDLE_VALUE ? GetCurrentProcess() : handleProcess), /*TOKEN_QUERY |*/ TOKEN_ADJUST_PRIVILEGES, &hToken) != 0))
		{
			reussite = (AdjustTokenPrivileges(hToken, false, reinterpret_cast<TOKEN_PRIVILEGES *>(mesPrivileges), 0, NULL, NULL) != 0) && (GetLastError() == ERROR_SUCCESS);
		}
	}

	delete monBuffer;
	return reussite;
}
