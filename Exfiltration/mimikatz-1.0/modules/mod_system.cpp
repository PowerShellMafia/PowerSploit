/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : http://creativecommons.org/licenses/by/3.0/fr/
*/
#include "mod_system.h"

OSVERSIONINFOEX mod_system::GLOB_Version;

wstring mod_system::getWinError(bool automatique, DWORD code)
{
	bool reussite = false;
	DWORD dwError = (automatique ? GetLastError() : code);
	wostringstream resultat;
	wchar_t * monBuffer = NULL;
	
	resultat << L"(0x" << setw(sizeof(DWORD)*2) << setfill(wchar_t('0')) << hex << dwError << dec << L')';
	if(!(reussite = FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_MAX_WIDTH_MASK, NULL, dwError, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), reinterpret_cast<wchar_t *>(&monBuffer), 0, NULL) != 0))
		reussite = FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_MAX_WIDTH_MASK | FORMAT_MESSAGE_FROM_HMODULE, GetModuleHandle(L"ntdll"), dwError, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), reinterpret_cast<wchar_t *>(&monBuffer), 0, NULL) != 0;

	if(reussite)
	{
		resultat << L' ' << monBuffer;
		LocalFree(monBuffer);
	}
	else resultat << L" * Impossible d\'obtenir un message *";

	return resultat.str();
}

bool mod_system::getUserName(wstring * monUserName)
{
	bool reussite = false;
	unsigned long tailleRequise = 0;

	if(!GetUserNameEx(NameSamCompatible, NULL, &tailleRequise) && GetLastError() == ERROR_MORE_DATA)
	{
		wchar_t * monBuffer = new wchar_t[tailleRequise];
		if(reussite = (GetUserNameEx(NameSamCompatible, monBuffer, &tailleRequise) != 0))
		{
			monUserName->assign(monBuffer);
		}
		delete[] monBuffer;
	}
	return reussite;
}

bool mod_system::getComputerName(wstring * monComputerName)
{
	bool reussite = false;
	DWORD tailleRequise = 0;

	if(!GetComputerNameEx(ComputerNamePhysicalDnsFullyQualified , NULL, &tailleRequise) && GetLastError() == ERROR_MORE_DATA)
	{
		wchar_t * monBuffer = new wchar_t[tailleRequise];
		if(reussite = (GetComputerNameEx(ComputerNamePhysicalDnsFullyQualified, monBuffer, &tailleRequise) != 0))
		{
			monComputerName->assign(monBuffer);
		}
		delete[] monBuffer;
	}
	return reussite;
}

bool mod_system::getVersion(OSVERSIONINFOEX * maVersion)
{
	RtlZeroMemory(maVersion, sizeof(OSVERSIONINFOEX));
	maVersion->dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);
	return (GetVersionEx(reinterpret_cast<LPOSVERSIONINFO>(maVersion)) != 0);
}

bool mod_system::getCurrentDirectory(wstring * monRepertoire)
{
	bool reussite = false;
	DWORD tailleRequise = GetCurrentDirectory(0, NULL);
	wchar_t * monBuffer = new wchar_t[tailleRequise];
	if(tailleRequise > 0 && GetCurrentDirectory(tailleRequise, monBuffer) == tailleRequise - 1)
	{
		monRepertoire->assign(monBuffer);
		reussite = true;
	}
	delete monBuffer;
	return reussite;
}

bool mod_system::getAbsolutePathOf(wstring &thisData, wstring *reponse)
{
	bool reussite = false;
	wchar_t monBuffer[MAX_PATH];

	if(PathIsRelative(thisData.c_str()))
	{
		wstring monRep = L"";
		if(reussite = getCurrentDirectory(&monRep))
		{
			PathCombine(monBuffer, monRep.c_str(), thisData.c_str());
			reponse->assign(monBuffer);
		}
	}
	else
	{
		if(reussite = (PathCanonicalize(monBuffer, thisData.c_str()) != 0))
		{
			reponse->assign(monBuffer);
		}
	}
	return reussite;
}

bool mod_system::isFileExist(std::wstring &fichier, bool *resultat)
{
	bool reussite = false;
	HANDLE monFichier = CreateFile(fichier.c_str(), 0, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
	
	if(reussite = (monFichier && monFichier != INVALID_HANDLE_VALUE))
	{
		CloseHandle(monFichier);
		*resultat = true;
	}
	else if(reussite = (GetLastError() == ERROR_FILE_NOT_FOUND))
	{
		*resultat = false;
	}
	return reussite;
}

bool mod_system::getSystemHandles(vector<SYSTEM_HANDLE> * mesHandles, DWORD * pid)
{
	bool reussite = false;

	if(PNT_QUERY_SYSTEM_INFORMATION NtQuerySystemInformation = reinterpret_cast<PNT_QUERY_SYSTEM_INFORMATION>(GetProcAddress(GetModuleHandle(L"ntdll"), "NtQuerySystemInformation")))
	{
		DWORD size = 0x10000;
		BYTE * monBuffer = new BYTE[size];
		ULONG sizeReturn = 0;
		NTSTATUS status;

		while((status = NtQuerySystemInformation(SystemHandleInformation, monBuffer, size, &sizeReturn)) == STATUS_INFO_LENGTH_MISMATCH)
		{
			delete[] monBuffer;
			size <<= 1;
			monBuffer = new BYTE[size];
		}
		
		if(reussite = NT_SUCCESS(status))
		{
			PSYSTEM_HANDLE_INFORMATION mesInfos = reinterpret_cast<PSYSTEM_HANDLE_INFORMATION>(monBuffer);
			for(DWORD i = 0; i < mesInfos->HandleCount; i++)
			{
				if(!pid || *pid == mesInfos->Handles[i].ProcessId)
					mesHandles->push_back(mesInfos->Handles[i]);
			}
		}
		
		delete[] monBuffer;
	}

	return reussite;
}

bool mod_system::getHandleInfo(HANDLE monHandle, PBYTE * buffer, OBJECT_INFORMATION_CLASS typeInfo)
{
	bool reussite = false;

	if(PNT_QUERY_OBJECT NtQueryObject = reinterpret_cast<PNT_QUERY_OBJECT>(GetProcAddress(GetModuleHandle(L"ntdll"), "NtQueryObject")))
	{
		DWORD tailleRequise = 0;
		
		if(NtQueryObject(monHandle, typeInfo, NULL, 0, &tailleRequise) == STATUS_INFO_LENGTH_MISMATCH)
		{
			*buffer = new BYTE[tailleRequise];
			if(!(reussite = NT_SUCCESS(NtQueryObject(monHandle, typeInfo, *buffer, tailleRequise, &tailleRequise))))
			{
				delete[] buffer;
			}
		}
	}

	return reussite;
}

bool mod_system::getHandleType(HANDLE monHandle, wstring * strType)
{
	bool reussite = false;

	BYTE * monBuffer = NULL;
	if(reussite = getHandleInfo(monHandle, &monBuffer, ObjectTypeInformation))
	{
		POBJECT_TYPE_INFORMATION typeInfo = reinterpret_cast<POBJECT_TYPE_INFORMATION>(monBuffer);
		strType->assign(typeInfo->Name.Buffer, typeInfo->Name.Length / sizeof(wchar_t));
		delete[] monBuffer;
	}
	return reussite;
}

bool mod_system::getHandleName(HANDLE monHandle, wstring * strName)
{
	bool reussite = false;
	
	BYTE * monBuffer = NULL;
	if(reussite = getHandleInfo(monHandle, &monBuffer, ObjectNameInformation))
	{
		PUNICODE_STRING typeName = reinterpret_cast<PUNICODE_STRING>(monBuffer);
		strName->assign(typeName->Buffer, typeName->Length / sizeof(wchar_t));
		delete[] monBuffer;
	}
	return reussite;
}
