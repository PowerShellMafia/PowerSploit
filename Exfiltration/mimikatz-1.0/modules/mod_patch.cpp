/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : http://creativecommons.org/licenses/by/3.0/fr/
*/
#include "mod_patch.h"
#include "..\mimikatz\global.h"

bool mod_patch::patchModuleOfService(wstring serviceName, wstring moduleName, BYTE * patternToSearch, SIZE_T szPatternToSearch, BYTE * patternToPlace, SIZE_T szPatternToPlace, long offsetForPlace)
{
	bool reussite = false;

	mod_service::KIWI_SERVICE_STATUS_PROCESS monService;
	if(mod_service::getUniqueForName(&monService, &serviceName))
	{
		if(monService.ServiceStatusProcess.dwCurrentState != SERVICE_STOPPED && monService.ServiceStatusProcess.dwCurrentState != SERVICE_STOP_PENDING)
		{
			(*outputStream) << L"Service : " << monService.serviceDisplayName << endl;
			reussite = patchModuleOfPID(monService.ServiceStatusProcess.dwProcessId, moduleName, patternToSearch, szPatternToSearch, patternToPlace, szPatternToPlace, offsetForPlace);
		}
		else (*outputStream) << L"Le service : " << serviceName << L" (" << monService.serviceDisplayName << L") ; n\'a pas l\'air très actif" << endl;
	}
	else (*outputStream) << L"Impossible de trouver le service : " << serviceName << L" ; " << mod_system::getWinError() << endl;

	return reussite;
}

bool mod_patch::patchModuleOfPID(DWORD pid, wstring moduleName, BYTE * patternToSearch, SIZE_T szPatternToSearch, BYTE * patternToPlace, SIZE_T szPatternToPlace, long offsetForPlace)
{
	bool reussite = false;

	mod_process::KIWI_MODULEENTRY32 monModule;
	if(mod_process::getUniqueModuleForName(&monModule, (moduleName.empty() ? NULL : &moduleName), &pid))
	{
		BYTE * baseAddr = monModule.modBaseAddr;
		DWORD taille = monModule.modBaseSize;

		if(HANDLE processHandle = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, false, pid))
		{
			(*outputStream) << L"Recherche des patterns dans : " << moduleName << L"@pid(" << pid << L")" << endl;

			BYTE * addrPattern = NULL;
			if(mod_memory::searchMemory(baseAddr, baseAddr + taille, patternToSearch, &addrPattern, szPatternToSearch, true, processHandle))
			{
				reussite = mod_memory::writeMemory(addrPattern + offsetForPlace, patternToPlace, szPatternToPlace, processHandle);
				(*outputStream) << L"Patch " << moduleName << L"@pid(" << pid << L") : " << (reussite ? L"OK" : L"KO") << endl;
			}
			else (*outputStream) << L"mod_memory::searchMemory " << mod_system::getWinError() << endl;

			CloseHandle(processHandle);
		}
		else (*outputStream) << L"OpenProcess : " << mod_system::getWinError() << endl;
	}
	else (*outputStream) << L"mod_process::getUniqueModuleForName : " << mod_system::getWinError() << endl;
	return reussite;
}

bool mod_patch::getFullVersion(DWORD * majorVersion, DWORD * minorVersion, DWORD * build, bool * isServer, bool * is64)
{
	bool reussite = false;

	OSVERSIONINFOEX maVersion;
	if(reussite = mod_system::getVersion(&maVersion))
	{
		if(majorVersion) *majorVersion = maVersion.dwMajorVersion;
		if(majorVersion) *minorVersion = maVersion.dwMinorVersion;
		if(build) *build = maVersion.dwBuildNumber;
		if(isServer) *isServer = maVersion.wProductType != VER_NT_WORKSTATION;
		
		if(is64)
		{
			SYSTEM_INFO mesInfos;
			GetNativeSystemInfo(&mesInfos);

			*is64 = (mesInfos.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64);
		}
	}

	return reussite;
}

bool mod_patch::checkVersion(KIWI_OS_CHECK * monOsValide)
{
	bool reussite = false;
	
	DWORD majorVersion, minorVersion, build;
	bool isServer, is64;

	if(getFullVersion(&majorVersion, &minorVersion, &build, &isServer, &is64))
	{
			reussite = 
				(monOsValide->majorVersion == majorVersion) &&
				(monOsValide->minorVersion == minorVersion) &&
				((monOsValide->build == build) || (monOsValide->build == 0)) &&
				(monOsValide->isServer == isServer) &&
				(monOsValide->is64 == is64)
				;
	}
	else (*outputStream) << L"mod_patch::getFullVersion : " << mod_system::getWinError() << endl;
	return reussite;
}

bool mod_patch::checkVersion(OS monOsValide)
{	
	KIWI_OS_CHECK kOs;
	switch(monOsValide)
	{
		case WINDOWS_2000_PRO_x86: kOs.majorVersion = 5;	kOs.minorVersion = 0;	kOs.build = 0;	kOs.isServer = false;	kOs.is64 = false;	break;
		case WINDOWS_2000_SRV_x86: kOs.majorVersion = 5;	kOs.minorVersion = 0;	kOs.build = 0;	kOs.isServer = true;	kOs.is64 = false;	break;

		case WINDOWS_XP_PRO___x86: kOs.majorVersion = 5;	kOs.minorVersion = 1;	kOs.build = 0;	kOs.isServer = false;	kOs.is64 = false;	break;
		case WINDOWS_XP_PRO___x64: kOs.majorVersion = 5;	kOs.minorVersion = 2;	kOs.build = 0;	kOs.isServer = false;	kOs.is64 = true;	break;
		
		case WINDOWS_2003_____x86: kOs.majorVersion = 5;	kOs.minorVersion = 2;	kOs.build = 0;	kOs.isServer = true;	kOs.is64 = false;	break;
		case WINDOWS_2003_____x64: kOs.majorVersion = 5;	kOs.minorVersion = 2;	kOs.build = 0;	kOs.isServer = true;	kOs.is64 = true;	break;
		
		case WINDOWS_VISTA____x86: kOs.majorVersion = 6;	kOs.minorVersion = 0;	kOs.build = 0;	kOs.isServer = false;	kOs.is64 = false;	break;
		case WINDOWS_VISTA____x64: kOs.majorVersion = 6;	kOs.minorVersion = 0;	kOs.build = 0;	kOs.isServer = false;	kOs.is64 = true;	break;
		
		case WINDOWS_2008_____x86: kOs.majorVersion = 6;	kOs.minorVersion = 0;	kOs.build = 0;	kOs.isServer = true;	kOs.is64 = false;	break;
		case WINDOWS_2008_____x64: kOs.majorVersion = 6;	kOs.minorVersion = 0;	kOs.build = 0;	kOs.isServer = true;	kOs.is64 = true;	break;

		case WINDOWS_SEVEN____x86: kOs.majorVersion = 6;	kOs.minorVersion = 1;	kOs.build = 0;	kOs.isServer = false;	kOs.is64 = false;	break;
		case WINDOWS_SEVEN____x64: kOs.majorVersion = 6;	kOs.minorVersion = 1;	kOs.build = 0;	kOs.isServer = false;	kOs.is64 = true;	break;
		
		case WINDOWS_2008r2___x64: kOs.majorVersion = 6;	kOs.minorVersion = 1;	kOs.build = 0;	kOs.isServer = true;	kOs.is64 = true;	break;
	}

	return checkVersion(&kOs);
}


bool mod_patch::checkVersion(vector<OS> * vectorValid)
{
	bool reussite = false;
	
	for(vector<OS>::iterator monOs = vectorValid->begin(); monOs != vectorValid->end() && !reussite; monOs++)
	{
		reussite = checkVersion(*monOs);
	}	
	
	if(!reussite)
		(*outputStream) << L"La version du système d\'exploitation actuelle n\'est pas supportée par cette fonction." << endl;

	return reussite;
}
