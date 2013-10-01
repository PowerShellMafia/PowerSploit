/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : http://creativecommons.org/licenses/by/3.0/fr/
*/
#include "mod_mimikatz_winmine.h"
#include "..\global.h"

char DISP_WINMINE[] = " 123456789*x*?F.";

vector<KIWI_MIMIKATZ_LOCAL_MODULE_COMMAND> mod_mimikatz_winmine::getMimiKatzCommands()
{
	vector<KIWI_MIMIKATZ_LOCAL_MODULE_COMMAND> monVector;
	monVector.push_back(KIWI_MIMIKATZ_LOCAL_MODULE_COMMAND(infos,	L"infos",	L"Obtient des informations sur le démineur en cours"));
	monVector.push_back(KIWI_MIMIKATZ_LOCAL_MODULE_COMMAND(pause,	L"pause",	L"Met en pause le chronomètre du démineur en cours"));
	monVector.push_back(KIWI_MIMIKATZ_LOCAL_MODULE_COMMAND(reprise,	L"reprise",	L"Reprend le chronomètre du démineur en cours"));
	monVector.push_back(KIWI_MIMIKATZ_LOCAL_MODULE_COMMAND(start,	L"start",	L"Démarre une nouvelle partie"));
	monVector.push_back(KIWI_MIMIKATZ_LOCAL_MODULE_COMMAND(cheat,	L"cheat",	L"Triche au démineur"));
	return monVector;
}

bool mod_mimikatz_winmine::infos(vector<wstring> * arguments)
{
	return infosOrCheat(arguments, false);
}

bool mod_mimikatz_winmine::cheat(vector<wstring> * arguments)
{
	return infosOrCheat(arguments, true);
}

bool mod_mimikatz_winmine::infosOrCheat(vector<wstring> * arguments, bool cheat)
{
	structHandleAndAddr * maStruct = new structHandleAndAddr();
	if(giveHandleAndAddr(maStruct))
	{
		structMonDemineur monDemineur;
		if(mod_memory::readMemory(maStruct->addrMonDemineur, &monDemineur, sizeof(structMonDemineur), maStruct->hWinmine))
		{
			(*outputStream) << L"Mines           : " << monDemineur.nbMines << endl <<
				L"Dimension       : " << monDemineur.hauteur << L" lignes x " << monDemineur.longueur << L" colonnes" << endl <<
				L"Champ           : " << endl << endl;

			for (DWORD y = 1; y <= monDemineur.hauteur; y++)
			{
				if(!cheat)
					(*outputStream) << L'\t';
				
				for(DWORD x = 1; x <= monDemineur.longueur; x++)
				{
					BYTE laCase = monDemineur.tabMines[y][x];
					
					if(!cheat)
						(*outputStream) << L' ' << static_cast<wchar_t>((laCase & 0x80) ? '*' : DISP_WINMINE[laCase & 0x0f]);
					else if(laCase & 0x80)
						monDemineur.tabMines[y][x] = 0x4e;
				}
				if(!cheat)
					(*outputStream) << endl;
			}
		
			if(cheat)
			{
				if(mod_memory::writeMemory(maStruct->addrMonDemineur, &monDemineur, sizeof(structMonDemineur), maStruct->hWinmine))
					(*outputStream) << L"Patché ;)" << endl;

				vector<mod_windows::KIWI_HWND_ENTRY> mesHWNDS;
				if(mod_windows::getHWNDsFromProcessId(&mesHWNDS, maStruct->pidWinmine))
				{
					for(vector<mod_windows::KIWI_HWND_ENTRY>::iterator monHWND = mesHWNDS.begin(); monHWND != mesHWNDS.end(); monHWND++)
					{
						InvalidateRect(monHWND->monHandle, NULL, TRUE);
						UpdateWindow(monHWND->monHandle);
					}
				}
			}
		}
		CloseHandle(maStruct->hWinmine);
	}
	delete maStruct;
	return true;
}


bool mod_mimikatz_winmine::pause(vector<wstring> * arguments)
{
	startThreadAt(FIELD_OFFSET(structHandleAndAddr, addrPause));
	return true;
}

bool mod_mimikatz_winmine::reprise(vector<wstring> * arguments)
{
	startThreadAt(FIELD_OFFSET(structHandleAndAddr, addrResume));
	return true;
}

bool mod_mimikatz_winmine::start(vector<wstring> * arguments)
{
	startThreadAt(FIELD_OFFSET(structHandleAndAddr, addrStart));
	return true;
}

bool mod_mimikatz_winmine::startThreadAt(unsigned long structOffset)
{
	bool reussite = false;
	structHandleAndAddr * maStruct = new structHandleAndAddr();
	if(giveHandleAndAddr(maStruct))
	{
		if (HANDLE hRemoteThread = CreateRemoteThread(maStruct->hWinmine, NULL, 0, *reinterpret_cast<PTHREAD_START_ROUTINE *>(reinterpret_cast<PBYTE>(maStruct) + structOffset), NULL, 0, NULL))
		{
			reussite = true;
			WaitForSingleObject(hRemoteThread, INFINITE);
			CloseHandle(hRemoteThread);
		}
	}
	delete maStruct;
	return reussite;
}

bool mod_mimikatz_winmine::giveHandleAndAddr(structHandleAndAddr * monHandleAndAddr)
{
	BYTE patternStartGame[]	= {0x6a, 0x04, 0xeb, 0x02, 0x6a, 0x06, 0x5b, 0xa3};
	BYTE patternPause[]		= {0x02, 0x75, 0x0a, 0xa1};
	BYTE patternReprise[]	= {0x01, 0x74, 0x0a, 0xa1};
	BYTE patternStart[]		= {0x53, 0x56, 0x57, 0x33, 0xff, 0x3b, 0x05};

	RtlZeroMemory(monHandleAndAddr, sizeof(structHandleAndAddr));
	
	wstring nomDemineur(L"winmine.exe");
	mod_process::KIWI_PROCESSENTRY32 monDemineur;
	if(mod_process::getUniqueForName(&monDemineur, &nomDemineur))
	{
		monHandleAndAddr->pidWinmine = monDemineur.th32ProcessID;
		mod_process::KIWI_MODULEENTRY32 monModule;
		if(mod_process::getUniqueModuleForName(&monModule, NULL, &monDemineur.th32ProcessID))
		{
			PBYTE limit = monModule.modBaseAddr + monModule.modBaseSize, ptrTemp = NULL;
			if(monHandleAndAddr->hWinmine = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, false, monDemineur.th32ProcessID))
			{
				if(mod_memory::searchMemory(monModule.modBaseAddr, limit, patternStartGame, &ptrTemp, sizeof(patternStartGame), true, monHandleAndAddr->hWinmine))
					if(mod_memory::readMemory(ptrTemp + sizeof(patternStartGame), &ptrTemp, sizeof(ULONG), monHandleAndAddr->hWinmine)) // high bits of ptrTemp are already at 00000000
						monHandleAndAddr->addrMonDemineur = reinterpret_cast<structMonDemineur *>(ptrTemp - sizeof(ULONG));
				
				if(mod_memory::searchMemory(monModule.modBaseAddr, limit, patternPause, &ptrTemp, sizeof(patternPause), true, monHandleAndAddr->hWinmine))
					monHandleAndAddr->addrPause = reinterpret_cast<PTHREAD_START_ROUTINE>(ptrTemp - 11);
			
				if(mod_memory::searchMemory(monModule.modBaseAddr, limit, patternReprise, &ptrTemp, sizeof(patternReprise), true, monHandleAndAddr->hWinmine))
					monHandleAndAddr->addrResume = reinterpret_cast<PTHREAD_START_ROUTINE>(ptrTemp - 6);

				if(mod_memory::searchMemory(monModule.modBaseAddr, limit, patternStart, &ptrTemp, sizeof(patternStart), true, monHandleAndAddr->hWinmine))
					monHandleAndAddr->addrStart = reinterpret_cast<PTHREAD_START_ROUTINE>(ptrTemp - 11);
			}
		}
	}

	bool reussite = monHandleAndAddr->hWinmine && monHandleAndAddr->addrMonDemineur && monHandleAndAddr->addrStart && monHandleAndAddr->addrPause && monHandleAndAddr->addrResume;
	
	if(!reussite && monHandleAndAddr->hWinmine)
		CloseHandle(monHandleAndAddr->hWinmine);
	
	return reussite;
}