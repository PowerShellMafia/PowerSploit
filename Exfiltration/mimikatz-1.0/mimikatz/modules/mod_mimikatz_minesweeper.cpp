/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : http://creativecommons.org/licenses/by/3.0/fr/
*/
#include "mod_mimikatz_minesweeper.h"
#include "..\global.h"

char DISP_MINESWEEPER[] = "012345678.F? !!";

vector<KIWI_MIMIKATZ_LOCAL_MODULE_COMMAND> mod_mimikatz_minesweeper::getMimiKatzCommands()
{
	vector<KIWI_MIMIKATZ_LOCAL_MODULE_COMMAND> monVector;
	monVector.push_back(KIWI_MIMIKATZ_LOCAL_MODULE_COMMAND(infos,	L"infos",	L"Obtient des informations sur le démineur en cours"));
	return monVector;
}

bool mod_mimikatz_minesweeper::infos(vector<wstring> * arguments)
{
	structHandleAndAddr * maStruct = new structHandleAndAddr();
	if(giveHandleAndAddr(maStruct))
	{
		STRUCT_MINESWEEPER_GAME monGame;
		if(mod_memory::readMemory(maStruct->G, &monGame, sizeof(STRUCT_MINESWEEPER_GAME), maStruct->hMineSweeper))
		{
#ifdef _M_IX86
			if(mod_system::GLOB_Version.dwBuildNumber >= 7000)
				monGame.pBoard = monGame.pBoard_WIN7x86;
#endif
			STRUCT_MINESWEEPER_BOARD monBoard;
			if(mod_memory::readMemory(monGame.pBoard, &monBoard, sizeof(STRUCT_MINESWEEPER_BOARD), maStruct->hMineSweeper))
			{
				(*outputStream) << L"Mines           : " << monBoard.nbMines << endl <<
					L"Dimension       : " << monBoard.nbLignes << L" lignes x " << monBoard.nbColonnes << L" colonnes" << endl <<
					L"Champ           : " << endl << endl;

				char ** monTableau;
				monTableau = new char*[monBoard.nbLignes];
				for(DWORD l = 0; l < monBoard.nbLignes; l++)
					monTableau[l] = new char[monBoard.nbColonnes];
					
				parseField(maStruct, monBoard.ref_visibles, monTableau, true);
				parseField(maStruct, monBoard.ref_mines, monTableau, false);

				for(DWORD l = 0; l < monBoard.nbLignes; l++)
				{
					(*outputStream) << L'\t';
					for(DWORD c = 0; c < monBoard.nbColonnes; c++)
						(*outputStream) << monTableau[l][c] << L' ';
					(*outputStream) << endl;
					delete[] monTableau[l];
				}
				delete[] monTableau;
			} else (*outputStream) << L"Impossible de lire les données du plateau" << endl;
		} else (*outputStream) << L"Impossible de lire les données du jeu" << endl;
		CloseHandle(maStruct->hMineSweeper);
	}
	delete maStruct;

	return true;
}

bool mod_mimikatz_minesweeper::parseField(structHandleAndAddr * monHandleAndAddr, PSTRUCT_MINESWEEPER_REF_ELEMENT laBase, char ** monTableau, bool isVisible)
{
	DWORD tailleElementFinal = isVisible ? sizeof(DWORD) : sizeof(BYTE);
	
	STRUCT_MINESWEEPER_REF_ELEMENT maRefElements;
	if(mod_memory::readMemory(laBase, &maRefElements, sizeof(STRUCT_MINESWEEPER_REF_ELEMENT), monHandleAndAddr->hMineSweeper))
	{
		PSTRUCT_MINESWEEPER_REF_ELEMENT * ref_colonnes_elements = new PSTRUCT_MINESWEEPER_REF_ELEMENT[maRefElements.nbElements];
		if(mod_memory::readMemory(maRefElements.elements, ref_colonnes_elements, maRefElements.nbElements * sizeof(PSTRUCT_MINESWEEPER_REF_ELEMENT), monHandleAndAddr->hMineSweeper))
		{
			for(DWORD c = 0; c < maRefElements.nbElements; c++)
			{
				STRUCT_MINESWEEPER_REF_ELEMENT maRefColonneElement;	
				if(mod_memory::readMemory(ref_colonnes_elements[c], &maRefColonneElement, sizeof(STRUCT_MINESWEEPER_REF_ELEMENT), monHandleAndAddr->hMineSweeper))
				{		
					void * cellules = isVisible ? reinterpret_cast<void *>(new DWORD[maRefColonneElement.nbElements]) : reinterpret_cast<void *>(new BYTE[maRefColonneElement.nbElements]);
					if(mod_memory::readMemory(maRefColonneElement.elements, cellules, maRefColonneElement.nbElements * tailleElementFinal, monHandleAndAddr->hMineSweeper))
					{	
						for(DWORD l = 0; l < maRefColonneElement.nbElements; l++)
						{
							if(isVisible)
								monTableau[l][c] = DISP_MINESWEEPER[reinterpret_cast<DWORD *>(cellules)[l]];
							else
								if(reinterpret_cast<BYTE *>(cellules)[l]) monTableau[l][c] = '*';
						}
					} else (*outputStream) << L"Impossible de lire les élements de la colonne : "  << c << endl;
					delete[] cellules;
				} else (*outputStream) << L"Impossible de lire les références de la colonne : "  << c << endl;
			}
		} else (*outputStream) << L"Impossible de lire les références des colonnes" << endl;
		delete[] ref_colonnes_elements;
	} else (*outputStream) << L"Impossible de lire les références de l\'élement" << endl;

	return true;
}

bool mod_mimikatz_minesweeper::giveHandleAndAddr(structHandleAndAddr * monHandleAndAddr)
{
#ifdef _M_X64
	BYTE PTRN_WIN6_Game_SafeGetSingleton[] = {0x48, 0x89, 0x44, 0x24, 0x70, 0x48, 0x85, 0xc0, 0x74, 0x0a, 0x48, 0x8b, 0xc8, 0xe8};
	LONG OFFS_WIN6_ToG	= -(5 + 5 + 6 + 4 + 1);
#elif defined _M_IX86
	BYTE PTRN_WIN6_Game_SafeGetSingleton[] = {0x84, 0xc0, 0x75, 0x07, 0x6a, 0x67, 0xe8};
	LONG OFFS_WIN6_ToG	= sizeof(PTRN_WIN6_Game_SafeGetSingleton) + 4 + 1;
#endif
	RtlZeroMemory(monHandleAndAddr, sizeof(structHandleAndAddr));

	wstring nomDemineur(L"minesweeper.exe");
	mod_process::KIWI_PROCESSENTRY32 monDemineur;
	if(mod_process::getUniqueForName(&monDemineur, &nomDemineur))
	{
		monHandleAndAddr->pidMineSweeper = monDemineur.th32ProcessID;
		mod_process::KIWI_MODULEENTRY32 monModule;
		if(mod_process::getUniqueModuleForName(&monModule, NULL, &monDemineur.th32ProcessID))
		{
			PBYTE limit = monModule.modBaseAddr + monModule.modBaseSize, ptrTemp = NULL;
			if(monHandleAndAddr->hMineSweeper = OpenProcess(PROCESS_VM_READ, false, monHandleAndAddr->pidMineSweeper))
				if(mod_memory::searchMemory(monModule.modBaseAddr, limit, PTRN_WIN6_Game_SafeGetSingleton, &ptrTemp, sizeof(PTRN_WIN6_Game_SafeGetSingleton), true, monHandleAndAddr->hMineSweeper))
				{
#ifdef _M_X64
					long offsetTemp = 0;
					if(mod_memory::readMemory(ptrTemp + OFFS_WIN6_ToG, &offsetTemp, sizeof(offsetTemp), monHandleAndAddr->hMineSweeper))
						mod_memory::readMemory((ptrTemp + OFFS_WIN6_ToG) + sizeof(long) + offsetTemp + 1, &monHandleAndAddr->G, sizeof(monHandleAndAddr->G), monHandleAndAddr->hMineSweeper);
#elif defined _M_IX86
					if(mod_memory::readMemory(ptrTemp + OFFS_WIN6_ToG, &ptrTemp, sizeof(ptrTemp), monHandleAndAddr->hMineSweeper))
						mod_memory::readMemory(ptrTemp, &monHandleAndAddr->G, sizeof(monHandleAndAddr->G), monHandleAndAddr->hMineSweeper);
#endif
				}
		}
	}

	bool reussite = monHandleAndAddr->hMineSweeper && monHandleAndAddr->G;

	if(!reussite && monHandleAndAddr->hMineSweeper)
		CloseHandle(monHandleAndAddr->hMineSweeper);

	return reussite;
}