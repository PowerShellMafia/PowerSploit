/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : http://creativecommons.org/licenses/by/3.0/fr/
*/
#pragma once
#include "globdefs.h"
#include "mod_process.h"
#include "mod_memory.h"
#include "mod_system.h"
#include <iostream>

class mod_mimikatz_minesweeper
{
private:
	typedef struct _STRUCT_MINESWEEPER_REF_ELEMENT {
		DWORD nbElements;
		DWORD unk0;
		DWORD unk1;
		PVOID elements;
		DWORD unk2;
		DWORD unk3;
	} STRUCT_MINESWEEPER_REF_ELEMENT, *PSTRUCT_MINESWEEPER_REF_ELEMENT;

	typedef struct _STRUCT_MINESWEEPER_BOARD {
		PVOID Serializer;
		DWORD nbMines;
		DWORD nbLignes;
		DWORD nbColonnes;
		DWORD unk0;
		DWORD unk1;
		DWORD unk2;
		DWORD unk3;
		DWORD unk4;
		DWORD unk5;
		DWORD unk6;
		DWORD unk7;
		DWORD unk8;
		DWORD unk9;
#ifdef _M_X64
		DWORD unk_x64;
#endif
		DWORD unk10;
		PVOID unk11;
		PSTRUCT_MINESWEEPER_REF_ELEMENT	ref_visibles;
		PSTRUCT_MINESWEEPER_REF_ELEMENT	ref_mines;
		DWORD unk12;
		DWORD unk13;
	} STRUCT_MINESWEEPER_BOARD, *PSTRUCT_MINESWEEPER_BOARD;

	typedef struct _STRUCT_MINESWEEPER_GAME {
		PVOID Serializer;
		//PVOID pGameStat; on 7x86
		PVOID pNodeBase;
		PVOID pBoardCanvas;
		PSTRUCT_MINESWEEPER_BOARD pBoard;
		PSTRUCT_MINESWEEPER_BOARD pBoard_WIN7x86;
	} STRUCT_MINESWEEPER_GAME, *PSTRUCT_MINESWEEPER_GAME;

	typedef struct structHandleAndAddr{
		HANDLE hMineSweeper;
		DWORD pidMineSweeper;
		PVOID G;
	} structHandleAndAddr;

	static bool giveHandleAndAddr(structHandleAndAddr * monHandleAndAddr);
	static bool parseField(structHandleAndAddr * monHandleAndAddr, PSTRUCT_MINESWEEPER_REF_ELEMENT laBase, char ** monTableau, bool isVisible = true);

public:
	static vector<KIWI_MIMIKATZ_LOCAL_MODULE_COMMAND> getMimiKatzCommands();
	static bool infos(vector<wstring> * arguments);
};
