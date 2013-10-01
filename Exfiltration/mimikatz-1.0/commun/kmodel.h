/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : http://creativecommons.org/licenses/by/3.0/fr/
*/
#pragma once
#include "globdefs.h"
#include "mod_pipe.h"
#include "mod_parseur.h"

#define __kextdll extern "C" __declspec(dllexport)

typedef bool (__cdecl * ptrFunction) (mod_pipe * monPipe, vector<wstring> * mesArguments);
typedef bool (__cdecl * ptrFunctionString) (wstring * maDescription);

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved);
DWORD WINAPI ThreadProc(LPVOID lpParameter);

bool sendTo(mod_pipe * monPipe, wstring message);

__kextdll bool __cdecl ping(mod_pipe * monPipe, vector<wstring> * mesArguments);
