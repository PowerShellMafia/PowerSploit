/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : http://creativecommons.org/licenses/by/3.0/fr/
*/
#pragma once
#include "globdefs.h"
#include "secpkg.h"
#include "mod_ntddk.h"
#include "mod_memory.h"
#include "mod_text.h"
#include <security.h>
#include <tlhelp32.h>

class mod_process
{
public:
	typedef struct _KIWI_IAT_MODULE
	{
		PVOID ptrToFunc;
		PVOID ptrFunc;
		WORD Ordinal;		
		string funcName;
	} KIWI_IAT_MODULE, *PKIWI_IAT_MODULE;

	typedef struct _KIWI_PROCESSENTRY32
	{
		DWORD   dwSize;
		DWORD   cntUsage;
		DWORD   th32ProcessID;          // this process
		ULONG_PTR th32DefaultHeapID;
		DWORD   th32ModuleID;           // associated exe
		DWORD   cntThreads;
		DWORD   th32ParentProcessID;    // this process's parent process
		LONG    pcPriClassBase;         // Base priority of process's threads
		DWORD   dwFlags;
		wstring	szExeFile;    // Path
	} KIWI_PROCESSENTRY32, *PKIWI_PROCESSENTRY32;

	typedef struct _KIWI_MODULEENTRY32
	{
		DWORD   dwSize;
		DWORD   th32ModuleID;       // This module
		DWORD   th32ProcessID;      // owning process
		DWORD   GlblcntUsage;       // Global usage count on the module
		DWORD   ProccntUsage;       // Module usage count in th32ProcessID's context
		BYTE  * modBaseAddr;        // Base address of module in th32ProcessID's context
		DWORD   modBaseSize;        // Size in bytes of module starting at modBaseAddr
		HMODULE hModule;            // The hModule of this module in th32ProcessID's context
		wstring	szModule;
		wstring	szExePath;
	} KIWI_MODULEENTRY32, *PKIWI_MODULEENTRY32;

	typedef struct _KIWI_VERY_BASIC_MODULEENTRY
	{
		BYTE  * modBaseAddr;        // Base address of module in th32ProcessID's context
		DWORD   modBaseSize;        // Size in bytes of module starting at modBaseAddr
		wstring	szModule;
	} KIWI_VERY_BASIC_MODULEENTRY, *PKIWI_VERY_BASIC_MODULEENTRY;

	static bool getList(vector<KIWI_PROCESSENTRY32> * maProcessesvector, wstring * processName = NULL);
	static bool getUniqueForName(KIWI_PROCESSENTRY32 * monProcess, wstring * processName);

	static bool start(wstring * maCommandLine, PROCESS_INFORMATION * mesInfosProcess, bool paused = false, bool aUsurper = false, HANDLE leToken = NULL);
	static bool suspend(DWORD & processId);
	static bool resume(DWORD & processId);
	static bool stop(DWORD & processId, DWORD exitCode = 0);
	
	static bool debug(DWORD & processId);

	static bool getAuthentificationIdFromProcessId(DWORD & processId, LUID & AuthentificationId);
	static bool getModulesListForProcessId(vector<KIWI_MODULEENTRY32> * maModulevector, DWORD * processId = NULL);
	static bool getVeryBasicModulesListForProcess(vector<KIWI_VERY_BASIC_MODULEENTRY> * monModuleVector, HANDLE processHandle = INVALID_HANDLE_VALUE);
	static bool getUniqueModuleForName(KIWI_MODULEENTRY32 * monModule, wstring * moduleName = NULL, DWORD * processId = NULL); 

	static bool getProcessEntryFromProcessId(DWORD processId, KIWI_PROCESSENTRY32 * processKiwi, vector<mod_process::KIWI_PROCESSENTRY32> * mesProcess = NULL);

	static bool getProcessBasicInformation(PROCESS_BASIC_INFORMATION * mesInfos, HANDLE processHandle = INVALID_HANDLE_VALUE);
	static bool getPeb(PEB * peb, HANDLE processHandle = INVALID_HANDLE_VALUE);
	static bool getIAT(PBYTE ptrBaseAddr, vector<pair<string, vector<KIWI_IAT_MODULE>>> * monIAT, HANDLE handleProcess = INVALID_HANDLE_VALUE);

	static wstring getUnicodeStringOfProcess(UNICODE_STRING * ptrString, HANDLE process = INVALID_HANDLE_VALUE, PLSA_PROTECT_MEMORY unProtectFunction = NULL);
	static bool getUnicodeStringOfProcess(UNICODE_STRING * ptrString, BYTE ** monBuffer, HANDLE process, PLSA_PROTECT_MEMORY unProtectFunction = NULL);
};
