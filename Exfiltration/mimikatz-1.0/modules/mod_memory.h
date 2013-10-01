/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : http://creativecommons.org/licenses/by/3.0/fr/
*/
#pragma once
#include "globdefs.h"
#include <psapi.h>

class mod_memory
{
public:
	static bool readMemory(const void * adresseBase, void * adresseDestination,	size_t longueur = 1, HANDLE handleProcess = INVALID_HANDLE_VALUE);
	static bool writeMemory(void * adresseBase, const void * adresseSource,		size_t longueur = 1, HANDLE handleProcess = INVALID_HANDLE_VALUE);

	static bool searchMemory(const PBYTE adresseBase, const PBYTE adresseMaxMin, const PBYTE pattern, PBYTE * addressePattern, size_t longueur = 1, bool enAvant = true, HANDLE handleProcess = INVALID_HANDLE_VALUE);
	static bool searchMemory(const PBYTE adresseBase, const long offsetMaxMin,   const PBYTE pattern, long  * offsetPattern,   size_t longueur = 1, bool enAvant = true, HANDLE handleProcess = INVALID_HANDLE_VALUE);

	static bool genericPatternSearch(PBYTE * thePtr, wchar_t * moduleName, BYTE pattern[], ULONG taillePattern, LONG offSetToPtr, char * startFunc = NULL, bool enAvant = true, bool noPtr = false);

	/*static bool WhereIsMyFuckingRelativePattern(const PBYTE adresseBase, const PBYTE addrPattern, const PBYTE maskPattern, PBYTE *addressePattern, size_t longueurMask, const long offsetAddrInMask, const long offset = 1); // et merde je la documente pas celle là !*/
};
