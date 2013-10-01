/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : http://creativecommons.org/licenses/by/3.0/fr/
*/
#include "mod_memory.h"

bool mod_memory::readMemory(const void * adresseBase, void * adresseDestination, size_t longueur, HANDLE handleProcess)
{
	if(handleProcess == INVALID_HANDLE_VALUE)
	{
		return (memcpy_s(adresseDestination, longueur, adresseBase, longueur) == 0);
	}
	else
	{
		SIZE_T dwBytesRead = 0;
		return ((ReadProcessMemory(handleProcess, adresseBase, adresseDestination, longueur, &dwBytesRead) != 0) && (dwBytesRead == longueur));
	}
}

bool mod_memory::writeMemory(void * adresseBase, const void * adresseSource, size_t longueur, HANDLE handleProcess)
{
	bool reussite = false;
	DWORD OldProtect, OldProtect2;

	if(handleProcess == INVALID_HANDLE_VALUE)
	{
		if(VirtualProtect(adresseBase, longueur, PAGE_EXECUTE_READWRITE, &OldProtect) != 0)
		{
			reussite = (memcpy_s(adresseBase, longueur, adresseSource, longueur) == 0);
			VirtualProtect(adresseBase, longueur, OldProtect, &OldProtect2);
		}		
	}
	else
	{
		if(VirtualProtectEx(handleProcess, adresseBase, longueur, PAGE_EXECUTE_READWRITE, &OldProtect) != 0)
		{
			SIZE_T dwBytesWrite = 0;
			reussite = ((WriteProcessMemory(handleProcess, adresseBase, adresseSource, longueur, &dwBytesWrite) != 0) && (dwBytesWrite == longueur));
			VirtualProtectEx(handleProcess, adresseBase, longueur, OldProtect, &OldProtect2);
		}
	}

	return reussite;
}


bool mod_memory::searchMemory(const PBYTE adresseBase, const PBYTE adresseMaxMin, const PBYTE pattern, PBYTE * addressePattern, size_t longueur, bool enAvant, HANDLE handleProcess)
{
	BYTE * monTab = new BYTE[longueur];
	*addressePattern = adresseBase;
	bool succesLecture = true;
	bool succesPattern = false;
	
	while((!adresseMaxMin || (enAvant ? (*addressePattern + longueur) <= adresseMaxMin : (*addressePattern - longueur) >= adresseMaxMin)) && succesLecture && !succesPattern)
	{
		if(succesLecture = readMemory(*addressePattern, monTab, longueur, handleProcess))
		{
			if(!(succesPattern = (memcmp(monTab, pattern, longueur) == 0)))
			{
				*addressePattern += (enAvant ? 1 : -1);
			}
		}
	}
	delete[] monTab;

	if(!succesPattern)
		*addressePattern = NULL;

	return succesPattern;
}

bool mod_memory::searchMemory(const PBYTE adresseBase, const long offsetMaxMin, const PBYTE pattern, long * offsetPattern, size_t longueur, bool enAvant, HANDLE handleProcess)
{
	PBYTE addressePattern = NULL;
	bool resultat = mod_memory::searchMemory(adresseBase, (offsetMaxMin != 0 ? (adresseBase + offsetMaxMin) : NULL), pattern, &addressePattern, longueur, enAvant, handleProcess);
	*offsetPattern =  addressePattern - adresseBase;
	return resultat;
}

bool mod_memory::genericPatternSearch(PBYTE * thePtr, wchar_t * moduleName, BYTE pattern[], ULONG taillePattern, LONG offSetToPtr, char * startFunc, bool enAvant, bool noPtr)
{
	bool resultat = false;
	if(thePtr && pattern && taillePattern)
	{
		if(HMODULE monModule = GetModuleHandle(moduleName))
		{
			MODULEINFO mesInfos;
			if(GetModuleInformation(GetCurrentProcess(), monModule, &mesInfos, sizeof(MODULEINFO)))
			{
				PBYTE addrMonModule = reinterpret_cast<PBYTE>(mesInfos.lpBaseOfDll);

				if(PBYTE addrDebut = startFunc ? reinterpret_cast<PBYTE>(GetProcAddress(monModule, startFunc)) : addrMonModule)
				{
					if(resultat = mod_memory::searchMemory(addrDebut, enAvant ? (addrMonModule + mesInfos.SizeOfImage) : reinterpret_cast<PBYTE>(mesInfos.lpBaseOfDll), pattern, thePtr, taillePattern, enAvant))
					{
						*thePtr += offSetToPtr;
						if(!noPtr)
						{
#ifdef _M_X64
							*thePtr += sizeof(long) + *reinterpret_cast<long *>(*thePtr);
#elif defined _M_IX86
							*thePtr = *reinterpret_cast<PBYTE *>(*thePtr);
#endif
						}
					}
					else *thePtr = NULL;
				}
			}
		}
	}
	return resultat;
}

/*bool mod_memory::WhereIsMyFuckingRelativePattern(const PBYTE adresseBase, const PBYTE addrPattern, const PBYTE maskPattern, PBYTE *addressePattern, size_t longueurMask, const long offsetAddrInMask, const long offset) // et merde je la documente pas celle là !
{
	PBYTE autreAddr = adresseBase;
	PBYTE monMask = new BYTE[longueurMask];
	PBYTE monTab  = new BYTE[longueurMask];

	RtlCopyMemory(monMask, maskPattern, longueurMask);
	bool succesLecture = false, succesPattern = false;
	do
	{
		PBYTE funkyDiff = reinterpret_cast<PBYTE>(addrPattern - (autreAddr + offsetAddrInMask + 4));
		RtlCopyMemory(monMask+offsetAddrInMask, reinterpret_cast<PBYTE>(&funkyDiff), 4);
		succesLecture = readMemory(autreAddr, monTab, longueurMask);
		succesPattern = memcmp(monTab, monMask, longueurMask) == 0;
		autreAddr+=offset;
	} while(!succesPattern && succesLecture);

	delete[] monMask;

	if(succesPattern && succesLecture)
	{
		*addressePattern = autreAddr-offset;
		return true;
	}
	else return false;
}*/
