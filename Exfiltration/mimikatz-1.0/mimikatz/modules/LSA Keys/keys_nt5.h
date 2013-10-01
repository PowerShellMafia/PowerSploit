/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence    : http://creativecommons.org/licenses/by/3.0/fr/
	Ce fichier : http://creativecommons.org/licenses/by/3.0/fr/
*/
#pragma once
#include "../mod_mimikatz_sekurlsa.h"

class mod_mimikatz_sekurlsa_keys_nt5 {

private:
	static PBYTE *g_pRandomKey, *g_pDESXKey;
public:
	static bool searchAndInitLSASSData();
	static bool uninitLSASSData();
};
