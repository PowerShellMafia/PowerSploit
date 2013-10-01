/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : http://creativecommons.org/licenses/by/3.0/fr/
*/
#pragma once
#include "globdefs.h"
#include "mod_parseur.h"
#include "mod_pipe.h"
#include "mod_process.h"
#include "mod_system.h"

#include "modules/mod_mimikatz_standard.h"
#include "modules/mod_mimikatz_crypto.h"
#include "modules/mod_mimikatz_hash.h"
#include "modules/mod_mimikatz_system.h"
#include "modules/mod_mimikatz_process.h"
#include "modules/mod_mimikatz_thread.h"
#include "modules/mod_mimikatz_service.h"
#include "modules/mod_mimikatz_privilege.h"
#include "modules/mod_mimikatz_handle.h"
#include "modules/mod_mimikatz_winmine.h"
#include "modules/mod_mimikatz_minesweeper.h"
#include "modules/mod_mimikatz_nogpo.h"
#include "modules/mod_mimikatz_samdump.h"
#include "modules/mod_mimikatz_inject.h"
#include "modules/mod_mimikatz_terminalserver.h"
#include "modules/mod_mimikatz_divers.h"
#include "modules/mod_mimikatz_impersonate.h"
#include "modules/mod_mimikatz_sekurlsa.h"
#include "modules/mod_mimikatz_efs.h"
#include "global.h"

class mimikatz
{
private:
	static vector<KIWI_MIMIKATZ_LOCAL_MODULE_COMMAND> getMimiKatzCommands();
	vector<KIWI_MIMIKATZ_LOCAL_MODULE> mesModules;
	bool initLocalModules();
	bool tryToDispatch(wstring * maLigne);
	bool doCommandeLocale(wstring * fonction, vector<wstring> * arguments);
	bool doCommandeDistante(std::wstring &commande);
	bool doCommandeKernel(std::wstring &commande);

	bool openKernel();
	bool closeKernel();

	void listModules();
	void listCommandes(vector<KIWI_MIMIKATZ_LOCAL_MODULE>::iterator monModule);

	HANDLE Kmimikatz;

public:
	mimikatz(vector<wstring> * mesArguments = NULL);
	virtual ~mimikatz(void);
};

