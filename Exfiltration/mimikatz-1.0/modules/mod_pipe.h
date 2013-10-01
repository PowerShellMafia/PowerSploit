/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : http://creativecommons.org/licenses/by/3.0/fr/
*/
#pragma once
#include "globdefs.h"

class mod_pipe
{
private:
	HANDLE hPipe;
	wstring pipePath;

public:
	mod_pipe(wstring pipeName = L"mimikatz\\kiwi", wstring serveur = L".");
	virtual ~mod_pipe(void);

	bool closePipe();

	bool readFromPipe(wstring &laReponse);
	bool writeToPipe(const wstring &leMessage);

	bool createServer();
	bool createClient();

	bool isConnected();
};

