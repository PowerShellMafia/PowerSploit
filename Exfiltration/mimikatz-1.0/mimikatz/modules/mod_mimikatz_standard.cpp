/*	Benjamin DELPY `gentilkiwi`
http://blog.gentilkiwi.com
benjamin@gentilkiwi.com
Licence : http://creativecommons.org/licenses/by/3.0/fr/
*/
#include "mod_mimikatz_standard.h"
#include "..\global.h"

vector<KIWI_MIMIKATZ_LOCAL_MODULE_COMMAND> mod_mimikatz_standard::getMimiKatzCommands()
{
	vector<KIWI_MIMIKATZ_LOCAL_MODULE_COMMAND> monVector;
	monVector.push_back(KIWI_MIMIKATZ_LOCAL_MODULE_COMMAND(clearScreen,	L"cls",		L"Efface l\'écran (ne fonctionne pas en éxecution distante, via PsExec par exemple)"));
	monVector.push_back(KIWI_MIMIKATZ_LOCAL_MODULE_COMMAND(exit,		L"exit",	L"Quitte MimiKatz"));
	monVector.push_back(KIWI_MIMIKATZ_LOCAL_MODULE_COMMAND(reponse,		L"reponse",	L"Calcule la réponse à la Grande Question sur la Vie, l\'Univers et le Reste"));
	monVector.push_back(KIWI_MIMIKATZ_LOCAL_MODULE_COMMAND(cite,		L"cite",	L"Trouve une citation"));
	monVector.push_back(KIWI_MIMIKATZ_LOCAL_MODULE_COMMAND(version,		L"version",	L"Retourne la version de mimikatz"));
	monVector.push_back(KIWI_MIMIKATZ_LOCAL_MODULE_COMMAND(sleep,		L"sleep",	L"Mets en pause mimikatz un certains nombre de millisecondes"));
	//monVector.push_back(KIWI_MIMIKATZ_LOCAL_MODULE_COMMAND(test,		L"test",	L"Routine de test (ne devrait plus être là en release..."));
	return monVector;
}

/*bool mod_mimikatz_standard::test(vector<wstring> * arguments)
{
	return true;
}*/

bool mod_mimikatz_standard::version(vector<wstring> * arguments)
{
	(*outputStream) << MIMIKATZ_FULL << L" (" << __DATE__ << L' ' << __TIME__ << L')' << endl;
	return true;
}

bool mod_mimikatz_standard::clearScreen(vector<wstring> * arguments)
{
	HANDLE hStdOut = GetStdHandle(STD_OUTPUT_HANDLE);
	COORD coord = {0, 0};
	DWORD count;

	CONSOLE_SCREEN_BUFFER_INFO csbi;
	GetConsoleScreenBufferInfo(hStdOut, &csbi);

	FillConsoleOutputCharacter(hStdOut, L' ', csbi.dwSize.X * csbi.dwSize.Y, coord, &count);
	SetConsoleCursorPosition(hStdOut, coord);

	return true;
}

bool mod_mimikatz_standard::exit(vector<wstring> * arguments)
{
	return false;
}

bool mod_mimikatz_standard::reponse(vector<wstring> * arguments)
{
	(*outputStream) << L"La réponse est 42." << endl;
	return true;
}

bool mod_mimikatz_standard::cite(vector<wstring> * arguments)
{
	(*outputStream) << L"I edit the world in HEX" << endl;
	return true;
}

bool mod_mimikatz_standard::sleep(vector<wstring> * arguments)
{
	DWORD dwMilliseconds = 1000;
	if(!arguments->empty())
	{
		wstringstream z;
		z << arguments->front(); z >> dwMilliseconds;
	}
	(*outputStream) << L"Sleep : " << dwMilliseconds << L" ms... " << flush;
	Sleep(dwMilliseconds);
	(*outputStream) << L"Fin !" << endl;
	return true;
}
