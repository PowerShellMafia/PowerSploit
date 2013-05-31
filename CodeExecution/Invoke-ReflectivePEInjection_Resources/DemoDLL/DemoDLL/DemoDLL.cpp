// DemoDLL.cpp : Defines the exported functions for the DLL application.
//

#include "stdafx.h"
#include "DemoDLL.h"

using namespace std;


extern "C" __declspec( dllexport ) char* StringFunc()
{
	ostream *outputStream = NULL;

	//If you want to output to cout, simply set outputStream to &cout. This allows you to write a program that can switch between outputting to string or to cout.
	//outputStream = &cout;

	ostringstream *stringStream = new ostringstream();
	outputStream = stringStream;
	
	(*outputStream) << "String DLL function is working" << endl << endl;

	string output = (*stringStream).str();
	const char* outputStr = output.c_str();

	char* out = new char[output.size()+1];
	strcpy(out, outputStr);
	out[output.size()] = '\0';


	return out;
}

extern "C" __declspec( dllexport ) void VoidFunc()
{
	printf("Void DLL function is working, using printf to display. You will only see this if you run locally.\n\n");
	return;
}

extern "C" __declspec( dllexport ) wchar_t* WStringFunc()
{
	wostream *outputStream = NULL;

	//If you want to output to wcout, simply set outputStream to &cout. This allows you to write a program that can switch between outputting to wstring or to wcout.
	outputStream = &wcout;

	wostringstream *stringStream = new wostringstream();
	outputStream = stringStream;
	
	(*outputStream) << L"WString DLL function is working" << endl << endl;

	wstring output = (*stringStream).str();
	const wchar_t* outputStr = output.c_str();

	wchar_t* out = new wchar_t[output.size()+1];
	wcscpy(out, outputStr);
	out[output.size()] = '\0';


	return out;
}