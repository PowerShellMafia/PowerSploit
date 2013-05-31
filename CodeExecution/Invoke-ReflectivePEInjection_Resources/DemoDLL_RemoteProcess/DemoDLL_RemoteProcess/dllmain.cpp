// dllmain.cpp : Defines the entry point for the DLL application.
#include "stdafx.h"

using namespace std;

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
					 )
{
	ofstream myfile;

	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
			_mkdir("c:\\ReflectiveLoaderTest");
			myfile.open ("c:\\ReflectiveLoaderTest\\DllMain.txt");
			myfile << "DllMain successfully called.\n";
			myfile.close();
		break;
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}

