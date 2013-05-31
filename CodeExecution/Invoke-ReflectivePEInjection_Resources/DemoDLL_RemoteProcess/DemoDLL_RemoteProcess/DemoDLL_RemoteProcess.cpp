// DemoDLL_RemoteProcess.cpp : Defines the exported functions for the DLL application.
//

#include "stdafx.h"

using namespace std;

extern "C" __declspec( dllexport ) void VoidFunc();


extern "C" __declspec( dllexport ) void VoidFunc()
{
	ofstream myfile;
	_mkdir("c:\\ReflectiveLoaderTest");
	myfile.open ("c:\\ReflectiveLoaderTest\\DllVoidFunction.txt");
	myfile << "Dll Void function successfully called.\n";
	myfile.close();
	return;
}