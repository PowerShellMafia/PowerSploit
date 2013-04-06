// The following ifdef block is the standard way of creating macros which make exporting 
// from a DLL simpler. All files within this DLL are compiled with the DEMODLL_EXPORTS
// symbol defined on the command line. This symbol should not be defined on any project
// that uses this DLL. This way any other project whose source files include this file see 
// DEMODLL_API functions as being imported from a DLL, whereas this DLL sees symbols
// defined with this macro as being exported.
#ifdef DEMODLL_EXPORTS
#define DEMODLL_API __declspec(dllexport)
#else
#define DEMODLL_API __declspec(dllimport)
#endif

using namespace std;

extern "C" __declspec( dllexport ) char* StringFunc();
extern "C" __declspec( dllexport ) void VoidFunc();
extern "C" __declspec( dllexport ) wchar_t* WStringFunc();