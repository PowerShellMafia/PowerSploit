/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : http://creativecommons.org/licenses/by/3.0/fr/
*/
#pragma once
#include "globdefs.h"
#include <dbghelp.h>
#include "mod_text.h"

class mod_minidump
{
private:
	HANDLE monFichier, monFileMapping;
	LPVOID mesDonnees;

public:
	mod_minidump();
	virtual ~mod_minidump(void);

	LPVOID RVAtoPTR(RVA monRVA);
	bool open(wchar_t * filename);
	LPVOID getStream(MINIDUMP_STREAM_TYPE type);

	PMINIDUMP_MODULE getMinidumpModule(wstring & nomModule);
	bool getStreamsVector(vector<PMINIDUMP_DIRECTORY> * monVecteur);
	MINIDUMP_TYPE getFlags();
	bool FlagsToStrings(vector<wstring> * monVecteur);


	static wstring StreamTypeToString(MINIDUMP_STREAM_TYPE monType);
	static bool FlagsToStrings(MINIDUMP_TYPE Flags, vector<wstring> * monVecteur);
};
