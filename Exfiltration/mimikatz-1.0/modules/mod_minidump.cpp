/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : http://creativecommons.org/licenses/by/3.0/fr/
*/
#include "mod_minidump.h"

mod_minidump::mod_minidump() : monFichier(NULL), monFileMapping(NULL), mesDonnees(NULL)
{
}

mod_minidump::~mod_minidump(void)
{
	if(mesDonnees)
		UnmapViewOfFile(mesDonnees);

	if(monFileMapping)
		CloseHandle(monFileMapping);

	if(monFichier)
		CloseHandle(monFichier);
}

LPVOID mod_minidump::RVAtoPTR(RVA monRVA)
{
	return reinterpret_cast<PBYTE>(mesDonnees) + monRVA;
}

bool mod_minidump::open(wchar_t * filename)
{
	bool resultat = false;

	if(monFichier = CreateFile(filename, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL))
		if(monFileMapping = CreateFileMapping(monFichier, NULL, PAGE_READONLY, 0, 0, NULL))
			if(mesDonnees = MapViewOfFile(monFileMapping, FILE_MAP_READ, 0, 0, 0))
				resultat = (reinterpret_cast<PMINIDUMP_HEADER>(mesDonnees)->Signature == MINIDUMP_SIGNATURE) && (static_cast<WORD>(reinterpret_cast<PMINIDUMP_HEADER>(mesDonnees)->Version) == MINIDUMP_VERSION);

	return resultat;
}

MINIDUMP_TYPE mod_minidump::getFlags()
{
	return static_cast<MINIDUMP_TYPE>(reinterpret_cast<PMINIDUMP_HEADER>(mesDonnees)->Flags);
}

const wchar_t *FlagsString[] = {
	L"MiniDumpNormal",
	L"MiniDumpWithDataSegs",
	L"MiniDumpWithFullMemory",
	L"MiniDumpWithHandleData",
	L"MiniDumpFilterMemory",
	L"MiniDumpScanMemory",
	L"MiniDumpWithUnloadedModules",
	L"MiniDumpWithIndirectlyReferencedMemory",
	L"MiniDumpFilterModulePaths",
	L"MiniDumpWithProcessThreadData",
	L"MiniDumpWithPrivateReadWriteMemory",
	L"MiniDumpWithoutOptionalData",
	L"MiniDumpWithFullMemoryInfo",
	L"MiniDumpWithThreadInfo",
	L"MiniDumpWithCodeSegs",
	L"MiniDumpWithoutAuxiliaryState",
	L"MiniDumpWithFullAuxiliaryState",
	L"MiniDumpWithPrivateWriteCopyMemory",
	L"MiniDumpIgnoreInaccessibleMemory",
	L"MiniDumpWithTokenInformation"
};

bool mod_minidump::FlagsToStrings(vector<wstring> * monVecteur)
{
	return FlagsToStrings(getFlags(), monVecteur);
}

bool mod_minidump::FlagsToStrings(MINIDUMP_TYPE Flags, vector<wstring> * monVecteur)
{
	bool resultat = false;

	if(!Flags)
	{
		monVecteur->push_back(FlagsString[0]);
		resultat = true;
	}
	else if(Flags & MiniDumpValidTypeFlags)
	{
		DWORD shift, i;
		for(shift = MiniDumpWithDataSegs, i = 1; shift <= MiniDumpWithTokenInformation; shift<<=1, i++)
		{
			if((Flags & shift) == shift)
				monVecteur->push_back(FlagsString[i]);
		}
		resultat = true;
	}

	return resultat;
}

LPVOID mod_minidump::getStream(MINIDUMP_STREAM_TYPE type)
{
	PMINIDUMP_DIRECTORY mesRepertoires =  reinterpret_cast<PMINIDUMP_DIRECTORY>(RVAtoPTR(reinterpret_cast<PMINIDUMP_HEADER>(mesDonnees)->StreamDirectoryRva));
	for(DWORD i = 0; i < reinterpret_cast<PMINIDUMP_HEADER>(mesDonnees)->NumberOfStreams; i++)
	{
		if(mesRepertoires[i].StreamType == type)
			return RVAtoPTR(mesRepertoires[i].Location.Rva);
	}
	return NULL;
}

PMINIDUMP_MODULE mod_minidump::getMinidumpModule(wstring & nomModule)
{
	if(PMINIDUMP_MODULE_LIST monObject = reinterpret_cast<PMINIDUMP_MODULE_LIST>(getStream(ModuleListStream)))
	{
		for(DWORD i = 0; i < monObject->NumberOfModules; i++)
		{
			PMINIDUMP_MODULE monModule = &monObject->Modules[i];
			PMINIDUMP_STRING monModuleString = reinterpret_cast<PMINIDUMP_STRING>(RVAtoPTR(monObject->Modules[i].ModuleNameRva));
			if(mod_text::wstr_ends_with(monModuleString->Buffer, monModuleString->Length / sizeof(wchar_t), nomModule.c_str(), nomModule.size()))
				return monModule;
		}
	}	
	return NULL;
}

bool mod_minidump::getStreamsVector(vector<PMINIDUMP_DIRECTORY> * monVecteur)
{
	PMINIDUMP_DIRECTORY mesRepertoires =  reinterpret_cast<PMINIDUMP_DIRECTORY>(RVAtoPTR(reinterpret_cast<PMINIDUMP_HEADER>(mesDonnees)->StreamDirectoryRva));
	for(DWORD i = 0; i < reinterpret_cast<PMINIDUMP_HEADER>(mesDonnees)->NumberOfStreams; monVecteur->push_back(&mesRepertoires[i++]));
	return true;
}

const wchar_t *StreamTypeString[] = {
	L"UnusedStream",
	L"ReservedStream0",
	L"ReservedStream1",
	L"ThreadListStream",
	L"ModuleListStream",
	L"MemoryListStream",
	L"ExceptionStream",
	L"SystemInfoStream",
	L"ThreadExListStream",
	L"Memory64ListStream",
	L"CommentStreamA",
	L"CommentStreamW",
	L"HandleDataStream",
	L"FunctionTableStream",
	L"UnloadedModuleListStream",
	L"MiscInfoStream",
	L"MemoryInfoListStream",
	L"ThreadInfoListStream",
	L"HandleOperationListStream",
	L"TokenStream"
};

wstring mod_minidump::StreamTypeToString(MINIDUMP_STREAM_TYPE monType)
{
	if(monType <= TokenStream)
		return StreamTypeString[monType];
	else
	{
		wostringstream monStream;
		monStream << L"Inconnu (" << monType << L")";
		return monStream.str();
	}
}