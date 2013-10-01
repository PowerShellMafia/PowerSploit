#pragma once
#include "k_types.h"
#include "mod_memory.h"
#include "modules.h"

NTSTATUS kSSDT(LPWSTR pszDest, size_t cbDest, LPWSTR *ppszDestEnd, size_t *pcbRemaining);

#ifdef _M_IX86
	extern PSERVICE_DESCRIPTOR_TABLE	KeServiceDescriptorTable;
#else
	PSERVICE_DESCRIPTOR_TABLE	KeServiceDescriptorTable;
	NTSTATUS getKeServiceDescriptorTable();
#endif
