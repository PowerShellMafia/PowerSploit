#pragma once
#include <ntddk.h>
#include <aux_klib.h>
#include "k_types.h"

NTSTATUS kModulesList(LPWSTR pszDest, size_t cbDest, LPWSTR *ppszDestEnd, size_t *pcbRemaining);
NTSTATUS getModuleFromAddr(ULONG_PTR theAddr, LPWSTR pszDest, size_t cbDest, LPWSTR *ppszDestEnd, size_t *pcbRemaining);