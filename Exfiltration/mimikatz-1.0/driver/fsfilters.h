#pragma once
#include <ntifs.h>
#include "k_types.h"

NTSTATUS kFiltersList(LPWSTR pszDest, size_t cbDest, LPWSTR *ppszDestEnd, size_t *pcbRemaining);