#pragma once
#include <fltkernel.h>
#include "k_types.h"
#include "modules.h"

#define	INDEX_MF_CALLBACK_OFF		0
#define	INDEX_MF_CALLBACK_PRE_OFF	1
#define	INDEX_MF_CALLBACK_POST_OFF	2
#define	INDEX_MF_VOLUME_NAME_OFF	3
#define MAX_MF_LEN					4

NTSTATUS kMiniFiltersList(LPWSTR pszDest, size_t cbDest, LPWSTR *ppszDestEnd, size_t *pcbRemaining);