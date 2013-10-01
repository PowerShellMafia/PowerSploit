#pragma once

#include "minifilters.h"
#include "fsfilters.h"
#include "modules.h"
#include "processes.h"
#include "ssdt.h"

#include "notify.h"

#include "k_types.h"

#include <ntddk.h>

extern PSHORT	NtBuildNumber;
ULONG getWindowsIndex();

DRIVER_INITIALIZE	DriverEntry;
DRIVER_UNLOAD		DriverUnload;

DRIVER_DISPATCH		UnSupported;
__drv_dispatchType(IRP_MJ_READ)		DRIVER_DISPATCH Read;
__drv_dispatchType(IRP_MJ_WRITE)	DRIVER_DISPATCH Write;

NTSTATUS getLocalFuncFromName(PWSTR buffer, size_t taille, PWSTR *params, size_t * tailleParams, ptrLocalFunction * destFunc);
NTSTATUS kPing(LPWSTR pszDest, size_t cbDest, LPWSTR *ppszDestEnd, size_t *pcbRemaining);
