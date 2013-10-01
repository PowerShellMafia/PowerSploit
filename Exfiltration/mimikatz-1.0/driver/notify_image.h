#pragma once
#include "notify.h"

#define MAX_NT_PspLoadImageNotifyRoutine		8

ULONG * PspLoadImageNotifyRoutineCount;
PVOID * PspLoadImageNotifyRoutine;

NTSTATUS getPspLoadImageNotifyRoutine();
NTSTATUS kListNotifyImages(LPWSTR pszDest, size_t cbDest, LPWSTR *ppszDestEnd, size_t *pcbRemaining);
