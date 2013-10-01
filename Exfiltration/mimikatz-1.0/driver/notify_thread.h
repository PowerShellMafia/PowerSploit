#pragma once
#include "notify.h"

#define MAX_NT6_PspCreateThreadNotifyRoutine	64
#define MAX_NT5_PspCreateThreadNotifyRoutine	8

ULONG * PspCreateThreadNotifyRoutineCount;
PVOID * PspCreateThreadNotifyRoutine;

NTSTATUS getPspCreateThreadNotifyRoutine();
NTSTATUS kListNotifyThreads(LPWSTR pszDest, size_t cbDest, LPWSTR *ppszDestEnd, size_t *pcbRemaining);
