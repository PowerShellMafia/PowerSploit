#pragma once
#include <ntifs.h>
#include "k_types.h"
#include "modules.h"
#include "mod_memory.h"
#include "notify_process.h"
#include "notify_thread.h"
#include "notify_image.h"
#include "notify_reg.h"
#include "notify_object.h"

typedef struct _KIWI_CALLBACK
{
	#ifdef _M_IX86
		PVOID unk0;
	#endif
	PVOID * callback;
	LARGE_INTEGER * opt_cookie; // structure de feignant pour les process;threads;images aussi
} KIWI_CALLBACK, *PKIWI_CALLBACK;
