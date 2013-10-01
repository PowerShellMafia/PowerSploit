#pragma once
#include "k_types.h"

NTSTATUS searchMemory(const PUCHAR adresseBase, const PUCHAR adresseMaxMin, const PUCHAR pattern, PUCHAR *addressePattern, SIZE_T longueur);
NTSTATUS genericPointerSearch(PUCHAR *addressePointeur, const PUCHAR adresseBase, const PUCHAR adresseMaxMin, const PUCHAR pattern, SIZE_T longueur, LONG offsetTo);
