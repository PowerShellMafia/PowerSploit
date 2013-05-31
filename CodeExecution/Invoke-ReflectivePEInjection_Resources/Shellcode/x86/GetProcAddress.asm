[SECTION .text]

global _start

_start:
	; Save state of ebx and stack
	push ebx
	mov ebx, esp
	
	; Align stack
	and esp, 0xffffffc0

	; Call GetProcAddress
	mov eax, 0x41414141	; DllHandle, supplied by PS
	mov ecx, 0x41414141	; Function name, supplied by PS
	push ecx
	push eax
	mov eax, 0x41414141	; GetProcAddress address, supplied by PS
	call eax

	; Write GetProcAddress return value to an address supplied by PS
	mov ecx, 0x41414141	; Address supplied by PS
	mov [ecx], eax

	; Fix stack
	mov esp, ebx
	pop ebx
	ret
