[SECTION .text]
global _start

_start:
	; Get stack setup
	push ebx
	mov ebx, esp
	and esp, 0xfffffff0
	
	; Call DllMain
	mov ecx, 0x41414141		; DLLHandle, set by PowerShell
	mov edx, 0x1			; PROCESS_ATTACH
	mov eax, 0x0			; NULL
	push eax
	push edx
	push ecx
	mov eax, 0x41414141		; Address of DllMain, set by PS
	call eax

	; Fix stack
	mov esp, ebx
	pop ebx
	ret
