[SECTION .text]
global _start

_start:
	; Set a var to 1, let PS know the EXE is exiting
	mov ebx, 0x41414141
	mov [ebx], byte 0x01

	; Call exitthread instead of exit process
	sub esp, 0x20
	and esp, 0xFFFFFFc0 ; Needed for stack alignment
	mov ebx, 0x41414141
	call ebx
