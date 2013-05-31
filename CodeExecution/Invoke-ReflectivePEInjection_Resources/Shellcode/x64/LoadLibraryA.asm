[SECTION .text]

global _start

_start:
	; Save rsp and setup stack for function call
	push rbx
	mov rbx, rsp
	sub rsp, 0x20
	and sp, 0xffc0

	; Call LoadLibraryA
	mov rcx, 0x4141414141414141	; Ptr to string of library, set by PS
	mov rdx, 0x4141414141414141	; Address of LoadLibrary, set by PS
	call rdx

	mov rdx, 0x4141414141414141	; Ptr to save result, set by PS
	mov [rdx], rax

	; Fix stack
	mov rsp, rbx
	pop rbx
	ret
