[SECTION .text]

global _start

_start:
	; Save state of rbx and stack
	push rbx
	mov rbx, rsp

	; Set up stack for function call to GetProcAddress
	sub rsp, 0x20
	and sp, 0xffc0

	; Call getprocaddress
	mov rcx, 0x4141414141414141	; DllHandle, set by PS
	mov rdx, 0x4141414141414141	; Ptr to FuncName string, set by PS
	mov rax, 0x4141414141414141	; GetProcAddress address, set by PS
	call rax

	; Store the result
	mov rcx, 0x4141414141414141	; Ptr to buffer to save result,set by PS
	mov [rcx], rax

	; Restore stack
	mov rsp, rbx
	pop rbx
	ret
