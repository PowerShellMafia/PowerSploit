[SECTION .text]
global _start

_start:
	; Get stack setup
	push rbx
	mov rbx, rsp
	and sp, 0xff00
	
	; Call DllMain
	mov rcx, 0x4141414141414141	; DLLHandle, set by PowerShell
	mov rdx, 0x1			; PROCESS_ATTACH
	mov r8, 0x0			; NULL
	mov rax, 0x4141414141414141	; Address of DllMain, set by PS
	call rax

	; Fix stack
	mov rsp, rbx
	pop rbx
	ret
