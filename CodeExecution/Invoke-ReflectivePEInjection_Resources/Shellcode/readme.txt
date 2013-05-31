This contains the assembly code I used to build the shellcode the PowerShell script uses. Some of the assembly isn't included beause I didn't save it, this should just be for the SUPER easy stuff like moving an address to EAX and returning.

Compile:
x64:
nasm -f elf64 FileName.asm
ld -o FileName FileName.o
objdump -M intel -d FileName

x86:
nasm FileName.asm
ld -o FileName FileName.o
objdump -M intel -d FileName