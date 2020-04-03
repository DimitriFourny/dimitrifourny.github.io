---
layout: post
title:  "Writing Optimized Windows Shellcode"
---

You always have a lot of possibilities when you make a shellcode payload, 
especially on Windows. Do you need to write all your ASM manually or can you be 
helped by your compiler? Do I need to directly use syscall or to search the 
functions in memory? Because it’s not always simple to make it, I have made the 
decision to write an article about that. I have the habit to do all the work in 
C and compile it with Visual Studio: the source code is nicer in C, the compiler 
do a better job to optimize it and you can implement your own obfuscator with 
LLVM if you want.

For this example, I will work on a x86 shellcode. Of course this can be totally 
applied to a x86_64 shellcode or for another processor.


# Find the basics DLL
## Introduction

When a shellcode payload is loaded in Windows, the first step is to locate the 
functions that we will use. We start by searching the Dynamic Link Library 
(*DLL*) where the function is stored. To do that, we will need to use different 
structures that I will describe in the following sections.


## Thread Environment Block

The *TEB* is a structure used by Windows to describe a thread. Each thread can 
access to his own *TEB* by using the register `FS` on x86 platform and `GS` on 
x86_64 platform. The *TEB* has the following structure:

```
0:000> dt ntdll!_TEB
    +0x000 NtTib            : _NT_TIB
    +0x01c EnvironmentPointer : Ptr32 Void
    +0x020 ClientId         : _CLIENT_ID
    +0x028 ActiveRpcHandle  : Ptr32 Void
    +0x02c ThreadLocalStoragePointer : Ptr32 Void
    +0x030 ProcessEnvironmentBlock : Ptr32 _PEB
    ...
    +0xff0 EffectiveContainerId : _GUID
```

In consequence, if you want access to the PEB, you just need to do:

```c
PEB* getPeb() {
    __asm {
        mov eax, fs:[0x30];
    }
}
```


## Process Environment Block

If the *TEB* gives information about a thread, the *PEB* will give us 
information about the process itself. And the information that we need is the 
location of the basics DLL. In fact, when a process is loaded in memory by 
Windows, at least two DLL are mapped:

- `ntdll.dll`, which contain the functions which do the syscall. They begin all 
    with the prefix `Nt*` and are just calling the `Zw*` equivalent in the kernel
- `kernel32.dll`, which use the NTDLL functions in a higher level. For example, 
    `kernel32!CreateFileA` will call `ntdll!NtCreateFileW` which will call 
    `ntoskrnl!ZwCreateFileW`.

On some Windows version, others DLL can be already be present in memory but to 
be perfectly portable we will just assume that these two DLL are the only DLL 
already loaded.

Let’s take a look at the *TEB* structure:

```
0:000> dt nt!_PEB 
    +0x000 InheritedAddressSpace : UChar
    +0x001 ReadImageFileExecOptions : UChar
    +0x002 BeingDebugged    : UChar
    +0x003 BitField         : UChar
    +0x003 ImageUsesLargePages : Pos 0, 1 Bit
    +0x003 IsProtectedProcess : Pos 1, 1 Bit
    +0x003 IsImageDynamicallyRelocated : Pos 2, 1 Bit
    +0x003 SkipPatchingUser32Forwarders : Pos 3, 1 Bit
    +0x003 IsPackagedProcess : Pos 4, 1 Bit
    +0x003 IsAppContainer   : Pos 5, 1 Bit
    +0x003 IsProtectedProcessLight : Pos 6, 1 Bit
    +0x003 IsLongPathAwareProcess : Pos 7, 1 Bit
    +0x004 Mutant           : Ptr32 Void
    +0x008 ImageBaseAddress : Ptr32 Void
    +0x00c Ldr              : Ptr32 _PEB_LDR_DATA
    ...
    +0x25c WaitOnAddressHashTable : [128] Ptr32 Void
```

You can see that we have `PEB.BeingDebugged`, which is used by 
`IsDebuggerPresent()`. But the interesting part for us is that we have `PEB.Ldr` 
which corresponds to the following structure:

```
0:000> dt nt!_PEB_LDR_DATA
    +0x000 Length           : Uint4B
    +0x004 Initialized      : UChar
    +0x008 SsHandle         : Ptr32 Void
    +0x00c InLoadOrderModuleList : _LIST_ENTRY
    +0x014 InMemoryOrderModuleList : _LIST_ENTRY
    +0x01c InInitializationOrderModuleList : _LIST_ENTRY
    +0x024 EntryInProgress  : Ptr32 Void
    +0x028 ShutdownInProgress : UChar
    +0x02c ShutdownThreadId : Ptr32 Void
```

Like we can see by its name, `PEB.Ldr->In*OrderModuleList` are chained list 
(`LIST_ENTRY`) which contains all the DLL already loaded in memory. The three 
lists point on the same objects but in a different order. I prefer to use 
`InLoadOrderModuleList` because you can use `InLoadOrderModuleList.Flink` 
directly like a pointer to `_LDR_DATA_TABLE_ENTRY`. For example, if you want to 
use `InMemoryOrderModuleList`, the `LDR_DATA_TABLE_ENTRY` will be at the 
position `_InMemoryOrderModuleList.Flink-0x10` because 
`InMemoryOrderModuleList.Flink` point to the next `InMemoryOrderModuleList`. 
Each chained list element can be seen like the following structure:

```
0:000> dt nt!_LDR_DATA_TABLE_ENTRY
    +0x000 InLoadOrderLinks : _LIST_ENTRY
    +0x008 InMemoryOrderLinks : _LIST_ENTRY
    +0x010 InInitializationOrderLinks : _LIST_ENTRY
    +0x018 DllBase          : Ptr32 Void
    +0x01c EntryPoint       : Ptr32 Void
    +0x020 SizeOfImage      : Uint4B
    +0x024 FullDllName      : _UNICODE_STRING
    +0x02c BaseDllName      : _UNICODE_STRING
    ...
    +0x0a0 DependentLoadFlags : Uint4B
```

`BaseDllName` will contain the name of the DLL (e.g.: `ntdll.dll`) and `DllBase` 
will contain the addresses where the DLL is located in memory. Traditionnaly, 
the first element in `InLoadOrderModuleList` is the executable itself, and after 
we can found *NTDLL* and *KERNEL32*. But we are not always sure that they are in 
this order in all Windows version so it’s always better to base our research on 
the DLL name (which can be in uppercase or in lowercase).


## DJB Hash

Like I have said before, we will not trust the DLL orders and we will do our 
research based on the DLL name. But in a shellcode, it’s not always a good idea 
to use ASCII strings or worst, an UNICODE string: it will just make our 
shellcode bigger! So I recommend you to use a hash system to compare the DLL 
name. I will use a DJB hash because it’s a simple and sufficient hash:

```c
DWORD djbHashW(wchar_t* str) {
    unsigned int hash = 5381;
    unsigned int i = 0;

    for (i = 0; str[i] != 0; i++) {
        hash = ((hash << 5) + hash) + str[i];
    }

    return hash;
}
```

Due to the fact that the dll name can be in uppercase or lowercase, it’s a good 
idea to support it in your hash algorithm to have something like this:

```
djbHashW(L"ntdll.dll") == djbHashW(L"NTDLL.DLL")
```


## Code

Now that we have spoken about how to do it, it’s time to code our idea:

```c
typedef struct _LSA_UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} LSA_UNICODE_STRING, *PLSA_UNICODE_STRING, UNICODE_STRING, *PUNICODE_STRING;

typedef struct _LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY              InLoadOrderModuleList;
    LIST_ENTRY              InMemoryOrderModuleList;
    LIST_ENTRY              InInitializationOrderModuleList;
    PVOID                   BaseAddress;
    PVOID                   EntryPoint;
    ULONG                   SizeOfImage;
    UNICODE_STRING          FullDllName;
    UNICODE_STRING          BaseDllName;
    ULONG                   Flags;
    SHORT                   LoadCount;
    SHORT                   TlsIndex;
    LIST_ENTRY              HashTableEntry;
    ULONG                   TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

typedef struct _PEB_LDR_DATA {
    ULONG      Length;
    ULONG      Initialized;
    ULONG      SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _RTL_USER_PROCESS_PARAMETERS {
    BYTE           Reserved1[16];
    PVOID          Reserved2[10];
    UNICODE_STRING ImagePathName;
    UNICODE_STRING CommandLine;
} RTL_USER_PROCESS_PARAMETERS, *PRTL_USER_PROCESS_PARAMETERS;

typedef struct _PEB {
    BYTE                          Reserved1[2];
    BYTE                          BeingDebugged;
    BYTE                          Reserved2[1];
    PVOID                         Reserved3[2];
    PPEB_LDR_DATA                 Ldr;
    PRTL_USER_PROCESS_PARAMETERS  ProcessParameters;
    BYTE                          Reserved4[104];
    PVOID                         Reserved5[52];
    PVOID                         PostProcessInitRoutine;
    BYTE                          Reserved6[128];
    PVOID                         Reserved7[1];
    ULONG                         SessionId;
} PEB, *PPEB;

DWORD getDllByName(DWORD dllHash) {
  PEB* peb = getPeb();
  PPEB_LDR_DATA Ldr = peb->Ldr;
  PLDR_DATA_TABLE_ENTRY moduleList = (PLDR_DATA_TABLE_ENTRY)Ldr->InLoadOrderModuleList.Flink;

  wchar_t* pBaseDllName = moduleList->BaseDllName.Buffer;
  wchar_t* pFirstDllName = moduleList->BaseDllName.Buffer;

  do {
     if (pBaseDllName != NULL) {
        if (djbHashW(pBaseDllName) == dllHash) {
           return (DWORD)moduleList->BaseAddress;
        }
     }

     moduleList = (PLDR_DATA_TABLE_ENTRY)moduleList->InLoadOrderModuleList.Flink;
     pBaseDllName = moduleList->BaseDllName.Buffer;
  } while (pBaseDllName != pFirstDllName);

  return 0;
}
```

And if you want to use other DLLs, you will just need to load them with 
`LoadLibrary()`. Don’t worry, we will do that in our shellcode with `user32.dll`.


# Function address
## Introduction

Now that we have the DLL, we will need to search where are our functions in the 
DLL memory. Fortunately for us, it’s not really difficult with a good PE headers 
comprehension. Always keep in mind that when we talk about the PE headers, the 
majority of the addresses are relative to the executable address.


## Portable Executable headers

At the beginning of executable we have the DOS header, but it’s mainly here for 
historic part:

```
0:000> dt nt!_IMAGE_DOS_HEADER
    +0x000 e_magic          : Uint2B
    +0x002 e_cblp           : Uint2B
    +0x004 e_cp             : Uint2B
    +0x006 e_crlc           : Uint2B
    +0x008 e_cparhdr        : Uint2B
    +0x00a e_minalloc       : Uint2B
    +0x00c e_maxalloc       : Uint2B
    +0x00e e_ss             : Uint2B
    +0x010 e_sp             : Uint2B
    +0x012 e_csum           : Uint2B
    +0x014 e_ip             : Uint2B
    +0x016 e_cs             : Uint2B
    +0x018 e_lfarlc         : Uint2B
    +0x01a e_ovno           : Uint2B
    +0x01c e_res            : [4] Uint2B
    +0x024 e_oemid          : Uint2B
    +0x026 e_oeminfo        : Uint2B
    +0x028 e_res2           : [10] Uint2B
    +0x03c e_lfanew         : Int4B
```

The element `e_lfanew` will indicate the position of the NT headers. You will 
need to do `pFile + e_lfanew` because it’s a relative address.

```
0:000> dt -r1 nt!_IMAGE_NT_HEADERS
    +0x000 Signature        : Uint4B
    +0x004 FileHeader       : _IMAGE_FILE_HEADER
        +0x000 Machine          : Uint2B
        +0x002 NumberOfSections : Uint2B
        +0x004 TimeDateStamp    : Uint4B
        +0x008 PointerToSymbolTable : Uint4B
        +0x00c NumberOfSymbols  : Uint4B
        +0x010 SizeOfOptionalHeader : Uint2B
        +0x012 Characteristics  : Uint2B
    +0x018 OptionalHeader   : _IMAGE_OPTIONAL_HEADER
        +0x000 Magic            : Uint2B
        +0x002 MajorLinkerVersion : UChar
        +0x003 MinorLinkerVersion : UChar
        +0x004 SizeOfCode       : Uint4B
        +0x008 SizeOfInitializedData : Uint4B
        +0x00c SizeOfUninitializedData : Uint4B
        +0x010 AddressOfEntryPoint : Uint4B
        +0x014 BaseOfCode       : Uint4B
        +0x018 BaseOfData       : Uint4B
        +0x01c ImageBase        : Uint4B
        +0x020 SectionAlignment : Uint4B
        +0x024 FileAlignment    : Uint4B
        +0x028 MajorOperatingSystemVersion : Uint2B
        +0x02a MinorOperatingSystemVersion : Uint2B
        +0x02c MajorImageVersion : Uint2B
        +0x02e MinorImageVersion : Uint2B
        +0x030 MajorSubsystemVersion : Uint2B
        +0x032 MinorSubsystemVersion : Uint2B
        +0x034 Win32VersionValue : Uint4B
        +0x038 SizeOfImage      : Uint4B
        +0x03c SizeOfHeaders    : Uint4B
        +0x040 CheckSum         : Uint4B
        +0x044 Subsystem        : Uint2B
        +0x046 DllCharacteristics : Uint2B
        +0x048 SizeOfStackReserve : Uint4B
        +0x04c SizeOfStackCommit : Uint4B
        +0x050 SizeOfHeapReserve : Uint4B
        +0x054 SizeOfHeapCommit : Uint4B
        +0x058 LoaderFlags      : Uint4B
        +0x05c NumberOfRvaAndSizes : Uint4B
        +0x060 DataDirectory    : [16] _IMAGE_DATA_DIRECTORY
```

The data directory contain the addresses of some interesting members, and for us 
it contains above all the addresses of the exported functions.

```
0:000> dt nt!_IMAGE_DATA_DIRECTORY
    +0x000 VirtualAddress   : Uint4B
    +0x004 Size             : Uint4B
```

So we can use `DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress` to 
directly have the address of the export directory:

```c
typedef struct _IMAGE_EXPORT_DIRECTORY {
    DWORD   Characteristics;
    DWORD   TimeDateStamp;
    WORD    MajorVersion;
    WORD    MinorVersion;
    DWORD   Name;
    DWORD   Base;
    DWORD   NumberOfFunctions;
    DWORD   NumberOfNames;
    DWORD   AddressOfFunctions;     
    DWORD   AddressOfNames;         
    DWORD   AddressOfNameOrdinals;  
} IMAGE_EXPORT_DIRECTORY, *PIMAGE_EXPORT_DIRECTORY;
```

A function can be exported by name or by ordinal. In consequence, three arrays 
are kept updated:

- `AddressOfFunctions`, which keep the function’s addresses ordered by ordinal
- `AddressOfNames`, which keep the function names
- `AddressOfNameOrdinals`, which keep the ordinals. This array is in the same 
    order than the `AddressOfNames` array.

In consequence, if we want the function address based on its name, we will 
browse all the names in `AddressOfFunctions` and use the array index in the 
`AddressOfNameOrdinals[index]`. This will give us an ordinal that we can use in 
`AddressOfFunctions[ordinal]`. We can resume that with a pseudo code:

```c
int i = 0;
while (AddressOfNames[i] != searchedName) {
    i++;
}

return AddressOfFunctions[ AddressOfNamesOrdinals[i] ];
```

## Code

Like when we search the DLL, we will use the DJB hash (but with ASCII strings 
this time):

```c
PVOID getFunctionAddr(DWORD dwModule, DWORD functionHash) {
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)dwModule;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((DWORD)dosHeader + dosHeader->e_lfanew);
    PIMAGE_DATA_DIRECTORY dataDirectory = &ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (dataDirectory->VirtualAddress == 0) {
        return NULL;
    }

    PIMAGE_EXPORT_DIRECTORY exportDirectory = (PIMAGE_EXPORT_DIRECTORY)(dwModule + dataDirectory->VirtualAddress);
    PDWORD ardwNames = (PDWORD)(dwModule + exportDirectory->AddressOfNames);
    PWORD arwNameOrdinals = (PWORD)(dwModule + exportDirectory->AddressOfNameOrdinals);
    PDWORD ardwAddressFunctions = (PDWORD)(dwModule + exportDirectory->AddressOfFunctions);
    char* szName = 0;
    WORD wOrdinal = 0;

    for (unsigned int i = 0; i < exportDirectory->NumberOfNames; i++) {
        szName = (char*)(dwModule + ardwNames[i]);

        if (djbHash(szName) == functionHash) {
            wOrdinal = arwNameOrdinals[i];
            return (PVOID)(dwModule + ardwAddressFunctions[wOrdinal]);
        }
    }

    return NULL;
}
```


# Compilation
## Final code

We have talked about the important structures and the algorithm that we will use. Let’s see how to generate our shellcode.

```c
#pragma comment(linker, "/ENTRY:main")

#include "makestr.h"
#include "peb.h"

typedef HMODULE (WINAPI* _LoadLibraryA)(LPCSTR lpFileName);
typedef int (WINAPI* _MessageBoxA)(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType);

int main();
DWORD getDllByName(DWORD dllHash);
PVOID getFunctionAddr(DWORD dwModule, DWORD functionHash);
DWORD djbHash(char* str);
DWORD djbHashW(wchar_t* str);

int main() {
    DWORD hashKernel32 = 0x6DDB9555; // djbHashW(L"KERNEL32.DLL");
    DWORD hKernel32 = getDllByName(hashKernel32);
    if (hKernel32 == 0) {
        return 1;
    }

    DWORD hashLoadLibraryA = 0x5FBFF0FB; // djbHash("LoadLibraryA");
    _LoadLibraryA xLoadLibraryA = getFunctionAddr(hKernel32, hashLoadLibraryA);
    if (xLoadLibraryA == NULL) {
        return 1;
    }

    char szUser32[] = MAKESTR("user32.dll", 10);
    DWORD hUser32 = xLoadLibraryA(szUser32);
    if (hUser32 == 0) {
        return 1;
    }

    DWORD hashMessageBoxA = 0x384F14B4; // djbHash("MessageBoxA");
    _MessageBoxA xMessageBoxA = getFunctionAddr(hUser32, hashMessageBoxA);
    if (xMessageBoxA == NULL) {
        return 1;
    }

    char szMessage[] = MAKESTR("Hello World", 11);
    char szTitle[] = MAKESTR(":)", 2);
    xMessageBoxA(0, szMessage, szTitle, MB_OK|MB_ICONINFORMATION);

    return 0;
}

inline PEB* getPeb() {
    __asm {
        mov eax, fs:[0x30];
    }
}

DWORD djbHash(char* str) {
    unsigned int hash = 5381;
    unsigned int i = 0;

    for (i = 0; str[i] != 0; i++) {
        hash = ((hash << 5) + hash) + str[i];
    }

    return hash;
}
DWORD djbHashW(wchar_t* str) {
    unsigned int hash = 5381;
    unsigned int i = 0;

    for (i = 0; str[i] != 0; i++) {
        hash = ((hash << 5) + hash) + str[i];
    }

    return hash;
}

DWORD getDllByName(DWORD dllHash) {
    PEB* peb = getPeb();
    PPEB_LDR_DATA Ldr = peb->Ldr;
    PLDR_DATA_TABLE_ENTRY moduleList = (PLDR_DATA_TABLE_ENTRY)Ldr->InLoadOrderModuleList.Flink;

    wchar_t* pBaseDllName = moduleList->BaseDllName.Buffer;
    wchar_t* pFirstDllName = moduleList->BaseDllName.Buffer;

    do {
        if (pBaseDllName != NULL) {
            if (djbHashW(pBaseDllName) == dllHash) {
                return (DWORD)moduleList->BaseAddress;
            }
        }

        moduleList = (PLDR_DATA_TABLE_ENTRY)moduleList->InLoadOrderModuleList.Flink;
        pBaseDllName = moduleList->BaseDllName.Buffer;
    } while (pBaseDllName != pFirstDllName);

    return 0;
}

PVOID getFunctionAddr(DWORD dwModule, DWORD functionHash) {
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)dwModule;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((DWORD)dosHeader + dosHeader->e_lfanew);
    PIMAGE_DATA_DIRECTORY dataDirectory = &ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (dataDirectory->VirtualAddress == 0) {
        return NULL;
    }


    PIMAGE_EXPORT_DIRECTORY exportDirectory = (PIMAGE_EXPORT_DIRECTORY)(dwModule + dataDirectory->VirtualAddress);
    PDWORD ardwNames = (PDWORD)(dwModule + exportDirectory->AddressOfNames);
    PWORD arwNameOrdinals = (PWORD)(dwModule + exportDirectory->AddressOfNameOrdinals);
    PDWORD ardwAddressFunctions = (PDWORD)(dwModule + exportDirectory->AddressOfFunctions);
    char* szName = 0;
    WORD wOrdinal = 0;

    for (unsigned int i = 0; i < exportDirectory->NumberOfNames; i++) {
        szName = (char*)(dwModule + ardwNames[i]);

        if (djbHash(szName) == functionHash) {
            wOrdinal = arwNameOrdinals[i];
            return (PVOID)(dwModule + ardwAddressFunctions[wOrdinal]);
        }
    }

    return NULL;
}
```

The order of the functions declarations is very important: it will define the 
compilation order. In consequence, if we want to call the shellcode directly, 
it’s a good idea to declare in first our main function because it will be our 
entry point. I don’t know if it’s a specificity of Visual Studio or if all 
compilers do the same thing.

The ASCII string use the define `MAKESTR` to declare the string like an array. 
It will force the string to be allocated like this:

```nasm
mov  dword ptr [ebp+szUser32],   72657375h   ; user
mov  dword ptr [ebp+szUser32+4], 642E3233h   ; 32.d
mov  word ptr [ebp+szUser32+8],  6C6Ch       ; ll
mov  [ebp+szUser32+0Ah], 0                   ; '\x00'
```

And the code is generated by a Python script because it’s really redundant:

```c
#pragma once

#define MAKESTR(s, length) MAKESTR_##length(s)

/*
for i in range(1,51):
    s = "#define MAKESTR_%d(s) {" % i
    for j in range(i):
        s += "s[%d]," % j
    s += "0}"

    print(s)
*/

#define MAKESTR_1(s) {s[0],0}
#define MAKESTR_2(s) {s[0],s[1],0}
#define MAKESTR_3(s) {s[0],s[1],s[2],0}
#define MAKESTR_4(s) {s[0],s[1],s[2],s[3],0}
#define MAKESTR_5(s) {s[0],s[1],s[2],s[3],s[4],0}
#define MAKESTR_6(s) {s[0],s[1],s[2],s[3],s[4],s[5],0}
#define MAKESTR_7(s) {s[0],s[1],s[2],s[3],s[4],s[5],s[6],0}
#define MAKESTR_8(s) {s[0],s[1],s[2],s[3],s[4],s[5],s[6],s[7],0}
#define MAKESTR_9(s) {s[0],s[1],s[2],s[3],s[4],s[5],s[6],s[7],s[8],0}
#define MAKESTR_10(s) {s[0],s[1],s[2],s[3],s[4],s[5],s[6],s[7],s[8],s[9],0}
#define MAKESTR_11(s) {s[0],s[1],s[2],s[3],s[4],s[5],s[6],s[7],s[8],s[9],s[10],0}
```


## Compilation configuration

I use Visual Studio 2017, but I think it’s the same options in the others 
versions:

```
C / C++
    Optimisation
        Reduce the size /O1
        Smaller code /Os
    Code generation
        Disable security verifications /GS-
Linker
    Entries
        Ignore all the defaults libraries /NODEFAULTLIB
```

I get a *~3kB* file. To extract the shellcode from the file, a simple 
disassembler will do the job.


## Shellcode

The shellcode has a size of 339 bytes but the biggest part is the functions 
loading and the DLL research. In consequence, even if you have a bigger program, 
the shellcode will not be a lot bigger. Our shellcode is very simple because it 
only show a message box, but you can transform this in a downloader with few 
efforts for example.

```c
#include <Windows.h>

typedef void(__stdcall* _function)();

char shellcode[] = 
    "\x55\x8B\xEC\x83\xEC\x1C\x53\x56\x57\x64\xA1\x30\x00\x00\x00\x8B"
    "\x40\x0C\x8B\x50\x0C\x8B\x4A\x30\x8B\xD9\x85\xC9\x74\x29\x0F\xB7"
    "\x01\x33\xFF\xBE\x05\x15\x00\x00\x66\x85\xC0\x74\x1A\x6B\xF6\x21"
    "\x0F\xB7\xC0\x03\xF0\x47\x0F\xB7\x04\x79\x66\x85\xC0\x75\xEE\x81"
    "\xFE\x55\x95\xDB\x6D\x74\x17\x8B\x12\x8B\x4A\x30\x3B\xCB\x75\xCA"
    "\x33\xC9\x5F\x5E\x5B\x85\xC9\x75\x0A\x33\xC0\x40\xEB\x74\x8B\x4A"
    "\x18\xEB\xEF\xBA\xFB\xF0\xBF\x5F\xE8\x69\x00\x00\x00\x85\xC0\x74"
    "\xE8\x8D\x4D\xF0\xC7\x45\xF0\x75\x73\x65\x72\x51\xC7\x45\xF4\x33"
    "\x32\x2E\x64\x66\xC7\x45\xF8\x6C\x6C\xC6\x45\xFA\x00\xFF\xD0\x85"
    "\xC0\x74\xC6\xBA\xB4\x14\x4F\x38\x8B\xC8\xE8\x37\x00\x00\x00\x85"
    "\xC0\x74\xB6\x6A\x40\x8D\x4D\xFC\xC7\x45\xE4\x48\x65\x6C\x6C\x51"
    "\x8D\x4D\xE4\xC7\x45\xE8\x6F\x20\x57\x6F\x51\x6A\x00\xC7\x45\xEC"
    "\x72\x6C\x64\x00\x66\xC7\x45\xFC\x3A\x29\xC6\x45\xFE\x00\xFF\xD0"
    "\x33\xC0\x8B\xE5\x5D\xC3\x55\x8B\xEC\x83\xEC\x10\x8B\x41\x3C\x89"
    "\x55\xFC\x8B\x44\x08\x78\x85\xC0\x74\x56\x8B\x54\x08\x1C\x53\x8B"
    "\x5C\x08\x24\x03\xD1\x56\x8B\x74\x08\x20\x03\xD9\x8B\x44\x08\x18"
    "\x03\xF1\x89\x55\xF0\x33\xD2\x89\x75\xF4\x89\x45\xF8\x57\x85\xC0"
    "\x74\x29\x8B\x34\x96\xBF\x05\x15\x00\x00\x03\xF1\xEB\x09\x6B\xFF"
    "\x21\x0F\xBE\xC0\x03\xF8\x46\x8A\x06\x84\xC0\x75\xF1\x3B\x7D\xFC"
    "\x74\x12\x8B\x75\xF4\x42\x3B\x55\xF8\x72\xD7\x33\xC0\x5F\x5E\x5B"
    "\x8B\xE5\x5D\xC3\x0F\xB7\x04\x53\x8B\x55\xF0\x8B\x04\x82\x03\xC1"
    "\xEB\xEB";

int main() {
    char* payload = (char*) VirtualAlloc(NULL, sizeof(shellcode), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    memcpy(payload, shellcode, sizeof(shellcode));

    _function function = (_function)payload;
    function();

    return 0;
}
```
