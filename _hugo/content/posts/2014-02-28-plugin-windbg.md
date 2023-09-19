---
date: 2014-02-28
title: "Make a plugin for WinDbg"
url: /2014/02/28/plugin-windbg.html
---

WinDbg is a powerfull Windows debugger, it can debug x86 application and x64 
application, in user-land or in kernel-land. Despite its useful commands, we 
would like to make some plugin to do a faster and better debugging session. 
Fortunately for us, it's possible to write WinDbg plugins in C or C++ to add a 
lot of commands in our favorite debugger.

<!--more-->

I will use C++, but it's possible to use another language if this language
support the DLL creation. With Python, you can use PyKd. The plugin that you
will be able to code after this article and with a little documentation looks
like that:

```
0:004> !load C:\Users\Dimitri\Desktop\DbgDf0\Release\DbgDf0.dll

0:004> !df0 mod
Image Base 	Size 		ASLR    DEP     Safe SEH    Module Name 
0x00400000 	0x001C0000	Yes     Yes     No          HxD.exe 
0x77820000 	0x00180000	Yes     Yes     No          ntdll.dll 
0x75930000 	0x00110000	Yes     Yes     Yes         kernel32.dll 
0x753E0000 	0x00047000	Yes     Yes     Yes         KERNELBASE.dll 
0x77300000 	0x00100000	Yes     Yes     Yes         user32.dll 
0x75FA0000 	0x00090000	Yes     Yes     Yes         GDI32.dll 
0x76100000 	0x0000A000	Yes     Yes     Yes         LPK.dll 
0x761C0000 	0x0009D000	Yes     Yes     Yes         USP10.dll 
0x76110000 	0x000AC000	Yes     Yes     Yes         msvcrt.dll 
0x75EA0000 	0x000A0000	Yes     Yes     Yes         ADVAPI32.dll 
0x77400000 	0x00019000	Yes     Yes     Yes         sechost.dll 
0x75690000 	0x000F0000	Yes     Yes     Yes         RPCRT4.dll 
0x75380000 	0x00060000	Yes     Yes     Yes         SspiCli.dll 
0x75370000 	0x0000C000	Yes     Yes     Yes         CRYPTBASE.dll 
0x75430000 	0x0008F000	Yes     Yes     Yes         oleaut32.dll 
0x76260000 	0x0015C000	Yes     Yes     Yes         ole32.dll 
0x752A0000 	0x00009000	Yes     Yes     Yes         version.dll 
0x72820000 	0x0019E000	Yes     Yes     Yes         comctl32.dll 
0x75F40000 	0x00057000	Yes     Yes     Yes         SHLWAPI.dll 
0x76680000 	0x00C49000	Yes     Yes     Yes         shell32.dll 
0x754D0000 	0x000F5000	Yes     Yes     Yes         wininet.dll 
0x75D60000 	0x00136000	Yes     Yes     Yes         urlmon.dll 
0x75810000 	0x0011E000	Yes     Yes     Yes         CRYPT32.dll 
0x76670000 	0x0000C000	Yes     Yes     Yes         MSASN1.dll 
0x763E0000 	0x001FF000	Yes     Yes     Yes         iertutil.dll 
0x75630000 	0x00060000	Yes     Yes     Yes         imm32.dll 
0x76030000 	0x000CC000	Yes     Yes     Yes         MSCTF.dll 
0x75240000 	0x00051000	Yes     Yes     Yes         winspool.drv 
0x75CE0000 	0x0007B000	Yes     Yes     Yes         comdlg32.dll 
0x71FD0000 	0x00032000	Yes     Yes     Yes         winmm.dll 
0x10000000 	0x0005A000	Yes     Yes     Yes         guard32.dll 
0x75230000 	0x00007000	Yes     Yes     Yes         fltlib.dll 
0x71E90000 	0x00080000	Yes     Yes     Yes         uxtheme.dll 
0x71E70000 	0x00013000	Yes     Yes     Yes         dwmapi.dll 
0x754C0000 	0x00005000	Yes     Yes     No          PSAPI.dll 
0x71CE0000 	0x00005000	Yes     Yes     Yes         msimg32.dll 
0x75B00000 	0x0019D000	Yes     Yes     Yes         SETUPAPI.dll 
0x75A40000 	0x00027000	Yes     Yes     Yes         CFGMGR32.dll 
0x763C0000 	0x00012000	Yes     Yes     Yes         DEVOBJ.dll 
0x765E0000 	0x00083000	Yes     Yes     Yes         CLBCatQ.DLL 
0x71D30000 	0x000F5000	Yes     Yes     Yes         propsys.dll 
0x75200000 	0x00021000	Yes     Yes     Yes         ntmarta.dll 
0x755D0000 	0x00045000	Yes     Yes     Yes         WLDAP32.dll 

0:004> !unload DbgDf0
Unloading C:\Users\Dimitri\Desktop\DbgDf0\Release\DbgDf0.dll extension DLL
```

This command looks in *the Process Environment Block (PEB)* the module list in 
memory and check if ASLR, DEP or SafeSEH is activated on these modules. An 
useful functionality! So, after that, you can add a ROP gadgets searcher for 
example to save a precious time.


## Bases

First of all, you need to know that a WinDbg plugin is just a DLL which export 
by name its functions. Some exported functions are needed for WinDbg to load our
plugin, and the others are just our commands! Let me show you an example with my 
DbgDf0 plugin:

```c
extern "C" {
	_declspec(dllexport) VOID CheckVersion();
	_declspec(dllexport) LPEXT_API_VERSION ExtensionApiVersion();
	_declspec(dllexport) VOID WinDbgExtensionDllInit(PWINDBG_EXTENSION_APIS lpExtensionApis, USHORT usMajorVersion, USHORT usMinorVersion);
	_declspec(dllexport) DECLARE_API(df0);
}
```

The first is `CheckVersion()`, it's optional and it helps you to check the 
WinDbg version and show a warning if you don't have the correct version. 
Personnally, I never implement this function but I have implemented it to show 
you that it's possible.
Another function, `ExtensionApiVersion()`, is required and return the plugin 
version. An example with `ExtensionApiVersion()` wich return 1.0.0:

```
0:003> .chain
Extension DLL search Path:
    ...
Extension DLL chain:
    C:\Users\Dimitri\Desktop\DbgDf0\Release\DbgDf0.dll: API 1.0.0, built Fri Feb 28 19:24:19 2014
        [path: C:\Users\Dimitri\Desktop\DbgDf0\Release\DbgDf0.dll]
```

The next function, `WinDbgExtensionDllInit()` is required and important because 
it saves a pointer to WinDbg API list. Finally, `DECLARE_API(df0)` is our 
function that we can call with `!df0` in WinDbg:

```c
#define DECLARE_API(s)                             \
    VOID										   \
    s(                                             \
        HANDLE                 hCurrentProcess,    \
        HANDLE                 hCurrentThread,     \
        ULONG                  dwCurrentPc,        \
        ULONG                  dwProcessor,        \
        PCSTR                  args                \
     )
```

Last thing to know, all WinDbg SDK files are make for Visual Studio 2013. And if
you don’t like Windows 8, you can find the structures in 
`C:\Program Files (x86)\Windows Kits\8.1\Debuggers\inc\wdbgexts.h` and copy them 
in your own header (`windbg.h` for me).


## Functions

To get WinDbg API, you need to recover a specific pointer:

```c
VOID WinDbgExtensionDllInit(PWINDBG_EXTENSION_APIS lpExtensionApis, 
    USHORT usMajorVersion, USHORT usMinorVersion) {
     ExtensionApis = *lpExtensionApis;
}
```

Some preprocessor will help you to make a more readable source:

```c
#define dprintf          (ExtensionApis.lpOutputRoutine)
#define GetExpression    (ExtensionApis.lpGetExpressionRoutine)
#define CheckControlC    (ExtensionApis.lpCheckControlCRoutine)
#define GetContext       (ExtensionApis.lpGetThreadContextRoutine)
#define SetContext       (ExtensionApis.lpSetThreadContextRoutine)
#define Ioctl            (ExtensionApis.lpIoctlRoutine)
#define Disasm           (ExtensionApis.lpDisasmRoutine)
#define GetSymbol        (ExtensionApis.lpGetSymbolRoutine)
#define ReadMemory       (ExtensionApis.lpReadProcessMemoryRoutine)
#define WriteMemory      (ExtensionApis.lpWriteProcessMemoryRoutine)
#define StackTrace       (ExtensionApis.lpStackTraceRoutine)
```

Now, we will use `dprintf` to show a message in WinDbg: it works like `printf` 
from the C standard library.
To read WinDbg debugged process memory, we can use `ReadMemory` wich works like 
`ReadProcessMemory`.


## Code

You have now the base to writte a plugin like this:

```c
#include <Windows.h>
#include "windbg.h"
#include "ntdll.h"

#define ASLR_ENABLED 1
#define DEP_ENABLED 2
#define SAFESEH_ENABLED 4

extern "C" {
	_declspec(dllexport) VOID CheckVersion();
	_declspec(dllexport) LPEXT_API_VERSION ExtensionApiVersion();
	_declspec(dllexport) VOID WinDbgExtensionDllInit(PWINDBG_EXTENSION_APIS lpExtensionApis, USHORT usMajorVersion, USHORT usMinorVersion);
	_declspec(dllexport) DECLARE_API(df0);
}

EXT_API_VERSION ApiVersion = { 1, 0, 0, 0 };
WINDBG_EXTENSION_APIS ExtensionApis;

VOID CheckVersion() {
	return;
}

LPEXT_API_VERSION ExtensionApiVersion() {
    return &ApiVersion;
}

VOID WinDbgExtensionDllInit(PWINDBG_EXTENSION_APIS lpExtensionApis, USHORT usMajorVersion, USHORT usMinorVersion)
{
     ExtensionApis = *lpExtensionApis;
	 dprintf("DbgDf0 loaded! \n\n");
}

int checkProtections(DWORD baseAddress) {
	int ret = 0;
	ULONG returnLength;

	IMAGE_OPTIONAL_HEADER optionalHeader;
	ReadMemory((ULONG_PTR) baseAddress + sizeof(IMAGE_NT_HEADERS) - sizeof(IMAGE_OPTIONAL_HEADER), &optionalHeader, sizeof(optionalHeader), &returnLength); 

	if (optionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) {
		ret |= ASLR_ENABLED;
	}
	if (optionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_NX_COMPAT) {
		ret |= DEP_ENABLED;
	}
	if (optionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress != 0 && optionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].Size != 0) {
		ret |= SAFESEH_ENABLED;
	}

	return ret;
}

int listMod(HANDLE hCurrentProcess) {
	HMODULE pNtdll = GetModuleHandle(L"ntdll.dll");
	_NtQueryInformationProcess NtQueryInformationProcess = (_NtQueryInformationProcess) GetProcAddress(pNtdll, "NtQueryInformationProcess");

	PROCESS_BASIC_INFORMATION basicInfo;
	ULONG returnLength;
	NtQueryInformationProcess(hCurrentProcess, 0, &basicInfo, sizeof(basicInfo), &returnLength);

	PEB peb;
	ReadMemory((ULONG_PTR) basicInfo.PebBaseAddress, &peb, sizeof(peb), &returnLength);

	PEB_LDR_DATA ldrList;
	ReadMemory((ULONG_PTR) peb.Ldr, &ldrList, sizeof(ldrList), &returnLength);

	LIST_ENTRY listModules;
	LDR_DATA_TABLE_ENTRY module;
	DWORD firstModule = (DWORD) ldrList.InLoadOrderModuleList.Flink;

	ReadMemory((ULONG_PTR) firstModule, &listModules, sizeof(listModules), &returnLength);
	ReadMemory((ULONG_PTR) firstModule, &module, sizeof(module), &returnLength);

	wchar_t wModuleName[1024] = {0};
	char aModuleName[1024] = {0};
	int protections = 0;
	dprintf("Image Base \tSize \t\tASLR \tDEP \tSafe SEH \tModule Name \n");

	do {
		ReadMemory((ULONG_PTR) module.BaseDllName.Buffer, wModuleName, module.BaseDllName.Length+2, &returnLength);
		WideCharToMultiByte(CP_ACP, 0, wModuleName, -1, aModuleName, sizeof(aModuleName), NULL, NULL);

		protections = checkProtections((DWORD) module.DllBase);
		dprintf("0x%0.8X \t0x%0.8X", module.DllBase, module.SizeOfImage);
		(protections & ASLR_ENABLED) ? dprintf("\tYes") : dprintf("\tNo");
		(protections & DEP_ENABLED) ? dprintf("\tYes") : dprintf("\tNo");
		(protections & SAFESEH_ENABLED) ? dprintf("\tYes") : dprintf("\tNo");
		dprintf("\t\t%s \n", aModuleName);

		ReadMemory((ULONG_PTR) listModules.Flink, &module, sizeof(module), &returnLength);
		ReadMemory((ULONG_PTR) listModules.Flink, &listModules, sizeof(listModules), &returnLength); // Next
	} while ((DWORD) listModules.Flink != firstModule);

	return 1;
}

DECLARE_API(df0) 
{
	if (strcmp(args, "mod") == 0) {
		listMod(hCurrentProcess);
	}
}
```

And the headers to test:

```c
// windbg.h

#if !defined(WDBGAPI)
#define WDBGAPI __stdcall
#endif

#if !defined(WDBGAPIV)
#define WDBGAPIV __cdecl
#endif

typedef
VOID
(WDBGAPIV*PWINDBG_OUTPUT_ROUTINE)(
    PCSTR lpFormat,
    ...
    );

typedef
ULONG_PTR
(WDBGAPI*PWINDBG_GET_EXPRESSION)(
    PCSTR lpExpression
    );

typedef
ULONG
(WDBGAPI*PWINDBG_GET_EXPRESSION32)(
    PCSTR lpExpression
    );

typedef
ULONG64
(WDBGAPI*PWINDBG_GET_EXPRESSION64)(
    PCSTR lpExpression
    );

typedef
VOID
(WDBGAPI*PWINDBG_GET_SYMBOL)(
    PVOID      offset,
    PCHAR      pchBuffer,
    ULONG_PTR *pDisplacement
    );

typedef
VOID
(WDBGAPI*PWINDBG_GET_SYMBOL32)(
    ULONG      offset,
    PCHAR      pchBuffer,
    PULONG     pDisplacement
    );

typedef
VOID
(WDBGAPI*PWINDBG_GET_SYMBOL64)(
    ULONG64    offset,
    PCHAR      pchBuffer,
    PULONG64   pDisplacement
    );

typedef
ULONG
(WDBGAPI*PWINDBG_DISASM)(
    ULONG_PTR *lpOffset,
    PCSTR      lpBuffer,
    ULONG      fShowEffectiveAddress
    );

typedef
ULONG
(WDBGAPI*PWINDBG_DISASM32)(
    ULONG     *lpOffset,
    PCSTR      lpBuffer,
    ULONG      fShowEffectiveAddress
    );

typedef
ULONG
(WDBGAPI*PWINDBG_DISASM64)(
    ULONG64   *lpOffset,
    PCSTR      lpBuffer,
    ULONG      fShowEffectiveAddress
    );

typedef
ULONG
(WDBGAPI*PWINDBG_CHECK_CONTROL_C)(
    VOID
    );

typedef
ULONG
(WDBGAPI*PWINDBG_READ_PROCESS_MEMORY_ROUTINE)(
    ULONG_PTR  offset,
    PVOID      lpBuffer,
    ULONG      cb,
    PULONG     lpcbBytesRead
    );

typedef
ULONG
(WDBGAPI*PWINDBG_READ_PROCESS_MEMORY_ROUTINE32)(
    ULONG      offset,
    PVOID      lpBuffer,
    ULONG      cb,
    PULONG     lpcbBytesRead
    );

typedef
ULONG
(WDBGAPI*PWINDBG_READ_PROCESS_MEMORY_ROUTINE64)(
    ULONG64    offset,
    PVOID      lpBuffer,
    ULONG      cb,
    PULONG     lpcbBytesRead
    );

typedef
ULONG
(WDBGAPI*PWINDBG_WRITE_PROCESS_MEMORY_ROUTINE)(
    ULONG_PTR  offset,
    LPCVOID    lpBuffer,
    ULONG      cb,
    PULONG     lpcbBytesWritten
    );

typedef
ULONG
(WDBGAPI*PWINDBG_WRITE_PROCESS_MEMORY_ROUTINE32)(
    ULONG      offset,
    LPCVOID    lpBuffer,
    ULONG      cb,
    PULONG     lpcbBytesWritten
    );

typedef
ULONG
(WDBGAPI*PWINDBG_WRITE_PROCESS_MEMORY_ROUTINE64)(
    ULONG64    offset,
    LPCVOID    lpBuffer,
    ULONG      cb,
    PULONG     lpcbBytesWritten
    );

typedef
ULONG
(WDBGAPI*PWINDBG_GET_THREAD_CONTEXT_ROUTINE)(
    ULONG       Processor,
    PCONTEXT    lpContext,
    ULONG       cbSizeOfContext
    );

typedef
ULONG
(WDBGAPI*PWINDBG_SET_THREAD_CONTEXT_ROUTINE)(
    ULONG       Processor,
    PCONTEXT    lpContext,
    ULONG       cbSizeOfContext
    );

typedef
ULONG
(WDBGAPI*PWINDBG_IOCTL_ROUTINE)(
    USHORT   IoctlType,
    PVOID    lpvData,
    ULONG    cbSize
    );

typedef
ULONG
(WDBGAPI*PWINDBG_OLDKD_READ_PHYSICAL_MEMORY)(
    ULONGLONG        address,
    PVOID            buffer,
    ULONG            count,
    PULONG           bytesread
    );

typedef
ULONG
(WDBGAPI*PWINDBG_OLDKD_WRITE_PHYSICAL_MEMORY)(
    ULONGLONG        address,
    PVOID            buffer,
    ULONG            length,
    PULONG           byteswritten
    );


typedef struct _EXTSTACKTRACE {
    ULONG       FramePointer;
    ULONG       ProgramCounter;
    ULONG       ReturnAddress;
    ULONG       Args[4];
} EXTSTACKTRACE, *PEXTSTACKTRACE;

typedef struct _EXTSTACKTRACE32 {
    ULONG       FramePointer;
    ULONG       ProgramCounter;
    ULONG       ReturnAddress;
    ULONG       Args[4];
} EXTSTACKTRACE32, *PEXTSTACKTRACE32;

typedef struct _EXTSTACKTRACE64 {
    ULONG64     FramePointer;
    ULONG64     ProgramCounter;
    ULONG64     ReturnAddress;
    ULONG64     Args[4];
} EXTSTACKTRACE64, *PEXTSTACKTRACE64;


typedef
ULONG
(WDBGAPI*PWINDBG_STACKTRACE_ROUTINE)(
    ULONG             FramePointer,
    ULONG             StackPointer,
    ULONG             ProgramCounter,
    PEXTSTACKTRACE    StackFrames,
    ULONG             Frames
    );

typedef
ULONG
(WDBGAPI*PWINDBG_STACKTRACE_ROUTINE32)(
    ULONG             FramePointer,
    ULONG             StackPointer,
    ULONG             ProgramCounter,
    PEXTSTACKTRACE32  StackFrames,
    ULONG             Frames
    );

typedef
ULONG
(WDBGAPI*PWINDBG_STACKTRACE_ROUTINE64)(
    ULONG64           FramePointer,
    ULONG64           StackPointer,
    ULONG64           ProgramCounter,
    PEXTSTACKTRACE64  StackFrames,
    ULONG             Frames
    );

typedef struct _WINDBG_EXTENSION_APIS {
    ULONG                                  nSize;
    PWINDBG_OUTPUT_ROUTINE                 lpOutputRoutine;
    PWINDBG_GET_EXPRESSION                 lpGetExpressionRoutine;
    PWINDBG_GET_SYMBOL                     lpGetSymbolRoutine;
    PWINDBG_DISASM                         lpDisasmRoutine;
    PWINDBG_CHECK_CONTROL_C                lpCheckControlCRoutine;
    PWINDBG_READ_PROCESS_MEMORY_ROUTINE    lpReadProcessMemoryRoutine;
    PWINDBG_WRITE_PROCESS_MEMORY_ROUTINE   lpWriteProcessMemoryRoutine;
    PWINDBG_GET_THREAD_CONTEXT_ROUTINE     lpGetThreadContextRoutine;
    PWINDBG_SET_THREAD_CONTEXT_ROUTINE     lpSetThreadContextRoutine;
    PWINDBG_IOCTL_ROUTINE                  lpIoctlRoutine;
    PWINDBG_STACKTRACE_ROUTINE             lpStackTraceRoutine;
} WINDBG_EXTENSION_APIS, *PWINDBG_EXTENSION_APIS;

#define DECLARE_API(s)                             \
    VOID										   \
    s(                                             \
        HANDLE                 hCurrentProcess,    \
        HANDLE                 hCurrentThread,     \
        ULONG                  dwCurrentPc,        \
        ULONG                  dwProcessor,        \
        PCSTR                  args                \
     )
#define dprintf          (ExtensionApis.lpOutputRoutine)
#define GetExpression    (ExtensionApis.lpGetExpressionRoutine)
#define CheckControlC    (ExtensionApis.lpCheckControlCRoutine)
#define GetContext       (ExtensionApis.lpGetThreadContextRoutine)
#define SetContext       (ExtensionApis.lpSetThreadContextRoutine)
#define Ioctl            (ExtensionApis.lpIoctlRoutine)
#define Disasm           (ExtensionApis.lpDisasmRoutine)
#define GetSymbol        (ExtensionApis.lpGetSymbolRoutine)
#define ReadMemory       (ExtensionApis.lpReadProcessMemoryRoutine)
#define WriteMemory      (ExtensionApis.lpWriteProcessMemoryRoutine)
#define StackTrace       (ExtensionApis.lpStackTraceRoutine)

typedef struct EXT_API_VERSION {
    USHORT  MajorVersion;
    USHORT  MinorVersion;
    USHORT  Revision;
    USHORT  Reserved;
} EXT_API_VERSION, *LPEXT_API_VERSION;
```

```c
// ntdll.h

#include <Windows.h>

typedef NTSTATUS (WINAPI* _NtQueryInformationProcess)(
  _In_       HANDLE ProcessHandle,
  _In_       DWORD ProcessInformationClass,
  _Out_      PVOID ProcessInformation,
  _In_       ULONG ProcessInformationLength,
  _Out_opt_  PULONG ReturnLength
);

typedef struct _LSA_UNICODE_STRING {
  USHORT Length;
  USHORT MaximumLength;
  PWSTR  Buffer;
} LSA_UNICODE_STRING, *PLSA_UNICODE_STRING, UNICODE_STRING, *PUNICODE_STRING;

typedef struct _LDR_DATA_TABLE_ENTRY
{
     LIST_ENTRY InLoadOrderLinks;
     LIST_ENTRY InMemoryOrderLinks;
     LIST_ENTRY InInitializationOrderLinks;
     PVOID DllBase;
     PVOID EntryPoint;
     ULONG SizeOfImage;
     UNICODE_STRING FullDllName;
     UNICODE_STRING BaseDllName;
     ULONG Flags;
     WORD LoadCount;
     WORD TlsIndex;
     union
     {
          LIST_ENTRY HashLinks;
          struct
          {
               PVOID SectionPointer;
               ULONG CheckSum;
          };
     };
     union
     {
          ULONG TimeDateStamp;
          PVOID LoadedImports;
     };
     _ACTIVATION_CONTEXT * EntryPointActivationContext;
     PVOID PatchInformation;
     LIST_ENTRY ForwarderLinks;
     LIST_ENTRY ServiceTagLinks;
     LIST_ENTRY StaticLinks;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

typedef struct _PEB_LDR_DATA {
	ULONG Length;
	BOOLEAN Initialized;
	HANDLE SsHandle;
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
	PVOID EntryInProgress;
	BOOLEAN ShutdownInProgress;
	HANDLE ShutdownThreadId;
} PEB_LDR_DATA, *PPEB_LDR_DATA;


typedef struct _PEB {
  BYTE                          Reserved1[2];
  BYTE                          BeingDebugged;
  BYTE                          Reserved2[1];
  PVOID                         Reserved3[2];
  PPEB_LDR_DATA                 Ldr;
  DWORD							ProcessParameters;
  BYTE                          Reserved4[104];
  PVOID                         Reserved5[52];
  DWORD							PostProcessInitRoutine;
  BYTE                          Reserved6[128];
  PVOID                         Reserved7[1];
  ULONG                         SessionId;
} PEB, *PPEB;

typedef struct _PROCESS_BASIC_INFORMATION {
    PVOID Reserved1;
    PPEB PebBaseAddress;
    PVOID Reserved2[2];
    ULONG_PTR UniqueProcessId;
    PVOID Reserved3;
} PROCESS_BASIC_INFORMATION;
```