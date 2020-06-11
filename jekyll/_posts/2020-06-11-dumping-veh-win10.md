---
layout: post
title:  "Dumping the VEH in Windows 10"
---

The [Vectored Exception Handling][1] (VEH) is a Windows mecanism to handle application exceptions.
Even if you have an official Windows API to add and remove handlers via `AddVectoredExceptionHandler` and
`RemoveVectoredExceptionHandler`, there is no official way to list all registered handlers in an application.
Inside the source code of ReactOS you can find [a source file][2] with these API reimplemented and it can give us
good information about how it works.

I needed to dump the VEH list to be able to bypass a game anticheat and because there is not a lot of information about 
how to do it on the internet, I sharing my solution with you.

[1]: https://docs.microsoft.com/fr-fr/windows/win32/debug/vectored-exception-handling
[2]: https://github.com/reactos/reactos/blob/893a3c9d030fd8b078cbd747eeefd3f6ce57e560/sdk/lib/rtl/vectoreh.c


VEH use case
-------------

The VEH can be used to catch all catchable exceptions, in our example we are catching a division by zero:

```cpp
LONG NTAPI MyVEHHandler(PEXCEPTION_POINTERS ExceptionInfo) {
  printf("MyVEHHandler (0x%x)\n", ExceptionInfo->ExceptionRecord->ExceptionCode);

  if (ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_INT_DIVIDE_BY_ZERO) {
    printf("  Divide by zero at 0x%p\n", ExceptionInfo->ExceptionRecord->ExceptionAddress);
    ExceptionInfo->ContextRecord->Eip += 2;
    return EXCEPTION_CONTINUE_EXECUTION;
  }

  return EXCEPTION_CONTINUE_SEARCH;
}

int main() {
  AddVectoredExceptionHandler(1, MyVEHHandler);
  int except = 5;
  except /= 0;
  return 0;
}
```

Another application is done by CheatEngine which injects a DLL and use the VEH to catch hardware breakpoints. In 
consequence it can debug an application while bypassing the basics debugger checks.

![CheatEngine](/assets/img/CheatEngine.png "CheatEngine")


Exception path
---------------

When a CPU exception occurs, the kernel will call the function [`KiDispatchException`][3] (ring0) which will follow this 
exception to the ntdll method [`KiUserExceptionDispatcher`][4] (ring3). This function will call 
[`RtlDispatchException`][5] which will try to handle it via the VEH. To do it, it will read the VEH chained list via
[`RtlCallVectoredHandlers`][6] and calling each handlers until one return `EXCEPTION_CONTINUE_EXECUTION`. If a handler
returned `EXCEPTION_CONTINUE_EXECUTION`, the function [`RtlCallVectoredContinueHandlers`][7] is called and it will
call all the continue exception handlers.

![Exception trace](/assets/img/exception_trace.png "Exception trace")

The VEH handlers are important because the [SEH][8] handlers are called only if no VEH handler has caught the 
exception, so it could be the best method to catch all exceptions if you don't want to hook `KiUserExceptionDispatcher`.
If you want more information about the exceptions dispatcher, 0vercl0ck has made a [good paper about it][9].

[3]: https://github.com/reactos/reactos/blob/b20f81512688f26c91a131b81f41fc8cf9506f04/ntoskrnl/ke/i386/exp.c#L1026
[4]: https://github.com/reactos/reactos/blob/893a3c9d030fd8b078cbd747eeefd3f6ce57e560/dll/ntdll/dispatch/dispatch.c#L26
[5]: https://github.com/reactos/reactos/blob/ea6d427d10840e4b63f5af7a2012881379be74c1/sdk/lib/rtl/i386/except.c#L67
[6]: https://github.com/reactos/reactos/blob/893a3c9d030fd8b078cbd747eeefd3f6ce57e560/sdk/lib/rtl/vectoreh.c#L40
[7]: https://github.com/reactos/reactos/blob/893a3c9d030fd8b078cbd747eeefd3f6ce57e560/sdk/lib/rtl/vectoreh.c#L284
[8]: https://docs.microsoft.com/en-us/cpp/cpp/structured-exception-handling-c-cpp?view=vs-2019
[9]: https://doar-e.github.io/blog/2013/10/12/having-a-look-at-the-windows-userkernel-exceptions-dispatcher/


The chained list
-------------------

The VEH list is a circular linked list with the handlers functions pointers encoded:

![VEH](/assets/img/veh.png "VEH")

The exception handlers are encoded with a process cookie but you can decode them easily. If you are dumping the VEH
which is inside your own process, you can just use [`DecodePointer`][10] and you don't have to care about the process 
cookie. If it's a remote process you can use [`DecodeRemotePointer`][11] but you will need to create your own function
pointer with `GetModuleHandle("kernel32.dll")` and `GetProcAddress("DecodeRemotePointer")`.

The solution that I have chosen is to imitate `DecodePointer` by getting the process cookie with 
`ZwQueryProcessInformation` and applying the same algorithm:

![RtlDecodePointer](/assets/img/RtlDecodePointer.png "RtlDecodePointer")

```cpp
DWORD Process::GetProcessCookie() const {
  DWORD cookie = 0;
  DWORD return_length = 0;

  HMODULE ntdll = GetModuleHandleA("ntdll.dll");
  _NtQueryInformationProcess NtQueryInformationProcess =
      reinterpret_cast<_NtQueryInformationProcess>(
          GetProcAddress(ntdll, "NtQueryInformationProcess"));

  NTSTATUS success = NtQueryInformationProcess(
      process_handle_, ProcessCookie, &cookie, sizeof(cookie), &return_length);
  if (success < 0) {
    return 0;
  }
  return cookie;
}

#define ROR(x, y) ((unsigned)(x) >> (y) | (unsigned)(x) << 32 - (y))
DWORD Process::DecodePointer(DWORD pointer) {
  if (!process_cookie_) {
    process_cookie_ = GetProcessCookie();
    if (!process_cookie_) {
      return 0;
    }
  }

  unsigned char shift_size = 0x20 - (process_cookie_ & 0x1f);
  return ROR(pointer, shift_size) ^ process_cookie_;
}
```

[10]: https://docs.microsoft.com/en-us/previous-versions/bb432242(v%3Dvs.85)
[11]: https://docs.microsoft.com/en-us/previous-versions/dn877133(v=vs.85)


Finding the VEH list offset
----------------------------

Even if you can find the symbol `LdrpVectorHandlerList` in the ntdll pdb, there is no official API to get it easily.
My solution is to begin by getting a pointer to `RtlpAddVectoredHandler`:

![RtlAddVectoredExceptionHandler](/assets/img/RtlAddVectoredExceptionHandler.png "RtlAddVectoredExceptionHandler")

You can disassemble the method `RtlAddVectoredExceptionHandler` until you find the instruction `call` or you can
just pretend that its address is always at `0x16` bytes after it:

```cpp
BYTE* add_exception_handler = reinterpret_cast<BYTE*>(
    GetProcAddress(ntdll, "RtlAddVectoredExceptionHandler"));
BYTE* add_exception_handler_sub =
    add_exception_handler + 0x16;  // RtlpAddVectoredHandler
```

And from here the same byte offset method could work, but a simple signature system could prevent us to be broken after 
a small Windows update:

![LdrpVectorHandlerList](/assets/img/LdrpVectorHandlerList.png "LdrpVectorHandlerList")

```cpp
const BYTE pattern_list[] = {
    0x89, 0x46, 0x0c,          // mov [esi+0Ch], eax
    0x81, 0xc3, 0,    0, 0, 0  // add ebx, offset LdrpVectorHandlerList
};
const char mask_list[] = "xxxxx????";
BYTE* match_list =
    SearchPattern(add_exception_handler_sub, 0x100, pattern_list, mask_list);
BYTE* veh_list = *reinterpret_cast<BYTE**>(match_list + 5);
size_t veh_list_offset = veh_list - reinterpret_cast<BYTE*>(ntdll);
printf("LdrpVectorHandlerList: 0x%p (ntdll+0x%x)\n", veh_list, veh_list_offset);
```


Final code
----------

```cpp
#define ROR(x, y) ((unsigned)(x) >> (y) | (unsigned)(x) << 32 - (y))

DWORD Process::GetProcessCookie() const {
  DWORD cookie = 0;
  DWORD return_length = 0;

  HMODULE ntdll = GetModuleHandleA("ntdll.dll");
  _NtQueryInformationProcess NtQueryInformationProcess =
      reinterpret_cast<_NtQueryInformationProcess>(
          GetProcAddress(ntdll, "NtQueryInformationProcess"));

  NTSTATUS success = NtQueryInformationProcess(
      process_handle_, ProcessCookie, &cookie, sizeof(cookie), &return_length);
  if (success < 0) {
    return 0;
  }
  return cookie;
}

DWORD Process::DecodePointer(DWORD pointer) {
  if (!process_cookie_) {
    process_cookie_ = GetProcessCookie();
    if (!process_cookie_) {
      return 0;
    }
  }

  unsigned char shift_size = 0x20 - (process_cookie_ & 0x1f);
  return ROR(pointer, shift_size) ^ process_cookie_;
}

typedef struct _VECTORED_HANDLER_ENTRY {
  _VECTORED_HANDLER_ENTRY* next;
  _VECTORED_HANDLER_ENTRY* previous;
  ULONG refs;
  PVECTORED_EXCEPTION_HANDLER handler;
} VECTORED_HANDLER_ENTRY;

typedef struct _VECTORED_HANDLER_LIST {
  void* mutex_exception;
  VECTORED_HANDLER_ENTRY* first_exception_handler;
  VECTORED_HANDLER_ENTRY* last_exception_handler;
  void* mutex_continue;
  VECTORED_HANDLER_ENTRY* first_continue_handler;
  VECTORED_HANDLER_ENTRY* last_continue_handler;
} VECTORED_HANDLER_LIST;

DWORD GetVEHOffset() {
  HMODULE ntdll = LoadLibraryA("ntdll.dll");
  printf("ntdll: 0x%p\n", ntdll);
  perror_if_invalid(ntdll, "LoadLibrary");

  BYTE* add_exception_handler = reinterpret_cast<BYTE*>(
      GetProcAddress(ntdll, "RtlAddVectoredExceptionHandler"));
  printf("RtlAddVectoredExceptionHandler: 0x%p\n", add_exception_handler);
  perror_if_invalid(add_exception_handler, "GetProcAddress");

  BYTE* add_exception_handler_sub = add_exception_handler + 0x16;
  printf("RtlpAddVectoredExceptionHandler: 0x%p\n", add_exception_handler_sub);

  const BYTE pattern_list[] = {
      0x89, 0x46, 0x0c,          // mov [esi+0Ch], eax
      0x81, 0xc3, 0,    0, 0, 0  // add ebx, offset LdrpVectorHandlerList
  };
  const char mask_list[] = "xxxxx????";
  BYTE* match_list =
      SearchPattern(add_exception_handler_sub, 0x100, pattern_list, mask_list);
  perror_if_invalid(match_list, "SearchPattern");
  BYTE* veh_list = *reinterpret_cast<BYTE**>(match_list + 5);
  size_t veh_list_offset = veh_list - reinterpret_cast<BYTE*>(ntdll);
  printf("LdrpVectorHandlerList: 0x%p (ntdll+0x%x)\n", veh_list,
         veh_list_offset);

  return veh_list_offset;
}

int main() {
  auto process = Process::GetProcessByName(L"veh_dumper.exe");
  perror_if_invalid(process.get(), "GetProcessByName");
  printf("Process cookie: 0x%0x\n", process->GetProcessCookie());

  DWORD ntdll = process->GetModuleBase(L"ntdll.dll");
  VECTORED_HANDLER_LIST handler_list;
  DWORD veh_addr = ntdll + GetVEHOffset();
  printf("VEH: 0x%08x\n", veh_addr);
  process->ReadProcMem(veh_addr, &handler_list, sizeof(handler_list));
  printf("First entry: 0x%p\n", handler_list.first_exception_handler);
  printf("Last entry: 0x%p\n", handler_list.last_exception_handler);

  if (reinterpret_cast<DWORD>(handler_list.first_exception_handler) ==
      veh_addr + sizeof(DWORD)) {
    printf("VEH list is empty\n");
    return 0;
  }

  printf("Dumping the entries:\n");
  VECTORED_HANDLER_ENTRY entry;
  process->ReadProcMem(
      reinterpret_cast<DWORD>(handler_list.first_exception_handler), &entry,
      sizeof(entry));
  while (true) {
    DWORD handler = reinterpret_cast<DWORD>(entry.handler);
    printf("  handler = 0x%p => 0x%p\n", handler,
           process->DecodePointer(handler));

    if (reinterpret_cast<DWORD>(entry.next) == veh_addr + sizeof(DWORD)) {
      break;
    }
    process->ReadProcMem(reinterpret_cast<DWORD>(entry.next), &entry,
                         sizeof(entry));
  }
}
```

I plan to release a VEH debugger which works by shellcode injection, maybe it will be the subject of a next article.
Please take note that I have done it on a 32 bits process but it can be done on a 64 bits process too.