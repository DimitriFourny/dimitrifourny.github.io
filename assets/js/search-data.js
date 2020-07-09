var store = [{
        "title": "How to detect and exploit a buffer overflow",
        "excerpt":"The buffer overflow is the most classical vulnerability, on Linux and on Windows.In this article, I will try to show you how to exploit a buffer overflow on Windows with WinDbg and a little Python code. Etablishment #include &lt;stdio.h&gt;#include &lt;stdlib.h&gt;#include &lt;string.h&gt;int main(int argc, char* argv[]){ char tmp[100]; getchar() strcpy(tmp, argv[1]);...","categories": [],
        "tags": [],
        "url": "https://dimitrifourny.github.io//2014/02/06/buffer-overflow.html"
      },{
        "title": "Kernel buffer overflow on Windows",
        "excerpt":"The buffer overflow are cool in user-land but they can be more funny in kernel-land. This time, we will use a buffer overflow to make an escalade privilege to get the SYSTEM rights, so we will could make anything we want on the system. To train us, we don’t need...","categories": [],
        "tags": [],
        "url": "https://dimitrifourny.github.io//2014/02/26/kernel-buffer-overflow.html"
      },{
        "title": "Make a plugin for WinDbg",
        "excerpt":"WinDbg is a powerfull Windows debugger, it can debug x86 application and x64 application, in user-land or in kernel-land. Despite its useful commands, we would like to make some plugin to do a faster and better debugging session. Fortunately for us, it’s possible to write WinDbg plugins in C or...","categories": [],
        "tags": [],
        "url": "https://dimitrifourny.github.io//2014/02/28/plugin-windbg.html"
      },{
        "title": "Driver dereferenced pointer in Windows 7 x64",
        "excerpt":"In my previous article, I have talked about the exploitation of kernel buffer overflow. This time, I will not play with Windows XP x86 but with Windows 7 x64 on the 0vercl0k’s level 2 driver. 0vercl0k have coded this driver for a x86 environment, so we need to do some...","categories": [],
        "tags": [],
        "url": "https://dimitrifourny.github.io//2014/03/14/driver-dereferenced.html"
      },{
        "title": "Driver write-what-where vulnerability",
        "excerpt":"In this article, we will exploit a write-what-where vulnerability in Windows 7 x64. To do that, we will use the last level of 0vercl0k: the level 3. We need to do some changes to make a driver which work on a x64 system: #include &lt;Ntifs.h&gt;#include &lt;stdio.h&gt;#include &lt;string.h&gt;#define ERROR(_f_, _status_) DbgPrint(\"\\r\\n[!]...","categories": [],
        "tags": [],
        "url": "https://dimitrifourny.github.io//2014/03/16/driver-write-what-where.html"
      },{
        "title": "VTable Hooking",
        "excerpt":"Today, I will try to explain how we can make a hook on a C++ class method. This technique works on Linux and Windows, but my examples are compiled on Linux. VTable, what is it? C++ use the concept of inheritance. We will use two class in this article: class...","categories": [],
        "tags": [],
        "url": "https://dimitrifourny.github.io//2014/07/02/vtable-hooking.html"
      },{
        "title": "Attacking AES and DSA",
        "excerpt":"Recently I was involved in a security conference called SecuDay where I have presented Attacking Games for Fun and Profit. At the end of the conference, we have been invited to resolve some challenges conceived by Charles Bouillaguet. There was three levels, easy and medium level are based on the...","categories": [],
        "tags": [],
        "url": "https://dimitrifourny.github.io//2017/03/08/attacking-aes-dsa.html"
      },{
        "title": "Writing Optimized Windows Shellcode",
        "excerpt":"You always have a lot of possibilities when you make a shellcode payload, especially on Windows. Do you need to write all your ASM manually or can you be helped by your compiler? Do I need to directly use syscall or to search the functions in memory? Because it’s not...","categories": [],
        "tags": [],
        "url": "https://dimitrifourny.github.io//2017/04/28/optimized-shellcode.html"
      },{
        "title": "Dumping the VEH in Windows 10",
        "excerpt":"The Vectored Exception Handling (VEH) is a Windows mecanism to handle application exceptions.Even if you have an official Windows API to add and remove handlers via AddVectoredExceptionHandler andRemoveVectoredExceptionHandler, there is no official way to list all registered handlers in an application.Inside the source code of ReactOS you can find a...","categories": [],
        "tags": [],
        "url": "https://dimitrifourny.github.io//2020/06/11/dumping-veh-win10.html"
      }]
