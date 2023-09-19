---
date: 2014-07-02
title: "VTable Hooking"
url: /2014/07/02/vtable-hooking.html
---

Today, I will try to explain how we can make a hook on a C++ class method. This 
technique works on Linux and Windows, but my examples are compiled on Linux.

<!--more-->

## VTable, what is it?

C++ use the concept of inheritance. We will use two class in this article:

```cpp
class A {
    public:
        A() {
            printf("Init A\n");
            m_value = 0x1337;
        }

        void virtual  Hello() {
            printf("I'm a class A\n");
        }

        void virtual Useless() {
            printf("I'm an useless method\n");   
        }
    protected:
        unsigned long m_value;
};

class B : A {
     public:
        B() {
            printf("Init B\n");
            m_value = 0x1338;
        }

        void virtual Hello() {
            printf("I'm a class B\n");
        }   
};
```

B have three methods:

- This constructor: `B()`
- The overloaded method `Hello()`
- The inherited method `Useless()`
- And a `m_value` member.

To see the compiler problem to compile it, let’s see an example:

```cpp
A* varA = new A();
varA->Hello();
varA->Useless();

A* varB = reinterpret_cast<A*>(new B());
varB->Hello();
varB->Useless();
```

At the compilation time, how the compiler can know that `varB->Hello()` is a 
reference to `A::Hello()` or `B:Hello()`? Because when a C++ program is 
compiled, the compiled code will use a Virtual Call Table (*VTable*):

```
*A  ->  &VTable (ex: 0x401111)  ->  &Hello      (ex: 0x40AAAA)
        m_value (ex: 0x1337)        &Useless    (ex: 0x40BBBB)

*B  ->  &VTable (ex: 0x402222)  ->  &Hello      (ex: 0x40CCCC)
        m_value (ex: 0x1338)        &Useless    (ex: 0x40BBBB)
```

With this process, we just need the object address to call the right method!


## GDB is our friend

Now, we will compile it with `g++` and we will observe its comportement:

```cpp
#include <stdio.h>

class A {
    public:
        A() {
            printf("Init A\n");
            m_value = 0x1337;
        }

        void virtual  Hello() {
            printf("I'm a class A\n");
        }

        void virtual Useless() {
            printf("I'm an useless method\n");   
        }
    protected:
        unsigned long m_value;
};

class B : A {
     public:
        B() {
            printf("Init B\n");
            m_value = 0x1338;
        }

        void virtual Hello() {
            printf("I'm a class B\n");
        }   
};

int main() {
    A* varA = new A();
    varA->Hello();
    varA->Useless();
    A* varB = reinterpret_cast<A*>(new B());
    varB->Hello();
    varB->Useless();

    return 0;
}
```

Compile it and debug it with gdb:

```bash
$ g++ vtable.cpp -g -o vtable
$ gdb vtable
```

We will study how the compiler have compiled our code:

```
gdb-peda$ display/i $pc

gdb-peda$ disas main
Dump of assembler code for function main():
   0x0000000000400887 <+0>: push   rbp
   0x0000000000400888 <+1>: mov    rbp,rsp
   0x000000000040088b <+4>: push   r12
   0x000000000040088d <+6>: push   rbx
   0x000000000040088e <+7>: sub    rsp,0x40
   0x0000000000400892 <+11>:    mov    edi,0x10
=> 0x0000000000400897 <+16>:    call   0x400760 <_Znwm@plt>
   0x000000000040089c <+21>:    mov    rbx,rax
   0x000000000040089f <+24>:    mov    rdi,rbx
   0x00000000004008a2 <+27>:    call   0x400ace <A::A()>
   0x00000000004008a7 <+32>:    mov    QWORD PTR [rbp-0x48],rbx
   0x00000000004008ab <+36>:    mov    rax,QWORD PTR [rbp-0x48]
   0x00000000004008af <+40>:    mov    rax,QWORD PTR [rax]
   0x00000000004008b2 <+43>:    mov    rax,QWORD PTR [rax]
   0x00000000004008b5 <+46>:    mov    rdx,QWORD PTR [rbp-0x48]
   0x00000000004008b9 <+50>:    mov    rdi,rdx
   0x00000000004008bc <+53>:    call   rax
```

We start at:

```
   0x0000000000400892 <+11>:    mov    edi,0x10
=> 0x0000000000400897 <+16>:    call   0x400760 <_Znwm@plt>
```

EDI contains the class size and `_Znwm@plt` uses malloc to allocate memory for 
our object.

```
gdb-peda$ info registers 
rax            0x602010 0x602010
rbx            0x602010 0x602010

   0x000000000040089c <+21>:   mov    rbx,rax
   0x000000000040089f <+24>:   mov    rdi,rbx
=> 0x00000000004008a2 <+27>:   call   0x400ace <A::A()>
```

At the line `<+27>`, we call the constructor of the class *A* with one 
parameter, the pointer returned by `_Znwm@plt`:

```
gdb-peda$ x/3x $rax
0x602010:   0x0000000000000000  0x0000000000000000
0x602020:   0x0000000000000000
```

```
gdb-peda$ ni
Init A
0x00000000004008a7  38      A* varA = new A();
1: x/i $pc
=> 0x4008a7 <main()+32>:    mov    QWORD PTR [rbp-0x48],rbx

gdb-peda$ x/3x $rax
0x602010:   0x0000000000400df0  0x0000000000001337
0x602020:   0x0000000000000000
```

What is it? It's just our object allocated in memory! Here, `0x400df0` is a 
pointer to our VTable and `0x1337` is the value of our `m_value`! We continue 
the debugging session:

```
   0x00000000004008a2 <+27>:    call   0x400ace <A::A()>
   0x00000000004008a7 <+32>:    mov    QWORD PTR [rbp-0x48],rbx
   0x00000000004008ab <+36>:    mov    rax,QWORD PTR [rbp-0x48]
   0x00000000004008af <+40>:    mov    rax,QWORD PTR [rax]
   0x00000000004008b2 <+43>:    mov    rax,QWORD PTR [rax]
   0x00000000004008b5 <+46>:    mov    rdx,QWORD PTR [rbp-0x48]
   0x00000000004008b9 <+50>:    mov    rdi,rdx
=> 0x00000000004008bc <+53>:    call   rax
```

This manipulation call the member Hello() of our object: we just call the 
pointer stored at `vtable[0]`! And, of course, we stock in RDI the pointer on 
our object to pass it in parameter. Why are we doing this? When we do 
`this.m_value = 0x1337`, our method will need to know the address of our object 
(*this*), so we need to store it specify it.

```
gdb-peda$ info registers $rdi
rdi            0x602010 0x602010

gdb-peda$ x/2x $rdi
0x602010:   0x0000000000400df0  0x0000000000001337
```


# Dumping the VTable

Like in gdb, nothing magical:

```cpp
#include <stdio.h>

class A {
    public:
        A() {
            printf("Init A\n");
            m_value = 0x1337;
        }

        void virtual  Hello() {
            printf("I'm a class A\n");
        }

        void virtual Useless() {
            printf("I'm an useless method\n");   
        }
    protected:
        unsigned long m_value;
};

class B : A {
     public:
        B() {
            printf("Init B\n");
            m_value = 0x1338;
        }

        void virtual Hello() {
            printf("I'm a class B\n");
        }   
};

int main() {
    A* varA = new A();
    varA->Hello();
    varA->Useless();
    A* varB = reinterpret_cast<A*>(new B());
    varB->Hello();
    varB->Useless();

    printf("------------------------------\n");
    unsigned long* addrVarA = reinterpret_cast<unsigned long*>(&varA);
    printf("addrVarA: 0x%X\n", addrVarA);
    unsigned long* tableVarA = reinterpret_cast<unsigned long*>(*addrVarA);
    printf("tableVarA: 0x%X\n", tableVarA);
    unsigned long* vtableA = reinterpret_cast<unsigned long*>(tableVarA[0]); 
    printf("\ttableVarA[0] (VTable addr):   0x%X\n", vtableA);
    printf("\tVTable[0] (Hello ptr):        0x%X\n", vtableA[0]);
    printf("\tVTable[1] (Useless ptr):      0x%X\n", vtableA[1]);
    printf("tableVarA[1] (m_value):         0x%X\n", tableVarA[1]);

    printf("------------------------------\n");
    unsigned long* addrVarB = reinterpret_cast<unsigned long*>(&varB);
    printf("addrVarB: 0x%X\n", addrVarB);
    unsigned long* tableVarB = reinterpret_cast<unsigned long*>(*addrVarB);
    printf("tableVarB: 0x%X\n", tableVarB);
    unsigned long* vtableB = reinterpret_cast<unsigned long*>(tableVarB[0]); 
    printf("\ttableVarB[0] (VTable addr):   0x%X\n", vtableB);
    printf("\tVTable[0] (Hello ptr):        0x%X\n", vtableB[0]);
    printf("\tVTable[1] (Useless ptr):      0x%X\n", vtableB[1]);
    printf("tableVarB[1] (m_value):         0x%X\n", tableVarB[1]);


    return 0;
}
```

The output:

```
Init A
I'm a class A
I'm an useless method
Init A
Init B
I'm a class B
I'm an useless method
------------------------------
addrVarA: 0x6095DD28
tableVarA: 0x1523010
    tableVarA[0] (VTable addr):   0x400DF0
    VTable[0] (Hello ptr):        0x400AFE
    VTable[1] (Useless ptr):      0x400B16
tableVarA[1] (m_value):             0x1337
------------------------------
addrVarB: 0x6095DD20
tableVarB: 0x1523030
    tableVarB[0] (VTable addr):   0x400DD0
    VTable[0] (Hello ptr):        0x400B6A
    VTable[1] (Useless ptr):      0x400B16
tableVarB[1] (m_value):             0x1338
``` 

Do you see? The `Hello()` pointer is different for the two object, but the 
`Useless()` pointer is the same!


## Hooking the VTable

It's easy: just overwrite the `vtable[i]` pointer! And don’t forget to manage 
the object pointer stored in the first parameter.

```cpp
#include <stdio.h>
#include <errno.h>
#include <sys/mman.h>
#include <unistd.h>

class A {
    public:
        A() {
            printf("Init A\n");
            m_value = 0x1337;
        }

        void virtual  Hello() {                 // Index 0
            printf("I'm a class A\n");
        }

        void virtual Useless() {
            printf("I'm an useless method\n");  // Index 1 
        }
    protected:
        unsigned long m_value;
};

void hook_vtable(unsigned long* pClass, int methodIndex, unsigned long pFunction) {
    unsigned long* classTable = reinterpret_cast<unsigned long*>(*pClass);
    unsigned long* vTable = reinterpret_cast<unsigned long*>(*classTable);

    int pageSize = getpagesize();
    unsigned long pMethod = reinterpret_cast<unsigned long>(&vTable[methodIndex]);
    unsigned long* pMethodAligned = 
        reinterpret_cast<unsigned long*>(pMethod - (pMethod  % pageSize));    
    
    if (mprotect(pMethodAligned, pageSize, PROT_READ|PROT_WRITE|PROT_EXEC) < 0) { 
        // Do not forget PROT_EXEC: our code is in the same page!
        printf("Error: %d\n", errno);
        return;   
    } 
    
    vTable[methodIndex] = pFunction;
    
    if (mprotect(pMethodAligned, pageSize, PROT_READ|PROT_EXEC) < 0) { 
        // VirtualProtect on Windows
        printf("Error: %d\n", errno);
        return;    
    }
}

void hello_hooked(A* objectA) {
    unsigned long* classTable = reinterpret_cast<unsigned long*>(objectA);
    
    printf("I'm not a class A but your mValue is 0x%X\n", classTable[1]);
}

int main() {
    A* varA = new A();

    varA->Hello();
    hook_vtable(reinterpret_cast<unsigned long*>(&varA), 0, 
        reinterpret_cast<unsigned long>(&hello_hooked));
    varA->Hello();

    return 0;
}
```

Output:


```
Init A
I'm a class A
I'm not a class A but your mValue is 0x1337
```