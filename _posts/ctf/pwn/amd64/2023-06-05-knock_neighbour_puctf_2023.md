---
title: knock_neighbout  , NahamCon 2023
author: megachar0x01
date: 2023-06-05
categories: [Pwn, amd64, ctf]
---


## Description:
The program generates a random value at runtime using the current time as the seed. It then prompts the user for input and compares it to the previously generated random value. If the user's input matches the generated value, the program prints the flag; otherwise, it terminates.

The vulnerability lies in the random value generation seed, which is based on the current time. To complete this challenge, you can create a program that generates the same random value by using the same seed (current time) at the exact moment the target program is executed. By sending this pre-generated value to the program, you can bypass the check and obtain the flag.

## Protections

<img src="https://i.imgur.com/whi1eCW.png" alt="protection_1">

## Vulnerable Code

<img src="https://i.imgur.com/54W6CpV.png" alt="vuln_1">
<img src="https://i.imgur.com/VMM2eI1.png" alt="vuln_2">
<img src="https://i.imgur.com/MgYlQuD.png" alt="vuln_3">


## Exploit

```python

#!/usr/bin/python3
from pwn import *
import struct
import random
from ctypes import *

# context.terminal = ['tmux','splitw','-h']
os.environ['XDG_CACHE_HOME'] = '/tmp/'

context.log_level = 'error'

# Allows you to switch between local/GDB/remote from terminal
def start(argv=[], *a, **kw):
    if args.GDB:  # Set GDBscript below
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE:  # ('server', 'port')
        return remote(sys.argv[1], sys.argv[2], *a, **kw)
    else:  # Run locally
        return process([exe] + argv, *a, **kw)


# Specify GDB script here (breakpoints etc)
gdbscript = '''
break *main+301
continue
'''.format(**locals())

# Create bytearrays for the buffer and a temporary variable
buff = bytearray(0x3f)
temp_2 = bytearray(0x3f)

exe = './knock_neighbour'
elf = context.binary = ELF(exe, checksec=False)
exe_rop = ROP(elf, checksec=False)

libc = elf.libc
libc_rop = ROP(libc, checksec=False)

io = start()

# Load the libc library and get the current time
libc = cdll.LoadLibrary('libc.so.6')
time_1 = libc.time(0x0)
libc.srand(time_1)

# Generate random numbers and fill the buffers
for i in range(0x3f):
    temp = libc.rand()

    bVar1 = (temp >> 0x1f)
    buff[i] = (temp + (bVar1 >> 1) & 0x7f) - (bVar1 >> 1)
    temp_2[i] = buff[i]

padd = 104

# Set the payload as the generated buffer
payload = temp_2

# Send the first input
io.sendlineafter(b"Give me your lucky number:\n", b"1")

# Send the payload as the second input
io.sendafter(b"Give me your wish:\n", payload)

# Switch to interactive mode to interact with the exploited binary
io.interactive()


```
