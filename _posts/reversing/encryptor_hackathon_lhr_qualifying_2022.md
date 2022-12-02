---
title: Encryptor hackathon lhr Qualifier 2022
author: megachar0x01
date: 2022-12-02
categories: [Reversing, amd64, ctf]
---

After Opening Binary in ghidra get to know that it's C++ Binary. Converted it into python to get clear insight as to what binary is doing.

```python
#!/usr/bin/python3

def second_algo(data):
    local_data=bytearray(1)
    local_data=data
    local_data = local_data ^ (local_data>>1)
    local_data = local_data ^ (local_data>>2)
    local_data = local_data ^ (local_data>>3)
    local_data = local_data ^ (local_data>>7)
    return local_data

def first_algo(data):
    local_data = bytearray(len(data))
    for i in range(len(data)):
        if (i % 2) == 0 :
            local_data[i]=ord(data[i])+3
        else:
            local_data[i]=ord(data[i])+23
    local_data.reverse()
    local_data_1 = bytearray(4)
    key="toka"
    for i in range(4):
        if (i%2)==0:
            local_data_1[i]=ord(key[i]) - 3
        else:
            local_data_1[i]=ord(key[i]) + 3
    
    return local_data+local_data_1


print("Please input your input")
input_user=input()
x = first_algo(input_user)
y = bytearray(len(x))
y = x

for i in range(len(x)):
    if i > 0:
        y[i]=y[i-1] ^ y[i]
    y[i]=second_algo(y[i])    
print(y.hex())


```


we can see that it is taking input and then passing it to the first algo which is converting characters into hex then if the loop variable is even added 3 and if the loop variable is odd it adds 23 then reverse the array and concat "toka" but after encrypting it. for which the even word is added 3 and odd 3 is subtracted.
then the string is passed to the second algo which except the array's first value xor it with the previous value and then saves it after that char is xor with itself shifted bits values which in first is 1 then 2 then 3 and lastly 7.


# Solution :

```python

#!/usr/bin/python3
from pwn import *

enc = "472d630655246b1c5f207019473d611d47306d"
enc_flag = ['0x47', '0x2d', '0x63', '0x06', '0x55', '0x24', '0x6b', '0x1c', '0x5f', '0x20', '0x70', '0x19', '0x47', '0x3d', '0x61', '0x1d', '0x47', '0x30', '0x6d',]

flag=bytearray(19)

def second_algo(data):
    local_data=bytearray(1)
    local_data=data
    local_data = local_data ^ (local_data>>1)
    local_data = local_data ^ (local_data>>2)
    local_data = local_data ^ (local_data>>3)
    local_data = local_data ^ (local_data>>7)
    return local_data

for i in range(19):
    for z in range(256):
        y = bytearray(19)
        y = flag
        y[i]=z
        if i > 0:
            y[i]=y[i-1] ^ y[i]
        y[i]=second_algo(y[i])    
        if y[i] == int(enc_flag[i],16):
            print(f"i:{i}  char:{chr(z)}")            

            break
flag=bytearray(b"oxqfpfuzdjdfvbbqrhd")[0:15][::-1]

                    
def first_algo_d(data):
    local_data = bytearray(len(data))
    local_data=data
    for i in range(len(data)):
        print(local_data[i])
        if (i%2) == 0:
            local_data[i]=local_data[i]-3
        else:
            local_data[i]=local_data[i]-23
    return local_data

flag=first_algo_d(flag)

print(flag)


```
The encrypted flag was converted into a hex value. Right-bit shift values are lost so recovering is impossible I Bruteforce it word by word and then reversed the first algorithm to get the Flag.
