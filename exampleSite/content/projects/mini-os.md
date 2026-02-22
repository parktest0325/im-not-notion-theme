---
title: "miniOS"
description: "A minimal x86_64 operating system kernel written in Rust. Boots from UEFI, has a basic scheduler, and runs in QEMU."
featured_image: "https://images.unsplash.com/photo-1629654297299-c8506221ca97?w=800&q=80"
tags: ["os", "rust", "low-level"]
technologies: ["Rust", "x86_64", "UEFI", "QEMU"]
status: "active"
links:
  blog: "/blog/security/ctf-writeup/"
  github: "https://github.com/example/mini-os"
weight: 2
---

## Overview

miniOS is a hobby OS project for learning low-level systems programming.

### Implemented

- UEFI bootloader
- Physical & virtual memory management
- Basic preemptive scheduler
- PS/2 keyboard driver
- VGA text mode output
- Simple shell

### Boot Sequence

```
UEFI → bootloader → kernel_main → init_memory → init_interrupts → scheduler → shell
```

### Building & Running

```bash
cargo build --target x86_64-unknown-none
qemu-system-x86_64 -bios OVMF.fd -drive format=raw,file=target/boot.img
```
