---
title: "Parsing and Loading ELF Kernel Images"
date: 2026-01-26
description: "Understanding the ELF format and loading kernel segments into memory"
tags: ["os-dev", "elf", "bootloader"]
weight: 2
---

## ELF Format Overview

The kernel is compiled as an ELF (Executable and Linkable Format) binary. The bootloader must parse it to know where to load code and data in memory.

```
┌─────────────────┐
│   ELF Header    │  Magic, entry point, program header offset
├─────────────────┤
│ Program Headers │  Segments to load (PT_LOAD)
├─────────────────┤
│  Section Headers│  Debug info, symbols (not needed for loading)
├─────────────────┤
│                 │
│    Segments     │  Actual code and data
│                 │
└─────────────────┘
```

## ELF Header

```rust
#[repr(C)]
pub struct ElfHeader {
    pub magic: [u8; 4],        // \x7fELF
    pub class: u8,             // 2 = 64-bit
    pub endian: u8,            // 1 = little-endian
    pub version: u8,
    pub os_abi: u8,
    pub _pad: [u8; 8],
    pub ty: u16,               // 2 = executable
    pub machine: u16,          // 0x3E = x86-64
    pub version2: u32,
    pub entry: u64,            // kernel entry point!
    pub ph_offset: u64,        // program header table offset
    pub sh_offset: u64,
    pub flags: u32,
    pub eh_size: u16,
    pub ph_entry_size: u16,
    pub ph_count: u16,
    // ...
}
```

## Program Header (PT_LOAD)

```rust
#[repr(C)]
pub struct ProgramHeader {
    pub ty: u32,          // 1 = PT_LOAD
    pub flags: u32,       // PF_R | PF_W | PF_X
    pub offset: u64,      // offset in file
    pub vaddr: u64,       // virtual address to load at
    pub paddr: u64,       // physical address (unused)
    pub file_size: u64,   // size in file
    pub mem_size: u64,    // size in memory (>= file_size, zero-filled)
    pub align: u64,
}
```

## Loading Segments

```rust
pub fn load_elf(elf_data: &[u8]) -> u64 {
    let header = unsafe { &*(elf_data.as_ptr() as *const ElfHeader) };

    // Validate
    assert_eq!(&header.magic, b"\x7fELF");
    assert_eq!(header.class, 2);      // 64-bit
    assert_eq!(header.machine, 0x3E); // x86-64

    // Load each PT_LOAD segment
    let ph_base = &elf_data[header.ph_offset as usize..];
    for i in 0..header.ph_count {
        let offset = i as usize * header.ph_entry_size as usize;
        let ph = unsafe { &*(ph_base[offset..].as_ptr() as *const ProgramHeader) };

        if ph.ty != 1 { continue; } // Skip non-LOAD segments

        let src = &elf_data[ph.offset as usize..][..ph.file_size as usize];
        let dst = ph.vaddr as *mut u8;

        unsafe {
            // Copy segment data
            core::ptr::copy_nonoverlapping(src.as_ptr(), dst, ph.file_size as usize);

            // Zero-fill BSS (mem_size > file_size)
            let bss_size = (ph.mem_size - ph.file_size) as usize;
            if bss_size > 0 {
                core::ptr::write_bytes(dst.add(ph.file_size as usize), 0, bss_size);
            }
        }
    }

    header.entry // return entry point
}
```

## Typical Kernel Segments

```bash
$ readelf -l kernel.elf

Type   Offset   VirtAddr           FileSiz  MemSiz   Flg
LOAD   0x001000 0xffff800000100000 0x05a000 0x05a000 R E  # .text (code)
LOAD   0x05b000 0xffff800000200000 0x002000 0x002000 R    # .rodata
LOAD   0x05d000 0xffff800000300000 0x001000 0x008000 RW   # .data + .bss
```

The `.bss` segment has `MemSiz > FileSiz` — the extra bytes are zero-initialized global variables.
