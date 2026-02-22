---
title: "Writing a UEFI Bootloader in Rust"
date: 2026-01-25
description: "Loading a kernel ELF from disk using UEFI protocols — GOP, memory map, ExitBootServices"
tags: ["os-dev", "uefi", "bootloader"]
weight: 1
---

## UEFI vs Legacy BIOS

| Feature | Legacy BIOS | UEFI |
|---------|------------|------|
| Bit mode at handoff | 16-bit Real Mode | 64-bit Long Mode |
| Boot media | MBR (2TB limit) | GPT (no practical limit) |
| Filesystem | None (raw sectors) | FAT32 on ESP |
| API | INT 10h/13h | Protocol-based C API |
| Secure Boot | No | Yes |

UEFI is better for OS development — we start in 64-bit mode with a proper API.

## Project Setup

```toml
# Cargo.toml
[dependencies]
uefi = "0.32"
uefi-services = "0.29"
```

```rust
#![no_std]
#![no_main]

use uefi::prelude::*;

#[entry]
fn main(image: Handle, mut st: SystemTable<Boot>) -> Status {
    uefi_services::init(&mut st).unwrap();
    // Bootloader code here
    loop {}
}
```

## Step 1: Set Video Mode (GOP)

```rust
fn setup_framebuffer(st: &SystemTable<Boot>) -> FramebufferInfo {
    let gop = st.boot_services()
        .locate_protocol::<GraphicsOutput>()
        .unwrap();

    // Find 1920x1080 mode
    let mode = gop.modes()
        .find(|m| {
            let info = m.info();
            info.resolution() == (1920, 1080)
        })
        .expect("1080p mode not found");

    gop.set_mode(&mode).unwrap();

    FramebufferInfo {
        base: gop.frame_buffer().as_mut_ptr() as u64,
        width: 1920,
        height: 1080,
        stride: mode.info().stride(),
    }
}
```

## Step 2: Load Kernel from Disk

```rust
fn load_kernel(st: &SystemTable<Boot>) -> &'static [u8] {
    let fs = st.boot_services()
        .locate_protocol::<SimpleFileSystem>()
        .unwrap();

    let mut root = fs.open_volume().unwrap();
    let mut file = root.open(
        cstr16!("\\EFI\\BOOT\\kernel.elf"),
        FileMode::Read,
        FileAttribute::empty(),
    ).unwrap();

    let info = file.get_info::<FileInfo>(&mut [0u8; 256]).unwrap();
    let size = info.file_size() as usize;

    let buffer = st.boot_services()
        .allocate_pool(MemoryType::LOADER_DATA, size)
        .unwrap();

    let buf = unsafe { core::slice::from_raw_parts_mut(buffer, size) };
    file.read(buf).unwrap();
    buf
}
```

## Step 3: Exit Boot Services

This is the point of no return. After this, UEFI firmware is gone — no more boot services.

```rust
fn exit_and_jump(
    image: Handle,
    st: SystemTable<Boot>,
    kernel_entry: u64,
    boot_info: &BootInfo,
) -> ! {
    let (_, memory_map) = st.exit_boot_services(MemoryType::LOADER_DATA);

    // Jump to kernel
    let entry: extern "sysv64" fn(&BootInfo) -> ! =
        unsafe { core::mem::transmute(kernel_entry) };
    entry(boot_info);
}
```

## Boot Sequence

```
Power On → UEFI Firmware → ESP (FAT32) → bootx64.efi
  → Set video mode (GOP)
  → Load kernel.elf from disk
  → Get memory map
  → Exit boot services
  → Jump to kernel entry point
```

![UEFI boot process](https://images.unsplash.com/photo-1518770660439-4636190af475?w=600&q=80)
