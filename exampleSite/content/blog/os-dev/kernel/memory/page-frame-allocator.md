---
title: "Building a Page Frame Allocator"
date: 2026-02-01
description: "Bitmap-based physical memory allocator for 4KB page frames"
tags: ["os-dev", "kernel", "memory"]
weight: 1
---

## Physical Memory Layout

After boot, the kernel needs to know which physical memory regions are usable. UEFI provides a memory map:

```rust
#[repr(C)]
pub struct MemoryDescriptor {
    pub ty: MemoryType,
    pub phys_start: u64,
    pub virt_start: u64,
    pub page_count: u64,
    pub attribute: u64,
}
```

We only care about `ConventionalMemory` regions — everything else is reserved (ACPI, MMIO, firmware).

## Bitmap Allocator

Track each 4KB page frame with a single bit. 0 = free, 1 = used.

```rust
pub struct BitmapAllocator {
    bitmap: &'static mut [u8],
    total_pages: usize,
    free_pages: usize,
}

impl BitmapAllocator {
    pub fn alloc_page(&mut self) -> Option<PhysAddr> {
        for (byte_idx, byte) in self.bitmap.iter_mut().enumerate() {
            if *byte == 0xFF { continue; } // all bits set

            for bit in 0..8 {
                if *byte & (1 << bit) == 0 {
                    *byte |= 1 << bit;
                    self.free_pages -= 1;
                    let page_idx = byte_idx * 8 + bit;
                    return Some(PhysAddr::new(page_idx as u64 * PAGE_SIZE));
                }
            }
        }
        None // out of memory
    }

    pub fn free_page(&mut self, addr: PhysAddr) {
        let page_idx = addr.as_u64() as usize / PAGE_SIZE as usize;
        let byte_idx = page_idx / 8;
        let bit = page_idx % 8;
        self.bitmap[byte_idx] &= !(1 << bit);
        self.free_pages += 1;
    }
}
```

## Initialization from UEFI Memory Map

```rust
pub fn init_from_memory_map(map: &[MemoryDescriptor]) -> BitmapAllocator {
    // Find highest address to determine bitmap size
    let max_addr = map.iter()
        .map(|d| d.phys_start + d.page_count * 4096)
        .max()
        .unwrap();

    let total_pages = (max_addr / PAGE_SIZE) as usize;
    let bitmap_size = (total_pages + 7) / 8;

    // Place bitmap in first available conventional memory
    let bitmap_region = find_region_for_bitmap(map, bitmap_size);
    let bitmap = unsafe {
        core::slice::from_raw_parts_mut(bitmap_region as *mut u8, bitmap_size)
    };

    // Mark all as used, then free conventional memory regions
    bitmap.fill(0xFF);
    let mut allocator = BitmapAllocator { bitmap, total_pages, free_pages: 0 };

    for desc in map {
        if desc.ty == MemoryType::CONVENTIONAL {
            for i in 0..desc.page_count {
                let addr = PhysAddr::new(desc.phys_start + i * 4096);
                allocator.free_page(addr);
            }
        }
    }

    allocator
}
```

## Memory: 16GB System

- Total pages: 4,194,304 (16GB / 4KB)
- Bitmap size: 512KB
- Overhead: 0.003%
