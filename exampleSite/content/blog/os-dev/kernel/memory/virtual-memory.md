---
title: "x86-64 Virtual Memory & Page Tables"
date: 2026-02-02
description: "Setting up 4-level page tables for virtual address translation on x86-64"
tags: ["os-dev", "kernel", "x86-64", "paging"]
weight: 2
---

## Virtual Address Translation

x86-64 uses 4-level page tables. A 48-bit virtual address is split into:

```
┌────────┬────────┬────────┬────────┬──────────┐
│ PML4   │  PDPT  │   PD   │   PT   │  Offset  │
│ [47:39]│ [38:30]│ [29:21]│ [20:12]│  [11:0]  │
│ 9 bits │ 9 bits │ 9 bits │ 9 bits │ 12 bits  │
└────────┴────────┴────────┴────────┴──────────┘
```

Each level has 512 entries (9 bits = 512). Each entry is 8 bytes.

## Page Table Entry

```rust
bitflags! {
    pub struct PageTableFlags: u64 {
        const PRESENT       = 1 << 0;
        const WRITABLE      = 1 << 1;
        const USER          = 1 << 2;
        const WRITE_THROUGH = 1 << 3;
        const NO_CACHE      = 1 << 4;
        const ACCESSED      = 1 << 5;
        const DIRTY         = 1 << 6;
        const HUGE_PAGE     = 1 << 7;
        const GLOBAL        = 1 << 8;
        const NO_EXECUTE    = 1 << 63;
    }
}

#[repr(transparent)]
pub struct PageTableEntry(u64);

impl PageTableEntry {
    pub fn set(&mut self, addr: PhysAddr, flags: PageTableFlags) {
        self.0 = addr.as_u64() | flags.bits();
    }

    pub fn frame(&self) -> Option<PhysAddr> {
        if self.0 & PageTableFlags::PRESENT.bits() != 0 {
            Some(PhysAddr::new(self.0 & 0x000F_FFFF_FFFF_F000))
        } else {
            None
        }
    }
}
```

## Mapping a Page

```rust
pub fn map_page(
    pml4: &mut PageTable,
    virt: VirtAddr,
    phys: PhysAddr,
    flags: PageTableFlags,
    allocator: &mut BitmapAllocator,
) {
    let indices = [
        virt.pml4_index(),
        virt.pdpt_index(),
        virt.pd_index(),
        virt.pt_index(),
    ];

    let mut table = pml4;
    for &index in &indices[..3] {
        let entry = &mut table[index];
        if !entry.is_present() {
            // Allocate a new page table
            let frame = allocator.alloc_page().expect("OOM");
            unsafe { core::ptr::write_bytes(frame.as_mut_ptr::<u8>(), 0, PAGE_SIZE); }
            entry.set(frame, PageTableFlags::PRESENT | PageTableFlags::WRITABLE);
        }
        table = unsafe { &mut *entry.frame().unwrap().as_mut_ptr::<PageTable>() };
    }

    table[indices[3]].set(phys, flags | PageTableFlags::PRESENT);
}
```

## Kernel Memory Layout

```
Virtual Address Space (48-bit canonical)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
0xFFFF_FFFF_FFFF_FFFF  ┬ Kernel stack
                        │
0xFFFF_8000_0000_0000  ┼ Direct physical map
                        │ (all physical memory mapped here)
                        │
    ─ ─ ─ canonical hole ─ ─ ─

0x0000_7FFF_FFFF_FFFF  ┬ User space (top)
                        │
0x0000_0000_0040_0000  ┼ User code (.text)
0x0000_0000_0000_0000  ┴ NULL page (unmapped)
```

## TLB Flush

After modifying page tables, you must flush the TLB for the affected addresses:

```rust
pub fn flush_tlb(addr: VirtAddr) {
    unsafe {
        core::arch::asm!("invlpg [{}]", in(reg) addr.as_u64());
    }
}
```
