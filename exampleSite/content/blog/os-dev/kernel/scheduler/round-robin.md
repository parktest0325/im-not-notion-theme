---
title: "Implementing a Round-Robin Scheduler"
date: 2026-01-28
description: "Preemptive multitasking with timer interrupts and context switching"
tags: ["os-dev", "kernel", "scheduler"]
weight: 1
---

## Task Structure

Each task has a saved CPU context for context switching:

```rust
#[repr(C)]
pub struct Task {
    pub id: u64,
    pub state: TaskState,
    pub context: Context,
    pub kernel_stack: VirtAddr,
    pub page_table: PhysAddr,
}

#[repr(C)]
pub struct Context {
    pub rsp: u64,
    pub rbp: u64,
    pub rbx: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub rip: u64,
    pub rflags: u64,
}

pub enum TaskState {
    Ready,
    Running,
    Blocked,
    Terminated,
}
```

## Context Switch

The assembly code that saves/restores registers:

```asm
; switch_context(old: *mut Context, new: *const Context)
global switch_context
switch_context:
    ; Save old context
    mov [rdi + 0x00], rsp
    mov [rdi + 0x08], rbp
    mov [rdi + 0x10], rbx
    mov [rdi + 0x18], r12
    mov [rdi + 0x20], r13
    mov [rdi + 0x28], r14
    mov [rdi + 0x30], r15
    lea rax, [rel .resume]
    mov [rdi + 0x38], rax     ; rip = return address
    pushfq
    pop qword [rdi + 0x40]    ; rflags

    ; Restore new context
    mov rsp, [rsi + 0x00]
    mov rbp, [rsi + 0x08]
    mov rbx, [rsi + 0x10]
    mov r12, [rsi + 0x18]
    mov r13, [rsi + 0x20]
    mov r14, [rsi + 0x28]
    mov r15, [rsi + 0x30]
    push qword [rsi + 0x40]
    popfq                      ; rflags
    jmp [rsi + 0x38]           ; rip

.resume:
    ret
```

## Scheduler

```rust
pub struct Scheduler {
    tasks: VecDeque<Task>,
    current: Option<Task>,
}

impl Scheduler {
    pub fn schedule(&mut self) {
        if let Some(mut current) = self.current.take() {
            if current.state == TaskState::Running {
                current.state = TaskState::Ready;
                self.tasks.push_back(current);
            }
        }

        while let Some(mut next) = self.tasks.pop_front() {
            if next.state == TaskState::Ready {
                next.state = TaskState::Running;
                let old_ctx = /* previous context */;
                let new_ctx = &next.context;
                self.current = Some(next);

                unsafe { switch_context(old_ctx, new_ctx); }
                return;
            }
        }

        // No ready tasks — halt until next interrupt
        unsafe { core::arch::asm!("hlt"); }
    }
}
```

## Timer Interrupt (Preemption)

The APIC timer fires every 10ms, calling `schedule()`:

```rust
extern "x86-interrupt" fn timer_handler(_frame: InterruptStackFrame) {
    SCHEDULER.lock().schedule();
    // Send EOI to APIC
    unsafe { LAPIC.as_mut().unwrap().end_of_interrupt(); }
}
```

This gives us **preemptive multitasking** — no task can hog the CPU.
