---
title: "Priority-Based Scheduling with CFS"
date: 2026-01-30
description: "Implementing a Completely Fair Scheduler inspired by Linux CFS using a red-black tree"
tags: ["os-dev", "kernel", "scheduler", "algorithms"]
weight: 2
---

## Problem with Round-Robin

Round-robin treats all tasks equally. But an interactive shell needs lower latency than a background compiler. We need **priority-based scheduling**.

## Linux CFS Concept

CFS (Completely Fair Scheduler) tracks **virtual runtime** — how much CPU time each task has consumed, weighted by priority. The task with the lowest virtual runtime runs next.

```rust
pub struct CfsTask {
    pub id: u64,
    pub vruntime: u64,     // virtual runtime in nanoseconds
    pub nice: i8,          // priority: -20 (high) to 19 (low)
    pub weight: u32,       // derived from nice
    pub context: Context,
}

// Weight table (subset) — from Linux kernel
const NICE_TO_WEIGHT: [u32; 40] = [
    88761, 71755, 56483, 46273, 36291, // nice -20 to -16
    29154, 23254, 18705, 14949, 11916, // nice -15 to -11
    9548,  7620,  6100,  4904,  3906,  // nice -10 to -6
    3121,  2501,  1991,  1586,  1277,  // nice  -5 to -1
    1024,   820,   655,   526,   423,  // nice   0 to  4
     335,   272,   215,   172,   137,  // nice   5 to  9
     110,    87,    70,    56,    45,  // nice  10 to 14
      36,    29,    23,    18,    15,  // nice  15 to 19
];
```

## Virtual Runtime Calculation

```rust
impl CfsTask {
    pub fn update_vruntime(&mut self, delta_ns: u64) {
        // Higher weight = slower vruntime growth = more CPU time
        self.vruntime += delta_ns * 1024 / self.weight as u64;
    }
}
```

A task with nice 0 (weight 1024) advances vruntime at 1:1. A high-priority task (nice -5, weight 3121) advances ~3x slower, so it gets ~3x more CPU time.

## Red-Black Tree

CFS uses a red-black tree sorted by vruntime. The leftmost node (lowest vruntime) runs next — O(1) lookup, O(log n) insert/remove.

```rust
use alloc::collections::BTreeMap;

pub struct CfsScheduler {
    tree: BTreeMap<(u64, u64), CfsTask>,  // (vruntime, id) → task
    min_vruntime: u64,
    current: Option<CfsTask>,
}

impl CfsScheduler {
    pub fn pick_next(&mut self) -> Option<CfsTask> {
        let key = *self.tree.keys().next()?;
        self.tree.remove(&key)
    }

    pub fn enqueue(&mut self, mut task: CfsTask) {
        // New tasks start at min_vruntime to prevent starvation
        if task.vruntime < self.min_vruntime {
            task.vruntime = self.min_vruntime;
        }
        self.tree.insert((task.vruntime, task.id), task);
    }
}
```

## Latency Target

CFS aims for a **scheduling period** where every task runs at least once:

```
period = max(6ms, nr_tasks * 0.75ms)
timeslice = period * task_weight / total_weight
```

With 8 tasks of equal priority: each gets 6ms / 8 = 0.75ms per period.
