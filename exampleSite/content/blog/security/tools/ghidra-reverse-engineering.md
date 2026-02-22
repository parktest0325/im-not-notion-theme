---
title: "Reverse Engineering with Ghidra"
date: 2026-02-04
description: "Using NSA's Ghidra to analyze stripped binaries — decompilation, patching, scripting"
tags: ["reverse-engineering", "ghidra", "binary-analysis"]
weight: 2
---

## Why Ghidra?

Ghidra is a free, open-source reverse engineering tool by the NSA. It rivals IDA Pro for most tasks:

- **Decompiler** — produces readable C-like pseudocode
- **Scripting** — Java/Python API for automation
- **Multi-arch** — x86, ARM, MIPS, RISC-V, etc.
- **Collaboration** — shared projects via Ghidra Server

## Workflow

### 1. Import and Analyze

```
File → Import File → select binary
Analysis → Auto Analyze (accept defaults)
```

Wait for analysis to complete. Ghidra identifies functions, strings, cross-references.

### 2. Find Interesting Functions

**String search**: `Search → For Strings` → look for error messages, "password", "flag", etc.

**Imports**: Check `Symbol Tree → Imports` for interesting library calls (`strcmp`, `system`, `exec`).

### 3. Decompiler View

Navigate to a function → `Window → Decompile`. Ghidra produces:

```c
// Decompiled output
undefined8 check_password(char *input) {
    int result;
    char expected[32];

    strncpy(expected, "s3cr3t_p4ss", 11);
    result = strcmp(input, expected);
    if (result == 0) {
        puts("Access granted!");
        return 1;
    }
    puts("Wrong password.");
    return 0;
}
```

### 4. Patching

To bypass a check, right-click the conditional jump → `Patch Instruction`:

```asm
; Original
JNZ  LAB_00401050    ; jump if password wrong

; Patched
JZ   LAB_00401050    ; inverted — always succeeds
; or
NOP                  ; remove the check entirely
NOP
```

`File → Export Program → Binary` to save the patched binary.

## Ghidra Scripting

Automate analysis with Python (Jython):

```python
# find_crypto_constants.py
# Searches for known crypto S-box values

from ghidra.program.model.mem import MemoryAccessException

AES_SBOX_FIRST = [0x63, 0x7c, 0x77, 0x7b]

listing = currentProgram.getListing()
memory = currentProgram.getMemory()

for block in memory.getBlocks():
    if not block.isInitialized():
        continue
    start = block.getStart()
    end = block.getEnd()
    addr = start
    while addr < end:
        try:
            match = True
            for i, val in enumerate(AES_SBOX_FIRST):
                if memory.getByte(addr.add(i)) & 0xFF != val:
                    match = False
                    break
            if match:
                print(f"Possible AES S-box at {addr}")
        except MemoryAccessException:
            pass
        addr = addr.add(1)
```

## Tips

- **Rename variables** as you understand them — Ghidra propagates names through the code
- **Set function signatures** for library calls the decompiler misidentifies
- **Bookmarks** for important locations you want to revisit
- Use `References → Find References To` to track data flow
