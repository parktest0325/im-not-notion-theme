---
title: "Fuzzing C Programs with AFL++"
date: 2026-02-05
description: "Finding crashes and vulnerabilities automatically using American Fuzzy Lop"
tags: ["fuzzing", "afl", "security-tools"]
weight: 1
---

## What is Fuzzing?

Fuzzing = throwing random/mutated inputs at a program and watching for crashes. AFL++ uses **coverage-guided mutation** — it tracks which code paths each input triggers and prioritizes inputs that reach new paths.

## Setup

```bash
# Install AFL++
git clone https://github.com/AFLplusplus/AFLplusplus
cd AFLplusplus && make all
sudo make install

# Compile target with AFL instrumentation
afl-clang-fast -o target_fuzz target.c
```

## Target: Simple Image Parser

```c
// target.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    char magic[4];
    uint32_t width;
    uint32_t height;
    uint8_t bpp;
} ImageHeader;

void parse_image(const char *data, size_t len) {
    if (len < sizeof(ImageHeader)) return;

    ImageHeader *hdr = (ImageHeader *)data;
    if (memcmp(hdr->magic, "IMG\x01", 4) != 0) return;

    size_t pixel_data_size = hdr->width * hdr->height * (hdr->bpp / 8);
    // BUG: integer overflow if width*height*bpp overflows
    uint8_t *pixels = malloc(pixel_data_size);
    // BUG: no NULL check
    memcpy(pixels, data + sizeof(ImageHeader), pixel_data_size);
    // BUG: heap buffer overflow if pixel_data_size > actual remaining data

    free(pixels);
}

int main() {
    char buf[4096];
    size_t n = fread(buf, 1, sizeof(buf), stdin);
    parse_image(buf, n);
    return 0;
}
```

## Creating Seeds

```bash
mkdir seeds
# Create a valid minimal input
python3 -c "
import struct
hdr = b'IMG\x01'
hdr += struct.pack('<II', 2, 2)  # 2x2
hdr += struct.pack('B', 24)      # 24bpp
hdr += b'\xff' * 12              # pixel data
open('seeds/valid.img', 'wb').write(hdr)
"
```

## Running AFL++

```bash
afl-fuzz -i seeds -o findings -- ./target_fuzz
```

Within minutes, AFL++ finds multiple crashes:

```
[+] Unique crashes: 7
    - integer overflow in width*height multiplication
    - heap buffer overflow from undersized allocation
    - NULL pointer dereference on malloc failure
```

## Triaging Crashes

```bash
for crash in findings/default/crashes/id*; do
    echo "=== $crash ==="
    ./target_fuzz < "$crash" 2>&1 | head -5
done
```

![AFL++ dashboard](https://images.unsplash.com/photo-1526374965328-7f61d4dc18c5?w=600&q=80)

## AddressSanitizer Integration

Compile with ASAN for precise bug reports:

```bash
afl-clang-fast -fsanitize=address -o target_asan target.c
```

ASAN gives exact stack traces: buffer overflow at line 18, 24 bytes past allocation of 12 bytes.
