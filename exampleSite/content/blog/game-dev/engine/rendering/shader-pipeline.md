---
title: "SPIR-V Shader Pipeline"
date: 2026-02-17
description: "Compiling GLSL to SPIR-V and hot-reloading shaders at runtime"
tags: ["vulkan", "shaders", "glsl"]
weight: 2
---

## Why SPIR-V?

Vulkan doesn't accept GLSL directly. Instead, shaders must be compiled to **SPIR-V** (Standard Portable Intermediate Representation). This gives us:

- Offline compilation — catch errors at build time
- Optimization — `glslangValidator` applies optimizations
- Cross-platform — same binary format everywhere

## Build-time Compilation

We use a `build.rs` script to compile shaders during `cargo build`:

```rust
// build.rs
fn main() {
    let shader_dir = std::path::Path::new("shaders");
    for entry in std::fs::read_dir(shader_dir).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().map_or(false, |e| e == "vert" || e == "frag") {
            let output = path.with_extension(format!(
                "{}.spv",
                path.extension().unwrap().to_str().unwrap()
            ));
            std::process::Command::new("glslangValidator")
                .args(&["-V", path.to_str().unwrap(), "-o", output.to_str().unwrap()])
                .status()
                .expect("Failed to compile shader");
        }
    }
}
```

## Vertex Shader

```glsl
#version 450

layout(location = 0) in vec2 inPosition;
layout(location = 1) in vec2 inTexCoord;
layout(location = 2) in vec4 inColor;

layout(set = 0, binding = 0) uniform UniformBuffer {
    mat4 projection;
    mat4 view;
};

layout(push_constant) uniform PushConstants {
    mat4 model;
};

layout(location = 0) out vec2 fragTexCoord;
layout(location = 1) out vec4 fragColor;

void main() {
    gl_Position = projection * view * model * vec4(inPosition, 0.0, 1.0);
    fragTexCoord = inTexCoord;
    fragColor = inColor;
}
```

## Hot Reload

For development, we watch the `shaders/` directory and recompile + recreate the pipeline on change:

```rust
pub struct ShaderWatcher {
    watcher: notify::RecommendedWatcher,
    rx: std::sync::mpsc::Receiver<notify::Event>,
}

impl ShaderWatcher {
    pub fn poll(&self) -> bool {
        self.rx.try_recv().is_ok()
    }
}
```

![Shader visual debugging](https://images.unsplash.com/photo-1550751827-4bd374c3f58b?w=600&q=80)

This gives us instant visual feedback — edit a shader, save, see the result in under 100ms.
