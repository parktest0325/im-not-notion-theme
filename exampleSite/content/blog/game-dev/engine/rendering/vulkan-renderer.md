---
title: "Writing a Vulkan Renderer"
date: 2026-02-16
description: "Setting up a Vulkan rendering pipeline from scratch in Rust using ash"
tags: ["rust", "vulkan", "graphics"]
weight: 1
---

## Vulkan vs OpenGL

Vulkan gives us explicit control over the GPU. Unlike OpenGL's hidden state machine, Vulkan makes everything visible — memory allocation, command buffers, synchronization.

```rust
use ash::vk;

pub struct Renderer {
    instance: ash::Instance,
    device: ash::Device,
    swapchain: vk::SwapchainKHR,
    render_pass: vk::RenderPass,
    pipeline: vk::Pipeline,
    command_buffers: Vec<vk::CommandBuffer>,
}
```

## Pipeline Setup

The Vulkan graphics pipeline is **immutable** — you create it once with all state baked in:

1. **Vertex Input** — describes vertex buffer layout
2. **Input Assembly** — triangle list, strip, fan
3. **Viewport / Scissor** — render region
4. **Rasterizer** — fill mode, cull mode, depth bias
5. **Multisampling** — MSAA settings
6. **Color Blending** — alpha blending config
7. **Pipeline Layout** — descriptor set and push constant layouts

![Vulkan Pipeline](https://images.unsplash.com/photo-1633356122544-f134324a6cee?w=600&q=80)

## Render Loop

```rust
impl Renderer {
    pub fn draw_frame(&mut self) {
        // 1. Acquire swapchain image
        let image_index = self.acquire_next_image();

        // 2. Record command buffer
        self.record_commands(image_index);

        // 3. Submit to graphics queue
        self.submit_commands();

        // 4. Present to screen
        self.present(image_index);
    }
}
```

## Integration with ECS

Our renderer queries the ECS world for entities with `Sprite` + `Transform` components and batches draw calls by texture atlas.
