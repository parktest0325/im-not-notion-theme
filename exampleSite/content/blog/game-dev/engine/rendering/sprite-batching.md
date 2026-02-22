---
title: "Sprite Batching for 2D Rendering"
date: 2026-02-18
description: "Reducing draw calls from thousands to single digits with texture atlas batching"
tags: ["graphics", "optimization", "2d"]
weight: 3
---

## The Problem

Naive 2D rendering issues one draw call per sprite. With 1000 enemies on screen, that's 1000 draw calls — way too many for 60fps.

## Texture Atlas

Pack all sprites into a single large texture (atlas). Now every sprite uses the same texture, enabling batching.

```rust
pub struct TextureAtlas {
    texture: vk::Image,
    regions: HashMap<String, AtlasRegion>,
}

pub struct AtlasRegion {
    pub u_min: f32,
    pub v_min: f32,
    pub u_max: f32,
    pub v_max: f32,
}
```

## Batch Renderer

Collect all sprites into a single vertex buffer and draw in one call:

```rust
pub struct SpriteBatch {
    vertices: Vec<SpriteVertex>,
    max_sprites: usize,
}

impl SpriteBatch {
    pub fn draw(&mut self, sprite: &Sprite, transform: &Transform) {
        let region = &sprite.atlas_region;
        let corners = transform.corners();

        // Push 4 vertices (quad)
        self.vertices.push(SpriteVertex {
            position: corners[0],
            tex_coord: [region.u_min, region.v_min],
            color: sprite.color,
        });
        // ... 3 more vertices
    }

    pub fn flush(&mut self, cmd: vk::CommandBuffer) {
        // Upload vertices and issue single draw call
        // vkCmdDrawIndexed(cmd, self.vertices.len() / 4 * 6, ...)
        self.vertices.clear();
    }
}
```

## Results

| Approach | Draw Calls | Frame Time |
|----------|-----------|------------|
| Naive (1 per sprite) | 1000 | 16.2ms |
| Batched (1 per atlas) | 3 | 0.4ms |
| Instanced | 3 | 0.3ms |

40x performance improvement with minimal code complexity.
