---
title: "Phantom Engine"
description: "Custom 2D game engine built from scratch in Rust with Vulkan rendering, ECS architecture, and hot-reload scripting."
featured_image: "https://images.unsplash.com/photo-1550745165-9bc0b252726f?w=800&q=80"
tags: ["game-dev", "rust", "graphics"]
technologies: ["Rust", "Vulkan", "ECS", "Lua"]
status: "active"
links:
  blog: "/blog/game-dev/ecs-from-scratch/"
  showcase: "https://example.com/phantom"
  demo: "https://demo.example.com/phantom"
  github: "https://github.com/example/phantom-engine"
weight: 1
---

## Overview

Phantom Engine is a custom 2D game engine focused on performance and developer experience.

### Features

- **ECS Architecture**: Archetype-based Entity Component System for cache-friendly iteration
- **Vulkan Renderer**: Sprite batching, texture atlases, 10K+ sprites at 60fps
- **Hot-reload Scripting**: Lua scripting with live reload during development
- **Built-in Editor**: Level editor with tilemap support

### Architecture

```
phantom-engine/
├── crates/
│   ├── phantom-ecs/      # Entity Component System
│   ├── phantom-render/   # Vulkan 2D renderer
│   ├── phantom-script/   # Lua scripting bridge
│   ├── phantom-audio/    # Audio system (OpenAL)
│   └── phantom-editor/   # Level editor UI
└── examples/
    ├── platformer/
    └── top-down-rpg/
```

### Roadmap

- [x] ECS core
- [x] Vulkan sprite rendering
- [x] Lua scripting
- [ ] Physics (Box2D integration)
- [ ] Networking (peer-to-peer)
- [ ] WebGPU backend
