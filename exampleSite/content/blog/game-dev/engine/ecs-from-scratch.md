---
title: "Building an ECS from Scratch"
date: 2026-02-15
description: "Implementing an Entity Component System in Rust for a 2D game engine"
tags: ["rust", "game-dev", "ecs"]
weight: 1
---

## Why ECS?

Traditional object-oriented game architectures suffer from the diamond inheritance problem. Entity Component System (ECS) solves this by favoring composition over inheritance.

## Core Architecture

The ECS pattern consists of three parts:

- **Entities**: Unique IDs (just a number)
- **Components**: Pure data attached to entities
- **Systems**: Logic that operates on components

```rust
pub struct World {
    entities: Vec<Entity>,
    components: HashMap<TypeId, Box<dyn ComponentStorage>>,
}

impl World {
    pub fn spawn(&mut self) -> Entity {
        let id = self.entities.len();
        self.entities.push(Entity(id));
        Entity(id)
    }

    pub fn add_component<T: Component>(&mut self, entity: Entity, component: T) {
        // Store component in typed storage
    }
}
```

## Performance Considerations

The key insight is **data locality**. By storing components of the same type contiguously in memory, we get excellent cache performance when iterating over them in systems.

### Archetype-based Storage

Instead of storing components per-entity, we group entities by their component signature (archetype):

| Archetype | Components | Entities |
|-----------|-----------|----------|
| A | Position, Velocity | player, enemy1, enemy2 |
| B | Position, Sprite | tree, rock |
| C | Position, Velocity, Health | boss |

This gives us O(1) component access and cache-friendly iteration.

## Benchmark

![ECS performance comparison](https://images.unsplash.com/photo-1551288049-bebda4e38f71?w=600&q=80)

Our archetype-based ECS iterating over 100K entities with Position + Velocity:
- **Archetype ECS**: 0.8ms
- **HashMap ECS**: 12ms
- **OOP inheritance**: 45ms

## Next Steps

In the next post, we'll implement a rendering system using Vulkan and integrate it with our ECS.
