---
title: "Getting Started with Rust Game Development"
date: 2026-02-10
description: "Setting up a Rust project for game development — crates, window creation, game loop"
tags: ["rust", "tutorial", "beginner"]
weight: 1
---

## Prerequisites

- Rust toolchain (rustup)
- A GPU with Vulkan support
- Basic Rust knowledge

## Project Setup

```bash
cargo new phantom-game --bin
cd phantom-game
```

Add dependencies to `Cargo.toml`:

```toml
[dependencies]
winit = "0.30"      # Window creation
ash = "0.38"        # Vulkan bindings
glam = "0.29"       # Math (vectors, matrices)
image = "0.25"      # Image loading
log = "0.4"
env_logger = "0.11"
```

## Window Creation

```rust
use winit::{
    event::{Event, WindowEvent},
    event_loop::EventLoop,
    window::WindowBuilder,
};

fn main() {
    env_logger::init();

    let event_loop = EventLoop::new().unwrap();
    let window = WindowBuilder::new()
        .with_title("Phantom Engine")
        .with_inner_size(winit::dpi::LogicalSize::new(1280, 720))
        .build(&event_loop)
        .unwrap();

    event_loop.run(|event, target| {
        match event {
            Event::WindowEvent { event: WindowEvent::CloseRequested, .. } => {
                target.exit();
            }
            Event::AboutToWait => {
                window.request_redraw();
            }
            Event::WindowEvent { event: WindowEvent::RedrawRequested, .. } => {
                // Game loop here
            }
            _ => {}
        }
    }).unwrap();
}
```

## Game Loop

A proper game loop separates update (logic) from render (drawing):

```rust
struct GameState {
    last_time: std::time::Instant,
    accumulator: f64,
}

const TICK_RATE: f64 = 1.0 / 60.0;

impl GameState {
    fn frame(&mut self) {
        let now = std::time::Instant::now();
        let dt = (now - self.last_time).as_secs_f64();
        self.last_time = now;
        self.accumulator += dt;

        while self.accumulator >= TICK_RATE {
            self.update(TICK_RATE);
            self.accumulator -= TICK_RATE;
        }

        self.render();
    }
}
```

## Next Steps

Now you have a window and a game loop. Next tutorials cover:
1. [ECS Architecture](/blog/game-dev/engine/ecs-from-scratch/)
2. [Vulkan Rendering](/blog/game-dev/engine/rendering/vulkan-renderer/)
3. [Sprite Animation](/blog/game-dev/tutorials/sprite-animation/)
