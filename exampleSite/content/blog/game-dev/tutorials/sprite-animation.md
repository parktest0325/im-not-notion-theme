---
title: "2D Sprite Animation System"
date: 2026-02-11
description: "Frame-based animation with state machines for character sprites"
tags: ["animation", "2d", "tutorial"]
weight: 2
---

## Animation Data

An animation is a sequence of atlas regions played at a fixed rate:

```rust
pub struct Animation {
    pub name: String,
    pub frames: Vec<AtlasRegion>,
    pub frame_duration: f32,  // seconds per frame
    pub looping: bool,
}

pub struct Animator {
    pub current: String,
    pub timer: f32,
    pub frame_index: usize,
    pub animations: HashMap<String, Animation>,
}
```

## Animator System

```rust
fn animator_system(world: &mut World, dt: f32) {
    for (_, (animator, sprite)) in world.query::<(&mut Animator, &mut Sprite)>() {
        let anim = &animator.animations[&animator.current];

        animator.timer += dt;
        if animator.timer >= anim.frame_duration {
            animator.timer -= anim.frame_duration;
            animator.frame_index += 1;

            if animator.frame_index >= anim.frames.len() {
                if anim.looping {
                    animator.frame_index = 0;
                } else {
                    animator.frame_index = anim.frames.len() - 1;
                }
            }
        }

        sprite.region = anim.frames[animator.frame_index];
    }
}
```

## Animation State Machine

Characters have multiple animations (idle, run, jump, attack). We use a simple state machine:

```rust
pub enum AnimState {
    Idle,
    Run,
    Jump,
    Fall,
    Attack,
}

fn update_anim_state(
    velocity: &Velocity,
    grounded: bool,
    attacking: bool,
    animator: &mut Animator,
) {
    let new_state = if attacking {
        AnimState::Attack
    } else if !grounded && velocity.y < 0.0 {
        AnimState::Jump
    } else if !grounded && velocity.y > 0.0 {
        AnimState::Fall
    } else if velocity.x.abs() > 0.1 {
        AnimState::Run
    } else {
        AnimState::Idle
    };

    let name = match new_state {
        AnimState::Idle => "idle",
        AnimState::Run => "run",
        AnimState::Jump => "jump",
        AnimState::Fall => "fall",
        AnimState::Attack => "attack",
    };

    if animator.current != name {
        animator.current = name.to_string();
        animator.frame_index = 0;
        animator.timer = 0.0;
    }
}
```

![Sprite sheet example](https://images.unsplash.com/photo-1550745165-9bc0b252726f?w=600&q=80)

## Aseprite Integration

We parse Aseprite JSON exports to automatically load frame data:

```rust
#[derive(Deserialize)]
struct AsepriteData {
    frames: Vec<AseFrame>,
    meta: AseMeta,
}

fn load_aseprite(path: &str) -> HashMap<String, Animation> {
    let data: AsepriteData = serde_json::from_str(
        &std::fs::read_to_string(path).unwrap()
    ).unwrap();
    // Parse frame tags into Animation structs
    // ...
}
```
