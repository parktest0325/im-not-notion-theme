---
title: "Rigid Body Dynamics"
date: 2026-02-13
description: "Implementing velocity, forces, and collision response for 2D rigid bodies"
tags: ["physics", "game-dev", "math"]
weight: 2
---

## Physics Step

Every frame, the physics engine:

1. Apply forces (gravity, player input, explosions)
2. Integrate velocity → position
3. Detect collisions
4. Resolve collisions (push apart + apply impulse)

```rust
pub struct RigidBody {
    pub position: Vec2,
    pub velocity: Vec2,
    pub angular_velocity: f32,
    pub mass: f32,
    pub restitution: f32, // bounciness
    pub friction: f32,
}

pub fn physics_step(world: &mut World, dt: f32) {
    // 1. Apply gravity
    for (_, body) in world.query::<&mut RigidBody>() {
        body.velocity.y += GRAVITY * dt;
    }

    // 2. Integrate
    for (_, body) in world.query::<&mut RigidBody>() {
        body.position += body.velocity * dt;
    }

    // 3-4. Detect and resolve collisions
    let collisions = detect_collisions(world);
    for collision in &collisions {
        resolve_collision(world, collision);
    }
}
```

## Collision Response

When two bodies collide, we calculate an **impulse** that changes their velocities to separate them:

```rust
fn resolve_collision(a: &mut RigidBody, b: &mut RigidBody, info: &CollisionInfo) {
    let relative_vel = b.velocity - a.velocity;
    let vel_along_normal = relative_vel.dot(info.normal);

    // Don't resolve if moving apart
    if vel_along_normal > 0.0 { return; }

    let e = a.restitution.min(b.restitution);
    let j = -(1.0 + e) * vel_along_normal
        / (1.0 / a.mass + 1.0 / b.mass);

    let impulse = info.normal * j;
    a.velocity -= impulse / a.mass;
    b.velocity += impulse / b.mass;
}
```

## Fixed Timestep

Physics must run at a fixed rate regardless of frame rate. We use an accumulator pattern:

```rust
let mut accumulator = 0.0;
const FIXED_DT: f32 = 1.0 / 60.0;

loop {
    let frame_time = timer.elapsed();
    accumulator += frame_time;

    while accumulator >= FIXED_DT {
        physics_step(&mut world, FIXED_DT);
        accumulator -= FIXED_DT;
    }

    let alpha = accumulator / FIXED_DT;
    render_interpolated(&world, alpha);
}
```
