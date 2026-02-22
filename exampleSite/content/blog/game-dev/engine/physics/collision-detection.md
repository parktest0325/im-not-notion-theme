---
title: "Broad & Narrow Phase Collision Detection"
date: 2026-02-14
description: "Spatial hashing for broad phase + SAT for narrow phase collision in a 2D engine"
tags: ["physics", "game-dev", "algorithms"]
weight: 1
---

## Two-Phase Approach

Checking every pair of objects is O(n²). We split collision detection into two phases:

1. **Broad Phase** — quickly reject pairs that can't possibly collide
2. **Narrow Phase** — precise collision test on remaining candidates

## Broad Phase: Spatial Hashing

Divide the world into a grid. Objects occupy cells based on their AABB. Only check collisions between objects in the same cell.

```rust
pub struct SpatialHash {
    cell_size: f32,
    cells: HashMap<(i32, i32), Vec<Entity>>,
}

impl SpatialHash {
    pub fn insert(&mut self, entity: Entity, aabb: &AABB) {
        let min_cell = self.to_cell(aabb.min);
        let max_cell = self.to_cell(aabb.max);

        for x in min_cell.0..=max_cell.0 {
            for y in min_cell.1..=max_cell.1 {
                self.cells.entry((x, y))
                    .or_default()
                    .push(entity);
            }
        }
    }

    fn to_cell(&self, pos: Vec2) -> (i32, i32) {
        ((pos.x / self.cell_size) as i32,
         (pos.y / self.cell_size) as i32)
    }
}
```

## Narrow Phase: SAT (Separating Axis Theorem)

For convex polygons, if we can find an axis where the projections don't overlap, the shapes don't collide.

```rust
pub fn sat_test(a: &Polygon, b: &Polygon) -> Option<CollisionInfo> {
    let mut min_overlap = f32::MAX;
    let mut min_axis = Vec2::ZERO;

    for edge in a.edges().chain(b.edges()) {
        let axis = edge.perpendicular().normalize();
        let proj_a = project_polygon(a, axis);
        let proj_b = project_polygon(b, axis);

        let overlap = proj_a.overlap(&proj_b);
        if overlap <= 0.0 {
            return None; // Separating axis found
        }
        if overlap < min_overlap {
            min_overlap = overlap;
            min_axis = axis;
        }
    }

    Some(CollisionInfo {
        normal: min_axis,
        depth: min_overlap,
    })
}
```

![Collision detection visualization](https://images.unsplash.com/photo-1535378917042-10a22c95931a?w=600&q=80)

## Performance

With spatial hashing, 10K objects go from 50M pair checks to ~2K — a 25,000x reduction.
