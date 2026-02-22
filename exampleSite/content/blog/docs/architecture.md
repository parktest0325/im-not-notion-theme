---
title: "Architecture Overview"
date: 2026-02-21
description: "How the system is designed — tech stack, data flow, and key design decisions"
tags: ["docs", "architecture"]
weight: 2
---

## Tech Stack

| Layer | Technology | Why |
|-------|-----------|-----|
| Frontend | Svelte 4 + TypeScript | Fast, reactive, small bundle |
| Backend | Rust (Tauri v2) | Native performance, memory safe |
| Connection | SSH/SFTP | No server agent needed |
| Styling | Tailwind CSS | Utility-first, fast iteration |

## System Architecture

```
┌─────────────────────────────────────────────┐
│  Desktop App (Tauri)                        │
│                                             │
│  ┌──────────┐  IPC   ┌──────────────────┐  │
│  │ Svelte   │ ←────→ │ Rust Backend     │  │
│  │ Frontend  │        │                  │  │
│  │          │        │ ┌──────────────┐ │  │
│  │ Editor   │        │ │ SSH Service  │ │  │
│  │ FileTree │        │ │ File Service │ │  │
│  │ Plugins  │        │ │ Plugin Svc   │ │  │
│  └──────────┘        │ └──────┬───────┘ │  │
│                      └────────┼─────────┘  │
└───────────────────────────────┼─────────────┘
                                │ SSH/SFTP
                    ┌───────────┴───────────┐
                    │  Remote Server         │
                    │                       │
                    │  Hugo Site + Plugins  │
                    └───────────────────────┘
```

## Data Flow

1. User edits content in the Svelte editor
2. Save triggers IPC call to Rust backend
3. Backend connects via SSH/SFTP to remote server
4. File is written to Hugo content directory
5. Hugo server auto-rebuilds the site

## Key Design Decisions

### Why SSH instead of a server agent?

- Zero setup on the server side
- Works with any hosting provider
- No ports to open beyond SSH (22)
- Leverages existing SSH key infrastructure

### Why plugins run on the server?

- Direct filesystem access (no SFTP overhead for bulk operations)
- Can use server-installed tools (git, python, etc.)
- Cron scheduling via server's crontab

![Architecture diagram](https://images.unsplash.com/photo-1558494949-ef010cbdcc31?w=600&q=80)
