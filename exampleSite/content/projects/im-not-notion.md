---
title: "im-not-notion"
description: "A Tauri-based Hugo CMS with SSH remote editing, plugin system, and Git integration. Manage your blog from anywhere."
featured_image: "https://images.unsplash.com/photo-1555066931-4365d14bab8c?w=800&q=80"
tags: ["tools", "rust", "svelte"]
technologies: ["Tauri", "Rust", "Svelte", "TypeScript"]
status: "completed"
links:
  github: "https://github.com/example/im-not-notion"
  showcase: "https://example.com/im-not-notion"
weight: 3
---

## Overview

im-not-notion is a desktop app for managing Hugo blogs remotely via SSH.

### Key Features

- **Remote Editing**: Edit Hugo content over SSH with real-time preview
- **Plugin System**: Extensible manifest-based plugins (git-autopush, backup, image-fix)
- **Multi-server**: Connect to multiple Hugo sites
- **Image Sync**: Automatic image reference tracking and orphan cleanup

### Tech Stack

| Layer | Technology |
|-------|-----------|
| Frontend | Svelte 4 + TypeScript |
| Backend | Rust (Tauri v2) |
| Connection | SSH/SFTP |
| Styling | Tailwind CSS |
