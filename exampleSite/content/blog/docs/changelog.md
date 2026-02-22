---
title: "Changelog"
date: 2026-02-22
description: "Version history and release notes"
tags: ["docs", "changelog"]
weight: 3
---

## v1.0.1 — 2026-02-22

### Fixed
- Font path resolution on Windows
- Edit menu appearing on macOS (Windows-only fix)
- Orphan image detection for `<img>` tags
- Git autosquash date handling (author date vs committer date)

### Added
- Deploy theme plugin
- Blog backup cron at 19:00 weekly
- Plugin usage documentation

---

## v1.0.0 — 2026-02-15

### Features
- Remote Hugo content editing via SSH/SFTP
- File tree with drag & drop, hide/show
- Markdown editor with live preview
- Plugin system (manual, cron, hook triggers)
- Git auto-push / auto-squash plugins
- Blog backup plugin
- Image link verification & fix plugins
- Multi-server configuration
- Dark/light theme

### Technical
- Tauri v2 + Svelte 4 frontend
- Rust backend with 6 command modules, 6 service modules
- typeshare for TS type generation from Rust
- 45 IPC commands

---

## v0.9.0 — 2026-01-20

### Initial Release
- Basic SSH connection
- File tree browsing
- Content editing
- Single server support
