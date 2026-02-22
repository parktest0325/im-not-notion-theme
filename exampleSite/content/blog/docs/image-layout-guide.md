---
title: "Image Layout Guide"
description: "이미지 렌더 훅 사용법 — 정렬, 크기 조절, float 레이아웃"
date: 2026-02-22
weight: 10
tags: ["guide", "theme"]
---

> **Deploy version: v3** — render-image hook 테스트 (2026-02-22)

이 테마는 마크다운 이미지 문법에 `#fragment`를 추가하여 이미지 레이아웃을 제어할 수 있습니다.

## 기본 이미지

아무 옵션 없이 사용하면 전체 폭으로 표시됩니다.

![기본 이미지](https://placehold.co/800x400/1a1a2e/e0e0e8?text=Default+Image)

---

## 가운데 정렬 + 크기 조절

`#center`를 붙이면 가운데 정렬됩니다. `-wNN`을 추가하면 폭을 퍼센트로 조절합니다.

### 100% 가운데 — `#center`

![가운데 정렬](https://placehold.co/800x300/7c5cfc/ffffff?text=center#center)

### 60% 가운데 — `#center-w60`

![60% 가운데](https://placehold.co/800x300/00f0ff/1a1a2e?text=center-w60#center-w60)

### 40% 가운데 — `#center-w40`

![40% 가운데](https://placehold.co/800x300/ff00ff/ffffff?text=center-w40#center-w40)

---

## Float Left — 왼쪽 이미지 + 오른쪽 텍스트

`#float-left`를 사용하면 이미지가 왼쪽에 배치되고 텍스트가 오른쪽으로 흐릅니다.

### 기본 float-left — `#float-left`

![왼쪽 플로팅](https://placehold.co/400x300/00ff88/1a1a2e?text=float-left#float-left)

Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum. Sed ut perspiciatis unde omnis iste natus error sit voluptatem accusantium doloremque laudantium.

---

### 40% float-left — `#float-left-w40`

![40% 왼쪽](https://placehold.co/400x300/7c5cfc/ffffff?text=float-left-w40#float-left-w40)

Nemo enim ipsam voluptatem quia voluptas sit aspernatur aut odit aut fugit, sed quia consequuntur magni dolores eos qui ratione voluptatem sequi nesciunt. Neque porro quisquam est, qui dolorem ipsum quia dolor sit amet, consectetur, adipisci velit. Ut enim ad minima veniam, quis nostrum exercitationem ullam corporis suscipit laboriosam.

---

## Float Right — 오른쪽 이미지 + 왼쪽 텍스트

`#float-right`를 사용하면 이미지가 오른쪽에 배치됩니다.

### 기본 float-right — `#float-right`

![오른쪽 플로팅](https://placehold.co/400x300/ffee00/1a1a2e?text=float-right#float-right)

Quis autem vel eum iure reprehenderit qui in ea voluptate velit esse quam nihil molestiae consequatur, vel illum qui dolorem eum fugiat quo voluptas nulla pariatur? At vero eos et accusamus et iusto odio dignissimos ducimus qui blanditiis praesentium voluptatum deleniti atque corrupti quos dolores et quas molestias excepturi sint occaecati cupiditate non provident.

---

### 30% float-right — `#float-right-w30`

![30% 오른쪽](https://placehold.co/300x300/00f0ff/1a1a2e?text=float-right-w30#float-right-w30)

Temporibus autem quibusdam et aut officiis debitis aut rerum necessitatibus saepe eveniet ut et voluptates repudiandae sint et molestiae non recusandae. Itaque earum rerum hic tenetur a sapiente delectus, ut aut reiciendis voluptatibus maiores alias consequatur aut perferendis doloribus asperiores repellat.

---

## 문법 정리

| 마크다운 | 결과 |
|---|---|
| `![alt](image.png)` | 기본 (전체 폭) |
| `![alt](image.png#center)` | 가운데 정렬 |
| `![alt](image.png#center-w60)` | 60% 너비 + 가운데 |
| `![alt](image.png#center-w40)` | 40% 너비 + 가운데 |
| `![alt](image.png#float-left)` | 왼쪽 float (최대 50%) |
| `![alt](image.png#float-left-w30)` | 30% 너비 + 왼쪽 float |
| `![alt](image.png#float-right)` | 오른쪽 float (최대 50%) |
| `![alt](image.png#float-right-w30)` | 30% 너비 + 오른쪽 float |

> `-wNN` 값은 퍼센트 단위입니다. `alt` 텍스트는 캡션으로 표시됩니다.
> 모바일(600px 이하)에서는 float가 자동 해제됩니다.
