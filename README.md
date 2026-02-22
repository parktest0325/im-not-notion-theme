# im-not-notion-theme

A Hugo theme with HugoBook-style blog sidebar and cyberpunk project portfolio.

Built for [im-not-notion](https://github.com/parktest0325/im-not-notion) — a Tauri-based desktop CMS that manages Hugo sites over SSH. Write markdown, manage images, and deploy from a native app.

## Features

- **Dark / Light mode** — `localStorage` 기반 테마 전환, 배경 이미지·댓글 테마 자동 동기화
- **Blog** — 계층형 폴더 사이드바 (접기/펼치기, 깊이별 색상 가이드라인), 목차(TOC), 이전/다음 글 네비게이션
- **Projects** — 네온 글로우 + 글리치 효과 카드 그리드, 태그 필터, 모달 상세보기, 상태 뱃지 (active/completed/archived)
- **Search** — Fuse.js 기반 전문(full-text) 검색, `⌘K` / `Ctrl+K` 단축키, 키보드 탐색
- **Background image** — 다크/라이트별 배경 이미지 & 투명도 설정, 로컬/외부 URL 모두 지원
- **Comments** — Giscus (GitHub Discussions) 통합, 방명록 페이지 지원
- **Analytics** — GoatCounter 연동, 푸터 방문자 수 표시
- **Image render hook** — 마크다운 이미지에 `#center`, `#float-left`, `#center-w60` 등 레이아웃 제어
- **Syntax highlighting** — Dracula 기반 코드 하이라이팅, D2Coding 폰트
- **Responsive** — 모바일 사이드바 토글, 반응형 그리드

## Quick Start

### With im-not-notion (Recommended)

[im-not-notion](https://github.com/parktest0325/im-not-notion) 앱에서 **deploy-theme** 플러그인으로 원클릭 배포할 수 있습니다.

1. im-not-notion 앱에서 플러그인 메뉴 열기
2. **Deploy Theme** 실행
3. 옵션 선택:
   - `deploy_content` — 데모 콘텐츠 배포 (블로그 예제 글, 프로젝트 등)
   - `overwrite_toml` — hugo.toml을 예제 설정으로 덮어쓰기

테마, 설정, 데모 콘텐츠가 Hugo 사이트에 자동 배포됩니다.

### Manual

```bash
# 1. Hugo 사이트 생성
hugo new site my-site
cd my-site

# 2. 테마 설치
git clone https://github.com/parktest0325/im-not-notion-theme themes/im-not-notion-theme

# 3. 예제 설정 복사
cp themes/im-not-notion-theme/exampleSite/hugo.toml hugo.toml

# 4. 예제 콘텐츠 복사 (선택)
cp -r themes/im-not-notion-theme/exampleSite/content .

# 5. 실행
hugo server
```

## Configuration

`hugo.toml` 주요 설정:

```toml
baseURL = "https://example.com/"
languageCode = "ko-kr"
title = "My Site"
theme = "im-not-notion-theme"

[params]
  description = "Developer portfolio & technical blog"
  author = "Your Name"
  github = "https://github.com/yourname"

  # Homepage hero
  heroTitle = "Your Name"
  heroSubtitle = "Developer / Designer / Creator"
  heroTagline = "I build things that break things."
```

### Background Image

다크/라이트 모드별 배경 이미지를 설정할 수 있습니다. `static/images/`에 파일을 넣거나 외부 URL을 사용합니다.

```toml
[params.background]
  image = "/images/bg-dark.jpg"       # 다크 모드 배경
  opacity = 0.06                       # 다크 모드 투명도 (0~1)
  lightImage = "/images/bg-light.jpg"  # 라이트 모드 배경
  lightOpacity = 0.15                  # 라이트 모드 투명도
  fixed = true                         # 스크롤 시 배경 고정
```

### About Section

홈페이지에 자기소개 섹션을 표시합니다. 블록을 제거하면 숨겨집니다.

```toml
[params.about]
  name = "Your Name"
  avatar = "/images/avatar.jpg"
  bio = "A short bio about yourself."
  detail = """Longer description.
Supports **markdown**."""

  [[params.about.links]]
    name = "GitHub"
    url = "https://github.com/yourname"
  [[params.about.links]]
    name = "Email"
    url = "mailto:you@example.com"
```

### Giscus Comments

[giscus.app](https://giscus.app)에서 설정값을 확인한 후 입력합니다.

```toml
[params.giscus]
  repo = "yourname/blog-comments"
  repoId = ""
  category = "Announcements"
  categoryId = ""
  mapping = "pathname"
  lang = "ko"
```

### GoatCounter Analytics

[goatcounter.com](https://www.goatcounter.com)에서 가입 후 코드를 입력합니다.

```toml
[params]
  goatcounterCode = "mysite"    # mysite.goatcounter.com
  goatcounterShow = true
```

### Homepage Layout

```toml
[params.homepage]
  featuredProjectsCount = 4     # 홈에 표시할 프로젝트 수
  recentPostsCount = 5          # 홈에 표시할 최근 글 수
```

### Navigation Menu

```toml
[menu]
  [[menu.main]]
    name = "Blog"
    url = "/blog/"
    weight = 1
  [[menu.main]]
    name = "Projects"
    url = "/projects/"
    weight = 2
  [[menu.main]]
    name = "Guestbook"
    url = "/guestbook/"
    weight = 3
```

### Outputs (Search)

검색 기능을 위해 JSON 출력을 활성화해야 합니다.

```toml
[outputs]
  home = ["HTML", "JSON"]
```

## Content

### Blog Posts

`content/blog/` 하위에 폴더를 만들어 카테고리를 구성합니다. 사이드바에 폴더 트리로 표시됩니다.

```
content/blog/
├── game-dev/
│   ├── _index.md
│   ├── engine/
│   │   ├── _index.md
│   │   └── ecs-from-scratch.md
│   └── tutorials/
│       └── getting-started.md
└── security/
    └── ctf/
        └── buffer-overflow.md
```

글의 front matter:

```yaml
---
title: "My Post"
date: 2024-01-15
description: "Short description"
tags: ["rust", "game-dev"]
---
```

### Projects

`content/projects/` 하위에 프로젝트를 추가합니다.

```yaml
---
title: "Project Name"
description: "Short description"
featured_image: "/images/project-cover.png"
tags: ["game-dev", "rust"]
technologies: ["Rust", "Vulkan", "ECS"]
status: "active"           # active | completed | archived
weight: 1                  # 정렬 순서 (낮을수록 앞)
links:
  blog: "/blog/my-post/"
  showcase: "https://..."
  demo: "https://..."
  github: "https://github.com/..."
---

Detailed project description in markdown...
```

### Image Layout

마크다운 이미지에 URL fragment로 레이아웃을 제어할 수 있습니다.

```markdown
![alt](image.png)                  기본 (전체 폭)
![alt](image.png#center)           가운데 정렬
![alt](image.png#center-w60)       가운데 정렬, 60% 폭
![alt](image.png#float-left)       왼쪽 플로팅
![alt](image.png#float-right-w40)  오른쪽 플로팅, 40% 폭
```

### Guestbook

`content/guestbook/_index.md` 하나만 만들면 Giscus 댓글이 방명록으로 동작합니다.

```yaml
---
title: "Guestbook"
---
```

## Requirements

- Hugo >= 0.112.0 (extended edition recommended)

## Related

- [im-not-notion](https://github.com/parktest0325/im-not-notion) — Desktop CMS for Hugo (Tauri + Svelte)
- [deploy-theme plugin](https://github.com/parktest0325/im-not-notion-plugins/tree/main/deploy-theme) — One-click theme deployment plugin

## License

MIT
