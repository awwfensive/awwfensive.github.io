# Updating the site

The existing Hugo theme and portfolio layout are retained. Production still builds with Hugo 0.164.0 and the existing GitHub Pages action.

## Pages

- `content/about.md` — personal background and experience.
- `content/now.md` — current priorities; edit Markdown and update the review date in the body.
- `content/projects/hackbot.md` — ongoing research, proposed approach, evaluation questions, and public log.
- `data/projects.yaml` — existing open-source projects and development status.
- `data/findings.yaml` — public disclosures with source links.

## Writing

Existing posts stay in `content/blog/` with their original URLs. The `/research/` and `/notes/` indexes collect these posts automatically through metadata, without moving or duplicating their content.

Entries with `content_type: note` appear under Notes and are excluded from the Blog list, Blog RSS feed, and related writing on non-note articles. Their existing URLs remain available. The Research index and site-wide RSS continue to collect all indexed writing.

Create new formal work with `hugo new content research/my-title.md --kind research`. Create a notebook entry with `hugo new content notes/my-title.md --kind note`.

Research metadata:

```yaml
title: "Title"
slug: "stable-url-slug"
date: 2026-11-01
description: "Search and social preview description."
summary: "A short summary for the index."
category: "AI for Security"
status: "Published"
content_type: "research"
authors: ["Aniket"]
tags: ["harnesses"]
indexed: true
featured: false
draft: true
links:
  - title: "Source"
    url: "https://github.com/awwfensive"
# cover: "/images/cover.png"
# cover_alt: "Describe the image."
# disclosure: "Public advisory identifier and status, when relevant."
```

Allowed categories: AI for Security, Security of AI, Vulnerability Research, Benchmarks, Security Engineering.

`content_type` is `research`, `analysis`, or `note`. The `note` type appears in `/notes/`. The homepage keeps a compact Research & tools section: Hackbot followed by up to two featured technical analyses, sorted by recency. The original disclosure stays in Findings, so it is not repeated in the writing list.

The research index validates required metadata during the build. Draft and future-dated content are excluded from production pages, related writing, RSS, and sitemap by Hugo. Do not build with `--buildDrafts` or `--buildFuture` for deployment. A scheduled post becomes public on the next site rebuild after its date; GitHub Pages does not trigger a rebuild solely because time has passed.

Markdown supports code fences, tables, local images, heading anchors, and the existing `figure` and `toc` shortcodes. The article template adds reading time, author and disclosure metadata, contents, optional source links, and related writing. Research archetypes include sections for methods, evidence, limitations, reproduction, and references.

Use published sources for findings. Only the Flyto disclosure is represented as an original finding; CVE analyses and CTF write-ups retain their correct attribution.

## Check locally

```sh
hugo --minify --cleanDestinationDir --environment production
hugo server --disableFastRender
```

No JavaScript package installation is needed. RSS is available at `/index.xml`, `/research/index.xml`, `/notes/index.xml`, and the preserved `/blog/index.xml`. Hugo generates `/sitemap.xml` and `/robots.txt`.

## Search and social metadata

Each page gets one canonical URL, description, shared browser/Open Graph/Twitter title, and JSON-LD. The homepage and About describe a personal profile; indexed research uses TechArticle with authors and publication dates. Breadcrumbs connect articles to Research and Hackbot to Projects.

Use `seo_title` for an optional search title, `description` for a page description, and `social_image` plus `social_image_alt` for a custom share image. The default image is `static/images/social.png` (1200 × 630), with its editable vector source alongside it. These are social preview assets only; they do not add a visible homepage section. Per-page `cover` and `cover_alt` also work.

Development previews, 404 pages, and explicitly built draft/future pages carry noindex metadata. Production builds use the configured GitHub Pages origin and remain indexable. Draft and future content are excluded entirely by the normal production build.
