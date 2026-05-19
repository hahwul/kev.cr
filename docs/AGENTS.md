# AGENTS.md - AI Agent Instructions for the kev.cr Documentation Site

This document is for AI agents editing the kev.cr documentation site under `docs/`.

## Project Overview

This is a static website built with [Hwaro](https://github.com/hahwul/hwaro), a fast and lightweight static site generator written in Crystal. It is the documentation companion to the [kev.cr](https://github.com/hahwul/kev.cr) library — a Crystal client for the CISA Known Exploited Vulnerabilities (KEV) catalog.

## Hwaro Usage

### Installation

**Homebrew:**
```bash
brew tap hahwul/hwaro
brew install hwaro
```

**From Source (Crystal):**
```bash
git clone https://github.com/hahwul/hwaro.git
cd hwaro
shards install
shards build --release --no-debug --production
# Binary: ./bin/hwaro
```

### Essential Commands

| Command | Description |
|---------|-------------|
| `hwaro build` | Build the site to `public/` |
| `hwaro serve` | Local dev server with live reload |
| `hwaro version` | Show version information |

Run from inside `docs/`.

## Directory Structure

```
docs/
├── config.toml          # Site configuration
├── content/             # Markdown content
│   ├── index.md         # Homepage
│   ├── user-guide/
│   │   ├── _index.md
│   │   ├── getting-started.md
│   │   ├── basic-usage.md
│   │   ├── queries.md
│   │   ├── fetching.md
│   │   └── json.md
│   └── api-reference/
│       ├── _index.md
│       ├── catalog.md
│       ├── vulnerability.md
│       ├── query.md
│       ├── client.md
│       ├── ransomware-use.md
│       └── errors.md
├── templates/           # Jinja2 (Crinja) templates
│   ├── header.html
│   ├── footer.html
│   ├── page.html
│   ├── section.html
│   └── 404.html
└── static/              # Static assets (CSS, JS, icons)
```

## Content Guidelines

### Front matter

Use TOML front matter:

```toml
+++
title = "Page Title"
description = "Short SEO description"
weight = 1   # for sort_by = "weight" sections
+++
```

### Editing rules

- **Always preserve front matter** when editing.
- Keep terminology consistent with the library and the upstream KEV schema: "catalog", "vulnerability entry", "CVE id", "CWE", "ransomware-flagged", "due date".
- Cross-link generously between User Guide pages and API Reference pages.
- Code samples must be valid Crystal that runs against the latest kev.cr — when in doubt, copy from the working examples in the repo's `examples/` directory or assertions in `spec/`.

### Adding a new page

1. Create the `.md` under `content/user-guide/` or `content/api-reference/`.
2. Add a sidebar entry in **both** `templates/page.html` and `templates/section.html` (the sidebars are duplicated by design — Hwaro does not currently share partials for them in this site).
3. Include a `weight` value so the section's `sort_by = "weight"` picks up the right ordering.

## Notes for AI Agents

1. **Don't invent APIs.** Only document methods that exist in `src/kev/**`. Verify by grepping the source before adding examples.
2. **Match real feed values** in examples to current CISA output when possible — running `crystal run examples/fetch.cr` against the live feed will print up-to-date numbers.
3. **Use `crystal spec`** (run from the repo root) to confirm any code sample you add still passes type-checking semantically.
4. **Keep URLs relative** — `{{ base_url }}/...` in templates, `/section/page/` in markdown links.
5. **Don't add JS dependencies.** The site uses only `static/js/search.js` and Hwaro's auto-included assets.
6. **Never recommend `KEV.fetch` in time-sensitive examples** — it hits CISA every call. If you need an example of network use, gate it behind a flag or annotate that it makes a live request.
