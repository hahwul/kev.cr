+++
title = "Getting Started"
description = "Install kev.cr and parse your first CISA KEV feed"
weight = 1
+++

## Prerequisites

| Requirement | Version    |
|-------------|------------|
| Crystal     | >= 1.19.0  |

kev.cr is pure Crystal with no native dependencies — it runs anywhere Crystal does.

## Installation

Add the dependency to your `shard.yml`:

```yaml
dependencies:
  kev:
    github: hahwul/kev.cr
```

Then install:

```bash
shards install
```

## Your First Program

Save a snapshot of the KEV feed locally so you don't hit CISA on every run:

```bash
curl -o kev.json https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
```

Then create `hello.cr`:

```crystal
require "kev"

catalog = KEV.parse(File.read("kev.json"))
puts "version: #{catalog.catalog_version}"
puts "entries: #{catalog.size}"

log4j = catalog["CVE-2021-44228"]
puts "log4j vendor:  #{log4j.vendor_project}"
puts "log4j vendor:  #{log4j.product}"
puts "ransomware?    #{log4j.known_ransomware?}"
puts "remediation:   #{log4j.remediation_window_days}d"
```

Run it:

```bash
crystal run hello.cr
```

## Fetching the live feed

For one-off scripts you can pull directly from CISA:

```crystal
require "kev"
KEV.fetch.size # => 1500+
```

For polling, prefer a long-lived `KEV::Client` so you can use conditional GETs — see [Fetching the Live Feed](/user-guide/fetching/).

## Non-raising parse

When validating user input or files of uncertain provenance, prefer `parse?` over wrapping `parse` in `begin/rescue`:

```crystal
if catalog = KEV.parse?(user_input)
  # use catalog
else
  # malformed JSON or schema violation
end
```

## Next Steps

- **[Basic Usage](/user-guide/basic-usage/)** — catalog lookups, predicates, equality
- **[Queries & Filters](/user-guide/queries/)** — chainable filter builder
- **[Fetching the Live Feed](/user-guide/fetching/)** — HTTPS client + ETag handling
- **[JSON Round-Trip](/user-guide/json/)** — serialization shape and gotchas
