+++
title = "kev.cr"
description = "A Crystal client for the CISA Known Exploited Vulnerabilities catalog"
+++

A Crystal library that parses, queries, fetches, and serializes the
[CISA Known Exploited Vulnerabilities (KEV) catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog).

| Surface | Status | Notes |
|---------|--------|-------|
| Parser  | ✅     | Strict, schema-bound against the official CISA JSON schema |
| Queries | ✅     | Vendor, product, CWE, ransomware, due-date filters |
| Client  | ✅     | HTTPS, ETag / If-Modified-Since, configurable timeouts |
| JSON    | ✅     | Lossless round-trip with the upstream feed (verified against live data) |

## Quick Links

- **[Getting Started](/user-guide/getting-started/)** — installation and first parse
- **[Basic Usage](/user-guide/basic-usage/)** — catalog, lookups, predicates
- **[Queries & Filters](/user-guide/queries/)** — chainable query builder
- **[Fetching the Live Feed](/user-guide/fetching/)** — HTTPS client + conditional GETs
- **[JSON Round-Trip](/user-guide/json/)** — serialization shape, byte parity with CISA
- **[API Reference](/api-reference/catalog/)** — every class and method

## Highlights

- Schema-bound parser: missing required fields surface as typed exceptions, not silent nulls.
- Verified lossless round-trip against the live CISA feed (1,500+ entries).
- `Catalog` is `Enumerable` + `Indexable`; `Vulnerability` is `Comparable`.
- Chainable `Query` for `vendor` / `product` / `cwe` / `ransomware` / `due_within` filters.
- Built-in `Client` with `ETag` / `If-Modified-Since` short-circuiting for polling.
- Non-raising `KEV.parse?` for input validation paths.

## Installation

Add the dependency to your `shard.yml`:

```yaml
dependencies:
  kev:
    github: hahwul/kev.cr
```

Then run:

```bash
shards install
```

## Quick Example

```crystal
require "kev"

catalog = KEV.parse(File.read("known_exploited_vulnerabilities.json"))
catalog.size                            # => 1592
catalog["CVE-2021-44228"].vendor_project # => "Apache"
catalog.query.ransomware.year(2024).to_a # ransomware-flagged 2024 CVEs

# Or fetch the live feed directly:
live = KEV.fetch
```
