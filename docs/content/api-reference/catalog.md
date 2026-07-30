+++
title = "Catalog"
description = "The KEV::Catalog class — collection-level operations on a parsed feed"
weight = 1
+++

## `KEV::Catalog`

An immutable view over a parsed KEV feed. Includes `Enumerable(Vulnerability)` and `Indexable(Vulnerability)`.

## Construction

| Method | Description |
|--------|-------------|
| `Catalog.parse(input : String \| IO) : Catalog` | Parse a feed payload. Raises `KEV::ParseError`. |
| `Catalog.from_json(input : String \| IO) : Catalog` | Alias for `parse`. |
| `Catalog.parse?(input : String \| IO) : Catalog?` | Non-raising — returns `nil` on any parse failure. |
| `Catalog.new(catalog_version, date_released, count, vulnerabilities, title = nil)` | Programmatic construction (e.g. to build a filtered envelope). |

## Metadata

| Method | Type | Description |
|--------|------|-------------|
| `title` | `String?` | Catalog title from the feed (always present in live feed). |
| `catalog_version` | `String` | E.g. `"2026.05.15"`. |
| `date_released` | `Time` | Publish timestamp, UTC. |
| `count` | `Int32` | CISA-reported entry count. |
| `vulnerabilities` | `Array(Vulnerability)` | Entries in feed order. |

## Lookups

| Method | Description |
|--------|-------------|
| `find(cve_id : String) : Vulnerability?` | Returns the entry or `nil`. O(1) after first call. |
| `[](cve_id : String) : Vulnerability` | Raises `KeyError` on miss. |
| `[]?(cve_id : String) : Vulnerability?` | Returns `nil` on miss. |
| `reindex! : Nil` | Drops the memoised CVE → entry index. Call after in-place mutation. |

## Convenience filters

Each returns a fresh `Array(Vulnerability)`:

| Method | Description |
|--------|-------------|
| `by_vendor(name : String)` | Case-insensitive vendor match. |
| `by_product(name : String)` | Case-insensitive product match. |
| `by_cwe(code : String)` | Match by CWE (`"CWE-79"`, `"79"`, or `"079"`). |
| `ransomware` | `knownRansomwareCampaignUse == "Known"`. |
| `added_on_or_after(date : Time)` | `date_added >= date`. |
| `added_on_or_before(date : Time)` | `date_added <= date`. |
| `overdue(now : Time = Time.utc)` | Due day fully elapsed (`now >= due_date + 1 day`). |
| `due_within(span : Time::Span, now : Time = Time.utc)` | Not yet overdue and `due_date <= now + span`. |

For multi-step pipelines see [`Catalog#query`](/api-reference/query/).

## Summaries

| Method | Description |
|--------|-------------|
| `vendors : Array(String)` | Distinct vendor names, sorted. |
| `products : Array(String)` | Distinct product names, sorted. |
| `cwes : Array(String)` | Distinct CWE codes, sorted. |

## Enumerable + Indexable

Standard collection methods come for free:

```crystal
catalog.size
catalog[0]
catalog.first
catalog.count(&.known_ransomware?)
catalog.group_by(&.vendor_project)
catalog.partition(&.known_ransomware?)
catalog.tally_by(&.vendor_project)
```

## JSON

| Method | Description |
|--------|-------------|
| `to_json(json : JSON::Builder) : Nil` | Canonical feed-shaped serialisation. |
| `to_json : String` | Convenience wrapper. |

## Mutability and the index memo

`vulnerabilities` is a `getter`, so callers can read the underlying array — but the catalog is intended to be immutable. The CVE → entry index memo auto-invalidates when the array's `size` changes; for in-place replacements (same length, different entries), call `reindex!` explicitly.

The memo is not synchronised — if you share a `Catalog` across preemptive threads, prime the index by calling `find` once on the owning thread before publishing the reference.

## See also

- **[Vulnerability](/api-reference/vulnerability/)** — what each entry looks like.
- **[Query](/api-reference/query/)** — the chainable filter builder returned by `#query`.
