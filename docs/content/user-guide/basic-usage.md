+++
title = "Basic Usage"
description = "Lookups, predicates, equality, and ordering on a parsed KEV catalog"
weight = 2
+++

## Parsing

`KEV.parse` accepts either a `String` or an `IO`:

```crystal
catalog = KEV.parse(File.read("kev.json"))
# or
File.open("kev.json") { |io| KEV.parse(io) }
```

The return value is a [`KEV::Catalog`](/api-reference/catalog/), an immutable view over the feed at a point in time.

## Catalog metadata

```crystal
catalog.title           # => "CISA Catalog of Known Exploited Vulnerabilities"
catalog.catalog_version # => "2026.05.15"
catalog.date_released   # => Time(UTC)
catalog.count           # => 1592   (CISA-reported)
catalog.size            # => 1592   (in-memory length)
```

`count` is the value CISA published in the feed metadata; `size` is the number of entries actually parsed. They almost always match — if they ever diverge, trust `size`.

## Lookups

```crystal
catalog.find("CVE-2021-44228")   # => KEV::Vulnerability | nil
catalog["CVE-2021-44228"]        # => raises KeyError on miss
catalog["CVE-9999-99999"]?       # => nil
```

Lookups are O(1) — the catalog memoises a CVE → entry index lazily on first call.

## Convenience filters

```crystal
catalog.by_vendor("Microsoft")    # case-insensitive
catalog.by_product("Log4j2")      # case-insensitive
catalog.by_cwe("CWE-79")          # or "79" — numeric width is normalised
catalog.ransomware                # entries with knownRansomwareCampaignUse == "Known"
catalog.overdue                   # due day fully elapsed (vs Time.utc now)
catalog.due_within(30.days)
catalog.added_on_or_after(Time.utc(2024, 1, 1))
```

Each returns a fresh `Array(KEV::Vulnerability)` so you can sort or filter further without affecting the catalog.

## Catalog summaries

```crystal
catalog.vendors  # => ["Adobe", "Apache", "Apple", "Cisco", ...]
catalog.products # => ["Acrobat", "Acrobat Reader", ...]
catalog.cwes     # => ["CWE-20", "CWE-22", "CWE-77", ...]
```

All sorted, distinct.

## Vulnerability predicates

```crystal
v = catalog["CVE-2021-44228"]
v.known_ransomware?            # => true
v.overdue?                     # => true (relative to now)
v.days_until_due               # 0 on the due day, negative once overdue
v.remediation_window_days      # => 14 (dueDate - dateAdded)
v.has_cwe?("CWE-917")          # accepts "CWE-917", "917", "cwe-079" — width-normalised
v.cve_year                     # => 2021
```

## Equality and ordering

`Vulnerability` equality is **structural** — every field must match:

```crystal
a = catalog["CVE-2021-44228"]
b = catalog["CVE-2021-44228"]
a == b      # => true (every field equal)
a.hash == b.hash  # => true
```

For the common dedup-across-snapshots case, use `#same_cve?` instead of `==`:

```crystal
old_snapshot["CVE-2021-44228"].same_cve?(new_snapshot["CVE-2021-44228"])  # => true
```

Vulnerabilities are `Comparable` by `date_added` (with `cve_id` as a stable tiebreak), so sorting and `min` / `max` / `sort` work directly:

```crystal
catalog.sort.first.cve_id   # oldest entry in the catalog
catalog.sort.last.cve_id    # newest entry
```

## Enumerable

`Catalog` includes `Enumerable(Vulnerability)`, so the full collection API works:

```crystal
catalog.count(&.known_ransomware?)
catalog.group_by(&.vendor_project)
catalog.partition(&.known_ransomware?)
catalog.tally_by(&.vendor_project)
```

## Next steps

- **[Queries & Filters](/user-guide/queries/)** — chainable filter builder for multi-step pipelines.
- **[Vulnerability API](/api-reference/vulnerability/)** — every getter and predicate.
