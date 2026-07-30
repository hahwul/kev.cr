+++
title = "Queries & Filters"
description = "Chainable Query builder over a KEV catalog"
weight = 3
+++

`Catalog#query` returns a [`KEV::Query`](/api-reference/query/) — a chainable, immutable filter pipeline.

```crystal
catalog.query
  .vendor("Microsoft")
  .ransomware
  .added_on_or_after(Time.utc(2024, 1, 1))
  .sort_by_due_date
  .to_a
```

Every chain step returns a new `Query`, so the source catalog is never mutated.

## Available filters

| Method | Description |
|--------|-------------|
| `vendor(name)` | Exact vendor match, case-insensitive |
| `product(name)` | Exact product match, case-insensitive |
| `name_matches(substr)` | Substring match against `vulnerability_name` |
| `description_matches(substr)` | Substring match against `short_description` |
| `cwe(code)` | Match by CWE code (`"CWE-79"` or `"79"` or `"079"`) |
| `ransomware` | Only `knownRansomwareCampaignUse == "Known"` |
| `non_ransomware` | Inverse of `ransomware` |
| `year(year)` | Match by CVE year (the YYYY portion of the id) |
| `added_on_or_after(date)` / `added_on_or_before(date)` | Bracket by `date_added` |
| `due_on_or_after(date)` / `due_on_or_before(date)` | Bracket by `due_date` |
| `overdue(now = Time.utc)` | Due day fully elapsed |
| `due_within(span, now = Time.utc)` | Deadline in `[now, now + span]` |
| `where { \|v\| ... }` | Generic escape hatch |

## Sorting

`Query` exposes two ordering helpers that produce a sorted copy:

```crystal
catalog.query.ransomware.sort_by_due_date
catalog.query.vendor("Microsoft").sort_by_date_added
```

## Materialising results

```crystal
q = catalog.query.vendor("Apple").ransomware
q.size              # length (without materialising an Array)
q.to_a              # plain Array(Vulnerability)
q.first?            # nil-safe first
q.last?
```

`Query` itself is `Enumerable + Indexable`, so the usual collection methods also work directly:

```crystal
q.each { |v| handle(v) }
q.group_by(&.vendor_project)
```

## Examples

### Critical Microsoft entries from 2024

```crystal
catalog.query
  .vendor("Microsoft")
  .added_on_or_after(Time.utc(2024, 1, 1))
  .ransomware
  .to_a
  .each { |v| puts "#{v.cve_id}  #{v.due_date.to_s("%Y-%m-%d")}  #{v.vulnerability_name}" }
```

### "Due in the next 14 days that affect Apache"

```crystal
catalog.query
  .vendor("Apache")
  .due_within(14.days)
  .sort_by_due_date
  .to_a
```

### Server-side rendering: a CWE breakdown

```crystal
breakdown = catalog.cwes.each_with_object({} of String => Int32) do |cwe, h|
  h[cwe] = catalog.query.cwe(cwe).size
end
```

## See also

- **[Catalog convenience filters](/user-guide/basic-usage/#convenience-filters)** — when a one-shot filter is enough, use the `Catalog` methods directly.
- **[Query API reference](/api-reference/query/)** — full method list with signatures.
