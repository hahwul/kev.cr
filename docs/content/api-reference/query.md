+++
title = "Query"
description = "Chainable filter builder over a list of Vulnerabilities"
weight = 3
+++

## `KEV::Query`

A chainable, immutable filter over an `Array(Vulnerability)`. Returned by `Catalog#query`.

Each filter method returns a *new* `Query`; the source list is never modified.

```crystal
catalog.query
  .vendor("Microsoft")
  .ransomware
  .added_on_or_after(Time.utc(2024, 1, 1))
  .sort_by_due_date
  .to_a
```

`Query` includes `Enumerable(Vulnerability)` and `Indexable(Vulnerability)`, so the standard collection methods (`each`, `map`, `select`, `group_by`, `[i]`, etc.) are all available.

## Filter methods

| Method | Effect |
|--------|--------|
| `vendor(name : String) : Query` | Exact vendor match (case-insensitive). |
| `product(name : String) : Query` | Exact product match (case-insensitive). |
| `name_matches(substr : String) : Query` | Substring against `vulnerability_name`. |
| `description_matches(substr : String) : Query` | Substring against `short_description`. |
| `cwe(code : String) : Query` | Match CWE (`"CWE-79"`, `"79"`, or `"079"`). |
| `ransomware : Query` | Only `Known` ransomware-flagged entries. |
| `non_ransomware : Query` | Inverse of `ransomware`. |
| `year(year : Int32) : Query` | Match CVE year. |
| `added_on_or_after(date : Time) : Query` | `date_added >= date`. |
| `added_on_or_before(date : Time) : Query` | `date_added <= date`. |
| `due_on_or_after(date : Time) : Query` | `due_date >= date`. |
| `due_on_or_before(date : Time) : Query` | `due_date <= date`. |
| `overdue(now : Time = Time.utc) : Query` | Due day fully elapsed (`now >= due_date + 1 day`). |
| `due_within(span : Time::Span, now : Time = Time.utc) : Query` | Not yet overdue and `due_date <= now + span`. |
| `where(&block : Vulnerability -> Bool) : Query` | Arbitrary predicate. |

## Sorting

Returns a new sorted `Query`:

| Method | Description |
|--------|-------------|
| `sort_by_date_added : Query` | Ascending by `date_added`. |
| `sort_by_due_date : Query` | Ascending by `due_date`. |

## Materialisation

| Method | Description |
|--------|-------------|
| `to_a : Array(Vulnerability)` | Fresh copy of the current selection. |
| `first? : Vulnerability?` | First element, or `nil`. |
| `last? : Vulnerability?` | Last element, or `nil`. |
| `size : Int32` | Length of the current selection. |

## Performance

Each filter step calls `Array#select`, producing a new array. For typical KEV sizes (~1,500 entries) this is well under a millisecond per step. If you need a streaming filter for much larger datasets, drop down to `vulnerabilities.each` and write the predicate inline.

## See also

- **[Queries & Filters user guide](/user-guide/queries/)** — narrative examples.
- **[Catalog](/api-reference/catalog/)** — the source of `#query`.
