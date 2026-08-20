# kev

A Crystal implementation of the [CISA Known Exploited Vulnerabilities (KEV)
catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) —
parsing, querying, fetching, and JSON serialization for the official feed.

- Strict, schema-bound parser modeled on the [official KEV JSON
  schema](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities_schema.json)
  — validates `cveID`/CWE patterns at parse time
- Type-safe `Vulnerability` and `Catalog` models
- Chainable `Query` builder for vendor / product / CWE / ransomware /
  due-date filters
- Built-in HTTP `Client` with `ETag` / `If-Modified-Since` support,
  optional redirect-following, and URL-rich error messages
- Lossless JSON round-trips against the canonical CISA feed —
  including unknown-but-valid `knownRansomwareCampaignUse` strings
  preserved on `known_ransomware_campaign_use_raw`
- CSV mirror support via `Catalog.parse_csv` / `Client.fetch_csv` and
  CSV export via `Catalog#to_csv`
- Explicit `validate!` / `valid?` for re-running schema checks on
  programmatically constructed records
- Convenience surface: `Catalog#search`, `#diff`, `#stats`,
  `#group_by_*`, `#latest` / `#oldest`, and per-entry deep links
  (`#cisa_url` / `#nvd_url` / `#mitre_url`)

## Installation

Add the dependency to your `shard.yml`:

```yaml
dependencies:
  kev:
    github: hahwul/kev.cr
```

Then `shards install`.

## Usage

### Parse a catalog

```crystal
require "kev"

catalog = KEV.parse(File.read("known_exploited_vulnerabilities.json"))
catalog.size                              # => 1592
catalog.catalog_version                   # => "2026.05.15"
catalog["CVE-2021-44228"].vendor_project  # => "Apache"
```

### Fetch the live CISA feed

```crystal
catalog = KEV.fetch
puts "#{catalog.size} entries, released #{catalog.date_released}"

# Long-lived client with conditional GETs:
client = KEV::Client.new
first = client.fetch
later = client.fetch_if_modified  # => nil when the feed is unchanged

# CSV mirror — same per-row data, no catalog metadata:
csv_catalog = KEV::Client.fetch_csv

# Follow redirects (off by default — set when pointing at a mirror):
KEV::Client.new(url: "https://example.com/kev.json", max_redirects: 3).fetch
```

### Snapshot diff and summary

```crystal
old = KEV::Catalog.parse(File.read("kev-yesterday.json"))
new = KEV.fetch

delta = old.diff(new)
delta.added.each   { |v| puts "added: #{v.summary}" }
delta.removed.each { |v| puts "removed: #{v.cve_id}" }
delta.changed.each { |before, after| puts "edited: #{after.cve_id}" }

# One-call rollup — totals, ransomware, overdue, top vendors / CWEs / years.
puts new.stats(top: 5)
# => #<KEV::Stats total=1592 ransomware=321 overdue=1590 years=12 top_vendor=Microsoft(371)>
```

### Search and group

```crystal
catalog.search("log4j")          # substring across cve_id, name, description, vendor, product
catalog.latest(10)               # newest first
catalog.oldest(5)                # earliest first
catalog.group_by_year[2024]      # all 2024-numbered CVEs
catalog.group_by_vendor["Microsoft"]
catalog.group_by_cwe["CWE-79"]
catalog.group_by_ransomware[KEV::RansomwareUse::Known]
```

### Per-entry deep links

```crystal
v = catalog["CVE-2021-44228"]
v.cisa_url   # CISA catalog page filtered to this CVE
v.nvd_url    # NVD detail page
v.mitre_url  # MITRE CVE record
v.summary    # one-line digest with [ransomware]/[overdue] flags
```

### Export to CSV

```crystal
File.write("kev.csv", catalog.to_csv)
KEV::Catalog.parse_csv(File.read("kev.csv"))  # round-trips
```

### Validate programmatic records

`from_json` enforces every schema-level constraint, but constructor and
in-place edits bypass that path. `validate!` / `valid?` re-run the
schema checks on demand:

```crystal
catalog.validate!         # raises KEV::InvalidValueError on the first bad entry
catalog.valid?            # => true / false

vuln.validate!            # same, scoped to one entry
```

### Look up and filter

```crystal
catalog.find("CVE-2021-44228")          # => KEV::Vulnerability | nil
catalog["CVE-2021-44228"]               # => raises KeyError on miss
catalog["CVE-2021-44228"]?              # => same as find

catalog.by_vendor("Microsoft")          # case-insensitive
catalog.by_cwe("CWE-79")                # or just "79"
catalog.ransomware                      # Array(Vulnerability)
catalog.overdue                         # due day fully elapsed
catalog.due_within(30.days)
```

### Chainable queries

```crystal
catalog.query
  .vendor("Microsoft")
  .ransomware
  .added_on_or_after(Time.utc(2024, 1, 1))
  .sort_by_due_date
  .to_a
```

Other `Query` filters: `product`, `name_matches`, `description_matches`,
`cwe`, `non_ransomware`, `year`, `due_on_or_after`, `due_on_or_before`,
`overdue`, `due_within`, and a generic `where { |v| ... }` escape hatch.

### Vulnerability predicates

```crystal
v = catalog["CVE-2021-44228"]
v.known_ransomware?            # => true
v.overdue?                     # => true (relative to now)
v.days_until_due               # => 0 on the due day, negative once overdue
v.remediation_window_days      # => 14
v.has_cwe?("CWE-917")          # => true
v.cve_year                     # => 2021
```

### Equality, ordering, sets

`Vulnerability` equality is *structural* — two records are `==` only when
every field matches — so a `Set` deduplicates identical snapshots but
keeps two revisions of the same CVE apart:

```crystal
seen = Set(KEV::Vulnerability).new
catalog.each { |v| seen << v }
```

To dedup by identity across snapshots, where CISA may have edited the
description, notes, or CWEs in place, key on the CVE id instead:

```crystal
by_cve = catalog.to_h { |v| {v.cve_id, v} }   # or `catalog.find(id)`
old.same_cve?(new)                            # => true for a revised entry
```

Entries sort by `date_added` (with `cve_id` as a tiebreak, then the
remaining fields so `<=>` agrees with `==`), and `Catalog` is
`Enumerable` + `Indexable`, so all the usual collection methods work
directly.

### JSON serialization

`Vulnerability#to_json` and `Catalog#to_json` emit output that matches the
canonical CISA feed shape — field names and order are preserved, and the
result round-trips through `KEV::Catalog.parse`. Empty optional strings
(`notes: ""`) and unknown-but-valid `knownRansomwareCampaignUse` values
are preserved verbatim so byte-level diffs against the upstream feed do
not show spurious deltas.

```crystal
require "json"

catalog = KEV.parse(File.read("kev.json"))
File.write("kev_filtered.json", catalog.query.ransomware.to_a.to_json)

reparsed = KEV::Catalog.parse(catalog.to_json)
reparsed.size == catalog.size  # => true
```

### Errors

All exceptions inherit from `KEV::Error`:

- `KEV::ParseError` — malformed JSON, missing fields, bad dates.
- `KEV::MissingFieldError < ParseError` — a schema-required field is absent.
- `KEV::InvalidValueError < ParseError` — a field value violates a
  schema-level pattern (e.g. a malformed `cveID` or a CWE that does not
  match `^CWE-[0-9]+$`).
- `KEV::FetchError` — transport-level failures in `KEV::Client`.

`KEV.parse?` and `KEV::Catalog.parse?` return `nil` instead of raising.

## Development

```sh
crystal spec
```

## License

MIT. See `LICENSE`.

The KEV catalog itself is published by the U.S. Cybersecurity and
Infrastructure Security Agency (CISA) and is in the public domain.

## Contributors

- [hahwul](https://github.com/hahwul) — creator and maintainer
