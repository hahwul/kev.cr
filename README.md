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
- Built-in HTTP `Client` with `ETag` / `If-Modified-Since` support
- Lossless JSON round-trips against the canonical CISA feed —
  including unknown-but-valid `knownRansomwareCampaignUse` strings
  preserved on `known_ransomware_campaign_use_raw`

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
```

### Look up and filter

```crystal
catalog.find("CVE-2021-44228")          # => KEV::Vulnerability | nil
catalog["CVE-2021-44228"]               # => raises KeyError on miss
catalog["CVE-2021-44228"]?              # => same as find

catalog.by_vendor("Microsoft")          # case-insensitive
catalog.by_cwe("CWE-79")                # or just "79"
catalog.ransomware                      # Array(Vulnerability)
catalog.overdue                         # past their due date
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
v.days_until_due               # => negative when overdue
v.remediation_window_days      # => 14
v.has_cwe?("CWE-917")          # => true
v.cve_year                     # => 2021
```

### Equality, ordering, sets

`Vulnerability` equality is keyed by `cve_id`, so deduping across feed
snapshots is straightforward:

```crystal
seen = Set(KEV::Vulnerability).new
catalog.each { |v| seen << v }
```

Vectors sort by `date_added` (with `cve_id` as a stable tiebreak), and
`Catalog` is `Enumerable` + `Indexable`, so all the usual collection
methods work directly.

### JSON serialization

`Vulnerability#to_json` and `Catalog#to_json` emit output that matches the
canonical CISA feed shape — field names and order are preserved, and the
result round-trips through `KEV::Catalog.parse`:

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
