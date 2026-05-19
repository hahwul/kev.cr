+++
title = "JSON Round-Trip"
description = "Serialize and re-parse KEV data losslessly against the upstream feed"
weight = 5
+++

`Vulnerability#to_json` and `Catalog#to_json` emit output that matches the canonical CISA feed shape — field names, ordering, and key presence are preserved. The result re-parses through `KEV::Catalog.parse` without information loss.

## Catalog round-trip

```crystal
catalog  = KEV.parse(File.read("kev.json"))
emitted  = catalog.to_json          # canonical KEV-shaped JSON
reparsed = KEV::Catalog.parse(emitted)

reparsed.size == catalog.size       # true
reparsed.vulnerabilities == catalog.vulnerabilities  # true
```

## Verified against the live feed

The library is regression-tested against the live CISA feed: every entry's
field set is preserved across `parse → to_json → parse`. The most subtle
case — entries with `"cwes": []` — is preserved verbatim. The feed always
emits the key even when no CWEs are tagged, so the library does too.

```crystal
catalog["CVE-2014-0160"].cwes        # => []
JSON.parse(catalog["CVE-2014-0160"].to_json)["cwes"]
# => JSON::Any([])      (always present, even when empty)
```

## Single-vulnerability serialization

You can serialize a single `Vulnerability` directly — useful for SIEM events, message-queue payloads, or per-CVE storage:

```crystal
v = catalog["CVE-2021-44228"]
File.write("log4j.json", v.to_json)
KEV::Vulnerability.from_json(File.read("log4j.json"))  # => Vulnerability
```

## Hash export

If you need a plain `Hash` instead of a JSON string (e.g. for further mutation or for piping into a templating engine), use `#to_h`:

```crystal
catalog["CVE-2021-44228"].to_h
# => {"cveID" => "CVE-2021-44228", "vendorProject" => "Apache", ...,
#     "cwes" => ["CWE-20", "CWE-917"]}
```

Keys are the canonical CISA field names. Dates are formatted as `YYYY-MM-DD` strings.

## Persisting filtered subsets

`Vulnerability` serialises element-by-element, so `Array#to_json` works directly for a subset:

```crystal
ransomware = catalog.query.ransomware.to_a
File.write("kev-ransomware.json", ransomware.to_json)
```

The output is a JSON array of vulnerability objects. To produce a *catalog-shaped* envelope (with `catalogVersion`, `count`, etc.), construct a new `Catalog`:

```crystal
ransomware = catalog.query.ransomware.to_a
subset = KEV::Catalog.new(
  catalog_version: "#{catalog.catalog_version}-ransomware",
  date_released:   catalog.date_released,
  count:           ransomware.size,
  vulnerabilities: ransomware,
  title:           "Ransomware subset of #{catalog.title}",
)
File.write("kev-ransomware.json", subset.to_json)
```

## Known precision gotcha

`dateReleased` arrives from CISA with 3- or 4-digit fractional seconds. Crystal's `Time.parse_iso8601` only accepts up to 3 digits, so the library normalises the input to millisecond precision before parsing. A 4-digit input (`.6086Z`) round-trips as 3 digits (`.608Z`).

This affects only the catalog-level `dateReleased` timestamp; per-entry `dateAdded` / `dueDate` are date-only (`YYYY-MM-DD`) and have no precision concern.

## See also

- **[Vulnerability API](/api-reference/vulnerability/#to_json)** — `to_json`, `to_h`, `from_json`.
- **[Errors](/api-reference/errors/)** — what raises during JSON ingestion.
