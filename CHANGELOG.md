# Changelog

## Unreleased

### Fixed

- **Impossible dates escaped as `ArgumentError`.** `Time.parse_utc` /
  `Time.parse_iso8601` reach `Time.utc` with the parsed components and let
  it raise a bare `ArgumentError` for a day that does not exist
  (`"2024-02-30"`, `"2024-13-01"`, `"2024-01-00"`, `"0000-01-01"`). That is
  not a `Time::Format::Error`, so it slipped past the rescue in
  `Vulnerability`/`Catalog` and out of `KEV::Error` entirely — including
  through `KEV.parse?`, `Catalog.parse?`, and `Catalog.parse_csv?`, all of
  which are documented to answer `nil`. Affects `dateAdded`, `dueDate`, and
  `dateReleased`, on both the JSON and CSV paths.
- **`dateAdded` / `dueDate` accepted values that are not `YYYY-MM-DD`.**
  `Time.parse_utc` stops as soon as its format string is satisfied and
  ignores the remainder, and reads unpadded components — so
  `"2024-01-02T00:00:00Z"` silently decayed to a bare date, `"2024-01-02junk"`
  parsed clean, and `"2024-1-2"` was accepted. The schema declares these
  `format: date`; the shape is now enforced up front.
- **`dateReleased` lost sub-millisecond precision.** The fraction was
  trimmed to three digits before parsing, on the premise that
  `Time.parse_iso8601` could not read more — it reads up to nine. The live
  feed publishes a 4-digit fraction, so every parse discarded a digit CISA
  published. The value is now parsed as published and re-emitted at the
  narrowest of 3/6/9 fraction digits that preserves it, keeping `parse →
  to_json → parse` lossless. Whole milliseconds still emit CISA's canonical
  `.sssZ`.
- **`Client`** raised a bare `ArgumentError` from `HTTP::Client` for an
  `http(s)` URL with no host (`"http:///feed.json"`, `"https://:8080/x"`) —
  these cleared the scheme check and then failed outside the documented
  "`FetchError` on any transport failure" contract. Now a `FetchError`.
- **`Catalog.parse_csv`** failed a whole feed with "invalid value '' for
  field 'cveID'" when it hit a blank line, such as the one a stray trailing
  newline leaves behind. Wholly empty rows are skipped.
- **Deadline off-by-one.** `Vulnerability#overdue?` compared `due_date <
  now`, so every entry reported itself overdue from one second past
  midnight on the day it was actually still due. It now compares against
  the end of the due day. `days_until_due` counts whole UTC calendar days
  and returns `0` on the due date (previously `-1`), and
  `Catalog#due_within` / `Query#due_within` no longer drop entries due
  today. `Catalog#overdue`, `Query#overdue`, `Stats#overdue`, and
  `Vulnerability#summary` all inherited the old behaviour.
- **`Vulnerability#has_cwe?`** only stripped the `CWE-` prefix in
  all-upper or all-lower spelling, so `"Cwe-79"` silently reported no
  match. Prefix casing, surrounding whitespace, and leading zeros are now
  all normalised. Applies to `Catalog#by_cwe` and `Query#cwe` too.
- **`Catalog#group_by_cwe`** returned a Hash carrying a default block, so
  reading an absent code inserted an empty bucket into the caller's
  result instead of raising `KeyError`.
- **`Vulnerability#cwes`** handed out the instance's own array, so
  `v.cwes << ...` rewrote the record — and with it equality, hashing, and
  serialisation. The accessor now returns a copy; `#each_cwe` and
  `#cwes_size` cover read-only traversal without allocating.
- **`Vulnerability#<=>`** stopped after `date_added` and `cve_id`, so two
  differing revisions of the same CVE compared equal through `<=>` while
  `==` disagreed — breaking the documented `Comparable` contract and the
  derived `<`, `>`, `<=`, `>=`.
- **`Catalog.parse_csv`** rejected a feed carrying a UTF-8 BOM with "CSV
  is missing required column(s): cveID".
- **CWE ordering.** `Catalog#cwes` and `Stats#top_cwes` sorted codes as
  text, putting `CWE-100` ahead of `CWE-20`; equal-count ties in
  `top_cwes` were decided the same way. Both now order by weakness
  number. New helpers: `Vulnerability.cwe_number` /
  `Vulnerability.cwe_sort_key`.
- **`Client`** treated the whole 3xx range as followable redirects, so a
  `304 Not Modified` reaching `fetch` with `max_redirects > 0` was
  reported as "redirect … missing Location header". Only
  301/302/303/307/308 are followed now, and exhausting the redirect
  budget says so instead of blaming the status.
- **`Client#fetch_if_modified`** discarded the response headers on a
  `304`, pinning the client to the first `ETag` it ever saw; once the
  origin rotated its validator every later poll re-downloaded the whole
  feed. A `304` now refreshes the validators it carries, without wiping
  ones it omits.
- **Requires.** `src/kev/catalog.cr` and `src/kev/ransomware_use.cr`
  referenced constants they never required, so `require "kev/catalog"`
  alone failed at the first call to `#stats` / `#query` / `#diff`.
  `scripts/check_self_contained.sh` now guards this in CI.

## v0.1.0

- First release
