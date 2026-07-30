+++
title = "Client"
description = "HTTPS fetcher for the live CISA KEV feed"
weight = 4
+++

## `KEV::Client`

Fetches the CISA Known Exploited Vulnerabilities feed over HTTPS and parses the result into a `Catalog`.

## Constants

| Constant | Description |
|----------|-------------|
| `Client::DEFAULT_URL` | Canonical feed URL: `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` |
| `Client::DEFAULT_USER_AGENT` | `kev.cr/<VERSION> (+https://github.com/hahwul/kev.cr)` |

## Construction

```crystal
KEV::Client.new(
  url: KEV::Client::DEFAULT_URL,
  user_agent: KEV::Client::DEFAULT_USER_AGENT,
  connect_timeout: 10.seconds,
  read_timeout: 30.seconds,
)
```

## Methods

| Method | Description |
|--------|-------------|
| `fetch : Catalog` | Unconditional fetch. Raises `KEV::FetchError` on transport or HTTP failures. |
| `fetch_if_modified : Catalog?` | Conditional fetch using `If-None-Match` / `If-Modified-Since`. Returns `nil` on `304 Not Modified`. |
| `Client.fetch(url = DEFAULT_URL) : Catalog` | Class-level convenience for a single fetch. |

## State

After each successful fetch the client captures the upstream cache validators:

| Getter | Description |
|--------|-------------|
| `last_etag : String?` | Captured from the response `ETag` header; also refreshed from a `304`. |
| `last_modified : String?` | Captured from the response `Last-Modified` header; also refreshed from a `304`. |

These are used automatically by `fetch_if_modified` and can be persisted manually for cross-process caching.

## Exception mapping

| Failure | Exception |
|---------|-----------|
| DNS / connect / TLS error | `KEV::FetchError` (wraps `IO::Error`, `Socket::Error`, or `OpenSSL::SSL::Error`) |
| Non-2xx response (incl. 3xx — see below) | `KEV::FetchError` |
| Body is not JSON | `JSON::ParseException` |
| JSON valid but schema-malformed | `KEV::ParseError` |

## Redirects

`KEV::Client` does **not** follow HTTP redirects by default (`max_redirects` is `0`). A `301` / `302` / `303` / `307` / `308` surfaces as a `FetchError` so the caller can update the configured URL deliberately, rather than silently route to a different host. Raise `max_redirects` when pointing at a mirror or proxy that issues a canonical redirect; once the budget is spent the error says so explicitly.

Only those five statuses are treated as redirects. `304 Not Modified` is a 3xx but carries no `Location`, so it is reported as itself rather than chased.

## Non-http(s) URLs

URLs with a scheme other than `http` or `https` (e.g. `file://`) are rejected eagerly with a `FetchError` — the library will not read from the local filesystem under the guise of a feed fetch.

## Example: polling loop

```crystal
client = KEV::Client.new
loop do
  if catalog = client.fetch_if_modified
    publish(catalog)
  end
  sleep 1.hour
end
```

## See also

- **[Fetching the Live Feed](/user-guide/fetching/)** — narrative guide.
- **[Errors](/api-reference/errors/)** — full exception hierarchy.
