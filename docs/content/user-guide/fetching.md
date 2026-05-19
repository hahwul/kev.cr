+++
title = "Fetching the Live Feed"
description = "Use KEV::Client to pull and poll the CISA KEV feed over HTTPS"
weight = 4
+++

The `KEV::Client` class fetches the live CISA feed over HTTPS, parses it, and returns a `Catalog`. The module-level `KEV.fetch` is a thin wrapper for one-shot use.

## One-shot fetch

```crystal
require "kev"

catalog = KEV.fetch
puts "#{catalog.size} entries, released #{catalog.date_released}"
```

The default endpoint is the canonical feed URL:

```
https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
```

## Long-lived client (recommended for polling)

For repeated calls — a CI job, a cron sync, a Slack notifier — use a `KEV::Client` instance so you can short-circuit on unchanged feeds:

```crystal
client = KEV::Client.new
first  = client.fetch
later  = client.fetch_if_modified  # => nil if the feed has not changed
```

`fetch_if_modified` sends `If-None-Match` (from the last `ETag`) and `If-Modified-Since` (from the last `Last-Modified` header) and returns `nil` on a `304 Not Modified` response. The first call (no validators yet) behaves like a regular `fetch`.

```crystal
client.last_etag         # => "\"kev-v1\"" (or nil before first fetch)
client.last_modified     # => "Wed, 15 May 2026 16:55:06 GMT" (or nil)
```

## Configuration

```crystal
KEV::Client.new(
  url: KEV::Client::DEFAULT_URL,
  user_agent: "my-app/0.1 (+https://example.com)",
  connect_timeout: 5.seconds,
  read_timeout: 15.seconds,
)
```

A descriptive `User-Agent` is recommended — CISA may reach out to maintainers if a misbehaving client is identified. The library defaults to `kev.cr/<version> (+https://github.com/hahwul/kev.cr)`.

## Error handling

| Failure | Exception |
|---------|-----------|
| DNS / connect / TLS errors | `KEV::FetchError` |
| Non-2xx response | `KEV::FetchError` (status code embedded in the message) |
| Body present but not JSON | `JSON::ParseException` |
| JSON valid but schema-malformed | `KEV::ParseError` |

```crystal
begin
  catalog = KEV.fetch
rescue ex : KEV::FetchError
  STDERR.puts "transport error: #{ex.message}"
  exit 1
end
```

## Redirects are not followed

`KEV::Client` deliberately does **not** follow `3xx` redirects. CISA's feed URL has been stable, and a silent follow could route the client to an attacker-controlled host if the upstream is ever compromised. A `301` / `302` surfaces as a `FetchError` so you notice and update your configuration.

If you need to point the client at a known mirror or proxy, pass that URL to `KEV::Client.new(url: ...)` directly.

## Persisting between fetches

If you want to keep the conditional-fetch state across process restarts, serialize `client.last_etag` and `client.last_modified` and pass them back manually — there is no automatic disk cache (and adding one would couple this library to a filesystem layout).

```crystal
File.write("kev.etag", client.last_etag.to_s) if client.last_etag
```

## See also

- **[Client API reference](/api-reference/client/)** — full constructor and method list.
- **[Errors](/api-reference/errors/)** — exception hierarchy.
