+++
title = "Errors"
description = "Exception hierarchy raised by kev.cr"
weight = 6
+++

All exceptions raised by this library descend from `KEV::Error`.

```
KEV::Error
├── KEV::ParseError
│   ├── KEV::MissingFieldError
│   └── KEV::InvalidValueError
└── KEV::FetchError
```

## `KEV::Error`

Catch this if you want to handle "anything KEV-related went wrong" without enumerating the subclasses.

## `KEV::ParseError`

The input cannot be decoded — malformed JSON shape, missing required fields, or values that fail their schema-level shape checks (e.g. a `dateAdded` that is not `YYYY-MM-DD`).

| Subclass | Raised when |
|----------|-------------|
| `MissingFieldError` | A schema-required field is absent. Exposes `#field : String`. |
| `InvalidValueError` | A field value is outside its permitted set (e.g. an unknown `knownRansomwareCampaignUse`). Exposes `#field : String` and `#value : String`. |

`JSON::ParseException` — raised by Crystal's stdlib for raw JSON syntax errors — is **not** wrapped. It propagates unchanged, matching the [cvss.cr](https://cvss.cr.hahwul.com) precedent. Catch both if you want to handle "any kind of ingestion failure":

```crystal
begin
  catalog = KEV.parse(payload)
rescue ex : KEV::ParseError | JSON::ParseException
  STDERR.puts "could not parse KEV input: #{ex.message}"
end
```

## `KEV::FetchError`

Transport-level failure in `KEV::Client`: DNS, connect, TLS, timeout, or a non-2xx HTTP status. The original cause's message is preserved.

```crystal
begin
  catalog = KEV.fetch
rescue ex : KEV::FetchError
  STDERR.puts "could not reach CISA: #{ex.message}"
end
```

## Non-raising entry points

When you need a `nil` return rather than an exception:

| Method | Description |
|--------|-------------|
| `KEV.parse?(input)` | Catches `KEV::Error` and `JSON::ParseException`. |
| `KEV::Catalog.parse?(input)` | Same. |
| `KEV::Vulnerability.from_json(input)` | Always raises on failure — no `parse?` variant. Pre-validate with `JSON.parse` if you need it. |
| `KEV::RansomwareUse.parse?(raw)` | Returns `nil` instead of raising `InvalidValueError`. |

## See also

- **[Getting Started](/user-guide/getting-started/)** — non-raising parse pattern.
- **[Client](/api-reference/client/)** — transport-level error mapping.
