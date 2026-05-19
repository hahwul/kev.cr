+++
title = "RansomwareUse"
description = "Enum modelling the knownRansomwareCampaignUse field"
weight = 5
+++

## `KEV::RansomwareUse`

A Crystal `enum` mirroring CISA's `knownRansomwareCampaignUse` field:

```crystal
KEV::RansomwareUse::Known     # CISA has confirmed ransomware-campaign use
KEV::RansomwareUse::Unknown   # CISA lacks confirmation (NOT a denial)
```

The third state — "no value at all" — is represented as `nil` at the
`Vulnerability` level (`Vulnerability#known_ransomware_campaign_use`
returns `RansomwareUse?`). The current live feed always populates the
field, but the schema treats it as optional, so legacy snapshots may
carry `nil`.

## Class methods

| Method | Description |
|--------|-------------|
| `RansomwareUse.parse(raw : String) : RansomwareUse` | Strict — raises `KEV::InvalidValueError` on unknown input. |
| `RansomwareUse.parse?(raw : String) : RansomwareUse?` | Non-raising. |

## Instance methods

| Method | Description |
|--------|-------------|
| `to_s : String` | Canonical CISA spelling (`"Known"` or `"Unknown"`). |
| Standard enum methods | `known?`, `unknown?`, `<=>`, etc. — provided by Crystal. |

## Forward compatibility

If CISA introduces a new value in the future, `RansomwareUse.parse` raises `KEV::InvalidValueError` rather than silently swallowing it. The strict behaviour is intentional: feed-schema drift should be loud so this library can be updated. If you need permissive ingestion, pre-filter the raw string before constructing a `Vulnerability`.

## Predicate on Vulnerability

`Vulnerability#known_ransomware?` returns `true` only for `Known` — both `Unknown` and `nil` answer `false`. This matches the predicate's English-language meaning ("has CISA confirmed ransomware exploitation?").

## See also

- **[Vulnerability](/api-reference/vulnerability/)** — where this enum is used.
