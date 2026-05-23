# Contributing

Thanks for your interest in kev.cr.

## Local development

```sh
shards install
crystal spec                # 184 examples
crystal tool format --check
```

Run an example end-to-end (some examples reach out to the CISA feed):

```sh
crystal run examples/basic.cr     # uses the bundled fixture
crystal run examples/fetch.cr     # fetches the live CISA KEV catalog
```

## Submitting changes

1. Fork the repository and create a branch.
2. Add or update specs under `spec/` for any code change. Catalog fixtures live
   under `spec/fixtures/`.
3. Make sure `crystal spec` and `crystal tool format --check` pass — CI runs both.
4. Open a pull request describing the change and linking to the relevant CISA
   KEV documentation if applicable.

## Reporting issues

Please open an issue with:

- The CVE ID or query that triggers the problem.
- The expected result (with a link to the CISA KEV page if possible).
- The result kev.cr returned.

## Data source

kev.cr reads the [CISA Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) catalog. When CISA changes the JSON schema, the
`Catalog`/`Vulnerability` types in `src/kev/` and the fixtures under
`spec/fixtures/` need to be updated together.
