#!/usr/bin/env bash
# Every file under src/kev/ must be usable on its own: a consumer that
# reaches for one piece of the shard (`require "kev/catalog"`) should not
# have to know which sibling files it happens to depend on.
#
# Crystal only type-checks methods that are actually called, so a missing
# `require` stays invisible until someone invokes the method that needs
# it — `crystal build` on the file alone is not enough. Each probe below
# therefore requires one file *and* exercises the surface it declares,
# which is what forces its constants to resolve.
set -euo pipefail

cd "$(dirname "$0")/.."

# Crystal resolves `require` relative to the requiring file, and rejects
# absolute paths, so the probes have to live inside the repo.
probe_dir=".self-contained-probe"
rm -rf "$probe_dir"
mkdir -p "$probe_dir"
trap 'rm -rf "$probe_dir"' EXIT

# Shared preamble for the files that build on Catalog. `error`, `version`,
# `ransomware_use`, and `vulnerability` sit below it and get their own.
catalog_new='empty = KEV::Catalog.new("v", Time.utc, 0, [] of KEV::Vulnerability)'

status=0
for file in src/kev/*.cr; do
  name="$(basename "$file" .cr)"
  probe="$probe_dir/$name.cr"

  {
    echo "require \"../${file%.cr}\""
    case "$name" in
      catalog)
        echo "$catalog_new"
        echo 'empty.stats; empty.query; empty.diff(empty); empty.to_csv; empty.to_json'
        echo 'empty.group_by_cwe; empty.cwes; empty.latest; empty.overdue; empty.validate!'
        ;;
      stats)
        echo "$catalog_new"
        echo 'KEV::Stats.compute(empty).inspect'
        ;;
      client)
        echo 'KEV::Client.new.backoff_delay(1)'
        ;;
      diff)
        echo 'none = [] of KEV::Vulnerability'
        echo 'KEV::Diff.new(added: none, removed: none, changed: [] of Tuple(KEV::Vulnerability, KEV::Vulnerability), unchanged: none).inspect'
        ;;
      query)
        echo 'KEV::Query.new([] of KEV::Vulnerability).ransomware.overdue.cwe("79").to_a'
        ;;
      vulnerability)
        echo 'v = KEV::Vulnerability.from_json(%({"cveID":"CVE-2024-1234","vendorProject":"v","product":"p","vulnerabilityName":"n","dateAdded":"2024-01-01","shortDescription":"s","requiredAction":"r","dueDate":"2024-02-01"}))'
        echo 'v.validate!; v.to_json; v.to_h; v.summary; v.has_cwe?("79"); v.cve_year'
        ;;
      ransomware_use)
        echo 'KEV::RansomwareUse.parse?("Known").to_s'
        echo 'begin; KEV::RansomwareUse.parse("nope"); rescue KEV::InvalidValueError; end'
        ;;
      error)
        echo 'KEV::MissingFieldError.new("f", "c"); KEV::InvalidValueError.new("f", "v"); KEV::FetchError.new("x")'
        ;;
      version)
        echo 'puts KEV::VERSION'
        ;;
      *)
        echo "unhandled source file: $file — add a probe for it" >&2
        exit 1
        ;;
    esac
  } >"$probe"

  if crystal build --no-codegen "$probe" >"$probe_dir/$name.log" 2>&1; then
    echo "ok   $file"
  else
    echo "FAIL $file is not self-contained:"
    sed 's/^/       /' "$probe_dir/$name.log"
    status=1
  fi
done

exit $status
