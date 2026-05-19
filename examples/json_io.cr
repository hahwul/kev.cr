# Demonstrates JSON round-tripping — useful when persisting filtered
# subsets to disk or POST'ing them to downstream services.
require "json"
require "../src/kev"

catalog = KEV.parse(File.read("spec/fixtures/sample_catalog.json"))

# A single vulnerability serialises to canonical KEV-shaped JSON.
log4j = catalog["CVE-2021-44228"]
puts JSON.parse(log4j.to_json).to_pretty_json

# A whole catalog round-trips losslessly.
reparsed = KEV::Catalog.parse(catalog.to_json)
puts
puts "Round-trip: #{catalog.size} == #{reparsed.size}"
