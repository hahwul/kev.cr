# Parse a local KEV feed dump and print high-level statistics.
#
#   crystal run examples/basic.cr -- path/to/known_exploited_vulnerabilities.json
require "../src/kev"

path = ARGV.first? || "spec/fixtures/sample_catalog.json"
catalog = KEV.parse(File.read(path))

puts "Catalog version: #{catalog.catalog_version}"
puts "Released:        #{catalog.date_released}"
puts "Entries:         #{catalog.size} (reported count: #{catalog.count})"
puts "Vendors:         #{catalog.vendors.size}"
puts "CWEs:            #{catalog.cwes.size}"
puts "Ransomware-flagged: #{catalog.ransomware.size}"
