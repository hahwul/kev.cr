# Pull the live CISA KEV feed and print a per-vendor breakdown.
#
#   crystal run examples/fetch.cr
require "../src/kev"

catalog = KEV.fetch
puts "Fetched #{catalog.size} entries (catalog #{catalog.catalog_version})"
puts

catalog.vendors.first(10).each do |vendor|
  count = catalog.by_vendor(vendor).size
  puts "  #{vendor.ljust(30)} #{count}"
end
