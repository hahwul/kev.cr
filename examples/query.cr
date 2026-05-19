# Chainable query examples — find Microsoft ransomware-flagged CVEs from
# 2023 and onward, sorted by remediation due date.
require "../src/kev"

catalog = KEV.parse(File.read("spec/fixtures/sample_catalog.json"))

results = catalog.query
  .vendor("Microsoft")
  .ransomware
  .added_on_or_after(Time.utc(2023, 1, 1))
  .sort_by_due_date
  .to_a

results.each do |v|
  puts "#{v.cve_id}  due #{v.due_date.to_s("%Y-%m-%d")}  #{v.vulnerability_name}"
end
