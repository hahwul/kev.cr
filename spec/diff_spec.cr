require "./spec_helper"

private def base_catalog : KEV::Catalog
  SpecFixtures.sample_catalog
end

private def with_replaced(catalog : KEV::Catalog, cve_id : String, &block : KEV::Vulnerability -> KEV::Vulnerability) : KEV::Catalog
  KEV::Catalog.new(
    catalog_version: catalog.catalog_version,
    date_released: catalog.date_released,
    count: catalog.count,
    vulnerabilities: catalog.vulnerabilities.map { |v| v.cve_id == cve_id ? block.call(v) : v },
    title: catalog.title,
  )
end

describe KEV::Catalog do
  describe "#diff" do
    it "reports no changes between identical snapshots" do
      delta = base_catalog.diff(base_catalog)
      delta.empty?.should be_true
      delta.added.should be_empty
      delta.removed.should be_empty
      delta.changed.should be_empty
      delta.unchanged.size.should eq(base_catalog.size)
    end

    it "captures added entries on the after-side" do
      synthetic = KEV::Vulnerability.new(
        cve_id: "CVE-2099-0001", vendor_project: "Acme", product: "Widget",
        vulnerability_name: "synthetic", date_added: Time.utc(2099, 1, 1),
        short_description: "x", required_action: "x", due_date: Time.utc(2099, 2, 1),
      )
      after = KEV::Catalog.new(
        catalog_version: base_catalog.catalog_version,
        date_released: base_catalog.date_released,
        count: base_catalog.count + 1,
        vulnerabilities: base_catalog.vulnerabilities + [synthetic],
      )
      delta = base_catalog.diff(after)
      delta.added.map(&.cve_id).should eq(["CVE-2099-0001"])
      delta.removed.should be_empty
      delta.changed.should be_empty
    end

    it "captures removed entries on the before-side" do
      shorter = KEV::Catalog.new(
        catalog_version: base_catalog.catalog_version,
        date_released: base_catalog.date_released,
        count: base_catalog.count - 1,
        vulnerabilities: base_catalog.vulnerabilities[1..].to_a,
      )
      delta = base_catalog.diff(shorter)
      delta.added.should be_empty
      delta.removed.map(&.cve_id).should eq([base_catalog.vulnerabilities.first.cve_id])
    end

    it "reports changed entries as (before, after) pairs" do
      after = with_replaced(base_catalog, "CVE-2021-44228") do |v|
        KEV::Vulnerability.new(
          cve_id: v.cve_id, vendor_project: v.vendor_project, product: v.product,
          vulnerability_name: v.vulnerability_name, date_added: v.date_added,
          short_description: "DESCRIPTION WAS REVISED",
          required_action: v.required_action, due_date: v.due_date,
          known_ransomware_campaign_use: v.known_ransomware_campaign_use,
          notes: v.notes, cwes: v.cwes,
        )
      end
      delta = base_catalog.diff(after)
      delta.changed.size.should eq(1)
      before_v, after_v = delta.changed.first
      before_v.short_description.should_not eq(after_v.short_description)
      delta.size.should eq(1)
    end
  end
end
