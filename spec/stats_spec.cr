require "./spec_helper"

describe KEV::Stats do
  catalog = SpecFixtures.sample_catalog

  it "reports basic totals" do
    s = catalog.stats(top: 2, now: Time.utc(2030, 1, 1))
    s.total.should eq(catalog.size)
    s.ransomware.should eq(catalog.ransomware.size)
    s.overdue.should eq(catalog.size) # all fixture due dates are pre-2030
  end

  it "groups counts by CVE year" do
    s = catalog.stats(top: 5)
    s.by_year[2021].should eq(1)
    s.by_year[2023].should eq(1)
    s.by_year[2024].should eq(1)
    # Heartbleed (CVE-2014-0160) was added in 2022 but its CVE year is 2014.
    s.by_year[2014].should eq(1)
  end

  it "produces top-N vendor / product / CWE rollups, descending and tie-stable" do
    s = catalog.stats(top: 2)
    s.top_vendors.size.should be <= 2
    # Every fixture vendor appears once, so any pair is valid; verify the
    # ordering invariant (counts descending).
    s.top_vendors.map(&.[1]).should eq(s.top_vendors.map(&.[1]).sort!.reverse!)
    # CWEs across the fixture: CWE-20, CWE-917, CWE-294, CWE-77 — all 1 each.
    s.top_cwes.size.should be <= 2
  end

  it "breaks equal-count CWE ties by weakness number, not by text" do
    # All four fixture CWEs occur once, so the tiebreak alone decides who
    # makes the cut. Sorting the codes as strings put CWE-294 ahead of
    # CWE-77 and pushed CWE-77 out of a top-2.
    s = catalog.stats(top: 4)
    s.top_cwes.map(&.[0]).should eq(["CWE-20", "CWE-77", "CWE-294", "CWE-917"])

    catalog.stats(top: 2).top_cwes.map(&.[0]).should eq(["CWE-20", "CWE-77"])
  end

  it "still ranks CWEs by count before applying the tiebreak" do
    common = KEV::Vulnerability.new(
      cve_id: "CVE-2024-1234", vendor_project: "V", product: "P",
      vulnerability_name: "N", date_added: Time.utc(2024, 1, 1),
      short_description: "S", required_action: "R",
      due_date: Time.utc(2024, 2, 1), cwes: ["CWE-9999"])
    c = KEV::Catalog.new("v", Time.utc, 2, [common, common.dup])

    s = c.stats(top: 1)
    s.top_cwes.should eq([{"CWE-9999", 2}])
  end

  it "raises on negative top" do
    expect_raises(ArgumentError) { catalog.stats(top: -1) }
  end
end
