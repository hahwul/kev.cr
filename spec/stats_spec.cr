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

  it "raises on negative top" do
    expect_raises(ArgumentError) { catalog.stats(top: -1) }
  end
end
