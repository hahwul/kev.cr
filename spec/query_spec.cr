require "./spec_helper"

describe KEV::Query do
  catalog = SpecFixtures.sample_catalog

  it "filters by vendor" do
    catalog.query.vendor("Apache").to_a.map(&.cve_id).should eq(["CVE-2021-44228"])
  end

  it "filters by ransomware" do
    catalog.query.ransomware.size.should eq(2)
    catalog.query.non_ransomware.size.should eq(2)
  end

  it "filters by CVE year" do
    catalog.query.year(2024).map(&.cve_id).should eq(["CVE-2024-21887"])
  end

  it "filters by CWE" do
    catalog.query.cwe("CWE-917").size.should eq(1)
  end

  it "chains multiple filters" do
    result = catalog.query
      .ransomware
      .added_on_or_after(Time.utc(2022, 1, 1))
      .to_a
    result.map(&.cve_id).should eq(["CVE-2023-23397"])
  end

  it "supports a custom predicate via #where" do
    result = catalog.query.where(&.product.starts_with?("Connect")).to_a
    result.map(&.cve_id).should eq(["CVE-2024-21887"])
  end

  it "supports substring search on name and description" do
    catalog.query.name_matches("log4j").size.should eq(1)
    catalog.query.description_matches("jndi").size.should eq(1)
  end

  it "sorts a result set without mutating the source" do
    sorted = catalog.query.sort_by_due_date
    sorted.first.cve_id.should eq("CVE-2021-44228")
    # Source untouched
    catalog.vulnerabilities.first.cve_id.should eq("CVE-2021-44228")
  end

  it "is Enumerable" do
    catalog.query.vendor("Microsoft").map(&.cve_id).should eq(["CVE-2023-23397"])
  end

  it "exposes first?/last?" do
    catalog.query.ransomware.first?.try(&.cve_id).should eq("CVE-2021-44228")
    catalog.query.vendor("Nope").first?.should be_nil
  end
end
