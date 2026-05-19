require "./spec_helper"

describe KEV::Catalog do
  describe ".parse" do
    it "reads metadata and entries from the canonical feed shape" do
      c = SpecFixtures.sample_catalog
      c.title.should eq("CISA Catalog of Known Exploited Vulnerabilities")
      c.catalog_version.should eq("2024.01.15")
      c.count.should eq(4)
      c.vulnerabilities.size.should eq(4)
      c.date_released.should eq(Time.utc(2024, 1, 15, 16, 55, 6, nanosecond: 608_000_000))
    end

    it "parses with no top-level title (schema permits absence)" do
      json = <<-JSON
        {
          "catalogVersion": "1.0",
          "dateReleased": "2024-01-01T00:00:00.000Z",
          "count": 0,
          "vulnerabilities": []
        }
      JSON
      c = KEV::Catalog.parse(json)
      c.title.should be_nil
      c.size.should eq(0)
    end

    it "tolerates 4-digit fractional seconds in dateReleased" do
      # Seen on the live feed: ".6086Z"
      json = <<-JSON
        {
          "catalogVersion": "1.0",
          "dateReleased": "2026-05-15T16:55:06.6086Z",
          "count": 0,
          "vulnerabilities": []
        }
      JSON
      c = KEV::Catalog.parse(json)
      c.date_released.year.should eq(2026)
    end

    it "raises MissingFieldError when catalogVersion is missing" do
      expect_raises(KEV::MissingFieldError, /catalogVersion/) do
        KEV::Catalog.parse(%({"dateReleased": "2024-01-01T00:00:00Z", "count": 0, "vulnerabilities": []}))
      end
    end

    it "raises MissingFieldError when vulnerabilities array is missing" do
      expect_raises(KEV::MissingFieldError, /vulnerabilities/) do
        KEV::Catalog.parse(%({"catalogVersion": "1.0", "dateReleased": "2024-01-01T00:00:00Z", "count": 0}))
      end
    end
  end

  describe "Enumerable/Indexable" do
    catalog = SpecFixtures.sample_catalog

    it "is iterable" do
      ids = catalog.map(&.cve_id)
      ids.should contain("CVE-2021-44228")
      ids.should contain("CVE-2024-21887")
    end

    it "supports positional access" do
      catalog[0].cve_id.should eq("CVE-2021-44228")
    end

    it "supports select/reject from Enumerable" do
      catalog.select(&.known_ransomware?).size.should eq(2)
    end
  end

  describe "lookups" do
    catalog = SpecFixtures.sample_catalog

    it "#find returns the matching entry or nil" do
      catalog.find("CVE-2021-44228").try(&.vendor_project).should eq("Apache")
      catalog.find("CVE-9999-99999").should be_nil
    end

    it "#[] raises on miss, #[]? returns nil" do
      catalog["CVE-2021-44228"].vendor_project.should eq("Apache")
      catalog["CVE-9999-99999"]?.should be_nil
      expect_raises(KeyError) { catalog["CVE-9999-99999"] }
    end

    it "#by_vendor matches case-insensitively" do
      catalog.by_vendor("microsoft").map(&.cve_id).should eq(["CVE-2023-23397"])
    end

    it "#by_product matches case-insensitively" do
      catalog.by_product("Log4j2").size.should eq(1)
    end

    it "#by_cwe matches with or without prefix" do
      catalog.by_cwe("CWE-917").size.should eq(1)
      catalog.by_cwe("294").size.should eq(1)
    end

    it "#ransomware filters by known ransomware use" do
      ids = catalog.ransomware.map(&.cve_id).sort
      ids.should eq(["CVE-2021-44228", "CVE-2023-23397"])
    end

    it "#added_on_or_after / added_on_or_before bracket the range" do
      cut = Time.utc(2023, 1, 1)
      catalog.added_on_or_after(cut).size.should eq(2)
      catalog.added_on_or_before(cut).size.should eq(2)
    end

    it "#overdue and #due_within use the provided clock" do
      # All fixture due dates are < 2025; from a 2030 vantage all are overdue.
      catalog.overdue(Time.utc(2030, 1, 1)).size.should eq(4)
      # And none are upcoming.
      catalog.due_within(30.days, Time.utc(2030, 1, 1)).should be_empty
    end
  end

  describe "summaries" do
    catalog = SpecFixtures.sample_catalog

    it "#vendors lists distinct sorted vendors" do
      catalog.vendors.should eq(["Apache", "Ivanti", "Microsoft", "OpenSSL"])
    end

    it "#products lists distinct sorted products" do
      catalog.products.should contain("Log4j2")
      catalog.products.should contain("Outlook")
    end

    it "#cwes lists distinct sorted CWE codes" do
      catalog.cwes.should eq(["CWE-20", "CWE-294", "CWE-77", "CWE-917"])
    end
  end

  describe "JSON round-trip" do
    it "parse → to_json → parse preserves the catalog" do
      original = SpecFixtures.sample_catalog
      reparsed = KEV::Catalog.parse(original.to_json)
      reparsed.catalog_version.should eq(original.catalog_version)
      reparsed.size.should eq(original.size)
      reparsed.vulnerabilities.zip(original.vulnerabilities).each do |a, b|
        a.should eq(b)
        a.to_h.should eq(b.to_h)
      end
    end
  end
end
