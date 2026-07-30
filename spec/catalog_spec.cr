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
      ids = catalog.ransomware.map(&.cve_id).sort!
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

    it "#due_within keeps an entry whose deadline is today" do
      # log4j is due 2021-12-24. Half-way through that day it is still
      # upcoming, not overdue — `due_date >= now` used to drop it.
      noon = Time.utc(2021, 12, 24, 12, 0, 0)
      catalog.due_within(30.days, noon).map(&.cve_id).should contain("CVE-2021-44228")
      catalog.overdue(noon).map(&.cve_id).should_not contain("CVE-2021-44228")
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

    it "emits cwes as [] for entries with explicit empty array in source" do
      # Live KEV feed always emits `"cwes": []` for entries with no CWEs.
      # Confirmed against the 2026-05-15 feed: 167/1592 entries take this
      # shape. The library must preserve the key (audit cycle finding).
      json = <<-JSON
        {
          "catalogVersion": "1.0",
          "dateReleased": "2024-01-01T00:00:00.000Z",
          "count": 1,
          "vulnerabilities": [
            {
              "cveID": "CVE-2020-0001",
              "vendorProject": "ACME",
              "product": "Widget",
              "vulnerabilityName": "Foo",
              "dateAdded": "2020-01-01",
              "shortDescription": "x",
              "requiredAction": "x",
              "dueDate": "2020-01-15",
              "cwes": []
            }
          ]
        }
        JSON

      emitted = JSON.parse(KEV::Catalog.parse(json).to_json)
      entry = emitted["vulnerabilities"].as_a.first.as_h
      entry["cwes"]?.should_not be_nil
      entry["cwes"].as_a.should be_empty
    end

    it "tolerates a feed with no top-level title and no cwes anywhere" do
      json = <<-JSON
        {
          "catalogVersion": "1.0",
          "dateReleased": "2024-01-01T00:00:00.000Z",
          "count": 0,
          "vulnerabilities": []
        }
        JSON
      KEV::Catalog.parse(json).should be_a(KEV::Catalog)
    end
  end

  describe "CVE index lifecycle" do
    it "invalidates the memo when the vulnerabilities array grows" do
      catalog = SpecFixtures.sample_catalog
      catalog.find("CVE-2021-44228").should_not be_nil # primes memo

      synthetic = KEV::Vulnerability.new(
        cve_id: "CVE-9999-1", vendor_project: "X", product: "X",
        vulnerability_name: "x", date_added: Time.utc(2030, 1, 1),
        short_description: "x", required_action: "x",
        due_date: Time.utc(2030, 1, 15),
      )
      catalog.vulnerabilities << synthetic
      catalog.find("CVE-9999-1").should eq(synthetic)
    end

    it "#reindex! recovers from in-place edits that don't change array length" do
      catalog = SpecFixtures.sample_catalog
      catalog.find("CVE-2021-44228").should_not be_nil # primes memo

      replacement = KEV::Vulnerability.new(
        cve_id: "CVE-9999-REPLACED", vendor_project: "X", product: "X",
        vulnerability_name: "x", date_added: Time.utc(2030, 1, 1),
        short_description: "x", required_action: "x",
        due_date: Time.utc(2030, 1, 15),
      )
      catalog.vulnerabilities[0] = replacement
      # Size didn't change → memo doesn't auto-invalidate.
      catalog.find("CVE-9999-REPLACED").should be_nil
      catalog.reindex!
      catalog.find("CVE-9999-REPLACED").should eq(replacement)
    end
  end

  describe "convenience helpers" do
    catalog = SpecFixtures.sample_catalog

    it "#search matches across cve_id / name / description / vendor / product" do
      catalog.search("log4j").map(&.cve_id).should eq(["CVE-2021-44228"])
      catalog.search("outlook").map(&.cve_id).should eq(["CVE-2023-23397"])
      catalog.search("heartbeat").map(&.cve_id).should eq(["CVE-2014-0160"])
      # case-insensitive
      catalog.search("APACHE").map(&.cve_id).should eq(["CVE-2021-44228"])
    end

    it "#group_by_year buckets entries by their CVE year" do
      grouped = catalog.group_by_year
      grouped[2021].map(&.cve_id).should eq(["CVE-2021-44228"])
      grouped[2014].map(&.cve_id).should eq(["CVE-2014-0160"])
    end

    it "#group_by_vendor uses verbatim vendor strings" do
      grouped = catalog.group_by_vendor
      grouped["Apache"].size.should eq(1)
      grouped["Microsoft"].size.should eq(1)
    end

    it "#group_by_cwe places multi-CWE vulns under each code" do
      grouped = catalog.group_by_cwe
      grouped["CWE-20"].map(&.cve_id).should eq(["CVE-2021-44228"])
      grouped["CWE-917"].map(&.cve_id).should eq(["CVE-2021-44228"])
      grouped["CWE-294"].map(&.cve_id).should eq(["CVE-2023-23397"])
    end

    it "#group_by_ransomware splits Known from Unknown" do
      grouped = catalog.group_by_ransomware
      grouped[KEV::RansomwareUse::Known].map(&.cve_id).sort!.should eq(["CVE-2021-44228", "CVE-2023-23397"])
      grouped[KEV::RansomwareUse::Unknown].map(&.cve_id).sort!.should eq(["CVE-2014-0160", "CVE-2024-21887"])
    end

    it "#latest returns the N newest entries, newest first" do
      latest = catalog.latest(2)
      latest.size.should eq(2)
      latest.first.cve_id.should eq("CVE-2024-21887")
      latest.first.date_added.should be >= latest.last.date_added
    end

    it "#oldest returns the N earliest entries, oldest first" do
      oldest = catalog.oldest(2)
      oldest.first.cve_id.should eq("CVE-2021-44228")
      oldest.first.date_added.should be <= oldest.last.date_added
    end

    it "#latest / #oldest raise on negative N" do
      expect_raises(ArgumentError) { catalog.latest(-1) }
      expect_raises(ArgumentError) { catalog.oldest(-1) }
    end
  end

  describe "CSV export" do
    it "round-trips through parse_csv" do
      original = SpecFixtures.sample_catalog
      reparsed = KEV::Catalog.parse_csv(original.to_csv)
      reparsed.size.should eq(original.size)
      original.vulnerabilities.zip(reparsed.vulnerabilities).each do |a, b|
        a.cve_id.should eq(b.cve_id)
        a.cwes.should eq(b.cwes)
        a.known_ransomware?.should eq(b.known_ransomware?)
      end
    end

    it "writes the canonical header row in CISA order" do
      catalog = SpecFixtures.sample_catalog
      header = catalog.to_csv.lines.first
      header.should eq("cveID,vendorProject,product,vulnerabilityName,dateAdded,shortDescription,requiredAction,dueDate,knownRansomwareCampaignUse,notes,cwes")
    end
  end

  describe "#validate! / #valid?" do
    it "validates a well-formed catalog from the fixture" do
      c = SpecFixtures.sample_catalog
      c.valid?.should be_true
      c.validate!.should be_nil
    end

    it "fails when any contained vulnerability fails its schema check" do
      c = SpecFixtures.sample_catalog
      c.vulnerabilities << KEV::Vulnerability.new(
        cve_id: "bogus",
        vendor_project: "x", product: "x", vulnerability_name: "x",
        date_added: Time.utc(2020, 1, 1), short_description: "x",
        required_action: "x", due_date: Time.utc(2020, 1, 15),
      )
      c.valid?.should be_false
      expect_raises(KEV::InvalidValueError, /cveID/) { c.validate! }
    end
  end

  describe ".parse_csv" do
    it "parses a minimal CSV with header + one row" do
      csv = <<-CSV
        cveID,vendorProject,product,vulnerabilityName,dateAdded,shortDescription,requiredAction,dueDate,knownRansomwareCampaignUse,notes,cwes
        CVE-2021-44228,Apache,Log4j2,Apache Log4j2 RCE,2021-12-10,JNDI vuln,Apply updates,2021-12-24,Known,https://logging.apache.org,"CWE-20, CWE-917"
        CVE-2014-0160,OpenSSL,OpenSSL,Heartbleed,2022-05-04,Heartbleed,Apply updates,2022-05-25,Unknown,,
        CSV
      catalog = KEV::Catalog.parse_csv(csv, catalog_version: "test", date_released: Time.utc(2024, 1, 1))
      catalog.size.should eq(2)
      log4j = catalog["CVE-2021-44228"]
      log4j.vendor_project.should eq("Apache")
      log4j.cwes.should eq(["CWE-20", "CWE-917"])
      log4j.known_ransomware?.should be_true

      heartbleed = catalog["CVE-2014-0160"]
      heartbleed.notes.should be_nil
      heartbleed.cwes.should be_empty
      heartbleed.known_ransomware_campaign_use.should eq(KEV::RansomwareUse::Unknown)
    end

    it "raises when a required column is missing from the header" do
      csv = "cveID,vendorProject\nCVE-2021-44228,Apache\n"
      expect_raises(KEV::ParseError, /missing required column/) do
        KEV::Catalog.parse_csv(csv)
      end
    end

    it "validates cveID and cwes patterns at parse time" do
      bad_cve = <<-CSV
        cveID,vendorProject,product,vulnerabilityName,dateAdded,shortDescription,requiredAction,dueDate,knownRansomwareCampaignUse,notes,cwes
        NOT-A-CVE,x,x,x,2024-01-01,x,x,2024-01-15,,,
        CSV
      expect_raises(KEV::InvalidValueError, /cveID/) { KEV::Catalog.parse_csv(bad_cve) }

      bad_cwe = <<-CSV
        cveID,vendorProject,product,vulnerabilityName,dateAdded,shortDescription,requiredAction,dueDate,knownRansomwareCampaignUse,notes,cwes
        CVE-2024-0001,x,x,x,2024-01-01,x,x,2024-01-15,,,"CWE-79, oops"
        CSV
      expect_raises(KEV::InvalidValueError, /cwes/) { KEV::Catalog.parse_csv(bad_cwe) }
    end

    it ".parse_csv? returns nil on malformed input" do
      KEV::Catalog.parse_csv?("not csv at all\n,,,").should be_nil
    end
  end

  describe "defensive bounds" do
    it "raises KEV::ParseError when count is outside Int32 range" do
      huge = %({"catalogVersion":"x","dateReleased":"2024-01-01T00:00:00Z","count":99999999999999,"vulnerabilities":[]})
      expect_raises(KEV::ParseError, /Int32/) do
        KEV::Catalog.parse(huge)
      end
    end

    it "Catalog.parse? returns nil instead of leaking OverflowError" do
      huge = %({"catalogVersion":"x","dateReleased":"2024-01-01T00:00:00Z","count":99999999999999,"vulnerabilities":[]})
      KEV::Catalog.parse?(huge).should be_nil
    end
  end
end
