require "./spec_helper"

describe KEV do
  it "exposes a version constant" do
    KEV::VERSION.should be_a(String)
  end

  describe ".parse" do
    it "parses a catalog from a JSON string" do
      catalog = KEV.parse(SpecFixtures.sample_catalog_json)
      catalog.should be_a(KEV::Catalog)
      catalog.size.should eq(4)
    end

    it "parses from an IO" do
      io = IO::Memory.new(SpecFixtures.sample_catalog_json)
      catalog = KEV.parse(io)
      catalog.size.should eq(4)
    end

    it "raises ParseError on malformed JSON shape" do
      expect_raises(KEV::ParseError) do
        KEV.parse(%({"catalogVersion": "x"}))
      end
    end
  end

  describe ".parse?" do
    it "returns the catalog on success" do
      KEV.parse?(SpecFixtures.sample_catalog_json).should_not be_nil
    end

    it "returns nil on malformed JSON" do
      KEV.parse?("not json").should be_nil
    end

    it "returns nil on schema violations" do
      KEV.parse?(%({"catalogVersion": "x"})).should be_nil
    end
  end
end
