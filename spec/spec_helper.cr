require "spec"
require "../src/kev"

module SpecFixtures
  extend self

  FIXTURE_DIR = Path[__DIR__] / "fixtures"

  def sample_catalog_json : String
    File.read(FIXTURE_DIR / "sample_catalog.json")
  end

  def sample_catalog : KEV::Catalog
    KEV::Catalog.parse(sample_catalog_json)
  end
end
