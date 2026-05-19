require "./spec_helper"

describe KEV::RansomwareUse do
  it "parses the two canonical values" do
    KEV::RansomwareUse.parse("Known").should eq(KEV::RansomwareUse::Known)
    KEV::RansomwareUse.parse("Unknown").should eq(KEV::RansomwareUse::Unknown)
  end

  it "raises InvalidValueError on an unknown string" do
    expect_raises(KEV::InvalidValueError) do
      KEV::RansomwareUse.parse("maybe")
    end
  end

  it "parse? returns nil on unknown input" do
    KEV::RansomwareUse.parse?("maybe").should be_nil
  end

  it "round-trips via to_s" do
    KEV::RansomwareUse::Known.to_s.should eq("Known")
    KEV::RansomwareUse::Unknown.to_s.should eq("Unknown")
  end
end
