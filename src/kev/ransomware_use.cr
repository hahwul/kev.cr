require "./error"

module KEV
  # CISA's `knownRansomwareCampaignUse` field. The KEV catalog uses exactly
  # two string values: `"Known"` (confirmed leveraged in a ransomware
  # campaign) and `"Unknown"` (CISA lacks confirmation — *not* a denial).
  enum RansomwareUse
    Known
    Unknown

    def self.parse?(raw : String) : RansomwareUse?
      case raw.strip
      when "Known"   then Known
      when "Unknown" then Unknown
      end
    end

    def self.parse(raw : String) : RansomwareUse
      parse?(raw) || raise InvalidValueError.new("knownRansomwareCampaignUse", raw)
    end

    # Canonical CISA spelling (capitalised). Used for JSON serialization so
    # the output round-trips against the official feed.
    def to_s : String
      case self
      in Known   then "Known"
      in Unknown then "Unknown"
      end
    end

    def to_s(io : IO) : Nil
      io << to_s
    end
  end
end
