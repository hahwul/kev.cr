require "json"
require "./error"
require "./vulnerability"

module KEV
  # The full CISA Known Exploited Vulnerabilities catalog.
  #
  # A Catalog is `Enumerable` and `Indexable` over its vulnerabilities, so
  # the usual collection methods work directly:
  #
  # ```
  # catalog = KEV::Catalog.parse(File.read("kev.json"))
  # catalog.size                             # => 1592
  # catalog.first.cve_id                     # => "CVE-2021-..."
  # catalog.select(&.known_ransomware?).size # => 300+
  # ```
  #
  # `Catalog#query` returns a chainable `Query` for more elaborate filters.
  # Direct accessors are provided for the most common lookups (`by_vendor`,
  # `by_cwe`, `find`, `[]`).
  class Catalog
    include Enumerable(Vulnerability)
    include Indexable(Vulnerability)

    # Catalog metadata title. CISA hardcodes this to `"CISA Catalog of
    # Known Exploited Vulnerabilities"` in the current feed, but it is not
    # part of the schema's required fields, so we keep it nilable.
    getter title : String?

    # Calendar-style version string (e.g. `"2026.05.15"`).
    getter catalog_version : String

    # The catalog publish timestamp as a `Time` (UTC).
    getter date_released : Time

    # CISA-reported entry count — *not* necessarily equal to
    # `vulnerabilities.size`, since the value is what CISA reported at
    # publish time. Use `size` (or `vulnerabilities.size`) for the
    # in-memory count.
    getter count : Int32

    # The decoded vulnerability entries, in source-feed order.
    getter vulnerabilities : Array(Vulnerability)

    @by_cve : Hash(String, Vulnerability)?

    def initialize(
      @catalog_version : String,
      @date_released : Time,
      @count : Int32,
      @vulnerabilities : Array(Vulnerability),
      @title : String? = nil,
    )
    end

    # Parse a Catalog from a raw JSON string or IO.
    def self.parse(input : String | IO) : Catalog
      from_json_any(::JSON.parse(input))
    end

    # Alias for `parse`, mirroring the cvss.cr API surface.
    def self.from_json(input : String | IO) : Catalog
      parse(input)
    end

    # Non-raising parse — returns nil on malformed input.
    def self.parse?(input : String | IO) : Catalog?
      parse(input)
    rescue Error | ::JSON::ParseException
      nil
    end

    def self.from_json_any(any : ::JSON::Any) : Catalog
      obj = any.as_h? || raise ParseError.new("catalog root is not a JSON object")

      catalog_version = require_string(obj, "catalogVersion")
      date_released_raw = require_string(obj, "dateReleased")
      count = require_int(obj, "count")

      vulns_raw = obj["vulnerabilities"]? || raise MissingFieldError.new("vulnerabilities", "catalog")
      arr = vulns_raw.as_a? || raise ParseError.new("'vulnerabilities' is not an array")

      vulnerabilities = arr.map { |item| Vulnerability.from_json_any(item) }

      new(
        catalog_version: catalog_version,
        date_released: parse_datetime(date_released_raw),
        count: count,
        vulnerabilities: vulnerabilities,
        title: optional_string(obj, "title"),
      )
    end

    # Iteration / Indexable contract
    def each(& : Vulnerability ->) : Nil
      vulnerabilities.each { |v| yield v }
    end

    def size : Int32
      vulnerabilities.size
    end

    def unsafe_fetch(index : Int) : Vulnerability
      vulnerabilities.unsafe_fetch(index)
    end

    # Look up by CVE id. O(1) after the first call (the CVE → entry index
    # is memoised on first lookup).
    #
    # The memo is built lazily and not synchronised — if you share a
    # `Catalog` across preemptive threads, call `find` (or any other
    # by-CVE lookup) once on the owning thread before publishing the
    # reference, or guard the catalog with your own mutex.
    #
    # The memo auto-invalidates when the underlying `vulnerabilities`
    # array grows or shrinks (push/pop/concat). If you replace an entry
    # *in place* with a different `cve_id`, the size doesn't change and
    # the index won't notice — call `reindex!` explicitly in that case.
    def find(cve_id : String) : Vulnerability?
      cve_index[cve_id]?
    end

    # Drop the memoised CVE → entry index. The next `find` / `[]` call
    # rebuilds it from the current `vulnerabilities` array. Use this
    # after in-place edits that change a `cve_id` without changing the
    # array's length.
    def reindex! : Nil
      @by_cve = nil
    end

    # `find` that raises `KeyError` on miss — mirrors `Hash#[]`.
    def [](cve_id : String) : Vulnerability
      cve_index[cve_id]
    end

    # `find` that returns nil on miss — mirrors `Hash#[]?`.
    def []?(cve_id : String) : Vulnerability?
      cve_index[cve_id]?
    end

    # All entries for a given vendor (exact, case-insensitive match).
    def by_vendor(name : String) : Array(Vulnerability)
      n = name.downcase
      vulnerabilities.select { |v| v.vendor_project.downcase == n }
    end

    # All entries for a given product (exact, case-insensitive match).
    def by_product(name : String) : Array(Vulnerability)
      n = name.downcase
      vulnerabilities.select { |v| v.product.downcase == n }
    end

    # All entries tagged with the given CWE (e.g. `"CWE-79"` or `"79"`).
    def by_cwe(code : String) : Array(Vulnerability)
      vulnerabilities.select { |v| v.has_cwe?(code) }
    end

    # All entries flagged as known ransomware-campaign exploits.
    def ransomware : Array(Vulnerability)
      vulnerabilities.select(&.known_ransomware?)
    end

    # Entries added on or after the given date.
    def added_on_or_after(date : Time) : Array(Vulnerability)
      vulnerabilities.select { |v| v.date_added >= date }
    end

    # Entries added on or before the given date.
    def added_on_or_before(date : Time) : Array(Vulnerability)
      vulnerabilities.select { |v| v.date_added <= date }
    end

    # Entries whose remediation due date has already passed (relative to
    # `now`, default `Time.utc`).
    def overdue(now : Time = Time.utc) : Array(Vulnerability)
      vulnerabilities.select(&.overdue?(now))
    end

    # Entries due within the given time span from `now` and not yet overdue.
    def due_within(span : Time::Span, now : Time = Time.utc) : Array(Vulnerability)
      cutoff = now + span
      vulnerabilities.select { |v| v.due_date >= now && v.due_date <= cutoff }
    end

    # All distinct vendor names in the catalog, sorted.
    def vendors : Array(String)
      vulnerabilities.map(&.vendor_project).uniq!.sort!
    end

    # All distinct products, sorted.
    def products : Array(String)
      vulnerabilities.map(&.product).uniq!.sort!
    end

    # All distinct CWE codes referenced in the catalog, sorted.
    def cwes : Array(String)
      seen = Set(String).new
      vulnerabilities.each { |v| v.cwes.each { |c| seen << c } }
      seen.to_a.sort!
    end

    # Start a chainable `Query` over this catalog's entries.
    def query : Query
      Query.new(vulnerabilities)
    end

    # JSON serialization in the exact shape of the CISA feed. Round-trips
    # cleanly via `Catalog.parse(catalog.to_json)`.
    def to_json(json : ::JSON::Builder) : Nil
      json.object do
        if t = title
          json.field "title", t
        end
        json.field "catalogVersion", catalog_version
        json.field "dateReleased", format_datetime(date_released)
        json.field "count", count
        json.field "vulnerabilities" do
          json.array do
            vulnerabilities.each(&.to_json(json))
          end
        end
      end
    end

    def inspect(io : IO) : Nil
      io << "#<KEV::Catalog version=" << catalog_version
      io << " released=" << format_datetime(date_released)
      io << " entries=" << vulnerabilities.size
      io << " reported_count=" << count
      io << ">"
    end

    private def cve_index : Hash(String, Vulnerability)
      cached = @by_cve
      # Cheap staleness check: if a caller added or removed entries since
      # the memo was built, the cached hash and the live array no longer
      # agree on size. Drop the memo and rebuild.
      return cached if cached && cached.size == vulnerabilities.size
      @by_cve = vulnerabilities.each_with_object({} of String => Vulnerability) do |v, h|
        h[v.cve_id] = v
      end
    end

    # CISA emits ISO-8601 with `Z` suffix and a fractional-seconds field
    # whose precision drifts (the feed has been seen with 3 *and* 4 digits,
    # e.g. `".608Z"` and `".6086Z"`). `Time.parse_iso8601` only accepts up
    # to millisecond precision, so trim any longer fraction up front rather
    # than parse-then-retry on exception.
    private def self.parse_datetime(raw : String) : Time
      normalised = raw.sub(/\.(\d{3})\d+(Z|[+\-]\d)/, ".\\1\\2")
      Time.parse_iso8601(normalised)
    rescue ex : Time::Format::Error
      raise ParseError.new("malformed dateReleased '#{raw}': #{ex.message}")
    end

    private def format_datetime(t : Time) : String
      t.to_utc.to_rfc3339(fraction_digits: 3)
    end

    private def self.require_string(obj, key : String) : String
      raw = obj[key]? || raise MissingFieldError.new(key, "catalog")
      raw.as_s? || raise ParseError.new("catalog field '#{key}' is not a string")
    end

    private def self.optional_string(obj, key : String) : String?
      raw = obj[key]?
      return nil if raw.nil? || raw.raw.nil?
      raw.as_s? || raise ParseError.new("catalog field '#{key}' is not a string")
    end

    private def self.require_int(obj, key : String) : Int32
      raw = obj[key]? || raise MissingFieldError.new(key, "catalog")
      i = raw.as_i64? || raise ParseError.new("catalog field '#{key}' is not an integer")
      if i < Int32::MIN || i > Int32::MAX
        raise ParseError.new("catalog field '#{key}' value #{i} is out of Int32 range")
      end
      i.to_i32
    end
  end
end
