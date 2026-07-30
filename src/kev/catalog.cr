require "csv"
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
    @by_cve_size : Int32?

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

    # Column names CISA emits in the CSV feed, in source order. The CSV
    # has no metadata (catalogVersion, dateReleased, count), so callers
    # supply those via the `catalog_version` / `date_released` arguments —
    # defaults give a stable but obviously-synthetic identity.
    CSV_HEADERS = %w[
      cveID
      vendorProject
      product
      vulnerabilityName
      dateAdded
      shortDescription
      requiredAction
      dueDate
      knownRansomwareCampaignUse
      notes
      cwes
    ]

    # CWEs inside the CSV `cwes` column come comma-and-space-separated —
    # e.g. `"CWE-22, CWE-434"`. This splitter is permissive about the gap.
    private CSV_CWE_SEPARATOR = /\s*,\s*/

    # Parse the CSV form of the catalog. CISA publishes a CSV alongside
    # the JSON feed; it carries the same per-row fields but no
    # catalog-level metadata, so the metadata defaults are synthetic.
    #
    # ```
    # catalog = KEV::Catalog.parse_csv(File.read("kev.csv"))
    # ```
    def self.parse_csv(
      input : String | IO,
      catalog_version : String = "csv",
      date_released : Time = Time.utc,
      title : String? = nil,
    ) : Catalog
      csv = ::CSV.new(input, headers: true, strip: false)
      missing = CSV_HEADERS - csv.headers
      unless missing.empty?
        raise ParseError.new("CSV is missing required column(s): #{missing.join(", ")}")
      end

      vulns = [] of Vulnerability
      while csv.next
        cve_id = csv["cveID"]
        unless Vulnerability::CVE_ID_PATTERN.matches?(cve_id)
          raise InvalidValueError.new("cveID", cve_id)
        end

        # CSV blanks: there is no in-band way to tell `""` from absent, so
        # an empty cell maps to `nil` for optional fields. The JSON path
        # still preserves `""` verbatim, which matches that feed's
        # behavior (it omits the key when absent, never emits `""`).
        ransomware_raw = blank_to_nil(csv["knownRansomwareCampaignUse"])
        cwes = csv_cwes(csv["cwes"], cve_id)

        vulns << Vulnerability.new(
          cve_id: cve_id,
          vendor_project: csv["vendorProject"],
          product: csv["product"],
          vulnerability_name: csv["vulnerabilityName"],
          date_added: parse_csv_date(csv["dateAdded"], "dateAdded", cve_id),
          short_description: csv["shortDescription"],
          required_action: csv["requiredAction"],
          due_date: parse_csv_date(csv["dueDate"], "dueDate", cve_id),
          known_ransomware_campaign_use: ransomware_raw.try { |s| RansomwareUse.parse?(s) },
          known_ransomware_campaign_use_raw: ransomware_raw,
          notes: blank_to_nil(csv["notes"]),
          cwes: cwes,
        )
      end

      new(
        catalog_version: catalog_version,
        date_released: date_released,
        count: vulns.size,
        vulnerabilities: vulns,
        title: title,
      )
    end

    # Non-raising CSV parse — returns nil on malformed input.
    def self.parse_csv?(input : String | IO, **kwargs) : Catalog?
      parse_csv(input, **kwargs)
    rescue Error | ::CSV::MalformedCSVError
      nil
    end

    private def self.blank_to_nil(value : String) : String?
      value.empty? ? nil : value
    end

    private def self.csv_cwes(raw : String, cve_id : String) : Array(String)
      return [] of String if raw.empty?
      raw.split(CSV_CWE_SEPARATOR).map do |code|
        stripped = code.strip
        unless Vulnerability::CWE_PATTERN.matches?(stripped)
          raise InvalidValueError.new("cwes[#{cve_id}]", stripped)
        end
        stripped
      end
    end

    private def self.parse_csv_date(raw : String, field : String, cve_id : String) : Time
      Time.parse_utc(raw, "%Y-%m-%d")
    rescue Time::Format::Error
      raise ParseError.new("malformed #{field} '#{raw}' for #{cve_id}")
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
      @by_cve_size = nil
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
      vulnerabilities.select { |v| v.vendor_project.compare(name, case_insensitive: true) == 0 }
    end

    # All entries for a given product (exact, case-insensitive match).
    def by_product(name : String) : Array(Vulnerability)
      vulnerabilities.select { |v| v.product.compare(name, case_insensitive: true) == 0 }
    end

    # All entries tagged with the given CWE (e.g. `"CWE-79"` or `"79"`).
    def by_cwe(code : String) : Array(Vulnerability)
      vulnerabilities.select(&.has_cwe?(code))
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
    # "Not yet overdue" uses `Vulnerability#overdue?`, so an entry whose
    # deadline is *today* still counts as upcoming.
    def due_within(span : Time::Span, now : Time = Time.utc) : Array(Vulnerability)
      cutoff = now + span
      vulnerabilities.select { |v| !v.overdue?(now) && v.due_date <= cutoff }
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

    # Case-insensitive substring match across the user-facing text fields:
    # `cve_id`, `vulnerability_name`, `short_description`, `vendor_project`,
    # and `product`. Useful for a single "give me everything mentioning
    # log4j" hit without writing a custom `where` block.
    def search(query : String) : Array(Vulnerability)
      rx = Regex.new(Regex.escape(query), Regex::Options::IGNORE_CASE)
      vulnerabilities.select do |v|
        v.cve_id.matches?(rx) ||
          v.vulnerability_name.matches?(rx) ||
          v.short_description.matches?(rx) ||
          v.vendor_project.matches?(rx) ||
          v.product.matches?(rx)
      end
    end

    # Group every entry by `cve_year`. Years map to `Array(Vulnerability)`
    # in source-feed order (no sort on the inner arrays).
    def group_by_year : Hash(Int32, Array(Vulnerability))
      vulnerabilities.group_by(&.cve_year)
    end

    # Group every entry by vendor (verbatim string, not case-folded).
    def group_by_vendor : Hash(String, Array(Vulnerability))
      vulnerabilities.group_by(&.vendor_project)
    end

    # Group every entry by *each* of its CWE codes. A vulnerability with
    # multiple CWEs appears under each one. Entries without CWEs do not
    # contribute to the result.
    def group_by_cwe : Hash(String, Array(Vulnerability))
      acc = Hash(String, Array(Vulnerability)).new { |h, k| h[k] = [] of Vulnerability }
      vulnerabilities.each do |v|
        v.cwes.each { |c| acc[c] << v }
      end
      acc
    end

    # Group by the typed `RansomwareUse` value. Entries with no
    # `knownRansomwareCampaignUse` (legacy rows) are grouped under `nil`.
    def group_by_ransomware : Hash(RansomwareUse?, Array(Vulnerability))
      vulnerabilities.group_by(&.known_ransomware_campaign_use)
    end

    # The N most recently added entries (newest first). Ties on
    # `date_added` are broken by `cve_id` for stability.
    def latest(n : Int32 = 10) : Array(Vulnerability)
      raise ArgumentError.new("latest count must be >= 0") if n < 0
      vulnerabilities
        .sort_by { |v| {-v.date_added.to_unix, v.cve_id} }
        .first(n)
    end

    # The N oldest entries (earliest first). Ties broken by `cve_id`.
    def oldest(n : Int32 = 10) : Array(Vulnerability)
      raise ArgumentError.new("oldest count must be >= 0") if n < 0
      vulnerabilities.sort.first(n)
    end

    # Start a chainable `Query` over this catalog's entries.
    def query : Query
      Query.new(vulnerabilities)
    end

    # Compare two snapshots by CVE id. Returns a `Diff` describing what
    # was added, removed, or modified relative to `self`. The receiver is
    # the "before" snapshot; `other` is the "after".
    def diff(other : Catalog) : Diff
      before = index_by_cve
      after = other.index_by_cve

      added = [] of Vulnerability
      changed = [] of Tuple(Vulnerability, Vulnerability)
      unchanged = [] of Vulnerability

      after.each do |cve, after_v|
        if before_v = before[cve]?
          if after_v == before_v
            unchanged << after_v
          else
            changed << {before_v, after_v}
          end
        else
          added << after_v
        end
      end

      removed = [] of Vulnerability
      before.each do |cve, before_v|
        removed << before_v unless after.has_key?(cve)
      end

      Diff.new(
        added: added,
        removed: removed,
        changed: changed,
        unchanged: unchanged,
      )
    end

    # Compute a `Stats` summary in a single pass. See `KEV::Stats`.
    def stats(top : Int32 = 5, now : Time = Time.utc) : Stats
      Stats.compute(self, top: top, now: now)
    end

    # Lazy CVE-id index used by `diff` / lookup helpers. Same lazy memo
    # as `cve_index`, exposed under a private name so the diff path can
    # reuse it without leaking the underlying Hash.
    protected def index_by_cve : Hash(String, Vulnerability)
      cve_index
    end

    # Run `Vulnerability#validate!` on every entry. Use after constructing
    # a `Catalog` from non-feed sources (e.g. fixtures, partial JSON,
    # programmatic edits) to confirm schema-level shape compliance.
    # Raises on the first offending entry.
    def validate! : Nil
      vulnerabilities.each(&.validate!)
    end

    # `true` when every entry passes `Vulnerability#valid?`.
    def valid? : Bool
      validate!
      true
    rescue ParseError
      false
    end

    # Emit the catalog in the canonical CSV form (matches CISA's CSV
    # mirror byte-for-byte except where input was synthesized — the CSV
    # has no metadata, so `catalog_version` / `date_released` are
    # discarded). Round-trips through `Catalog.parse_csv`.
    def to_csv : String
      ::CSV.build do |csv|
        csv.row(CSV_HEADERS)
        vulnerabilities.each(&.to_csv_row(csv))
      end
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
      return cached if cached && @by_cve_size == vulnerabilities.size
      @by_cve_size = vulnerabilities.size
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
      return if raw.nil? || raw.raw.nil?
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
