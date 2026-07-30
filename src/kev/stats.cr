require "./vulnerability"

module KEV
  # Aggregate summary of a `Catalog`. Produced by `Catalog#stats`.
  #
  # The struct is a snapshot — it captures the catalog state at the
  # moment of computation and does not track later mutations of the
  # underlying array. Most fields are plain counts or `Hash` rollups so
  # they print nicely and serialize without extra glue.
  #
  # ```
  # s = catalog.stats(top: 5)
  # s.total       # => 1592
  # s.ransomware  # => 321
  # s.top_vendors # => [{"Microsoft", 320}, {"Cisco", 78}, ...]
  # s.by_year     # => {2024 => 187, 2025 => 142, ...}
  # ```
  struct Stats
    # Total number of entries.
    getter total : Int32

    # How many entries carry `knownRansomwareCampaignUse: "Known"`.
    getter ransomware : Int32

    # How many entries' remediation deadlines have passed (relative to
    # the `now` argument passed to `Catalog#stats`).
    getter overdue : Int32

    # `cve_year` => count of entries with that year segment.
    getter by_year : Hash(Int32, Int32)

    # Top vendors by entry count, descending. The length is bounded by
    # the `top` argument to `Catalog#stats` (default 5).
    getter top_vendors : Array(Tuple(String, Int32))

    # Top products by entry count, descending. Bounded by `top`.
    getter top_products : Array(Tuple(String, Int32))

    # Top CWEs by occurrence, descending. A vulnerability with N CWEs
    # contributes to N CWE buckets. Bounded by `top`.
    getter top_cwes : Array(Tuple(String, Int32))

    # The `Time` baseline used for the `overdue` calculation.
    getter as_of : Time

    def initialize(
      @total : Int32,
      @ransomware : Int32,
      @overdue : Int32,
      @by_year : Hash(Int32, Int32),
      @top_vendors : Array(Tuple(String, Int32)),
      @top_products : Array(Tuple(String, Int32)),
      @top_cwes : Array(Tuple(String, Int32)),
      @as_of : Time,
    )
    end

    # Build a `Stats` from a `Catalog` in one pass. Callers usually go
    # through `Catalog#stats(top:, now:)` rather than calling this
    # directly.
    def self.compute(catalog : Catalog, top : Int32 = 5, now : Time = Time.utc) : Stats
      raise ArgumentError.new("stats top must be >= 0") if top < 0

      ransomware = 0
      overdue = 0
      by_year = Hash(Int32, Int32).new(0)
      vendor_counts = Hash(String, Int32).new(0)
      product_counts = Hash(String, Int32).new(0)
      cwe_counts = Hash(String, Int32).new(0)

      catalog.each do |v|
        ransomware += 1 if v.known_ransomware?
        overdue += 1 if v.overdue?(now)
        by_year[v.cve_year] += 1
        vendor_counts[v.vendor_project] += 1
        product_counts[v.product] += 1
        v.each_cwe { |c| cwe_counts[c] += 1 }
      end

      new(
        total: catalog.size,
        ransomware: ransomware,
        overdue: overdue,
        by_year: by_year,
        top_vendors: top_n(vendor_counts, top),
        top_products: top_n(product_counts, top),
        top_cwes: top_n(cwe_counts, top),
        as_of: now,
      )
    end

    # Sort a count hash descending by count, then ascending by key so
    # ties are stable, then take the first `n`.
    private def self.top_n(counts : Hash(String, Int32), n : Int32) : Array(Tuple(String, Int32))
      counts.to_a.sort_by! { |k, c| {-c, k} }.first(n)
    end

    def inspect(io : IO) : Nil
      io << "#<KEV::Stats total=" << total
      io << " ransomware=" << ransomware
      io << " overdue=" << overdue
      io << " years=" << by_year.size
      io << " top_vendor="
      if first = top_vendors.first?
        io << first[0] << "(" << first[1] << ")"
      else
        io << "—"
      end
      io << ">"
    end
  end
end
