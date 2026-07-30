require "./vulnerability"

module KEV
  # Chainable filter over a list of `Vulnerability` records.
  #
  # Each filter method returns a *new* `Query` so chains compose cleanly:
  #
  # ```
  # catalog.query
  #   .vendor("Microsoft")
  #   .ransomware
  #   .added_on_or_after(Time.utc(2024, 1, 1))
  #   .to_a
  # ```
  #
  # The query is lazy in shape (each method is just a transformation), but
  # eager in execution — every step allocates an `Array` of the filtered
  # subset. For typical KEV sizes (~1.5k entries) this is fine; if you
  # need streaming you can drop down to `vulnerabilities.each` and write a
  # block-form filter yourself.
  class Query
    include Enumerable(Vulnerability)
    include Indexable(Vulnerability)

    getter vulnerabilities : Array(Vulnerability)

    def initialize(@vulnerabilities : Array(Vulnerability))
    end

    def each(& : Vulnerability ->) : Nil
      vulnerabilities.each { |v| yield v }
    end

    def size : Int32
      vulnerabilities.size
    end

    def unsafe_fetch(index : Int) : Vulnerability
      vulnerabilities.unsafe_fetch(index)
    end

    # Filter by vendor (exact, case-insensitive).
    def vendor(name : String) : Query
      chain { |v| v.vendor_project.compare(name, case_insensitive: true) == 0 }
    end

    # Filter by product (exact, case-insensitive).
    def product(name : String) : Query
      chain { |v| v.product.compare(name, case_insensitive: true) == 0 }
    end

    # Substring match against `vulnerability_name` (case-insensitive).
    def name_matches(substr : String) : Query
      rx = Regex.new(Regex.escape(substr), Regex::Options::IGNORE_CASE)
      chain(&.vulnerability_name.matches?(rx))
    end

    # Substring match against `short_description` (case-insensitive).
    def description_matches(substr : String) : Query
      rx = Regex.new(Regex.escape(substr), Regex::Options::IGNORE_CASE)
      chain(&.short_description.matches?(rx))
    end

    # Filter by CWE code (`"CWE-79"` or `"79"`).
    def cwe(code : String) : Query
      chain(&.has_cwe?(code))
    end

    # Keep only entries with `knownRansomwareCampaignUse: "Known"`.
    def ransomware : Query
      chain(&.known_ransomware?)
    end

    # Keep only entries where ransomware use is *not* known.
    def non_ransomware : Query
      chain { |v| !v.known_ransomware? }
    end

    # Keep entries with `date_added` on or after `date`.
    def added_on_or_after(date : Time) : Query
      chain { |v| v.date_added >= date }
    end

    # Keep entries with `date_added` on or before `date`.
    def added_on_or_before(date : Time) : Query
      chain { |v| v.date_added <= date }
    end

    # Keep entries with `due_date` on or after `date`.
    def due_on_or_after(date : Time) : Query
      chain { |v| v.due_date >= date }
    end

    # Keep entries with `due_date` on or before `date`.
    def due_on_or_before(date : Time) : Query
      chain { |v| v.due_date <= date }
    end

    # Keep entries whose remediation deadline has already passed.
    def overdue(now : Time = Time.utc) : Query
      chain(&.overdue?(now))
    end

    # Keep entries due within `span` from `now` and not yet overdue. An
    # entry whose deadline is *today* still counts as upcoming — see
    # `Vulnerability#overdue?`.
    def due_within(span : Time::Span, now : Time = Time.utc) : Query
      cutoff = now + span
      chain { |v| !v.overdue?(now) && v.due_date <= cutoff }
    end

    # Filter by CVE year (the YYYY portion of the CVE id).
    def year(year : Int32) : Query
      chain { |v| v.cve_year == year }
    end

    # Generic escape hatch — pass any predicate.
    def where(&block : Vulnerability -> Bool) : Query
      Query.new(vulnerabilities.select(&block))
    end

    # Sort the current set by `date_added` (ascending) into a new Query.
    def sort_by_date_added : Query
      Query.new(vulnerabilities.sort_by(&.date_added))
    end

    # Sort the current set by `due_date` (ascending) into a new Query.
    def sort_by_due_date : Query
      Query.new(vulnerabilities.sort_by(&.due_date))
    end

    # Materialise the query as a plain `Array`.
    def to_a : Array(Vulnerability)
      vulnerabilities.dup
    end

    def first? : Vulnerability?
      vulnerabilities.first?
    end

    def last? : Vulnerability?
      vulnerabilities.last?
    end

    private def chain(&block : Vulnerability -> Bool) : Query
      Query.new(vulnerabilities.select(&block))
    end
  end
end
