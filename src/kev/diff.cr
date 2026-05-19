require "./vulnerability"

module KEV
  # Snapshot-vs-snapshot delta for two `Catalog` instances.
  #
  # Produced by `Catalog#diff(other)`. Useful for KEV monitoring jobs
  # that want a single "what changed since the last poll" call.
  #
  # ```
  # delta = old_catalog.diff(new_catalog)
  # delta.added.each { |v| notify("new KEV", v) }
  # delta.removed.each { |v| audit_log("KEV removed", v) }
  # delta.changed.each { |before, after| diff_log(before, after) }
  # ```
  #
  # Membership is keyed by `cve_id`. `changed` contains pairs where the
  # CVE appears in both snapshots but at least one *other* field differs.
  # Use `same_cve?` semantics when reasoning about identity.
  struct Diff
    # CVEs in `after` that were absent from `before`.
    getter added : Array(Vulnerability)

    # CVEs in `before` that have been removed in `after`. CISA does
    # occasionally retract entries; this captures those.
    getter removed : Array(Vulnerability)

    # CVEs present in both snapshots whose fields differ. Tuples are
    # `(before, after)` so callers can render side-by-side diffs.
    getter changed : Array(Tuple(Vulnerability, Vulnerability))

    # CVEs present in both snapshots and field-for-field identical.
    # Not usually rendered, but exposed for completeness so callers can
    # assert "nothing changed" without re-computing.
    getter unchanged : Array(Vulnerability)

    def initialize(
      @added : Array(Vulnerability),
      @removed : Array(Vulnerability),
      @changed : Array(Tuple(Vulnerability, Vulnerability)),
      @unchanged : Array(Vulnerability),
    )
    end

    # `true` when nothing was added, removed, or modified.
    def empty? : Bool
      added.empty? && removed.empty? && changed.empty?
    end

    # Total count of CVEs that differ between the two snapshots
    # (added + removed + changed).
    def size : Int32
      added.size + removed.size + changed.size
    end

    def inspect(io : IO) : Nil
      io << "#<KEV::Diff added=" << added.size
      io << " removed=" << removed.size
      io << " changed=" << changed.size
      io << " unchanged=" << unchanged.size
      io << ">"
    end
  end
end
