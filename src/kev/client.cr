require "http/client"
require "openssl"
require "socket"
require "uri"
require "./error"
require "./catalog"
require "./version"

module KEV
  # HTTP client for the CISA KEV feed.
  #
  # The default endpoint is the canonical JSON feed:
  # `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`
  #
  # ```
  # catalog = KEV::Client.fetch
  # puts catalog.size
  # ```
  #
  # For repeated polling (e.g. a CI job), prefer a long-lived instance and
  # use `fetch_if_modified` so unchanged feeds short-circuit without a full
  # download:
  #
  # ```
  # client = KEV::Client.new
  # if catalog = client.fetch_if_modified
  #   process(catalog)
  # end
  # ```
  class Client
    # CISA's published JSON feed URL — the schema-bound source of truth.
    DEFAULT_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

    # CISA's CSV mirror of the same catalog. Same per-row data, no
    # catalog-level metadata (`catalogVersion`, `dateReleased`, `count`).
    DEFAULT_CSV_URL = "https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv"

    # `User-Agent` sent on every request. Identifies the client so CISA can
    # contact maintainers if the feed format changes — and so this library
    # is not silently lumped in with anonymous scrapers.
    DEFAULT_USER_AGENT = "kev.cr/#{VERSION} (+https://github.com/hahwul/kev.cr)"

    # Default ceiling for redirect chasing in `fetch`. Most KEV requests
    # answer 200 directly, so the default is `0`: no redirects are followed
    # and a `3xx` response raises `FetchError`. Raise this (via the
    # `max_redirects` argument) when pointing the client at a mirror or proxy
    # that issues a canonical redirect.
    DEFAULT_MAX_REDIRECTS = 0

    # Default number of *retries* (in addition to the initial attempt) for
    # transient failures. A single CISA hiccup — a 503 behind their CDN, a
    # reset connection, a read timeout — should not surface to the caller, so
    # the request is retried with exponential backoff before giving up.
    DEFAULT_MAX_RETRIES = 3

    # Base delay for the first backoff sleep. Subsequent retries double this
    # (capped at `MAX_BACKOFF`) and add jitter.
    DEFAULT_RETRY_BACKOFF = 500.milliseconds

    # Upper bound for a single exponential-backoff sleep. Without a cap the
    # doubling delay grows unbounded and can strand a fiber for minutes; 30s
    # is plenty to let a transient outage clear.
    MAX_BACKOFF = 30.seconds

    # HTTP status codes worth retrying: rate-limiting plus the transient
    # gateway/server-side 5xx family. A 4xx (404, 403, …) is the caller's
    # problem and is never retried.
    RETRIABLE_STATUS = {429, 500, 502, 503, 504}

    # Status codes that carry a `Location` the client is expected to
    # follow — the same set `HTTP::Client` itself chases.
    #
    # Deliberately *not* the whole 3xx range: `HTTP::Status#redirection?`
    # answers `true` for 304 Not Modified (and for 305/306), none of which
    # carry a `Location`. Testing that predicate made a plain `fetch`
    # against a caching intermediary report "redirect … missing Location
    # header" instead of the actual status.
    FOLLOWABLE_REDIRECTS = {301, 302, 303, 307, 308}

    getter url : String
    getter user_agent : String
    getter connect_timeout : Time::Span
    getter read_timeout : Time::Span

    # Maximum number of HTTP redirects to follow. `0` (the default) keeps
    # the original strict behavior — a `3xx` response raises `FetchError`.
    # Set this when pointing the client at a mirror or proxy that issues a
    # canonical redirect.
    getter max_redirects : Int32

    # Number of retries (beyond the first attempt) for transient failures.
    # `0` restores the original single-attempt behavior.
    getter max_retries : Int32

    # Base backoff delay; doubled per retry, capped at `MAX_BACKOFF`, plus
    # jitter. Injectable so tests can drive the retry path with a near-zero
    # delay and stay fast.
    getter retry_backoff : Time::Span

    # Last `ETag` observed on a successful fetch (or `nil` if the server
    # did not return one). Used by `fetch_if_modified`.
    getter last_etag : String?

    # Last `Last-Modified` header observed on a successful fetch.
    getter last_modified : String?

    def initialize(
      @url : String = DEFAULT_URL,
      @user_agent : String = DEFAULT_USER_AGENT,
      @connect_timeout : Time::Span = 10.seconds,
      @read_timeout : Time::Span = 30.seconds,
      @max_redirects : Int32 = DEFAULT_MAX_REDIRECTS,
      @max_retries : Int32 = DEFAULT_MAX_RETRIES,
      @retry_backoff : Time::Span = DEFAULT_RETRY_BACKOFF,
    )
      raise FetchError.new("max_redirects must be >= 0 (got #{@max_redirects})") if @max_redirects < 0
      raise FetchError.new("max_retries must be >= 0 (got #{@max_retries})") if @max_retries < 0
    end

    # Fetch and parse the catalog. Raises `FetchError` on any transport
    # or HTTP-level failure (including a non-2xx response — see below)
    # and `KEV::ParseError` on a schema-malformed body.
    # `JSON::ParseException` propagates unchanged for raw JSON syntax
    # errors, matching the cvss.cr precedent.
    #
    # NOTE: redirects are not followed by default (`max_redirects` is
    # `0`). CISA's canonical feed URL has been stable, so a `3xx` raises
    # `FetchError` rather than silently following to a possibly untrusted
    # host — resolve the final URL yourself and pass it to `initialize`,
    # or raise `max_redirects` if you are pointing at a mirror or proxy
    # that issues a canonical redirect.
    def fetch : Catalog
      response = get(extra_headers: HTTP::Headers.new)
      capture_validators(response)
      Catalog.parse(response.body)
    end

    # Conditional fetch using `If-None-Match` / `If-Modified-Since`.
    # Returns the new catalog on a 200 response and `nil` on a 304.
    #
    # First call (no validators recorded yet) behaves like `fetch`.
    #
    # A 304 still refreshes `last_etag` / `last_modified` when the server
    # sends updated ones, so a long-lived poller tracks validator rotation
    # instead of pinning the first pair it ever saw.
    def fetch_if_modified : Catalog?
      headers = HTTP::Headers.new
      headers["If-None-Match"] = last_etag.as(String) if last_etag
      headers["If-Modified-Since"] = last_modified.as(String) if last_modified

      response = get(extra_headers: headers, accept_304: true)
      if response.status_code == 304
        refresh_validators(response)
        return
      end
      capture_validators(response)
      Catalog.parse(response.body)
    end

    # Convenience: one-shot fetch using a fresh client.
    def self.fetch(url : String = DEFAULT_URL) : Catalog
      new(url).fetch
    end

    # Fetch the CSV form of the catalog from the configured `url`. CSV has
    # no catalog metadata, so the synthesized `catalog_version` and
    # `date_released` arguments flow through to `Catalog.parse_csv`.
    def fetch_csv(catalog_version : String = "csv", date_released : Time = Time.utc, title : String? = nil) : Catalog
      response = get(extra_headers: HTTP::Headers.new, accept: "text/csv")
      capture_validators(response)
      Catalog.parse_csv(response.body, catalog_version: catalog_version, date_released: date_released, title: title)
    end

    # One-shot CSV fetch using a fresh client pointed at the CSV mirror.
    def self.fetch_csv(url : String = DEFAULT_CSV_URL) : Catalog
      new(url).fetch_csv
    end

    private def get(extra_headers : HTTP::Headers, accept_304 : Bool = false, accept : String = "application/json") : HTTP::Client::Response
      do_get(url, extra_headers, accept_304, accept, redirects_left: max_redirects)
    end

    private def do_get(
      target_url : String,
      extra_headers : HTTP::Headers,
      accept_304 : Bool,
      accept : String,
      redirects_left : Int32,
    ) : HTTP::Client::Response
      uri = URI.parse(target_url)
      unless {"http", "https"}.includes?(uri.scheme)
        raise FetchError.new("KEV feed URL must be http(s): #{target_url}")
      end

      headers = HTTP::Headers{
        "Accept"     => accept,
        "User-Agent" => user_agent,
      }
      # Preserve multi-value headers — `HTTP::Headers#add` appends to the
      # existing array, where the previous `headers[k] = v.join(",")` would
      # have flattened multiple values into one comma-joined string.
      extra_headers.each do |k, values|
        values.each { |v| headers.add(k, v) }
      end

      response = request_with_retry(uri, target_url, headers)

      return response if accept_304 && response.status_code == 304

      if FOLLOWABLE_REDIRECTS.includes?(response.status_code)
        if redirects_left <= 0
          raise FetchError.new(
            "KEV feed at #{target_url} returned HTTP #{response.status_code} #{response.status_message} " \
            "but the redirect budget is exhausted (max_redirects=#{max_redirects}). " \
            "Resolve the final URL yourself, or construct the client with a higher max_redirects."
          )
        end
        location = response.headers["Location"]?
        raise FetchError.new("KEV feed redirect from #{target_url} missing Location header") unless location
        next_url = URI.parse(location).absolute? ? location : URI.parse(target_url).resolve(location).to_s
        return do_get(next_url, extra_headers, accept_304, accept, redirects_left - 1)
      end

      unless response.success?
        raise FetchError.new("KEV feed at #{target_url} returned HTTP #{response.status_code} #{response.status_message}")
      end
      response
    end

    # Issue a single GET, transparently retrying transient failures —
    # connection resets, timeouts, and the retriable 5xx/429 status family —
    # with capped exponential backoff and jitter. A `Retry-After` header on a
    # 429/503 overrides the computed backoff. Non-retriable statuses (2xx,
    # 3xx, and 4xx like 404) are returned to the caller untouched; redirect
    # and 304 handling stays in `do_get`.
    #
    # Each attempt opens its own `HTTP::Client`. GET is idempotent, so
    # replaying it is safe.
    private def request_with_retry(
      uri : URI,
      target_url : String,
      headers : HTTP::Headers,
    ) : HTTP::Client::Response
      attempt = 0

      loop do
        attempt += 1
        begin
          response = perform_request(uri, headers)

          if RETRIABLE_STATUS.includes?(response.status_code) && attempt <= @max_retries
            if hint = retry_after_delay(response.headers)
              sleep hint
            else
              sleep_backoff(attempt)
            end
            next
          end

          return response
        rescue ex : IO::Error | Socket::Error | OpenSSL::SSL::Error
          # IO::TimeoutError descends from IO::Error, so timeouts land here.
          if attempt > @max_retries
            raise FetchError.new("KEV feed request to #{target_url} failed: #{ex.message}")
          end
          sleep_backoff(attempt)
        end
      end
    end

    private def perform_request(uri : URI, headers : HTTP::Headers) : HTTP::Client::Response
      client = HTTP::Client.new(uri)
      begin
        client.connect_timeout = connect_timeout
        client.read_timeout = read_timeout
        client.get(uri.request_target, headers: headers)
      ensure
        client.close
      end
    end

    # Parse a `Retry-After` header. Supports both the delay-seconds form
    # (`Retry-After: 30`) and the HTTP-date form (`Retry-After: Wed, 21 Oct
    # 2015 07:28:00 GMT`). Returns `nil` if absent, unparseable, or negative.
    # Capped at one minute so a misbehaving server can't strand a fiber.
    private def retry_after_delay(headers : HTTP::Headers) : Time::Span?
      raw = headers["Retry-After"]?
      return unless raw
      raw = raw.strip
      if seconds = raw.to_i?
        return if seconds < 0
        return seconds.clamp(0, 60).seconds
      end
      begin
        target = HTTP.parse_time(raw)
        return unless target
        delta = target - Time.utc
        return if delta.negative?
        delta < 60.seconds ? delta : 60.seconds
      rescue
        nil
      end
    end

    private def sleep_backoff(attempt : Int32) : Nil
      sleep backoff_delay(attempt)
    end

    # Exponential backoff with a hard cap and decorrelated jitter:
    #   base * 2^(attempt-1), clamped to `MAX_BACKOFF`, plus up to 10% jitter.
    #
    # The cap keeps a long retry chain from sleeping for minutes, and the
    # jitter spreads concurrent retries so they don't all wake at once. This
    # is library runtime code (not a deterministic workflow), so a random
    # source is acceptable here.
    #
    # Public so the cap/jitter bounds can be unit-tested without sleeping.
    def backoff_delay(attempt : Int32) : Time::Span
      shift = attempt - 1
      # Guard against `1 << n` overflow for large attempt counts before the
      # cap is even applied.
      factor = shift >= 30 ? (1_i64 << 30) : (1_i64 << shift)
      base = @retry_backoff * factor
      capped = base < MAX_BACKOFF ? base : MAX_BACKOFF
      jitter = capped * (rand * 0.1)
      capped + jitter
    end

    # Record the validators for a 2xx response. A 200 is a *new*
    # representation, so validators are replaced wholesale — carrying a
    # stale `ETag` across a body change would make the next conditional
    # GET answer 304 for content we do not actually hold.
    private def capture_validators(response : HTTP::Client::Response) : Nil
      @last_etag = response.headers["ETag"]?
      @last_modified = response.headers["Last-Modified"]?
    end

    # Refresh the validators from a 304. Unlike a 200 this describes the
    # representation we already hold, so it *updates* rather than
    # replaces: RFC 9110 §15.4.5 requires an `ETag` when one would have
    # been sent on a 200, but a 304 need not repeat `Last-Modified`.
    # Overwrite only what the response actually carries, so a rotated
    # validator is picked up without a missing header wiping a good one.
    private def refresh_validators(response : HTTP::Client::Response) : Nil
      if etag = response.headers["ETag"]?
        @last_etag = etag
      end
      if modified = response.headers["Last-Modified"]?
        @last_modified = modified
      end
    end
  end
end
