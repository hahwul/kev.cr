require "http/client"
require "openssl"
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
    # answer 200 directly; we cap follow-throughs at 3 so a misconfigured
    # mirror cannot loop forever.
    DEFAULT_MAX_REDIRECTS = 0

    getter url : String
    getter user_agent : String
    getter connect_timeout : Time::Span
    getter read_timeout : Time::Span

    # Maximum number of HTTP redirects to follow. `0` (the default) keeps
    # the original strict behavior — a `3xx` response raises `FetchError`.
    # Set this when pointing the client at a mirror or proxy that issues a
    # canonical redirect.
    getter max_redirects : Int32

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
    )
      raise FetchError.new("max_redirects must be >= 0 (got #{@max_redirects})") if @max_redirects < 0
    end

    # Fetch and parse the catalog. Raises `FetchError` on any transport
    # or HTTP-level failure (including a non-2xx response — see below)
    # and `KEV::ParseError` on a schema-malformed body.
    # `JSON::ParseException` propagates unchanged for raw JSON syntax
    # errors, matching the cvss.cr precedent.
    #
    # NOTE: redirects are *not* followed. CISA's canonical feed URL has
    # been stable, but if you point the client at a URL that responds
    # with `3xx` you will get a `FetchError`, not the redirected body.
    # Resolve the final URL yourself and pass it to `initialize`.
    def fetch : Catalog
      response = get(extra_headers: HTTP::Headers.new)
      capture_validators(response)
      Catalog.parse(response.body)
    end

    # Conditional fetch using `If-None-Match` / `If-Modified-Since`.
    # Returns the new catalog on a 200 response and `nil` on a 304.
    #
    # First call (no validators recorded yet) behaves like `fetch`.
    def fetch_if_modified : Catalog?
      headers = HTTP::Headers.new
      headers["If-None-Match"] = last_etag.as(String) if last_etag
      headers["If-Modified-Since"] = last_modified.as(String) if last_modified

      response = get(extra_headers: headers, accept_304: true)
      return if response.status_code == 304
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

      client = HTTP::Client.new(uri)
      client.connect_timeout = connect_timeout
      client.read_timeout = read_timeout

      begin
        response = client.get(uri.request_target, headers: headers)
      rescue ex : IO::Error | Socket::Error | OpenSSL::SSL::Error
        raise FetchError.new("KEV feed request to #{target_url} failed: #{ex.message}")
      ensure
        client.close
      end

      return response if accept_304 && response.status_code == 304

      if response.status.redirection? && redirects_left > 0
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

    private def capture_validators(response : HTTP::Client::Response) : Nil
      @last_etag = response.headers["ETag"]?
      @last_modified = response.headers["Last-Modified"]?
    end
  end
end
