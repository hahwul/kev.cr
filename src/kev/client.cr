require "http/client"
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
    # CISA's published feed URL. CISA also publishes a CSV; this library
    # consumes the JSON form, which is the schema-bound source of truth.
    DEFAULT_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

    # `User-Agent` sent on every request. Identifies the client so CISA can
    # contact maintainers if the feed format changes — and so this library
    # is not silently lumped in with anonymous scrapers.
    DEFAULT_USER_AGENT = "kev.cr/#{VERSION} (+https://github.com/hahwul/kev.cr)"

    getter url : String
    getter user_agent : String
    getter connect_timeout : Time::Span
    getter read_timeout : Time::Span

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
    )
    end

    # Fetch and parse the catalog. Raises `FetchError` on any transport or
    # HTTP-level failure and `ParseError` on a malformed body.
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
      return nil if response.status_code == 304
      capture_validators(response)
      Catalog.parse(response.body)
    end

    # Convenience: one-shot fetch using a fresh client.
    def self.fetch(url : String = DEFAULT_URL) : Catalog
      new(url).fetch
    end

    private def get(extra_headers : HTTP::Headers, accept_304 : Bool = false) : HTTP::Client::Response
      uri = URI.parse(url)
      raise FetchError.new("KEV feed URL must be http(s): #{url}") unless {"http", "https"}.includes?(uri.scheme)

      headers = HTTP::Headers{
        "Accept"     => "application/json",
        "User-Agent" => user_agent,
      }
      extra_headers.each { |k, v| headers[k] = v.join(",") }

      client = HTTP::Client.new(uri)
      client.connect_timeout = connect_timeout
      client.read_timeout = read_timeout

      begin
        response = client.get(uri.request_target, headers: headers)
      rescue ex : IO::Error | Socket::Error
        raise FetchError.new("KEV feed request failed: #{ex.message}")
      ensure
        client.close
      end

      return response if accept_304 && response.status_code == 304
      unless response.success?
        raise FetchError.new("KEV feed returned HTTP #{response.status_code} #{response.status_message}")
      end
      response
    end

    private def capture_validators(response : HTTP::Client::Response) : Nil
      @last_etag = response.headers["ETag"]?
      @last_modified = response.headers["Last-Modified"]?
    end
  end
end
