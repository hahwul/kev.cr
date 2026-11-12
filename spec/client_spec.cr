require "./spec_helper"
require "http/server"
require "compress/gzip"

# Spins up a localhost `HTTP::Server` on an ephemeral port for the duration
# of the block. The handler closes over a per-request counter and the
# canonical fixture body, so individual tests can inspect what the client
# actually sent.
private def with_stub_server(&block : HTTP::Server, String, Array(HTTP::Request) ->)
  body = SpecFixtures.sample_catalog_json
  requests = [] of HTTP::Request

  server = HTTP::Server.new do |context|
    req = context.request
    requests << HTTP::Request.new(req.method, req.path, req.headers.dup)

    case req.path
    when "/feed.json"
      etag = %("kev-v1")
      last_modified = "Wed, 15 Jan 2024 16:55:06 GMT"

      ctx_etag = req.headers["If-None-Match"]?
      ctx_modified = req.headers["If-Modified-Since"]?
      if ctx_etag == etag || ctx_modified == last_modified
        context.response.status_code = 304
      else
        context.response.content_type = "application/json"
        context.response.headers["ETag"] = etag
        context.response.headers["Last-Modified"] = last_modified
        context.response.print body
      end
    when "/boom"
      context.response.status_code = 500
      context.response.print "nope"
    when "/garbage"
      context.response.content_type = "application/json"
      context.response.print "{not json"
    when "/redirect"
      context.response.status_code = 302
      context.response.headers["Location"] = "/feed.json"
    else
      context.response.status_code = 404
    end
  end

  address = server.bind_tcp("127.0.0.1", 0)
  spawn { server.listen }

  begin
    base = "http://#{address.address}:#{address.port}"
    block.call(server, base, requests)
  ensure
    server.close
  end
end

# Spins up a server driven by a caller-supplied handler. The handler closes
# over its own state (e.g. a per-request counter), which lets retry tests
# script a sequence of responses — "fail twice, then succeed" — without
# touching the canonical fixture server above.
# Serves one canned raw HTTP response per connection from a bare
# `TCPServer`, for wire-level failures `HTTP::Server` refuses to produce
# (garbled status lines, bodies cut short of their `Content-Length`).
private def with_raw_server(response : Bytes, &)
  server = TCPServer.new("127.0.0.1", 0)
  spawn do
    while client = server.accept?
      client.gets("\r\n\r\n")
      client.write(response)
      client.close
    end
  end

  begin
    yield "http://127.0.0.1:#{server.local_address.port}/feed.json"
  ensure
    server.close
  end
end

private def with_scripted_server(handler : HTTP::Server::Context ->, &)
  server = HTTP::Server.new { |context| handler.call(context) }
  address = server.bind_tcp("127.0.0.1", 0)
  spawn { server.listen }

  begin
    yield "http://#{address.address}:#{address.port}"
  ensure
    server.close
  end
end

describe KEV::Client do
  it "fetches and parses the live feed shape" do
    with_stub_server do |_, base, _|
      catalog = KEV::Client.new("#{base}/feed.json").fetch
      catalog.should be_a(KEV::Catalog)
      catalog.size.should eq(4)
    end
  end

  it "sends a User-Agent that identifies the library" do
    with_stub_server do |_, base, requests|
      KEV::Client.new("#{base}/feed.json").fetch
      ua = requests.last.headers["User-Agent"]
      ua.should contain("kev.cr/")
      ua.should contain(KEV::VERSION)
    end
  end

  it "captures ETag and Last-Modified from the response" do
    with_stub_server do |_, base, _|
      client = KEV::Client.new("#{base}/feed.json")
      client.fetch
      client.last_etag.should eq(%("kev-v1"))
      client.last_modified.should eq("Wed, 15 Jan 2024 16:55:06 GMT")
    end
  end

  it "fetch_if_modified does a full fetch on the first call" do
    with_stub_server do |_, base, _|
      client = KEV::Client.new("#{base}/feed.json")
      catalog = client.fetch_if_modified
      catalog.should_not be_nil
      catalog.not_nil!.size.should eq(4)
    end
  end

  it "fetch_if_modified short-circuits to nil on a 304" do
    with_stub_server do |_, base, requests|
      client = KEV::Client.new("#{base}/feed.json")
      client.fetch # primes ETag + Last-Modified

      result = client.fetch_if_modified
      result.should be_nil

      # The conditional request must include the captured validators.
      conditional = requests.last
      conditional.headers["If-None-Match"]?.should eq(%("kev-v1"))
      conditional.headers["If-Modified-Since"]?.should eq("Wed, 15 Jan 2024 16:55:06 GMT")
    end
  end

  it "picks up a validator rotated on a 304" do
    # RFC 9110 §15.4.5: a 304 carries an ETag when one would have been
    # sent on a 200. Dropping it pinned the client to the first validator
    # it ever saw, so once the origin rotated (CDN reissue, weak/strong
    # switch) every later poll missed the cache and re-downloaded the
    # whole feed with a 200.
    seen = [] of String?
    handler = ->(context : HTTP::Server::Context) do
      seen << context.request.headers["If-None-Match"]?
      case seen.size
      when 1
        context.response.headers["ETag"] = %("v1")
        context.response.headers["Last-Modified"] = "Wed, 15 Jan 2024 16:55:06 GMT"
        context.response.content_type = "application/json"
        context.response.print SpecFixtures.sample_catalog_json
      else
        # Same bytes, new validator.
        context.response.headers["ETag"] = %("v2")
        context.response.status_code = 304
      end
      nil
    end

    with_scripted_server(handler) do |base|
      client = KEV::Client.new("#{base}/feed.json")
      client.fetch
      client.last_etag.should eq(%("v1"))

      client.fetch_if_modified.should be_nil
      client.last_etag.should eq(%("v2"))

      client.fetch_if_modified.should be_nil
      seen.should eq([nil, %("v1"), %("v2")])
    end
  end

  it "does not wipe a stored validator the 304 omits" do
    # A 304 need not repeat Last-Modified. Replacing validators wholesale
    # would clear it and drop `If-Modified-Since` from later requests.
    handler = ->(context : HTTP::Server::Context) do
      if context.request.headers["If-None-Match"]?
        context.response.headers["ETag"] = %("v1")
        context.response.status_code = 304
      else
        context.response.headers["ETag"] = %("v1")
        context.response.headers["Last-Modified"] = "Wed, 15 Jan 2024 16:55:06 GMT"
        context.response.content_type = "application/json"
        context.response.print SpecFixtures.sample_catalog_json
      end
      nil
    end

    with_scripted_server(handler) do |base|
      client = KEV::Client.new("#{base}/feed.json")
      client.fetch
      client.fetch_if_modified.should be_nil

      client.last_etag.should eq(%("v1"))
      client.last_modified.should eq("Wed, 15 Jan 2024 16:55:06 GMT")
    end
  end

  it "replaces validators wholesale on a 200" do
    # The opposite case: a 200 is a new representation, so a validator
    # the response omits must not be carried over from the old one.
    handler = ->(context : HTTP::Server::Context) do
      context.response.headers["ETag"] = %("v2")
      context.response.content_type = "application/json"
      context.response.print SpecFixtures.sample_catalog_json
      nil
    end

    with_scripted_server(handler) do |base|
      client = KEV::Client.new("#{base}/feed.json")
      client.fetch
      client.last_etag.should eq(%("v2"))
      client.last_modified.should be_nil
    end
  end

  it "records no validators for a body that fails to parse" do
    # Recording the ETag before parsing made the next conditional GET
    # answer 304, so `fetch_if_modified` returned nil ("unchanged") for a
    # catalog the caller never got.
    good = SpecFixtures.sample_catalog_json
    seen = [] of String?
    handler = ->(context : HTTP::Server::Context) do
      seen << context.request.headers["If-None-Match"]?
      if context.request.headers["If-None-Match"]? == %("v2")
        context.response.status_code = 304
      else
        context.response.headers["ETag"] = %("v2")
        context.response.print(seen.size == 1 ? good[0, good.size // 2] : good)
      end
      nil
    end

    with_scripted_server(handler) do |base|
      client = KEV::Client.new("#{base}/feed.json")
      expect_raises(JSON::ParseException) { client.fetch_if_modified }
      client.last_etag.should be_nil
      client.fetch_if_modified.not_nil!.size.should eq(4)
      seen.should eq([nil, nil])
      client.last_etag.should eq(%("v2"))
    end
  end

  it "keeps the old validators when a changed body fails to parse" do
    etag = %("v1")
    handler = ->(context : HTTP::Server::Context) do
      context.response.headers["ETag"] = etag
      context.response.print(etag == %("v1") ? SpecFixtures.sample_catalog_json : "{}")
      nil
    end

    with_scripted_server(handler) do |base|
      client = KEV::Client.new("#{base}/feed.json")
      client.fetch
      etag = %("v2")
      expect_raises(KEV::ParseError) { client.fetch }
      client.last_etag.should eq(%("v1"))
      expect_raises(KEV::ParseError) { client.fetch_csv }
      client.last_etag.should eq(%("v1"))
    end
  end

  it "raises FetchError on an unparseable URL" do
    # `URI::Error`, then `OverflowError` from a port past `Int32`.
    ["http://127.0.0.1:abc/feed.json", "http://127.0.0.1:99999999999/feed.json"].each do |url|
      expect_raises(KEV::FetchError, /invalid KEV feed URL/) do
        KEV::Client.new(url, max_retries: 0).fetch
      end
    end
  end

  it "rejects an out-of-range port without retrying" do
    expect_raises(KEV::FetchError, /out-of-range port/) do
      KEV::Client.new("http://127.0.0.1:65536/feed.json", retry_backoff: 10.seconds).fetch
    end
  end

  it "raises FetchError on an unparseable redirect Location" do
    # A server-sent header: `URI.parse` raised a bare `URI::Error`.
    handler = ->(context : HTTP::Server::Context) do
      context.response.status_code = 302
      context.response.headers["Location"] = "http://127.0.0.1:abc/feed.json"
      nil
    end

    with_scripted_server(handler) do |base|
      expect_raises(KEV::FetchError, /redirect from .* has an invalid Location/) do
        KEV::Client.new("#{base}/feed.json", max_redirects: 1).fetch
      end
    end
  end

  it "raises FetchError on a non-2xx response" do
    with_stub_server do |_, base, _|
      expect_raises(KEV::FetchError, /500/) do
        KEV::Client.new("#{base}/boom").fetch
      end
    end
  end

  it "lets JSON::ParseException propagate on a malformed body" do
    # Matches the cvss.cr precedent — JSON-level errors stay JSON errors,
    # only KEV-level schema violations become KEV::ParseError.
    with_stub_server do |_, base, _|
      expect_raises(JSON::ParseException) do
        KEV::Client.new("#{base}/garbage").fetch
      end
    end
  end

  it "rejects non-http(s) URLs eagerly" do
    expect_raises(KEV::FetchError, /must be http/) do
      KEV::Client.new("file:///etc/passwd").fetch
    end
  end

  it "rejects an http(s) URL with no host as a FetchError" do
    # These clear the scheme check and then blow up inside
    # `HTTP::Client.new(uri)` with a bare `ArgumentError`, which is not
    # part of the documented "FetchError on any transport failure"
    # contract and is not catchable as a `KEV::Error`.
    ["http:///feed.json", "https://", "https://:8080/x"].each do |url|
      expect_raises(KEV::FetchError, /no host/) do
        KEV::Client.new(url).fetch
      end
    end
  end

  it "does not follow 3xx redirects (documented behaviour)" do
    # If CISA ever 301s to a new URL we want a loud failure so the
    # caller updates their config, not silent following to a possibly
    # untrusted host. Lock down the contract here.
    with_stub_server do |_, base, _|
      expect_raises(KEV::FetchError, /302/) do
        KEV::Client.new("#{base}/redirect").fetch
      end
    end
  end

  it "follows a redirect when max_redirects allows it" do
    with_stub_server do |_, base, _|
      catalog = KEV::Client.new("#{base}/redirect", max_redirects: 1).fetch
      catalog.size.should eq(4)
    end
  end

  it "says the redirect budget ran out rather than blaming the status" do
    # Two hops, one hop of budget. The old code fell through to the
    # generic non-2xx branch and reported "returned HTTP 302 Found",
    # which reads like the server misbehaved rather than like the client
    # gave up.
    handler = ->(context : HTTP::Server::Context) do
      context.response.status_code = 302
      context.response.headers["Location"] = "/hop"
      nil
    end

    with_scripted_server(handler) do |base|
      client = KEV::Client.new("#{base}/feed.json", max_redirects: 1)
      ex = expect_raises(KEV::FetchError, /redirect budget is exhausted/) { client.fetch }
      ex.message.not_nil!.should contain("max_redirects=1")
    end
  end

  it "does not chase a 304 as if it were a redirect" do
    # `HTTP::Status#redirection?` is true for 304 Not Modified, so testing
    # that predicate made a plain `fetch` against a caching intermediary
    # fail with "redirect ... missing Location header" instead of
    # surfacing the real status.
    handler = ->(context : HTTP::Server::Context) do
      context.response.status_code = 304
      nil
    end

    with_scripted_server(handler) do |base|
      client = KEV::Client.new("#{base}/feed.json", max_redirects: 5)
      ex = expect_raises(KEV::FetchError, /304/) { client.fetch }
      ex.message.not_nil!.should_not contain("Location")
    end
  end

  it "still short-circuits a 304 on the conditional path with redirects enabled" do
    with_stub_server do |_, base, _|
      client = KEV::Client.new("#{base}/feed.json", max_redirects: 5)
      client.fetch
      client.fetch_if_modified.should be_nil
    end
  end

  describe "retry/backoff" do
    it "retries a transient 5xx and succeeds on a later attempt" do
      body = SpecFixtures.sample_catalog_json
      attempts = 0
      handler = ->(context : HTTP::Server::Context) do
        attempts += 1
        if attempts < 3
          context.response.status_code = 503
          context.response.print "temporarily unavailable"
        else
          context.response.content_type = "application/json"
          context.response.print body
        end
        nil
      end

      with_scripted_server(handler) do |base|
        client = KEV::Client.new("#{base}/feed.json", max_retries: 3, retry_backoff: 1.millisecond)
        catalog = client.fetch
        catalog.size.should eq(4)
      end

      # 2 failures + 1 success.
      attempts.should eq(3)
    end

    it "exhausts retries on a persistent 500 and raises FetchError" do
      attempts = 0
      handler = ->(context : HTTP::Server::Context) do
        attempts += 1
        context.response.status_code = 500
        context.response.print "nope"
        nil
      end

      with_scripted_server(handler) do |base|
        client = KEV::Client.new("#{base}/feed.json", max_retries: 2, retry_backoff: 1.millisecond)
        expect_raises(KEV::FetchError, /500/) do
          client.fetch
        end
      end

      # 1 initial attempt + 2 retries.
      attempts.should eq(3)
    end

    it "does NOT retry a 404 (non-transient client error)" do
      attempts = 0
      handler = ->(context : HTTP::Server::Context) do
        attempts += 1
        context.response.status_code = 404
        context.response.print "not found"
        nil
      end

      with_scripted_server(handler) do |base|
        client = KEV::Client.new("#{base}/missing", max_retries: 3, retry_backoff: 1.millisecond)
        expect_raises(KEV::FetchError, /404/) do
          client.fetch
        end
      end

      # A single attempt — 404s are the caller's problem, never replayed.
      attempts.should eq(1)
    end

    it "honors Retry-After on a 503 instead of the computed backoff" do
      body = SpecFixtures.sample_catalog_json
      attempts = 0
      saw_retry_after = false
      handler = ->(context : HTTP::Server::Context) do
        attempts += 1
        if attempts == 1
          saw_retry_after = true
          context.response.headers["Retry-After"] = "0"
          context.response.status_code = 503
          context.response.print "slow down"
        else
          context.response.content_type = "application/json"
          context.response.print body
        end
        nil
      end

      with_scripted_server(handler) do |base|
        # A large retry_backoff would make the test slow if it were used;
        # the Retry-After: 0 hint must win, keeping this fast.
        client = KEV::Client.new("#{base}/feed.json", max_retries: 2, retry_backoff: 30.seconds)
        start = Time.instant
        catalog = client.fetch
        elapsed = Time.instant - start

        catalog.size.should eq(4)
        # Retry-After=0 was honored, so we didn't sleep the 30s base backoff.
        elapsed.should be < 5.seconds
      end

      saw_retry_after.should be_true
      attempts.should eq(2)
    end

    it "exposes backoff_delay with a hard cap and jitter" do
      client = KEV::Client.new(retry_backoff: 1.second)
      # base * 2^(attempt-1) for the low end.
      client.backoff_delay(1).should be >= 1.second
      client.backoff_delay(2).should be >= 2.seconds

      # Large attempts clamp to MAX_BACKOFF (plus <=10% jitter), never
      # growing unbounded.
      ceiling = KEV::Client::MAX_BACKOFF * 1.1
      [10, 20, 40, 100].each do |attempt|
        delay = client.backoff_delay(attempt)
        delay.should be >= KEV::Client::MAX_BACKOFF
        delay.should be <= ceiling
      end
    end

    it "raises FetchError on a body cut short of its Content-Length" do
      # `HTTP::Client` returns whatever arrived before the peer closed, so
      # a dropped connection used to parse as a short (but valid) CSV.
      csv = KEV::Catalog.parse(SpecFixtures.sample_catalog_json).to_csv
      cut = csv.byte_index("\nCVE-", csv.bytesize // 2).not_nil! + 1
      raw = "HTTP/1.1 200 OK\r\nContent-Length: #{csv.bytesize}\r\n\r\n#{csv.byte_slice(0, cut)}"
      KEV::Catalog.parse_csv(csv.byte_slice(0, cut)).size.should be < KEV::Catalog.parse_csv(csv).size

      with_raw_server(raw.to_slice) do |url|
        expect_raises(KEV::FetchError, /truncated/) do
          KEV::Client.new(url, max_retries: 0).fetch_csv
        end
      end
    end

    it "checks the first of repeated matching Content-Length headers" do
      body = SpecFixtures.sample_catalog_json
      raw = "HTTP/1.1 200 OK\r\nContent-Length: #{body.bytesize}\r\nContent-Length: #{body.bytesize}\r\n\r\n#{body.byte_slice(0, 10)}"
      with_raw_server(raw.to_slice) do |url|
        expect_raises(KEV::FetchError, /truncated/) { KEV::Client.new(url, max_retries: 0).fetch }
      end
    end

    it "ignores a stale Content-Length on a chunked body" do
      # RFC 9112 §6.1: Transfer-Encoding overrides Content-Length.
      body = SpecFixtures.sample_catalog_json
      raw = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: #{body.bytesize + 100}\r\n\r\n" \
            "#{body.bytesize.to_s(16)}\r\n#{body}\r\n0\r\n\r\n"
      with_raw_server(raw.to_slice) do |url|
        KEV::Client.new(url, max_retries: 0).fetch.size.should eq(SpecFixtures.sample_catalog.size)
      end
    end

    it "raises FetchError on a truncated gzip body" do
      io = IO::Memory.new
      Compress::Gzip::Writer.open(io, &.print(SpecFixtures.sample_catalog_json))
      gz = io.to_slice
      head = "HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: #{gz.size}\r\n\r\n"
      raw = IO::Memory.new
      raw << head
      raw.write(gz[0, gz.size // 2])

      with_raw_server(raw.to_slice) do |url|
        expect_raises(KEV::FetchError) { KEV::Client.new(url, max_retries: 0).fetch }
      end
    end

    it "raises FetchError on a response that is not HTTP" do
      ["garbage\r\n\r\n", "HTTP/1.1 abc OK\r\n\r\n", "HTTP/1.1 200 OK\r\nContent-Length: abc\r\n\r\n{}"].each do |raw|
        with_raw_server(raw.to_slice) do |url|
          # Not retried: another attempt would read the same bytes.
          expect_raises(KEV::FetchError, /malformed HTTP response/) do
            KEV::Client.new(url, max_retries: 3, retry_backoff: 10.seconds).fetch
          end
        end
      end
    end

    it "rejects a negative max_retries eagerly" do
      expect_raises(KEV::FetchError, /max_retries/) do
        KEV::Client.new(max_retries: -1)
      end
    end
  end
end
