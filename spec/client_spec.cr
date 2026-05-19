require "./spec_helper"
require "http/server"

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
end
