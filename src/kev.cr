# A Crystal implementation of the CISA Known Exploited Vulnerabilities (KEV)
# catalog.
#
# See: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
#
# Quick start:
#
# ```
# require "kev"
#
# catalog = KEV.parse(File.read("kev.json"))
# catalog.size                             # => 1592
# catalog["CVE-2021-44228"].vendor_project # => "Apache"
# catalog.query.ransomware.year(2024).to_a # ransomware-flagged 2024 CVEs
#
# # Or pull straight from CISA:
# live = KEV.fetch
# ```
require "./kev/version"
require "./kev/error"
require "./kev/ransomware_use"
require "./kev/vulnerability"
require "./kev/query"
require "./kev/catalog"
require "./kev/diff"
require "./kev/stats"
require "./kev/client"

module KEV
  # Parse a KEV catalog from a JSON string or IO. Raises `KEV::ParseError`
  # on malformed input.
  #
  # ```
  # KEV.parse(File.read("known_exploited_vulnerabilities.json")).size
  # ```
  def self.parse(input : String | IO) : Catalog
    Catalog.parse(input)
  end

  # Non-raising parse — returns nil on malformed JSON or schema violations.
  def self.parse?(input : String | IO) : Catalog?
    Catalog.parse?(input)
  end

  # Fetch the live CISA KEV catalog over HTTPS. Equivalent to
  # `KEV::Client.fetch`, included at the module level for one-liners.
  #
  # ```
  # KEV.fetch.ransomware.size
  # ```
  def self.fetch(url : String = Client::DEFAULT_URL) : Catalog
    Client.fetch(url)
  end
end
