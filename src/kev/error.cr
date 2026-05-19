module KEV
  # Base class for every exception raised by this library. Catch this if you
  # want to handle "anything KEV-related went wrong" without enumerating the
  # subclasses.
  class Error < Exception
  end

  # Raised when the input cannot be decoded — malformed JSON, missing
  # required fields, or values that fail their schema-level shape checks
  # (e.g. a `dateAdded` that is not `YYYY-MM-DD`).
  class ParseError < Error
  end

  # Raised when the catalog or a vulnerability object is missing a field
  # the KEV schema marks as required.
  class MissingFieldError < ParseError
    getter field : String

    def initialize(@field : String, context : String? = nil)
      super(context ? "missing required field '#{@field}' in #{context}" : "missing required field '#{@field}'")
    end
  end

  # Raised when a field's value fails its enumerated set (e.g. an unknown
  # `knownRansomwareCampaignUse` value).
  class InvalidValueError < ParseError
    getter field : String
    getter value : String

    def initialize(@field : String, @value : String)
      super("invalid value '#{@value}' for field '#{@field}'")
    end
  end

  # Raised by `Client` for transport-level failures: connection errors,
  # timeouts, or non-2xx responses from the CISA feed.
  class FetchError < Error
  end
end
