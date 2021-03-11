# frozen_string_literal: true

require "thor"
require_relative "../sparoid"

module Sparoid
  # CLI
  class CLI < Thor
    desc "send KEY HMAC_KEY HOST PORT", "Send a packet"
    def send(key, hmac_key, host, port)
      Sparoid.send(key, hmac_key, host, port.to_i)
    end

    desc "keygen", "Generate an encryption key and a HMAC key"
    def keygen
      Sparoid.keygen
    end

    def self.exit_on_failure?
      true
    end
  end
end
