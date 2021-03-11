# frozen_string_literal: true

require "thor"
require_relative "../sparoid"

module Sparoid
  # CLI
  class CLI < Thor
    desc "send HOST [PORT]", "Send a packet"
    method_option :config, default: "~/.sparoid.ini"
    def send(host, port = 8484)
      if File.exist? options[:config]
        c = parse_config(options[:config])
        key = c["key"]
        hmac_key = c["hmac-key"]
      else
        abort "Config not found"
      end
      Sparoid.send(key, hmac_key, host, port.to_i)
    end

    desc "keygen", "Generate an encryption key and a HMAC key"
    def keygen
      Sparoid.keygen
    end

    def self.exit_on_failure?
      true
    end

    private

    def parse_config(path)
      File.readlines(path).map! { |l| l.split("=", 2).map!(&:strip) }.to_h
    end
  end
end
