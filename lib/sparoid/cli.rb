# frozen_string_literal: true

require "thor"
require_relative "../sparoid"

module Sparoid
  # CLI
  class CLI < Thor
    desc "send HOST [PORT]", "Send a packet"
    method_option :config, default: "~/.sparoid.ini"
    def send(host, port = 8484)
      abort "Config not found" unless File.exist? options[:config]

      key, hmac_key = get_keys(parse_ini(options[:config]))
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

    def parse_ini(path)
      File.readlines(path).map! { |l| l.split("=", 2).map!(&:strip) }.to_h
    end

    def get_keys(config)
      config.values_at("key", "hmac-key")
    end
  end
end
