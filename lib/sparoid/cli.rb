# frozen_string_literal: true

require "thor"
require_relative "../sparoid"

module Sparoid
  # CLI
  class CLI < Thor
    desc "send HOST [PORT]", "Send a packet"
    method_option :config, desc: "Path to a config file, INI format, with key and hmac-key"
    method_option :fdpass,
                  type: :numeric,
                  desc: "After sending, open a TCP connection and pass the FD back to the calling process. \
                         For use with OpenSSH ProxyCommand and ProxyUseFdpass"
    def send(host, port = 8484)
      config = File.expand_path(options[:config] || "~/.sparoid.ini")
      abort "Config '#{config}' not found" unless File.exist? config

      key, hmac_key = get_keys(parse_ini(config))
      Sparoid.send(key, hmac_key, host, port.to_i)
      Sparoid.fdpass(host, options[:fdpass]) if options[:fdpass]
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
