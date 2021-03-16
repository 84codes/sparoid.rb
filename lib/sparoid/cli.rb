# frozen_string_literal: true

require "thor"
require_relative "../sparoid"

module Sparoid
  # CLI
  class CLI < Thor
    desc "auth HOST [PORT]", "Send a authorization packet"
    method_option :config, desc: "Path to a config file, INI format, with key and hmac-key"
    def auth(host, port = 8484)
      config = File.expand_path(options[:config] || "~/.sparoid.ini")
      abort "Config '#{config}' not found" unless File.exist? config

      key, hmac_key = get_keys(parse_ini(config))
      Sparoid.auth(key, hmac_key, host, port.to_i)
    rescue StandardError => e
      abort e.message
    end

    desc "connect HOST PORT [SPA-PORT]", "Send a SPA, TCP connect, and then pass the FD back to the parent"
    def connect(host, port, spa_port = 8484)
      auth(host, spa_port)
      Sparoid.fdpass(host, port)
    rescue StandardError => e
      abort e.message
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
