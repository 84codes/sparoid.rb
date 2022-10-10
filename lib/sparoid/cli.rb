# frozen_string_literal: true

require "thor"
require_relative "../sparoid"

module Sparoid
  # CLI
  class CLI < Thor
    map "-v" => :version

    desc "auth HOST [PORT]", "Send a authorization packet"
    method_option :config, desc: "Path to a config file, INI format, with key and hmac-key", default: "~/.sparoid.ini"
    def auth(host, port = 8484)
      send_auth(host, port, options[:config])
    rescue Errno::ENOENT
      abort "Sparoid: Config not found"
    rescue StandardError => e
      abort "Sparoid: #{e.message} (#{host})"
    end

    desc "connect HOST PORT [SPA-PORT]", "Send a SPA, TCP connect, and then pass the FD back to the parent"
    method_option :config, desc: "Path to a config file, INI format, with key and hmac-key", default: "~/.sparoid.ini"
    def connect(host, port, spa_port = 8484)
      ips = send_auth(host, spa_port, options[:config])
      Sparoid.fdpass(ips, port)
    rescue StandardError => e
      abort "Sparoid: #{e.message} (#{host})"
    end

    desc "keygen", "Generate an encryption key and a HMAC key"
    def keygen
      Sparoid.keygen
    end

    desc "version", "Show version and exit"
    def version
      puts "#{Sparoid::VERSION} (ruby)"
    end

    def self.exit_on_failure?
      true
    end

    private

    def send_auth(host, port, config)
      key, hmac_key = get_keys(parse_ini(config))
      Sparoid.auth(key, hmac_key, host, port.to_i)
    end

    def parse_ini(path)
      File.readlines(File.expand_path(path)).map! { |line| line.split("=", 2).map!(&:strip) }.to_h
    rescue Errno::ENOENT
      {
        "key" => ENV.fetch("SPAROID_KEY", nil),
        "hmac-key" => ENV.fetch("SPAROID_HMAC_KEY", nil)
      }
    end

    def get_keys(config)
      config.values_at("key", "hmac-key")
    end
  end
end
