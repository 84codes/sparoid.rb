# frozen_string_literal: true

require "thor"
require_relative "../sparoid"

module Sparoid
  # CLI
  class CLI < Thor
    desc "send HOST [PORT]", "Send a packet"
    method_option :config
    method_option :passfd, default: 22, type: :numeric
    def send(host, port = 8484)
      config = File.expand_path(options[:config] || "~/.sparoid.ini")
      abort "Config '#{config}' not found" unless File.exist? config

      key, hmac_key = get_keys(parse_ini(config))
      Sparoid.send(key, hmac_key, host, port.to_i)

      passfd(host, options[:passfd]) if options[:passfd]
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

    def passfd(host, port)
      ssh = TCPSocket.new host, port
      parent = Socket.for_fd(1)
      parent.sendmsg "\0", 0, nil, Socket::AncillaryData.unix_rights(ssh)
    end
  end
end
