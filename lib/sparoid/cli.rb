# frozen_string_literal: true

require "optparse"
require_relative "../sparoid"

module Sparoid
  # CLI
  module CLI
    def self.run(args = ARGV) # rubocop:disable Metrics/AbcSize
      subcommand = args.shift
      host = "0.0.0.0"
      port = 8484
      tcp_port = 22
      config_path = "~/.sparoid.ini"

      case subcommand
      when "keygen"
        Sparoid.keygen
      when "send"
        parse_send_options!(args, binding)
        key, hmac_key = read_keys(config_path)
        Sparoid.auth(key, hmac_key, host, port)
      when "connect"
        parse_connect_options!(args, binding)
        key, hmac_key = read_keys(config_path)
        ips = Sparoid.auth(key, hmac_key, host, port)
        Sparoid.fdpass(ips, tcp_port)
      when "--version"
        puts Sparoid::VERSION
      else
        puts "Usage: sparoid [subcommand] [options]"
        puts ""
        puts "Subcommands: keygen, send, connect"
        puts "Use --version to show version"
        exit 1
      end
    rescue StandardError => e
      warn "Sparoid error: #{e.message}"
      exit 1
    end

    def self.parse_send_options!(args, ctx, banner: "send")
      OptionParser.new do |p|
        p.banner = "Usage: sparoid #{banner} [options]"
        p.on("-h HOST", "--host=HOST", "Host to send to") { |v| ctx.local_variable_set(:host, v) }
        p.on("-p PORT", "--port=PORT", "UDP port (default: 8484)") { |v| ctx.local_variable_set(:port, v.to_i) }
        p.on("-c PATH", "--config=PATH", "Path to config file") { |v| ctx.local_variable_set(:config_path, v) }
        yield p if block_given?
      end.parse!(args)
    end

    def self.parse_connect_options!(args, ctx)
      parse_send_options!(args, ctx, banner: "connect") do |p|
        p.on("-P PORT", "--tcp-port=PORT", "TCP port (default: 22)") { |v| ctx.local_variable_set(:tcp_port, v.to_i) }
      end
    end

    def self.read_keys(config_path)
      parse_ini(config_path).values_at("key", "hmac-key")
    end

    def self.parse_ini(path)
      File.readlines(File.expand_path(path)).to_h { |line| line.split("=", 2).map(&:strip) }
    rescue Errno::ENOENT
      {
        "key" => ENV.fetch("SPAROID_KEY", nil),
        "hmac-key" => ENV.fetch("SPAROID_HMAC_KEY", nil)
      }
    end

    private_class_method :parse_send_options!, :parse_connect_options!, :read_keys, :parse_ini
  end
end
