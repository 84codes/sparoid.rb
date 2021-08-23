# frozen_string_literal: true

require_relative "sparoid/version"
require "socket"
require "openssl"
require "resolv"

# Single Packet Authorisation client
module Sparoid
  extend self

  SPAROID_CACHE_PATH = ENV.fetch("SPAROID_CACHE_PATH", "/tmp/.sparoid_public_ip")

  # Send an authorization packet
  def auth(key, hmac_key, host, port)
    sendmsg(host, port) do
      msg = message(cached_public_ip)
      prefix_hmac(hmac_key, encrypt(key, msg))
    end

    # wait some time for the server to actually open the port
    # if we don't wait the next SYN package will be dropped
    # and it have to be redelivered, adding 1 second delay
    sleep 0.02
  end

  # Generate new aes and hmac keys, print to stdout
  def keygen
    cipher = OpenSSL::Cipher.new("aes-256-cbc")
    key = cipher.random_key.unpack1("H*")
    hmac_key = OpenSSL::Random.random_bytes(32).unpack1("H*")
    puts "key = #{key}"
    puts "hmac-key = #{hmac_key}"
  end

  # Connect to a TCP server and pass the FD to the parent
  def fdpass(host, port, connect_timeout: 20)
    tcp = Socket.tcp host, port, connect_timeout: connect_timeout
    parent = Socket.for_fd(1)
    parent.sendmsg "\0", 0, nil, Socket::AncillaryData.unix_rights(tcp)
  end

  private

  def sendmsg(host, port, data = nil) # rubocop:disable Metrics/MethodLength
    ok = false
    UDPSocket.open do |socket|
      Resolv.each_address(host) do |ip|
        ok = true
        data = yield if block_given?
        socket.connect ip, port
        socket.sendmsg data, 0
      rescue StandardError => e
        warn "Sparoid error: #{e.message}"
      end
    end
    raise Error, "Sparoid failed to resolv #{host}" unless ok
  end

  def encrypt(key, data)
    key = [key].pack("H*") # hexstring to bytes
    raise ArgumentError, "Key must be 32 bytes hex encoded" if key.bytesize != 32

    cipher = OpenSSL::Cipher.new("aes-256-cbc")
    cipher.encrypt
    iv = cipher.random_iv
    cipher.key = key
    cipher.iv = iv
    output = iv
    output << cipher.update(data)
    output << cipher.final
  end

  def prefix_hmac(hmac_key, data)
    hmac_key = [hmac_key].pack("H*") # hexstring to bytes
    raise ArgumentError, "HMAC key must be 32 bytes hex encoded" if hmac_key.bytesize != 32

    hmac = OpenSSL::HMAC.digest("SHA256", hmac_key, data)
    hmac + data
  end

  def message(ip)
    version = 1
    ts = (Time.now.utc.to_f * 1000).floor
    nounce = OpenSSL::Random.random_bytes(16)
    [version, ts, nounce, ip.address].pack("N q> a16 a4")
  end

  def cached_public_ip
    if up_to_date_cache?
      read_cache
    else
      write_cache
    end
  rescue StandardError => e
    warn "Sparoid: #{e.inspect}"
    public_ip
  end

  def up_to_date_cache?
    mtime = File.mtime(SPAROID_CACHE_PATH)
    (Time.now - mtime) <= 60 # cache is valid for 1 min
  rescue Errno::ENOENT
    false
  end

  def read_cache
    File.open(SPAROID_CACHE_PATH, "r") do |f|
      f.flock(File::LOCK_SH)
      Resolv::IPv4.create f.read
    end
  rescue ArgumentError => e
    return write_cache if e.message =~ /cannot interpret as IPv4 address/

    raise e
  end

  def write_cache
    File.open(SPAROID_CACHE_PATH, File::WRONLY | File::CREAT, 0o0644) do |f|
      f.flock(File::LOCK_EX)
      ip = public_ip
      f.truncate(0)
      f.write ip.to_s
      ip
    end
  end

  def public_ip
    Resolv::DNS.open(nameserver: ["208.67.222.222", "208.67.220.220"]) do |dns|
      dns.getresource("myip.opendns.com", Resolv::DNS::Resource::IN::A).address
    end
  end

  class Error < StandardError; end

  # Instance of SPAroid that only resolved public_ip once
  class Instance
    include Sparoid

    private

    def public_ip
      @public_ip ||= super
    end
  end
end
