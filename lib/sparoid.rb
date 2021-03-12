# frozen_string_literal: true

require_relative "sparoid/version"
require "socket"
require "openssl"
require "resolv"

# Single Packet Authorisation client
module Sparoid
  def self.send(key, hmac_key, host, port)
    msg = message(public_ip)
    data = prefix_hmac(hmac_key, encrypt(key, msg))
    udp_send(host, port, data)
  end

  def self.udp_send(host, port, data)
    socket = UDPSocket.new
    socket.connect host, port
    socket.send data, 0
    socket.close
  end

  def self.encrypt(key, data)
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

  def self.prefix_hmac(hmac_key, data)
    hmac_key = [hmac_key].pack("H*") # hexstring to bytes
    raise ArgumentError, "HMAC key must be 32 bytes hex encoded" if hmac_key.bytesize != 32

    hmac = OpenSSL::HMAC.digest("SHA256", hmac_key, data)
    hmac + data
  end

  def self.message(ip)
    version = 1
    ts = (Time.now.utc.to_f * 1000).floor
    nounce = OpenSSL::Random.random_bytes(16)
    [version, ts, nounce, ip.address].pack("Nq>a16a4")
  end

  def self.public_ip
    Resolv::DNS.open(nameserver: ["resolver1.opendns.com"]) do |dns|
      dns.each_address("myip.opendns.com") do |resolv|
        case resolv
        when Resolv::IPv4 then return resolv
        end
      end
      raise Error, "No public IPv4 address found"
    end
  end

  def self.keygen
    cipher = OpenSSL::Cipher.new("aes-256-cbc")
    key = cipher.random_key.unpack1("H*")
    hmac_key = OpenSSL::Random.random_bytes(32).unpack1("H*")
    puts "key = #{key}"
    puts "hmac-key = #{hmac_key}"
  end

  def self.fdpass(host, port)
    ssh = Socket.tcp host, port
    parent = Socket.for_fd(1)
    parent.sendmsg "\0", 0, nil, Socket::AncillaryData.unix_rights(ssh)
  end

  class Error < StandardError; end
end
