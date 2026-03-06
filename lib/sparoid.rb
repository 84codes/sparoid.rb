# frozen_string_literal: true

require_relative "sparoid/version"
require "socket"
require "openssl"
require "resolv"
require "timeout"

# Single Packet Authorisation client
module Sparoid # rubocop:disable Metrics/ModuleLength
  extend self

  SPAROID_CACHE_PATH = ENV.fetch("SPAROID_CACHE_PATH", "/tmp/.sparoid_public_ip")

  URLS = [
    "ipv6.icanhazip.com",
    "ipv4.icanhazip.com"
  ].freeze

  GOOGLE_DNS_V6 = ["2001:4860:4860::8888", 53].freeze

  # Send an authorization packet
  def auth(key, hmac_key, host, port, open_for_ip: nil)
    addrs = resolve_ip_addresses(host, port)
    addrs.each do |addr|
      messages = generate_messages(open_for_ip)
      data = messages.map do |message|
        prefix_hmac(hmac_key, encrypt(key, message))
      end
      sendmsg(addr, data)
    end

    # wait some time for the server to actually open the port
    # if we don't wait the next SYN package will be dropped
    # and it have to be redelivered, adding 1 second delay
    sleep 0.02

    addrs
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
  def fdpass(addrs, port, connect_timeout: 10) # rubocop:disable Metrics/AbcSize
    # try connect to all IPs
    sockets = addrs.map do |addr|
      Socket.new(addr.afamily, Socket::SOCK_STREAM).tap do |s|
        s.connect_nonblock(Socket.sockaddr_in(port, addr.ip_address), exception: false)
      end
    end
    # wait for any socket to be connected
    until sockets.empty?
      _, writeable, errors = IO.select(nil, sockets, nil, connect_timeout) || break
      errors.each { |s| sockets.delete(s) }
      writeable.each do |s|
        idx = sockets.index(s)
        sockets.delete_at(idx) # don't retry this socket again
        addr = addrs.delete_at(idx) # find the IP for the socket
        begin
          s.connect_nonblock(Socket.sockaddr_in(port, addr.ip_address)) # check for errors
        rescue Errno::EISCONN
          # already connected, continue
        rescue SystemCallError
          next # skip connection errors, hopefully at least one succeeds
        end
        # pass the connected FD to the parent process over STDOUT
        Socket.for_fd(1).sendmsg "\0", 0, nil, Socket::AncillaryData.unix_rights(s)
        exit 0 # exit as fast as possible so that other sockets don't connect
      end
    end
    exit 1 # all connections failed
  end

  private

  def generate_messages(ip)
    if ip
      [message(string_to_ip(ip))]
    else
      ips = cached_public_ips
      native_ipv6 = public_ipv6_by_udp
      if native_ipv6
        ips = ips.reject { |i| i.is_a?(Resolv::IPv6) }
        ips << Resolv::IPv6.create(native_ipv6)
      end
      ips.map { |i| message(i) }
    end
  end

  def sendmsg(addr, data)
    socket = UDPSocket.new(addr.afamily)
    socket.nonblock = false
    data.each do |packet|
      socket.sendmsg packet, 0, addr
    rescue StandardError => e
      warn "Sparoid error: #{e.message}"
    end
  ensure
    socket.close
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

  # Message format: version(4) + timestamp(8) + nonce(16) + ip(4 or 16)
  # https://github.com/84codes/sparoid/blob/main/src/message.cr
  def message(ip)
    version = 1
    ts = (Time.now.utc.to_f * 1000).floor
    nounce = OpenSSL::Random.random_bytes(16)
    [version, ts, nounce, ip.address].pack("N q> a16 a*")
  end

  def cached_public_ips
    if up_to_date_cache?
      read_cache
    else
      write_cache
    end
  rescue StandardError => e
    warn "Sparoid: #{e.inspect}"
    public_ips
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
      f.readlines(chomp: true).map do |line|
        string_to_ip(line)
      end
    end
  rescue ArgumentError => e
    return write_cache if /cannot interpret as IPv4 address/.match?(e.message)

    raise e
  end

  def write_cache
    File.open(SPAROID_CACHE_PATH, File::WRONLY | File::CREAT, 0o0644) do |f|
      f.flock(File::LOCK_EX)
      ips = public_ips
      warn "Sparoid: Failed to retrieve public IPs" if ips.empty?
      f.truncate(0)
      f.rewind
      ips.each do |ip|
        f.puts ip.to_s
      end
      ips
    end
  end

  def public_ips(port = 80) # rubocop:disable Metrics/AbcSize
    URLS.map do |host|
      Timeout.timeout(5) do
        Socket.tcp(host, port, connect_timeout: 3, resolv_timeout: 3) do |sock|
          sock.sync = true
          sock.print "GET / HTTP/1.1\r\nHost: #{host}\r\nConnection: close\r\n\r\n"
          status = sock.readline(chomp: true)
          raise(ResolvError, "#{host}:#{port} response: #{status}") unless status.start_with? "HTTP/1.1 200 "

          content_length = 0
          until (header = sock.readline(chomp: true)).empty?
            if (m = header.match(/^Content-Length: (\d+)/))
              content_length = m[1].to_i
            end
          end
          ip = sock.read(content_length).chomp
          string_to_ip(ip)
        end
      end
    rescue StandardError
      nil
    end.compact
  end

  def string_to_ip(ip)
    case ip
    when Resolv::IPv4::Regex
      Resolv::IPv4.create(ip)
    when Resolv::IPv6::Regex
      Resolv::IPv6.create(ip)
    else
      raise ArgumentError, "Unsupported IP format #{ip}"
    end
  end

  def resolve_ip_addresses(host, port)
    addresses = Addrinfo.getaddrinfo(host, port)
    raise(ResolvError, "Sparoid failed to resolv #{host}") if addresses.empty?

    addresses.select { |addr| addr.socktype == Socket::SOCK_DGRAM }
  rescue SocketError
    raise(ResolvError, "Sparoid failed to resolv #{host}")
  end

  # Get the public IPv6 address by asking the OS which source address
  # it would use to reach a well-known IPv6 destination.
  # Returns nil if no global IPv6 address is available.
  def public_ipv6_by_udp
    socket = UDPSocket.new(Socket::AF_INET6)
    socket.connect(*GOOGLE_DNS_V6)
    addr = socket.local_address
    return addr.ip_address if global_ipv6?(addr)

    nil
  rescue StandardError
    nil
  ensure
    socket&.close
  end

  def global_ipv6?(addr)
    !(addr.ipv6_loopback? || addr.ipv6_linklocal? || addr.ipv6_unspecified? ||
      addr.ipv6_sitelocal? || addr.ipv6_multicast? || addr.ipv6_v4mapped? ||
      addr.ip_address.start_with?("fd"))
  end

  class Error < StandardError; end

  class ResolvError < Error; end

  # Instance of SPAroid that only resolved public_ips once
  class Instance
    include Sparoid

    def public_ips(*args)
      @public_ips ||= super
    end

    def cached_public_ips
      public_ips
    end
  end
end
