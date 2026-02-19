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
    messages = if ip
                 create_messages(string_to_ip(ip))
               else
                 generate_public_ip_messages
               end

    messages.flatten.sort_by!(&:bytesize)
  end

  def generate_public_ip_messages
    messages = []
    ipv6_added = false
    public_ipv6_with_range.each do |addr, prefixlen|
      ipv6 = Resolv::IPv6.create(addr)
      messages << message_v2(ipv6, prefixlen)
      ipv6_added = true
    end

    cached_public_ips.each do |ip|
      next if ip.is_a?(Resolv::IPv6) && ipv6_added

      messages << create_messages(ip)
    end
    messages
  end

  def create_messages(ip)
    case ip
    when Resolv::IPv4
      [message_v2(ip, 32), message(ip)]
    when Resolv::IPv6
      [message_v2(ip, 128)]
    else
      raise ArgumentError, "Unsupported IP type #{ip.class}"
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

  def message(ip)
    version = 1
    ts = (Time.now.utc.to_f * 1000).floor
    nounce = OpenSSL::Random.random_bytes(16)
    [version, ts, nounce, ip.address].pack("N q> a16 a4")
  end

  def message_v2(ip, range = nil)
    version = 2
    ts = (Time.now.utc.to_f * 1000).floor
    nounce = OpenSSL::Random.random_bytes(16)
    family = case ip
             when Resolv::IPv4 then 4
             when Resolv::IPv6 then 6
             else raise ArgumentError, "Unsupported IP type #{ip.class}"
             end
    range ||= (family == 4 ? 32 : 128)
    [version, ts, nounce, family, ip.address, range].pack("N q> a16 C a* C")
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

  def public_ipv6_with_range
    global_ipv6_ifs = Socket.getifaddrs.select do |addr|
      addrinfo = addr.addr
      addrinfo&.ipv6? && global_ipv6?(addrinfo)
    end

    global_ipv6_ifs.map do |iface|
      addrinfo = iface.addr
      netmask_addr = IPAddr.new(iface.netmask.ip_address)
      prefixlen = netmask_addr.to_i.to_s(2).count("1")
      next addrinfo.ip_address, prefixlen
    end
  end

  def global_ipv6?(addrinfo)
    !(addrinfo.ipv6_mc_global? || addrinfo.ipv6_loopback? || addrinfo.ipv6_v4mapped? ||
      addrinfo.ipv6_linklocal? || addrinfo.ipv6_multicast? || addrinfo.ipv6_sitelocal? ||
      addrinfo.ip_address.start_with?("fd00"))
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
