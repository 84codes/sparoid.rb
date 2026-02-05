# frozen_string_literal: true

require "test_helper"

class SparoidTest < Minitest::Test
  def test_that_it_has_a_version_number
    refute_nil ::Sparoid::VERSION
  end

  def test_it_resolves_public_ip
    addresses = Sparoid.send(:public_ip)
    assert(addresses.any? { |ip| ip.is_a?(Resolv::IPv4) || ip.is_a?(Resolv::IPv6) })
  end

  def test_it_creates_a_message
    ip = Resolv::IPv4.create("127.0.0.1")
    assert_equal 32, Sparoid.send(:message, ip).bytesize
  end

  def test_it_encrypts_messages
    key = "0000000000000000000000000000000000000000000000000000000000000000"
    ip = Resolv::IPv4.create("127.0.0.1")
    assert_equal 64, Sparoid.send(:encrypt, key, Sparoid.send(:message, ip)).bytesize
  end

  def test_it_adds_hmac
    key = "0000000000000000000000000000000000000000000000000000000000000000"
    ip = Resolv::IPv4.create("127.0.0.1")
    msg = Sparoid.send(:encrypt, key, Sparoid.send(:message, ip))
    hmac_key = "0000000000000000000000000000000000000000000000000000000000000000"

    assert_equal 96, Sparoid.send(:prefix_hmac, hmac_key, msg).bytesize
  end

  def test_it_sends_message
    key = "0000000000000000000000000000000000000000000000000000000000000000"
    hmac_key = "0000000000000000000000000000000000000000000000000000000000000000"
    UDPSocket.open do |server|
      server.bind("127.0.0.1", 0)
      port = server.addr[1]
      Sparoid.auth(key, hmac_key, "127.0.0.1", port)
      msg, = server.recvfrom(512)

      assert_equal 96, msg.bytesize
    end
  end

  def test_it_opens_for_passed_in_ip_argument
    key = "0000000000000000000000000000000000000000000000000000000000000000"
    hmac_key = "0000000000000000000000000000000000000000000000000000000000000000"
    UDPSocket.open do |server|
      server.bind("127.0.0.1", 0)
      port = server.addr[1]
      s = Sparoid::Instance.new
      s.stub(:public_ip, ->(*_) { raise "public_ip method not expected to be called" }) do
        s.auth(key, hmac_key, "127.0.0.1", port, open_for_ip: "127.0.1.1")
      end
    end
  end

  def test_it_sends_message_with_prepopulated_cache_file
    cache_file = Tempfile.new
    cache_file.write("127.0.0.1\n")
    cache_file.close
    # Touch the file to make it recent (within cache validity period)
    FileUtils.touch(cache_file.path)
    Sparoid.stub_const(:SPAROID_CACHE_PATH, cache_file.path) do
      assert_output(nil, "") { test_it_sends_message }
    end
  ensure
    cache_file.unlink
  end

  def test_it_resolves_public_ip_only_once_per_instance
    s = Sparoid::Instance.new
    call_count = 0
    mock_ips = [Resolv::IPv4.create("203.0.113.1"), Resolv::IPv6.create("2001:db8::1")]

    # Define a method on the singleton class that tracks calls
    s.define_singleton_method(:fetch_public_ip) do
      call_count += 1
      mock_ips
    end

    # Override public_ip to use our tracking method
    s.define_singleton_method(:public_ip) do |*_args|
      @public_ip ||= fetch_public_ip
    end

    2.times do
      ips = s.public_ip
      assert_equal mock_ips, ips
    end
    assert_equal 1, call_count, "public_ip should only resolve once"
  end

  def test_it_raises_resolve_error_on_dns_socket_error
    key = "0000000000000000000000000000000000000000000000000000000000000000"
    hmac_key = "0000000000000000000000000000000000000000000000000000000000000000"
    open_for_ip = Resolv::IPv4.create("1.1.1.1")
    error = ->(*_) { raise SocketError, "getaddrinfo: Name or service not known" }

    Addrinfo.stub(:getaddrinfo, error) do
      assert_raises(Sparoid::ResolvError) do
        Sparoid::Instance.new.auth(key, hmac_key, "127.0.0.1", 1337, open_for_ip: open_for_ip)
      end
    end
  end

  def test_instance_sends_message
    key = "0000000000000000000000000000000000000000000000000000000000000000"
    hmac_key = "0000000000000000000000000000000000000000000000000000000000000000"
    s = Sparoid::Instance.new
    UDPSocket.open do |server|
      server.bind("127.0.0.1", 0)
      port = server.addr[1]
      s.auth(key, hmac_key, "127.0.0.1", port)
      msg, = server.recvfrom(512)

      assert_equal 96, msg.bytesize
    end
  end

  def test_message_v2_ipv4
    ip = Resolv::IPv4.create("192.168.1.1")
    msg = Sparoid.send(:message_v2, ip, 24)
    # version(4) + timestamp(8) + nonce(16) + family(1) + ip(4) + range(1) = 34
    assert_equal 34, msg.bytesize
  end

  def test_message_v2_ipv6
    ip = Resolv::IPv6.create("2001:db8::1")
    msg = Sparoid.send(:message_v2, ip, 64)
    # version(4) + timestamp(8) + nonce(16) + family(1) + ip(16) + range(1) = 46
    assert_equal 46, msg.bytesize
  end

  def test_string_to_ip_ipv4
    ip = Sparoid.send(:string_to_ip, "192.168.1.1")
    assert_instance_of Resolv::IPv4, ip
    assert_equal "192.168.1.1", ip.to_s
  end

  def test_string_to_ip_ipv6
    ip = Sparoid.send(:string_to_ip, "2001:db8::1")
    assert_instance_of Resolv::IPv6, ip
  end

  def test_string_to_ip_invalid
    assert_raises(ArgumentError) do
      Sparoid.send(:string_to_ip, "not-an-ip")
    end
  end

  def test_create_messages_ipv4_returns_two_messages
    ip = Resolv::IPv4.create("127.0.0.1")
    messages = Sparoid.send(:create_messages, ip)
    # IPv4 returns both v2 and v1 message formats
    assert_equal 2, messages.size
  end

  def test_generate_messages_v1_message_first
    # v1 message (32 bytes) should come before v2 message (34 bytes) for backward compatibility
    messages = Sparoid.send(:generate_messages, "127.0.0.1")
    assert_equal 32, messages[0].bytesize
    assert_equal 34, messages[1].bytesize
  end

  def test_create_messages_ipv6_returns_one_message
    ip = Resolv::IPv6.create("::1")
    messages = Sparoid.send(:create_messages, ip)
    # IPv6 only returns v2 message format
    assert_equal 1, messages.size
  end

  def test_encrypt_raises_on_invalid_key_length
    short_key = "0000"
    assert_raises(ArgumentError) do
      Sparoid.send(:encrypt, short_key, "test data")
    end
  end

  def test_prefix_hmac_raises_on_invalid_key_length
    short_key = "0000"
    assert_raises(ArgumentError) do
      Sparoid.send(:prefix_hmac, short_key, "test data")
    end
  end

  def test_keygen_outputs_keys
    output = capture_io { Sparoid.keygen }.first
    assert_match(/^key = [0-9a-f]{64}$/, output.lines[0].chomp)
    assert_match(/^hmac-key = [0-9a-f]{64}$/, output.lines[1].chomp)
  end
end
