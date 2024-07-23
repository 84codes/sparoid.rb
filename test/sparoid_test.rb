# frozen_string_literal: true

require "test_helper"

class SparoidTest < Minitest::Test
  def test_that_it_has_a_version_number
    refute_nil ::Sparoid::VERSION
  end

  def test_it_resolves_public_ip
    assert_match(/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/, Sparoid.send(:public_ip).to_s)
  end

  def test_it_creates_a_message
    assert_equal 32, Sparoid.send(:message, Sparoid.send(:public_ip)).bytesize
  end

  def test_it_encrypts_messages
    key = "0000000000000000000000000000000000000000000000000000000000000000"

    assert_equal 64, Sparoid.send(:encrypt, key, Sparoid.send(:message, Sparoid.send(:public_ip))).bytesize
  end

  def test_it_adds_hmac
    key = "0000000000000000000000000000000000000000000000000000000000000000"
    msg = Sparoid.send(:encrypt, key, Sparoid.send(:message, Sparoid.send(:public_ip)))
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

  def test_it_sends_message_with_empty_cache_file
    Sparoid.stub_const(:SPAROID_CACHE_PATH, Tempfile.new.path) do
      assert_output(nil, "") { test_it_sends_message }
    end
  end

  def test_it_resolves_public_ip_only_once_per_instance # rubocop:disable Metrics/AbcSize, Metrics/MethodLength
    server = TCPServer.new "127.0.0.1", 0
    host = server.addr[3]
    port = server.addr[1]
    Thread.new do
      client = server.accept
      client_ip = client.addr[3]
      assert_equal "GET / HTTP/1.1", client.readline(chomp: true)
      assert_match "Host: ", client.readline(chomp: true)
      assert_equal "Connection: close", client.readline(chomp: true)

      client.print "HTTP/1.1 200 OK\r\n"
      client.print "Content-Length: #{client_ip.bytesize}\r\n"
      client.print "\r\n"
      client.print client_ip
      client.close
      server.close
    end

    s = Sparoid::Instance.new
    2.times do
      ip = s.public_ip host, port
      assert_equal Resolv::IPv4.create("127.0.0.1"), ip
    end
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
end
