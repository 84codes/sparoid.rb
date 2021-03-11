# frozen_string_literal: true

require "test_helper"

class SparoidTest < Minitest::Test
  def test_that_it_has_a_version_number
    refute_nil ::Sparoid::VERSION
  end

  def test_it_resolves_public_ip
    assert Sparoid.public_ip.to_s =~ /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/
  end

  def test_it_creates_a_message
    assert_equal 32, Sparoid.message(Sparoid.public_ip).bytesize
  end

  def test_it_encrypts_messages
    key = "0000000000000000000000000000000000000000000000000000000000000000"
    assert_equal 64, Sparoid.encrypt(key, Sparoid.message(Sparoid.public_ip)).bytesize
  end

  def test_it_adds_hmac
    key = "0000000000000000000000000000000000000000000000000000000000000000"
    msg = Sparoid.encrypt(key, Sparoid.message(Sparoid.public_ip))
    hmac_key = "0000000000000000000000000000000000000000000000000000000000000000"
    assert_equal 96, Sparoid.prefix_hmac(hmac_key, msg).bytesize
  end

  def test_it_sends_message
    key = "0000000000000000000000000000000000000000000000000000000000000000"
    hmac_key = "0000000000000000000000000000000000000000000000000000000000000000"
    UDPSocket.open do |server|
      server.bind("127.0.0.1", 0)
      port = server.addr[1]
      Sparoid.send(key, hmac_key, "127.0.0.1", port)
      msg, = server.recvfrom(512)
      assert_equal 96, msg.bytesize
    end
  end
end
