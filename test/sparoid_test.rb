# frozen_string_literal: true

require "test_helper"

# rubocop:disable GitlabSecurity/PublicSend
class SparoidTest < Minitest::Test
  def test_that_it_has_a_version_number
    refute_nil ::Sparoid::VERSION
  end

  def test_it_resolves_public_ip
    assert Sparoid.send(:public_ip).to_s =~ /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/
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

  def test_it_sends_message_with_empty_cache_file
    Sparoid.stub_const(:SPAROID_CACHE_PATH, Tempfile.new.path) do
      assert_output(nil, "") { test_it_sends_message }
    end
  end

  def test_it_resolves_public_ip_only_once_per_instance
    dns = MiniTest::Mock.new
    dns.expect :getresource, Resolv::IPv4.create("1.1.1.1"), ["myip.opendns.com", Resolv::DNS::Resource::IN::A]
    Resolv::DNS.stub(:open, ->(_, &blk) { blk.call dns }) do
      s = Sparoid::Instance.new
      2.times do
        s.send(:public_ip)
      end
    end
    dns.verify
  end
end
# rubocop:enable GitlabSecurity/PublicSend
