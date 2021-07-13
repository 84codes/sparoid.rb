# frozen_string_literal: true

require "tempfile"
ENV["SPAROID_CACHE_PATH"] ||= Tempfile.new("sparoid_cache").path

$LOAD_PATH.unshift File.expand_path("../lib", __dir__)
require "sparoid"

require "minitest/stub_const"
require "minitest/reporters"
require "minitest/autorun"
MiniTest::Reporters.use!(MiniTest::Reporters::SpecReporter.new)
