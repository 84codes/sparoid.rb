# frozen_string_literal: true

require "tempfile"
require "fileutils"
ENV["SPAROID_CACHE_PATH"] ||= Tempfile.new("sparoid_cache").path

$LOAD_PATH.unshift File.expand_path("../lib", __dir__)
require "sparoid"

require "minitest/stub_const"
require "minitest/autorun"
