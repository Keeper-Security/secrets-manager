#!/usr/bin/env ruby

# Master test runner for all integration tests

require 'optparse'
begin
  require 'colorize'
rescue StandardError
  nil
end

puts '=== Keeper Secrets Manager Ruby SDK - Integration Test Suite ==='
puts '=' * 60

# Define test files
TEST_FILES = {
  basic: {
    file: 'quick_test.rb',
    description: 'Basic CRUD operations'
  },
  error_handling: {
    file: 'test_error_handling.rb',
    description: 'Error handling and recovery'
  },
  file_operations: {
    file: 'test_file_operations.rb',
    description: 'File upload/download operations'
  },
  totp: {
    file: 'test_totp.rb',
    description: 'TOTP functionality'
  },
  batch: {
    file: 'test_batch_operations.rb',
    description: 'Batch operations'
  },
  search: {
    file: 'test_advanced_search.rb',
    description: 'Advanced search functionality'
  },
  performance: {
    file: 'test_performance.rb',
    description: 'Performance benchmarks'
  },
  full_crud: {
    file: 'full_crud_test.rb',
    description: 'Comprehensive CRUD test'
  }
}

# Parse command line options
options = {
  tests: [],
  verbose: false,
  stop_on_error: false
}

OptionParser.new do |opts|
  opts.banner = 'Usage: ruby run_all_tests.rb [options]'

  opts.on('-t', '--test TEST', "Run specific test (#{TEST_FILES.keys.join(', ')})") do |test|
    options[:tests] << test.to_sym
  end

  opts.on('-a', '--all', 'Run all tests') do
    options[:tests] = TEST_FILES.keys
  end

  opts.on('-v', '--verbose', 'Verbose output') do
    options[:verbose] = true
  end

  opts.on('-s', '--stop-on-error', 'Stop on first error') do
    options[:stop_on_error] = true
  end

  opts.on('-l', '--list', 'List available tests') do
    puts "\nAvailable tests:"
    TEST_FILES.each do |key, info|
      puts "  #{key.to_s.ljust(15)} - #{info[:description]}"
    end
    exit 0
  end

  opts.on('-h', '--help', 'Show this help') do
    puts opts
    exit 0
  end
end.parse!

# Default to all tests if none specified
options[:tests] = TEST_FILES.keys if options[:tests].empty?

# Check for config file
config_file = File.expand_path('../../config.base64', __dir__)
unless File.exist?(config_file)
  puts '❌ ERROR: config.base64 not found'
  puts 'Please create a config.base64 file with your Keeper credentials'
  exit 1
end

# Run selected tests
results = {}
start_time = Time.now

options[:tests].each do |test_key|
  test_info = TEST_FILES[test_key]
  unless test_info
    puts "❌ Unknown test: #{test_key}"
    next
  end

  test_file = File.join(__dir__, test_info[:file])
  unless File.exist?(test_file)
    puts "❌ Test file not found: #{test_file}"
    next
  end

  puts "\n" + '=' * 60
  puts "Running: #{test_info[:description]} (#{test_info[:file]})"
  puts '=' * 60

  begin
    test_start = Time.now

    # Run test in subprocess to isolate failures
    if options[:verbose]
      system("ruby -I ../../lib #{test_file}")
    else
      output = `ruby -I ../../lib #{test_file} 2>&1`

      # Show summary
      if $?.success?
        puts '✅ PASSED'
        results[test_key] = :passed
      else
        puts '❌ FAILED'
        results[test_key] = :failed
        puts "\nError output:"
        puts output.split("\n").last(10).join("\n")

        exit 1 if options[:stop_on_error]
      end
    end

    test_time = Time.now - test_start
    puts "⏱️  Time: #{test_time.round(2)}s"
  rescue StandardError => e
    puts "❌ ERROR: #{e.message}"
    results[test_key] = :error
    exit 1 if options[:stop_on_error]
  end
end

# Summary
total_time = Time.now - start_time
puts "\n" + '=' * 60
puts 'TEST SUMMARY'
puts '=' * 60

passed = results.values.count(:passed)
failed = results.values.count(:failed)
errors = results.values.count(:error)
total = results.length

puts "Total tests: #{total}"
puts "✅ Passed: #{passed}"
puts "❌ Failed: #{failed}" if failed > 0
puts "⚠️  Errors: #{errors}" if errors > 0
puts "\nTotal time: #{total_time.round(2)}s"

# Detailed results
if options[:verbose] || failed > 0 || errors > 0
  puts "\nDetailed results:"
  results.each do |test, result|
    status = case result
             when :passed then '✅ PASSED'
             when :failed then '❌ FAILED'
             when :error then '⚠️  ERROR'
             end
    puts "  #{test.to_s.ljust(15)} - #{status}"
  end
end

# Exit code
exit_code = (failed + errors) > 0 ? 1 : 0
exit exit_code
