#!/usr/bin/env ruby

# Script to update all integration tests to support mock mode
# This demonstrates the pattern to follow for each test file

puts "=== Test Update Pattern for Mock Support ==="
puts
puts "To update each test file for offline/mock support, follow this pattern:"
puts

example = <<~RUBY
# 1. Add mock_helper require at the top
require_relative 'mock_helper'

# 2. Update initialization to support mock mode
class YourTestClass
  def initialize
    @config_file = File.expand_path('../../config.base64', __dir__)
    
    # Allow tests to run in mock mode without config
    if !MockHelper.mock_mode? && !File.exist?(@config_file)
      puts "❌ ERROR: config.base64 not found (set KEEPER_MOCK_MODE=true for offline testing)"
      exit 1
    end
    
    # Use mock helper for all SDK initialization
    @sm = MockHelper.create_mock_secrets_manager
    
    # Or if you need custom config:
    config_data = MockHelper.get_config
    # ... modify config_data as needed ...
    @sm = MockHelper.create_mock_secrets_manager(config_data)
  end
end

# 3. For error testing, use mock error methods
def test_network_errors
  if MockHelper.mock_mode?
    # In mock mode, simulate the error
    begin
      MockHelper.mock_network_error
    rescue => e
      puts "✅ Mock network error: #{e.message}"
    end
  else
    # Real network test with invalid hostname
    # ... existing code ...
  end
end

# 4. For file operations (not yet implemented)
def test_file_upload
  if MockHelper.mock_mode?
    # Use mock file operations
    file_info = MockHelper.mock_file_upload('record_uid', {
      name: 'test.pdf',
      content: 'file content',
      mime_type: 'application/pdf'
    })
    puts "✅ Mock file uploaded: #{file_info['fileUid']}"
  else
    puts "⚠️  File upload API not yet implemented"
  end
end
RUBY

puts example

# List of files that need updating
files_to_update = [
  'test_error_handling.rb',
  'test_file_operations.rb', 
  'test_totp.rb',
  'test_batch_operations.rb',
  'test_advanced_search.rb',
  'test_performance.rb',
  'quick_test.rb',
  'full_crud_test.rb'
]

puts "\nFiles that need updating:"
files_to_update.each do |file|
  puts "  - #{file}"
end

puts "\nTo run tests in mock mode:"
puts "  export KEEPER_MOCK_MODE=true"
puts "  ruby test/integration/run_all_tests.rb --all"
puts
puts "To run tests with real API (requires config.base64):"
puts "  unset KEEPER_MOCK_MODE"
puts "  ruby test/integration/run_all_tests.rb --all"