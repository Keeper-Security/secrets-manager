#!/usr/bin/env ruby

# Verify that mock mode covers all test scenarios

require 'json'

puts '=== Mock Coverage Verification ==='
puts 'Checking that all test scenarios can run offline'
puts '-' * 50

# Read test files and extract test methods
test_coverage = {}

Dir.glob('test/integration/test_*.rb').each do |file|
  content = File.read(file)
  test_name = File.basename(file, '.rb')

  # Extract test methods
  test_methods = content.scan(/def (test_\w+)/).flatten

  # Check for API calls
  api_calls = {
    get_secrets: content.include?('.get_secrets'),
    get_folders: content.include?('.get_folders'),
    create_secret: content.include?('.create_secret'),
    update_secret: content.include?('.update_secret'),
    delete_secret: content.include?('.delete_secret'),
    file_upload: content.include?('upload_file') || content.include?('file_upload'),
    file_download: content.include?('download_file') || content.include?('file_download'),
    totp: content.include?('oneTimeCode') || content.include?('totp')
  }

  # Check for mock support
  has_mock_support = content.include?('mock_helper') || content.include?('MockHelper')

  test_coverage[test_name] = {
    methods: test_methods,
    api_calls: api_calls,
    has_mock_support: has_mock_support,
    requires_config: content.include?('config.base64 not found')
  }
end

# Summary
puts "\nTest File Coverage:"
puts

test_coverage.each do |test_name, info|
  puts "#{test_name}:"
  puts "  Test methods: #{info[:methods].length}"
  puts "  Has mock support: #{info[:has_mock_support] ? '✅' : '❌'}"
  puts "  Requires config: #{info[:requires_config] ? 'YES' : 'NO'}"

  api_usage = info[:api_calls].select { |_, used| used }
  puts "  API calls used: #{api_usage.keys.join(', ')}" if api_usage.any?
  puts
end

# Check mock_helper.rb coverage
puts "\nMock Helper Coverage:"
mock_helper = begin
  File.read('test/integration/mock_helper.rb')
rescue StandardError
  ''
end

mock_features = {
  'Config generation': mock_helper.include?('get_config'),
  'Get secrets mock': mock_helper.include?('mock_get_secrets_response'),
  'Get folders mock': mock_helper.include?('mock_get_folders_response'),
  'Create secret mock': mock_helper.include?('mock_create_secret_response'),
  'Update secret mock': mock_helper.include?('mock_update_secret_response'),
  'Delete secret mock': mock_helper.include?('mock_delete_secret_response'),
  'File operations mock': mock_helper.include?('mock_file_upload'),
  'Network error mock': mock_helper.include?('mock_network_error'),
  'Auth error mock': mock_helper.include?('mock_invalid_credentials'),
  'TOTP data': mock_helper.include?('oneTimeCode')
}

mock_features.each do |feature, covered|
  puts "  #{feature}: #{covered ? '✅' : '❌'}"
end

# Missing features
puts "\nPotential Gaps:"
missing = []

# Check for batch operations
missing << 'Batch operations (currently sequential in mock)' unless mock_helper.include?('batch')

# Check for search
missing << 'Server-side search (currently client-side filtering)' unless mock_helper.include?('search')

# Check for folder operations
missing << 'Folder creation/update/delete operations' unless mock_helper.include?('create_folder')

if missing.any?
  missing.each { |m| puts "  ⚠️  #{m}" }
else
  puts '  ✅ All major operations covered'
end

# Recommendations
puts "\nRecommendations:"
puts '1. Update all test files to use MockHelper'
puts "2. Add ENV['KEEPER_MOCK_MODE'] checks to test runners"
puts '3. Ensure Docker tests set KEEPER_MOCK_MODE when needed'
puts '4. Document both testing modes in README'

# Test the offline mock
puts "\nTesting offline mock functionality..."
system('KEEPER_MOCK_MODE=true ruby -I lib test/integration/test_offline_mock.rb > /dev/null 2>&1')
if $?.success?
  puts '✅ Offline mock test passes!'
else
  puts '❌ Offline mock test failed (may need Ruby 2.7+)'
end
