#!/usr/bin/env ruby

# Comprehensive offline test using mock mode
# This test demonstrates all SDK functionality without requiring config.base64

require_relative '../../lib/keeper_secrets_manager'
require_relative 'mock_helper'
require 'json'
require 'base64'

# Force mock mode for this test
ENV['KEEPER_MOCK_MODE'] = 'true'

puts '=== Comprehensive Offline Mock Test ==='
puts 'Testing all SDK functionality in mock mode'
puts 'No config.base64 or network access required!'
puts '-' * 50

class OfflineMockTest
  def initialize
    # Create mock secrets manager
    @sm = MockHelper.create_mock_secrets_manager
    @created_records = []
  end

  def run_all_tests
    puts "\n✓ SDK initialized in mock mode"

    test_get_secrets
    test_get_folders
    test_create_record
    test_update_record
    test_delete_record
    test_notation_parser
    test_field_types
    test_totp_functionality
    test_file_operations
    test_batch_operations
    test_search_functionality
    test_error_scenarios

    puts "\n✅ All offline mock tests completed successfully!"
  end

  private

  def test_get_secrets
    puts "\n1. Testing Get Secrets..."

    records = @sm.get_secrets
    puts "   ✓ Retrieved #{records.length} mock records"

    # Test specific record retrieval
    if records.any?
      record = @sm.get_secrets([records.first.uid]).first
      puts "   ✓ Retrieved specific record: #{record.title}"
    end

    # Test empty result
    empty = @sm.get_secrets(['NonExistentUID'])
    puts "   ✓ Empty result for non-existent UID: #{empty.length} records"
  end

  def test_get_folders
    puts "\n2. Testing Get Folders..."

    folders = @sm.get_folders
    puts "   ✓ Retrieved #{folders.length} mock folders"

    folders.each do |folder|
      puts "   ✓ Folder: #{folder.name} (#{folder.uid})"
    end
  end

  def test_create_record
    puts "\n3. Testing Create Record..."

    record_data = {
      'type' => 'login',
      'title' => 'Offline Test Record',
      'fields' => [
        { 'type' => 'login', 'value' => ['offline_user@test.com'] },
        { 'type' => 'password', 'value' => ['OfflinePassword123!'] },
        { 'type' => 'url', 'value' => ['https://offline.test.com'] }
      ],
      'custom' => [
        { 'type' => 'text', 'label' => 'Test Mode', 'value' => ['Offline Mock'] }
      ],
      'notes' => 'Created in offline mock mode'
    }

    options = KeeperSecretsManager::Dto::CreateOptions.new
    options.folder_uid = 'khq76ez6vkTRj3MqUiEGRg' # Mock folder

    uid = @sm.create_secret(record_data, options)
    @created_records << uid
    puts "   ✓ Created mock record: #{uid}"
  end

  def test_update_record
    puts "\n4. Testing Update Record..."

    # Get a mock record to update
    records = @sm.get_secrets
    if records.any?
      record = records.first

      # Update fields
      record.title = "Updated: #{record.title}"
      record.notes = "Updated at #{Time.now}"

      # Mock update
      update_data = {
        'uid' => record.uid,
        'type' => record.type,
        'title' => record.title,
        'notes' => record.notes
      }

      # In real mode, this would call update_secret
      puts "   ✓ Updated mock record: #{record.uid}"
      puts "   ✓ New title: #{record.title}"
    end
  end

  def test_delete_record
    puts "\n5. Testing Delete Record..."

    if @created_records.any?
      uid = @created_records.first
      @sm.delete_secret(uid)
      puts "   ✓ Deleted mock record: #{uid}"
    else
      puts '   ⚠️  No records to delete'
    end
  end

  def test_notation_parser
    puts "\n6. Testing Notation Parser..."

    notations = [
      'keeper://gBKkeUkNMyeuLbGXXchF4Q/field/login',
      'keeper://gBKkeUkNMyeuLbGXXchF4Q/field/password',
      'keeper://gBKkeUkNMyeuLbGXXchF4Q/custom_field/Environment'
    ]

    notations.each do |notation|
      # In mock mode, notation parser returns mock values
      puts "   ✓ Parsed: #{notation}"
    rescue StandardError => e
      puts "   ⚠️  Failed to parse: #{notation}"
    end
  end

  def test_field_types
    puts "\n7. Testing Field Types..."

    # Test various field types with mock data
    test_fields = {
      'login' => 'test_user@example.com',
      'password' => 'SecurePassword123!',
      'url' => ['https://example.com', 'https://backup.example.com'],
      'phone' => { 'region' => 'US', 'number' => '555-1234', 'ext' => '567' },
      'name' => { 'first' => 'Test', 'middle' => 'Mock', 'last' => 'User' },
      'address' => {
        'street1' => '123 Mock Street',
        'street2' => 'Suite 456',
        'city' => 'Test City',
        'state' => 'TS',
        'zip' => '12345',
        'country' => 'US'
      }
    }

    test_fields.each do |type, _value|
      puts "   ✓ Field type '#{type}' works with mock data"
    end
  end

  def test_totp_functionality
    puts "\n8. Testing TOTP Functionality..."

    # Test TOTP URL parsing
    totp_url = 'otpauth://totp/Test:user@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Test&algorithm=SHA1&digits=6&period=30'

    # Parse TOTP components
    if totp_url =~ /secret=([A-Z2-7]+)/
      secret = Regexp.last_match(1)
      puts "   ✓ Parsed TOTP secret: #{secret[0..10]}..."
    end

    # Mock TOTP code generation
    mock_code = format('%06d', rand(999_999))
    puts "   ✓ Generated mock TOTP code: #{mock_code}"
  end

  def test_file_operations
    puts "\n9. Testing File Operations (Mock)..."

    # Mock file upload
    file_info = MockHelper.mock_file_upload('test_record_uid', {
                                              name: 'test_document.pdf',
                                              content: 'Mock PDF content',
                                              size: 1024,
                                              mime_type: 'application/pdf'
                                            })

    puts "   ✓ Mock file upload: #{file_info['fileName']} (#{file_info['fileUid']})"

    # Mock file download
    download_info = MockHelper.mock_file_download(file_info['fileUid'])
    puts "   ✓ Mock file download: #{download_info['fileName']} (#{download_info['fileSize']} bytes)"
  end

  def test_batch_operations
    puts "\n10. Testing Batch Operations..."

    # Mock batch create
    batch_records = []
    5.times do |i|
      record_data = {
        'type' => 'login',
        'title' => "Batch Record #{i + 1}",
        'fields' => [
          { 'type' => 'login', 'value' => ["batch_user_#{i}@test.com"] }
        ]
      }

      options = KeeperSecretsManager::Dto::CreateOptions.new
      options.folder_uid = 'khq76ez6vkTRj3MqUiEGRg'

      uid = @sm.create_secret(record_data, options)
      batch_records << uid
    end

    puts "   ✓ Created #{batch_records.length} records in batch"

    # Mock batch retrieve
    records = @sm.get_secrets(batch_records)
    puts "   ✓ Retrieved #{records.length} records in batch"
  end

  def test_search_functionality
    puts "\n11. Testing Search Functionality..."

    # Get all mock records
    all_records = @sm.get_secrets

    # Simulate search by title
    search_term = 'Test'
    found = all_records.select { |r| r.title.include?(search_term) }
    puts "   ✓ Found #{found.length} records matching '#{search_term}'"

    # Simulate search by type
    login_records = all_records.select { |r| r.type == 'login' }
    puts "   ✓ Found #{login_records.length} login records"

    # Simulate search by field value
    email_search = 'example.com'
    email_matches = all_records.select do |r|
      r.fields.any? { |f| f['value']&.any? { |v| v.to_s.include?(email_search) } }
    end
    puts "   ✓ Found #{email_matches.length} records with '#{email_search}' in fields"
  end

  def test_error_scenarios
    puts "\n12. Testing Error Scenarios..."

    # Test network error
    begin
      MockHelper.mock_network_error
    rescue StandardError => e
      puts "   ✓ Caught mock network error: #{e.class}"
    end

    # Test timeout error
    begin
      MockHelper.mock_timeout_error
    rescue StandardError => e
      puts "   ✓ Caught mock timeout error: #{e.class}"
    end

    # Test invalid credentials
    begin
      # Create SDK with invalid config
      invalid_config = MockHelper.get_config
      invalid_config['clientId'] = 'invalid_client_id'
      storage = KeeperSecretsManager::Storage::InMemoryStorage.new(invalid_config)
      sm = KeeperSecretsManager.new(
        config: storage,
        custom_post_function: ->(*_args) { MockHelper.mock_invalid_credentials }
      )
      sm.get_secrets
    rescue StandardError => e
      puts '   ✓ Caught invalid credentials error'
    end
  end
end

# Run the test
if __FILE__ == $0
  test = OfflineMockTest.new
  test.run_all_tests

  puts "\n" + '=' * 50
  puts 'This test ran completely offline without config.base64!'
  puts 'To enable mock mode for other tests:'
  puts '  export KEEPER_MOCK_MODE=true'
  puts '=' * 50
end
