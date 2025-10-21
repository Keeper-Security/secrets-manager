#!/usr/bin/env ruby

# This script captures real API responses for creating mock data
# Run this once to generate fixture data for offline tests

require_relative '../../lib/keeper_secrets_manager'
require 'json'
require 'fileutils'
require 'securerandom'
require 'date'

# Setup
FIXTURES_DIR = File.expand_path('../../spec/fixtures', __dir__)
FileUtils.mkdir_p(FIXTURES_DIR)

# Load config
config_base64 = File.read(File.expand_path('../../config.base64', __dir__)).strip
config_json = Base64.decode64(config_base64)
config_data = JSON.parse(config_json)

storage = KeeperSecretsManager::Storage::InMemoryStorage.new(config_data)
secrets_manager = KeeperSecretsManager.new(config: storage)

puts '=== Keeper Secrets Manager - Response Capture ==='
puts 'This will create test records and capture responses for offline testing'
puts

responses = {}
test_records = []
test_folder = nil

begin
  # 1. Capture existing records
  puts '1. Capturing existing records...'
  all_records = secrets_manager.get_secrets
  responses['get_all_records'] = all_records.map do |record|
    {
      uid: record.uid,
      title: record.title,
      type: record.type,
      fields_count: record.fields.length,
      custom_count: record.custom.length,
      has_files: !record.files.empty?
    }
  end
  puts "   Found #{all_records.length} existing records"

  # Save sample record structure if any exist
  if all_records.any?
    sample_record = all_records.first
    responses['sample_record'] = {
      uid: sample_record.uid,
      title: sample_record.title,
      type: sample_record.type,
      fields: sample_record.fields.map { |f| { type: f['type'], label: f['label'] } },
      custom: sample_record.custom.map { |f| { type: f['type'], label: f['label'] } }
    }
  end

  # 2. Capture folders
  puts "\n2. Capturing folders..."
  folders = secrets_manager.get_folders
  responses['folders'] = folders.map do |folder|
    {
      uid: folder.uid,
      name: folder.name,
      type: folder.folder_type
    }
  end
  puts "   Found #{folders.length} folders"

  # 3. Create test folder
  puts "\n3. Creating test folder..."
  test_folder_name = "Ruby SDK Test #{Time.now.strftime('%Y%m%d_%H%M%S')}"
  test_folder_uid = secrets_manager.create_folder(test_folder_name)
  test_folder = { uid: test_folder_uid, name: test_folder_name }
  puts "   Created folder: #{test_folder_name} (#{test_folder_uid})"

  # 4. Create various test records
  puts "\n4. Creating test records..."

  # Simple login record
  puts '   Creating login record...'
  login_record = KeeperSecretsManager::Dto::KeeperRecord.new(
    title: "Test Login #{SecureRandom.hex(4)}",
    type: 'login',
    fields: [
      { 'type' => 'login', 'value' => ['testuser'] },
      { 'type' => 'password', 'value' => ['TestPass123!'] },
      { 'type' => 'url', 'value' => ['https://example.com'] }
    ],
    notes: 'Created by Ruby SDK test suite'
  )
  login_uid = secrets_manager.create_secret(login_record,
                                            KeeperSecretsManager::Dto::CreateOptions.new(folder_uid: test_folder_uid))
  test_records << { uid: login_uid, type: 'login' }
  puts "   ✓ Login record created: #{login_uid}"

  # Complex record with many field types
  puts '   Creating complex record...'
  complex_record = KeeperSecretsManager::Dto::KeeperRecord.new(
    title: "Test Complex #{SecureRandom.hex(4)}",
    type: 'login',
    fields: [
      { 'type' => 'login', 'value' => ['admin'] },
      { 'type' => 'password', 'value' => ['ComplexPass123!'] },
      { 'type' => 'url', 'value' => ['https://complex.example.com', 'https://backup.example.com'] },
      { 'type' => 'host', 'value' => [{ 'hostName' => '192.168.1.100', 'port' => '22' }], 'label' => 'SSH Server' },
      { 'type' => 'phone', 'value' => [{ 'region' => 'US', 'number' => '555-0123', 'type' => 'Mobile' }] },
      { 'type' => 'name', 'value' => [{ 'first' => 'John', 'middle' => 'Q', 'last' => 'Tester' }] },
      { 'type' => 'address', 'value' => [{
        'street1' => '123 Test St',
        'street2' => 'Suite 456',
        'city' => 'Test City',
        'state' => 'TC',
        'zip' => '12345',
        'country' => 'US'
      }] }
    ],
    custom: [
      { 'type' => 'text', 'label' => 'Environment', 'value' => ['Production'] },
      { 'type' => 'text', 'label' => 'Project', 'value' => ['Ruby SDK Testing'] },
      { 'type' => 'date', 'label' => 'Created Date', 'value' => [Date.today.to_time.to_i * 1000] }
    ]
  )
  complex_uid = secrets_manager.create_secret(complex_record,
                                              KeeperSecretsManager::Dto::CreateOptions.new(folder_uid: test_folder_uid))
  test_records << { uid: complex_uid, type: 'complex' }
  puts "   ✓ Complex record created: #{complex_uid}"

  # Server/SSH record
  puts '   Creating server record...'
  server_record = KeeperSecretsManager::Dto::KeeperRecord.new(
    title: "Test Server #{SecureRandom.hex(4)}",
    type: 'sshKeys',
    fields: [
      { 'type' => 'login', 'value' => ['root'] },
      { 'type' => 'host', 'value' => [{ 'hostName' => '10.0.0.50', 'port' => '2222' }] },
      { 'type' => 'sshKey', 'value' => [{
        'privateKey' => "-----BEGIN PRIVATE KEY-----\nTEST_PRIVATE_KEY_DATA\n-----END PRIVATE KEY-----",
        'publicKey' => 'ssh-rsa AAAAB3NzaC1yc2ETEST test@example.com'
      }] }
    ],
    custom: [
      { 'type' => 'text', 'label' => 'OS', 'value' => ['Ubuntu 22.04'] },
      { 'type' => 'text', 'label' => 'Location', 'value' => ['us-east-1'] }
    ]
  )
  server_uid = secrets_manager.create_secret(server_record,
                                             KeeperSecretsManager::Dto::CreateOptions.new(folder_uid: test_folder_uid))
  test_records << { uid: server_uid, type: 'server' }
  puts "   ✓ Server record created: #{server_uid}"

  # 5. Test record retrieval
  puts "\n5. Testing record retrieval..."

  # Get specific record
  retrieved_records = secrets_manager.get_secrets([login_uid])
  if retrieved_records.any?
    retrieved = retrieved_records.first
    responses['retrieved_record'] = {
      uid: retrieved.uid,
      title: retrieved.title,
      field_count: retrieved.fields.length
    }
    puts '   ✓ Retrieved record by UID'
  end

  # Get by title
  by_title = secrets_manager.get_secrets_by_title(login_record.title)
  puts "   ✓ Found #{by_title.length} records by title"

  # 6. Test notation
  puts "\n6. Testing notation..."
  notation_tests = []

  # Test various notations
  notations = [
    "keeper://#{login_uid}/field/login",
    "keeper://#{login_uid}/field/password",
    "keeper://#{complex_uid}/field/host[hostName]",
    "keeper://#{complex_uid}/custom_field/Environment"
  ]

  notations.each do |notation|
    value = secrets_manager.get_notation(notation)
    notation_tests << { notation: notation, success: true, value_type: value.class.name }
    puts "   ✓ Notation worked: #{notation}"
  rescue StandardError => e
    notation_tests << { notation: notation, success: false, error: e.message }
    puts "   ✗ Notation failed: #{notation} - #{e.message}"
  end
  responses['notation_tests'] = notation_tests

  # 7. Test record update
  puts "\n7. Testing record update..."
  if retrieved_records.any?
    record_to_update = retrieved_records.first
    original_notes = record_to_update.notes

    record_to_update.notes = "Updated by Ruby SDK at #{Time.now}"
    record_to_update.set_field('url', 'https://updated.example.com')

    secrets_manager.update_secret(record_to_update)
    puts '   ✓ Record updated successfully'

    # Verify update
    updated = secrets_manager.get_secrets([record_to_update.uid]).first
    puts '   ✓ Update verified' if updated.notes != original_notes
  end

  # 8. Test file operations (create a record with file)
  puts "\n8. Testing file operations..."
  file_content = "This is a test file created by Ruby SDK\nTimestamp: #{Time.now}\n"
  file_name = 'test_document.txt'

  # NOTE: File upload requires additional implementation
  # For now, we'll create a record that could have files
  file_record = KeeperSecretsManager::Dto::KeeperRecord.new(
    title: "Test with Files #{SecureRandom.hex(4)}",
    type: 'login',
    fields: [
      { 'type' => 'login', 'value' => ['fileuser'] },
      { 'type' => 'password', 'value' => ['FilePass123!'] }
    ],
    notes: 'This record would have file attachments'
  )
  file_uid = secrets_manager.create_secret(file_record,
                                           KeeperSecretsManager::Dto::CreateOptions.new(folder_uid: test_folder_uid))
  test_records << { uid: file_uid, type: 'file_record' }
  puts '   ✓ File record created (file upload would go here)'

  # 9. Save all responses
  puts "\n9. Saving fixture data..."

  # Save responses
  File.write(
    File.join(FIXTURES_DIR, 'api_responses.json'),
    JSON.pretty_generate(responses)
  )

  # Save test record info
  File.write(
    File.join(FIXTURES_DIR, 'test_records.json'),
    JSON.pretty_generate({
                           folder: test_folder,
                           records: test_records,
                           timestamp: Time.now.to_s
                         })
  )

  puts "   ✓ Fixtures saved to #{FIXTURES_DIR}"

  # 10. Test deletion
  puts "\n10. Testing deletion..."
  puts '   Delete test records? (y/n)'
  if gets.chomp.downcase == 'y'
    # Delete records
    test_records.each do |record|
      secrets_manager.delete_secret(record[:uid])
      puts "   ✓ Deleted record: #{record[:uid]}"
    rescue StandardError => e
      puts "   ✗ Failed to delete record: #{e.message}"
    end

    # Delete folder
    if test_folder_uid
      begin
        secrets_manager.delete_folder(test_folder_uid, force: true)
        puts "   ✓ Deleted folder: #{test_folder_uid}"
      rescue StandardError => e
        puts "   ✗ Failed to delete folder: #{e.message}"
      end
    end
  else
    puts '   Skipping deletion - records remain for manual inspection'
  end
rescue StandardError => e
  puts "\n✗ Error: #{e.class} - #{e.message}"
  puts e.backtrace.first(5)
ensure
  # Save any data we collected
  unless responses.empty?
    File.write(
      File.join(FIXTURES_DIR, 'api_responses_partial.json'),
      JSON.pretty_generate(responses)
    )
  end
end

puts "\n=== Response capture complete ==="
puts "Fixture data saved to: #{FIXTURES_DIR}"
puts 'You can now run offline tests using this captured data'
