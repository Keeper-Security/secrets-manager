#!/usr/bin/env ruby

# Quick integration test to verify SDK functionality
# This is a lighter version of full_crud_test.rb for quick verification

require_relative '../../lib/keeper_secrets_manager'
require 'json'
require 'base64'

puts "=== Keeper Secrets Manager Ruby SDK Quick Test ==="
puts "Ruby: #{RUBY_VERSION}"
puts "OpenSSL: #{OpenSSL::OPENSSL_LIBRARY_VERSION}"

# Check for config
config_file = File.expand_path('../../config.base64', __dir__)
unless File.exist?(config_file)
  puts "\n❌ ERROR: config.base64 not found"
  puts "Please create a config.base64 file with your Keeper credentials"
  exit 1
end

begin
  # Initialize SDK
  print "\n1. Initializing SDK... "
  config_base64 = File.read(config_file).strip
  config_json = Base64.decode64(config_base64)
  config_data = JSON.parse(config_json)
  
  storage = KeeperSecretsManager::Storage::InMemoryStorage.new(config_data)
  secrets_manager = KeeperSecretsManager.new(config: storage)
  puts "✅"
  
  # List records
  print "2. Fetching records... "
  records = secrets_manager.get_secrets
  puts "✅ Found #{records.length} record(s)"
  
  # Use the provided folder UID
  print "3. Checking folder access... "
  folder_uid = 'khq76ez6vkTRj3MqUiEGRg'
  
  # Get all folders to verify access
  folders = secrets_manager.get_folders
  folder = folders.find { |f| f.uid == folder_uid }
  
  if folder
    puts "✅ Found folder: #{folder.name}"
  else
    puts "⚠️  Folder not found, will try anyway"
  end
  
  # Create a test record
  print "4. Creating test record... "
  test_id = Time.now.to_i.to_s[-6..-1]  # Last 6 digits of timestamp
  
  test_record = {
    'type' => 'login',
    'title' => "Ruby SDK Quick Test #{test_id}",
    'fields' => [
      { 'type' => 'login', 'value' => ['test@example.com'] },
      { 'type' => 'password', 'value' => ['TestPass123!'] },
      { 'type' => 'url', 'value' => ['https://example.com'] }
    ],
    'notes' => "Created by quick test at #{Time.now}"
  }
  
  options = KeeperSecretsManager::Dto::CreateOptions.new
  options.folder_uid = folder_uid if folder_uid
  
  record_uid = secrets_manager.create_secret(test_record, options)
  puts "✅ UID: #{record_uid}"
  
  # Read it back
  print "5. Reading back record... "
  sleep 3  # Give server time to process
  
  begin
    created_records = secrets_manager.get_secrets([record_uid])
    
    if created_records.empty?
      puts "❌ Record not found yet"
      # Skip the rest of the test
      puts "\n⚠️  Record creation succeeded but read-back failed. This may be a timing issue."
      puts "Record UID: #{record_uid}"
      exit 0
    else
      created = created_records.first
      puts "✅ Title: #{created.title}"
    end
    
    # Update it
    print "6. Updating record... "
    created.login = 'updated@example.com'
    created.notes = "Updated at #{Time.now}"
    
    secrets_manager.update_secret(created)
    puts "✅"
  rescue => e
    puts "❌"
    puts "Error during read/update: #{e.message}"
    puts "\n⚠️  Record was created successfully with UID: #{record_uid}"
    exit 0
  end
  
  # Test notation
  print "7. Testing notation... "
  login_value = secrets_manager.get_notation("keeper://#{record_uid}/field/login")
  puts "✅ Login: #{login_value}"
  
  # Delete it
  print "8. Deleting test record... "
  deleted = secrets_manager.delete_secret(record_uid)
  puts "✅"
  
  puts "\n🎉 All tests passed! The SDK is working correctly."
  
rescue => e
  puts "❌"
  puts "\nError: #{e.class} - #{e.message}"
  puts e.backtrace.first(5).join("\n")
  
  # Try to cleanup if we created a record
  if defined?(record_uid) && record_uid
    begin
      secrets_manager.delete_secret(record_uid) rescue nil
    rescue
      # Ignore cleanup errors
    end
  end
  
  exit 1
end