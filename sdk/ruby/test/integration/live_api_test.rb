#!/usr/bin/env ruby

require_relative 'lib/keeper_secrets_manager'
require 'base64'
require 'json'

# Read config from file
config_base64 = File.read('/Users/mustinov/Source/secrets-manager/sdk/ruby/config.base64').strip
config_json = Base64.decode64(config_base64)
config_data = JSON.parse(config_json)

puts "Config loaded successfully"
puts "Hostname: #{config_data['hostname']}"
puts "Client ID: #{config_data['clientId'][0..20]}..."

# Create storage with config
storage = KeeperSecretsManager::Storage::InMemoryStorage.new(config_data)

# Initialize SDK
begin
  secrets_manager = KeeperSecretsManager.new(config: storage)
  puts "\n✓ SDK initialized successfully"
rescue => e
  puts "\n✗ Failed to initialize SDK: #{e.message}"
  exit 1
end

# Test 1: Get all secrets
puts "\n=== Test 1: Retrieving all secrets ==="
begin
  records = secrets_manager.get_secrets
  puts "✓ Retrieved #{records.length} records"
  
  records.each_with_index do |record, i|
    puts "\n  Record #{i + 1}:"
    puts "    Title: #{record.title}"
    puts "    Type: #{record.type}"
    puts "    UID: #{record.uid}"
    puts "    Fields: #{record.fields.length}"
    puts "    Custom Fields: #{record.custom.length}"
  end
rescue => e
  puts "✗ Error retrieving secrets: #{e.class} - #{e.message}"
  puts e.backtrace.first(5)
end

# Test 2: Get specific record (if any exist)
if defined?(records) && records && records.any?
  puts "\n=== Test 2: Get specific record ==="
  begin
    first_uid = records.first.uid
    specific_records = secrets_manager.get_secrets([first_uid])
    
    if specific_records.any?
      record = specific_records.first
      puts "✓ Retrieved record: #{record.title}"
      
      # Show some fields
      if record.get_field('login')
        puts "  Login: #{record.get_field_value_single('login')}"
      end
      
      if record.get_field('url')
        puts "  URL: #{record.get_field_value_single('url')}"
      end
    end
  rescue => e
    puts "✗ Error getting specific record: #{e.message}"
  end
end

# Test 3: Notation (if records exist)
if defined?(records) && records && records.any?
  puts "\n=== Test 3: Testing notation ==="
  
  record = records.first
  
  # Test type selector
  begin
    type_value = secrets_manager.get_notation("keeper://#{record.uid}/type")
    puts "✓ Type via notation: #{type_value}"
  rescue => e
    puts "✗ Type notation error: #{e.message}"
  end
  
  # Test title selector
  begin
    title_value = secrets_manager.get_notation("keeper://#{record.uid}/title")
    puts "✓ Title via notation: #{title_value}"
  rescue => e
    puts "✗ Title notation error: #{e.message}"
  end
  
  # Test field selector if login exists
  if record.get_field('login')
    begin
      login_value = secrets_manager.get_notation("keeper://#{record.uid}/field/login")
      puts "✓ Login via notation: #{login_value}"
    rescue => e
      puts "✗ Login notation error: #{e.message}"
    end
  end
end

# Test 4: Get folders
puts "\n=== Test 4: Retrieving folders ==="
begin
  folders = secrets_manager.get_folders
  puts "✓ Retrieved #{folders.length} folders"
  
  folders.each do |folder|
    puts "  - #{folder.name} (#{folder.uid})"
  end
rescue => e
  puts "✗ Error retrieving folders: #{e.message}"
end

# Test 5: Search by title
if defined?(records) && records && records.any?
  puts "\n=== Test 5: Search by title ==="
  begin
    title_to_find = records.first.title
    found_records = secrets_manager.get_secrets_by_title(title_to_find)
    puts "✓ Found #{found_records.length} records with title '#{title_to_find}'"
  rescue => e
    puts "✗ Error searching by title: #{e.message}"
  end
end

puts "\n=== Summary ==="
puts "All basic functionality tests completed!"
puts "Note: Create/Update/Delete operations not tested to avoid modifying data"