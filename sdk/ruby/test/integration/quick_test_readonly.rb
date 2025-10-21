#!/usr/bin/env ruby

require 'keeper_secrets_manager'
require 'base64'
require 'json'

puts '=== Keeper Secrets Manager Ruby SDK Read-Only Test ==='
puts "Ruby: #{RUBY_VERSION}"
puts "OpenSSL: #{OpenSSL::OPENSSL_VERSION}"
puts ''

# Load configuration from file
config_file = File.join(File.dirname(__FILE__), '..', '..', 'config.base64')
unless File.exist?(config_file)
  puts "❌ Config file not found: #{config_file}"
  exit 1
end

config_base64 = File.read(config_file).strip

begin
  # Initialize SDK
  print '1. Initializing SDK... '
  config_json = Base64.decode64(config_base64)
  config_data = JSON.parse(config_json)

  storage = KeeperSecretsManager::Storage::InMemoryStorage.new(config_data)
  secrets_manager = KeeperSecretsManager.new(config: storage)
  puts '✅'

  # Fetch all records
  print '2. Fetching all records... '
  records = secrets_manager.get_secrets
  puts "✅ Found #{records.length} record(s)"

  if records.empty?
    puts "\n⚠️  No records found in vault. This test requires existing records."
    puts 'Please create some records in your Keeper vault and try again.'
    exit 0
  end

  # Display record details
  puts "\n3. Record Details:"
  records.each_with_index do |record, i|
    puts "\n  Record ##{i + 1}:"
    puts "  - UID: #{record.uid}"
    puts "  - Title: #{record.title}"
    puts "  - Type: #{record.type}"

    # Try to access common fields
    puts "  - Login: #{record.login}" if record.respond_to?(:login)

    puts "  - Password: #{'*' * 8} (hidden)" if record.respond_to?(:password)

    puts "  - URL: #{record.url}" if record.respond_to?(:url)

    if record.notes && !record.notes.empty?
      puts "  - Notes: #{record.notes[0..50]}..." if record.notes.length > 50
      puts "  - Notes: #{record.notes}" if record.notes.length <= 50
    end
  end

  # Test notation
  if records.any?
    print "\n4. Testing notation with first record... "
    first_record = records.first

    # Try to get the title via notation
    title_value = secrets_manager.get_notation("keeper://#{first_record.uid}/title")
    if title_value == first_record.title
      puts '✅ Title matches'
    else
      puts '❌ Title mismatch'
    end

    # Try to get a field value
    if first_record.respond_to?(:login)
      login_value = secrets_manager.get_notation("keeper://#{first_record.uid}/field/login")
      puts "  - Login via notation: #{login_value}"
    end
  end

  # Test get_secret_by_title
  if records.any?
    print "\n5. Testing get_secret_by_title... "
    title_to_find = records.first.title
    found_record = secrets_manager.get_secret_by_title(title_to_find)

    if found_record && found_record.uid == records.first.uid
      puts '✅ Found correct record'
    else
      puts '❌ Failed to find record by title'
    end
  end

  # Get folders
  print "\n6. Getting folders... "
  folders = secrets_manager.get_folders
  puts "✅ Found #{folders.length} folder(s)"

  if folders.any?
    puts "\n  Folder Details:"
    folders.each_with_index do |folder, i|
      puts "  - Folder ##{i + 1}: #{folder.name} (#{folder.uid})"
    end
  end

  puts "\n✅ All read-only tests completed successfully!"
  puts "\nNote: This test only verifies read operations."
  puts 'To test write operations (create, update, delete), ensure your vault has at least one folder.'
rescue StandardError => e
  puts '❌'
  puts "\nError: #{e.class} - #{e.message}"
  puts e.backtrace.first(5).join("\n")
  exit 1
end
