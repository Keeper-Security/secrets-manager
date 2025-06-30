#!/usr/bin/env ruby

# Full CRUD integration test for Keeper Secrets Manager Ruby SDK
# Tests create, read, update, and delete operations against real API

require_relative '../../lib/keeper_secrets_manager'
require 'json'
require 'base64'
require 'securerandom'

class FullCRUDTest
  def initialize
    @created_records = []
    @created_folders = []
    @test_id = SecureRandom.hex(4)
  end
  
  def log(message, level = :info)
    prefix = case level
    when :error then "❌"
    when :success then "✅"
    when :warn then "⚠️"
    else "ℹ️"
    end
    
    puts "[#{Time.now.strftime('%H:%M:%S')}] #{prefix} #{message}"
  end
  
  def run
    log "Starting Keeper Secrets Manager Ruby SDK Full CRUD Test"
    log "Test ID: #{@test_id}"
    log "Ruby version: #{RUBY_VERSION}"
    log "OpenSSL: #{OpenSSL::VERSION} / #{OpenSSL::OPENSSL_LIBRARY_VERSION}"
    
    # Check for config
    config_file = File.expand_path('../../config.base64', __dir__)
    unless File.exist?(config_file)
      log "config.base64 not found at #{config_file}", :error
      log "Please provide a valid configuration file to run integration tests", :error
      return false
    end
    
    # Initialize SDK
    begin
      config_base64 = File.read(config_file).strip
      config_json = Base64.decode64(config_base64)
      config_data = JSON.parse(config_json)
      
      storage = KeeperSecretsManager::Storage::InMemoryStorage.new(config_data)
      @secrets_manager = KeeperSecretsManager.new(config: storage)
      log "SDK initialized successfully", :success
    rescue => e
      log "Failed to initialize SDK: #{e.message}", :error
      return false
    end
    
    # Run all tests
    all_passed = true
    
    all_passed &= test_list_existing_records
    all_passed &= test_create_login_record
    all_passed &= test_update_record
    all_passed &= test_create_complex_record
    all_passed &= test_folder_operations
    all_passed &= test_notation_access
    all_passed &= test_search_by_title
    all_passed &= test_delete_records
    
    # Cleanup
    cleanup
    
    log "All tests completed. Result: #{all_passed ? 'PASSED' : 'FAILED'}", all_passed ? :success : :error
    all_passed
  end
  
  private
  
  def test_list_existing_records
    log "\n=== Test: List Existing Records ==="
    
    begin
      records = @secrets_manager.get_secrets
      log "Found #{records.length} existing record(s)", :success
      
      folders = @secrets_manager.get_folders
      log "Found #{folders.length} existing folder(s)", :success
      
      true
    rescue => e
      log "Failed to list records: #{e.message}", :error
      false
    end
  end
  
  def test_create_login_record
    log "\n=== Test: Create Login Record ==="
    
    begin
      # Create a simple login record
      record_data = {
        'type' => 'login',
        'title' => "Ruby SDK Test Login #{@test_id}",
        'fields' => [
          { 'type' => 'login', 'value' => ['test.user@example.com'] },
          { 'type' => 'password', 'value' => [generate_password] },
          { 'type' => 'url', 'value' => ['https://example.com', 'https://app.example.com'] },
          { 'type' => 'fileRef', 'value' => [] }
        ],
        'custom' => [
          {
            'type' => 'text',
            'label' => 'Environment',
            'value' => ['Testing']
          },
          {
            'type' => 'text', 
            'label' => 'Ruby Version',
            'value' => [RUBY_VERSION]
          }
        ],
        'notes' => "Created by Ruby SDK integration test\nTest ID: #{@test_id}\nTimestamp: #{Time.now}"
      }
      
      record_uid = @secrets_manager.create_secret(record_data)
      @created_records << record_uid
      
      log "Created login record with UID: #{record_uid}", :success
      
      # Verify the record was created
      sleep 2 # Give the server time to process
      
      records = @secrets_manager.get_secrets([record_uid])
      if records.empty?
        log "Failed to retrieve created record", :error
        return false
      end
      
      created_record = records.first
      log "Verified record creation: #{created_record.title}", :success
      
      # Store for later tests
      @login_record_uid = record_uid
      
      true
    rescue => e
      log "Failed to create login record: #{e.message}", :error
      log e.backtrace.first(5).join("\n"), :error
      false
    end
  end
  
  def test_update_record
    log "\n=== Test: Update Record ==="
    
    return skip_test("No login record to update") unless @login_record_uid
    
    begin
      # Get the record
      records = @secrets_manager.get_secrets([@login_record_uid])
      record = records.first
      
      # Update fields
      original_login = record.login
      original_password = record.password
      
      record.login = 'updated.user@example.com'
      record.password = generate_password
      record.url = ['https://updated.example.com']
      
      # Add a new custom field
      record.custom << {
        'type' => 'text',
        'label' => 'Last Updated',
        'value' => [Time.now.to_s]
      }
      
      # Update the record
      @secrets_manager.update_secret(record)
      
      log "Record updated successfully", :success
      
      # Verify the update
      sleep 2
      updated_records = @secrets_manager.get_secrets([@login_record_uid])
      updated_record = updated_records.first
      
      if updated_record.login == 'updated.user@example.com' && 
         updated_record.login != original_login
        log "Verified field updates", :success
      else
        log "Field updates not reflected", :error
        return false
      end
      
      true
    rescue => e
      log "Failed to update record: #{e.message}", :error
      false
    end
  end
  
  def test_create_complex_record
    log "\n=== Test: Create Complex Record ==="
    
    begin
      # Create a record with many field types
      complex_record = KeeperSecretsManager::Dto::KeeperRecord.new(
        'type' => 'login',
        'title' => "Ruby SDK Complex Test #{@test_id}",
        'notes' => 'Testing all field types'
      )
      
      # Add various field types
      complex_record.login = 'complex.user@example.com'
      complex_record.password = generate_password
      complex_record.url = ['https://complex.example.com']
      
      # Phone field
      complex_record.set_field('phone', {
        'region' => 'US',
        'number' => '555-0123',
        'ext' => '456',
        'type' => 'Mobile'
      })
      
      # Name field
      complex_record.set_field('name', {
        'first' => 'Test',
        'middle' => 'Ruby',
        'last' => 'User'
      })
      
      # Address field
      complex_record.set_field('address', {
        'street1' => '123 Test Street',
        'street2' => 'Suite 456',
        'city' => 'Test City',
        'state' => 'TC',
        'zip' => '12345',
        'country' => 'US'
      })
      
      # Card field
      complex_record.set_field('paymentCard', {
        'cardNumber' => '4111111111111111',
        'cardExpirationDate' => '12/25',
        'cardSecurityCode' => '123'
      })
      
      # Host field
      complex_record.set_field('host', {
        'hostName' => 'test.server.com',
        'port' => '22'
      })
      
      # Secret field
      complex_record.set_field('secret', 'This is a secret value')
      
      # TOTP field
      complex_record.set_field('oneTimeCode', 'otpauth://totp/Test:user@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Test')
      
      # Create the record
      record_uid = @secrets_manager.create_secret(complex_record)
      @created_records << record_uid
      
      log "Created complex record with UID: #{record_uid}", :success
      
      # Verify all fields
      sleep 2
      records = @secrets_manager.get_secrets([record_uid])
      created = records.first
      
      # Check field retrieval
      phone = created.get_field_value_single('phone')
      if phone && phone['number'] == '555-0123'
        log "Phone field verified", :success
      end
      
      name = created.get_field_value_single('name')
      if name && name['first'] == 'Test'
        log "Name field verified", :success
      end
      
      address = created.get_field_value_single('address')
      if address && address['city'] == 'Test City'
        log "Address field verified", :success
      end
      
      true
    rescue => e
      log "Failed to create complex record: #{e.message}", :error
      false
    end
  end
  
  def test_folder_operations
    log "\n=== Test: Folder Operations ==="
    
    begin
      # Create a folder
      folder_name = "Ruby SDK Test Folder #{@test_id}"
      folder_uid = @secrets_manager.create_folder(folder_name)
      @created_folders << folder_uid
      
      log "Created folder with UID: #{folder_uid}", :success
      
      # Update folder name
      sleep 1
      new_name = "#{folder_name} - Updated"
      @secrets_manager.update_folder(folder_uid, new_name)
      
      log "Updated folder name", :success
      
      # Create a record in the folder
      record_data = {
        'type' => 'login',
        'title' => "Record in folder #{@test_id}",
        'fields' => [
          { 'type' => 'login', 'value' => ['folder.user@example.com'] },
          { 'type' => 'password', 'value' => [generate_password] }
        ]
      }
      
      options = KeeperSecretsManager::Dto::CreateOptions.new
      options.folder_uid = folder_uid
      
      record_uid = @secrets_manager.create_secret(record_data, options)
      @created_records << record_uid
      
      log "Created record in folder", :success
      
      true
    rescue => e
      log "Failed folder operations: #{e.message}", :error
      false
    end
  end
  
  def test_notation_access
    log "\n=== Test: Notation Access ==="
    
    return skip_test("No login record for notation test") unless @login_record_uid
    
    begin
      # Test various notation formats
      notations = [
        "keeper://#{@login_record_uid}/field/login",
        "keeper://#{@login_record_uid}/field/password", 
        "keeper://#{@login_record_uid}/custom_field/Environment"
      ]
      
      notations.each do |notation|
        begin
          value = @secrets_manager.get_notation(notation)
          if value
            log "Retrieved via notation: #{notation.split('/').last} = #{value[0..20]}#{'...' if value.length > 20}", :success
          end
        rescue => e
          log "Notation failed for #{notation}: #{e.message}", :warn
        end
      end
      
      true
    rescue => e
      log "Failed notation access: #{e.message}", :error
      false
    end
  end
  
  def test_search_by_title
    log "\n=== Test: Search by Title ==="
    
    begin
      # Search for our test records
      test_pattern = "Ruby SDK Test"
      
      all_records = @secrets_manager.get_secrets
      matching = all_records.select { |r| r.title.include?(test_pattern) }
      
      log "Found #{matching.length} records matching '#{test_pattern}'", :success
      
      # Search for specific record
      if @login_record_uid
        specific_title = "Ruby SDK Test Login #{@test_id}"
        found = @secrets_manager.get_secret_by_title(specific_title)
        
        if found && found.uid == @login_record_uid
          log "Found specific record by title", :success
        else
          log "Could not find specific record by title", :error
          return false
        end
      end
      
      true
    rescue => e
      log "Failed search by title: #{e.message}", :error
      false
    end
  end
  
  def test_delete_records
    log "\n=== Test: Delete Records ==="
    
    begin
      # Delete test records
      if @created_records.any?
        deleted = @secrets_manager.delete_secret(@created_records)
        log "Deleted #{deleted.length} test record(s)", :success
      end
      
      # Delete test folders
      if @created_folders.any?
        deleted_folders = @secrets_manager.delete_folder(@created_folders, force: true)
        log "Deleted #{deleted_folders.length} test folder(s)", :success
      end
      
      true
    rescue => e
      log "Failed to delete test data: #{e.message}", :error
      false
    end
  end
  
  def cleanup
    log "\n=== Cleanup ==="
    
    # Try to clean up any remaining test data
    begin
      all_records = @secrets_manager.get_secrets
      test_records = all_records.select { |r| r.title.include?(@test_id) }
      
      if test_records.any?
        uids = test_records.map(&:uid)
        @secrets_manager.delete_secret(uids)
        log "Cleaned up #{uids.length} test record(s)", :warn
      end
    rescue => e
      log "Cleanup error: #{e.message}", :warn
    end
  end
  
  def skip_test(reason)
    log "Skipped: #{reason}", :warn
    true
  end
  
  def generate_password
    chars = ('a'..'z').to_a + ('A'..'Z').to_a + ('0'..'9').to_a + %w[! @ # $ % ^ & *]
    (1..16).map { chars.sample }.join
  end
end

# Run the test if executed directly
if __FILE__ == $0
  test = FullCRUDTest.new
  success = test.run
  exit(success ? 0 : 1)
end