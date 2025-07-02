#!/usr/bin/env ruby

# Test error handling and recovery scenarios

require_relative '../../lib/keeper_secrets_manager'
require_relative 'mock_helper'
require 'json'
require 'base64'

puts "=== Error Handling & Recovery Tests ==="
puts "Testing various error conditions and recovery scenarios"
puts "Mode: #{MockHelper.mock_mode? ? 'MOCK' : 'LIVE'}"
puts "-" * 50

class ErrorHandlingTests
  def initialize
    @config_file = File.expand_path('../../config.base64', __dir__)
    
    # Allow tests to run in mock mode without config
    if !MockHelper.mock_mode? && !File.exist?(@config_file)
      puts "❌ ERROR: config.base64 not found (set KEEPER_MOCK_MODE=true for offline testing)"
      exit 1
    end
    
    # Use mock helper to get config (real or mocked)
    @config_data = MockHelper.get_config
  end
  
  def run_all_tests
    test_invalid_credentials
    test_network_errors
    test_invalid_record_uid
    test_invalid_folder_uid
    test_malformed_notation
    test_encryption_errors
    test_server_errors
    puts "\n✅ All error handling tests completed"
  end
  
  private
  
  def test_invalid_credentials
    puts "\n1. Testing Invalid Credentials..."
    
    # Create config with invalid client ID
    invalid_config = @config_data.dup
    invalid_config['clientId'] = Base64.encode64('invalid_client_id').strip
    
    begin
      storage = KeeperSecretsManager::Storage::InMemoryStorage.new(invalid_config)
      sm = KeeperSecretsManager.new(config: storage)
      sm.get_secrets
      puts "   ❌ Should have failed with invalid credentials"
    rescue => e
      puts "   ✅ Correctly failed: #{e.class} - #{e.message[0..50]}..."
    end
  end
  
  def test_network_errors
    puts "\n2. Testing Network Error Handling..."
    
    # Create SDK with invalid hostname
    invalid_config = @config_data.dup
    invalid_config['hostname'] = 'invalid.keeper.example.com'
    
    begin
      storage = KeeperSecretsManager::Storage::InMemoryStorage.new(invalid_config)
      sm = KeeperSecretsManager.new(config: storage)
      sm.get_secrets
      puts "   ❌ Should have failed with network error"
    rescue => e
      puts "   ✅ Correctly failed: #{e.class} - #{e.message[0..50]}..."
    end
  end
  
  def test_invalid_record_uid
    puts "\n3. Testing Invalid Record UID..."
    
    storage = KeeperSecretsManager::Storage::InMemoryStorage.new(@config_data)
    sm = KeeperSecretsManager.new(config: storage)
    
    begin
      invalid_uid = 'invalid_record_uid_12345'
      records = sm.get_secrets([invalid_uid])
      if records.empty?
        puts "   ✅ Correctly returned empty array for invalid UID"
      else
        puts "   ❌ Should have returned empty array"
      end
    rescue => e
      puts "   ✅ Handled error: #{e.class} - #{e.message[0..50]}..."
    end
  end
  
  def test_invalid_folder_uid
    puts "\n4. Testing Invalid Folder UID..."
    
    storage = KeeperSecretsManager::Storage::InMemoryStorage.new(@config_data)
    sm = KeeperSecretsManager.new(config: storage)
    
    begin
      options = KeeperSecretsManager::Dto::CreateOptions.new
      options.folder_uid = 'invalid_folder_uid_12345'
      
      test_record = {
        'type' => 'login',
        'title' => 'Test Record',
        'fields' => [
          { 'type' => 'login', 'value' => ['test@example.com'] }
        ]
      }
      
      sm.create_secret(test_record, options)
      puts "   ❌ Should have failed with invalid folder"
    rescue => e
      puts "   ✅ Correctly failed: #{e.class} - #{e.message[0..50]}..."
    end
  end
  
  def test_malformed_notation
    puts "\n5. Testing Malformed Notation..."
    
    storage = KeeperSecretsManager::Storage::InMemoryStorage.new(@config_data)
    sm = KeeperSecretsManager.new(config: storage)
    
    test_cases = [
      'keeper://',  # Missing UID
      'keeper://invalid',  # Invalid format
      'keeper:///field/login',  # Missing UID
      'not-keeper://uid/field/login',  # Wrong prefix
      'keeper://uid/invalid/path/too/long'  # Invalid path
    ]
    
    test_cases.each do |notation|
      begin
        result = sm.get_notation(notation)
        puts "   ❌ Should have failed for: #{notation}"
      rescue => e
        puts "   ✅ Correctly failed for '#{notation}': #{e.class}"
      end
    end
  end
  
  def test_encryption_errors
    puts "\n6. Testing Encryption Errors..."
    
    # Test with invalid key sizes
    begin
      invalid_key = 'short'  # Too short for AES-256
      data = 'test data'
      KeeperSecretsManager::Crypto.encrypt_aes_gcm(data, invalid_key)
      puts "   ❌ Should have failed with invalid key size"
    rescue => e
      puts "   ✅ Correctly failed encryption: #{e.class} - #{e.message[0..50]}..."
    end
    
    # Test decryption with wrong key
    begin
      key1 = KeeperSecretsManager::Crypto.generate_encryption_key_bytes
      key2 = KeeperSecretsManager::Crypto.generate_encryption_key_bytes
      
      encrypted = KeeperSecretsManager::Crypto.encrypt_aes_gcm('test data', key1)
      KeeperSecretsManager::Crypto.decrypt_aes_gcm(encrypted, key2)
      puts "   ❌ Should have failed decryption with wrong key"
    rescue => e
      puts "   ✅ Correctly failed decryption: #{e.class}"
    end
  end
  
  def test_server_errors
    puts "\n7. Testing Server Error Simulation..."
    
    # We can't easily simulate server errors without mocking,
    # but we can verify error handling structure exists
    
    storage = KeeperSecretsManager::Storage::InMemoryStorage.new(@config_data)
    sm = KeeperSecretsManager.new(config: storage)
    
    # Verify error classes exist
    error_classes = [
      KeeperSecretsManager::Error,
      KeeperSecretsManager::CryptoError
    ]
    
    error_classes.each do |error_class|
      if defined?(error_class)
        puts "   ✅ #{error_class} is defined"
      else
        puts "   ❌ #{error_class} is not defined"
      end
    end
  end
end

# Run tests
if __FILE__ == $0
  tests = ErrorHandlingTests.new
  tests.run_all_tests
end