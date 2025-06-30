#!/usr/bin/env ruby

require_relative '../../lib/keeper_secrets_manager'
require_relative 'mock_helper'
require 'json'
require 'base64'

# Test one-time token authentication
class TestTokenAuth
  def self.run
    puts "\n=== Testing One-Time Token Authentication ==="
    
    # Test token parsing
    test_token_parsing
    
    # Test client ID generation
    test_client_id_generation
    
    # Test mock token authentication
    test_mock_token_auth
    
    puts "\n✅ All token authentication tests passed!"
  end
  
  def self.test_token_parsing
    puts "\n1. Testing token parsing..."
    
    # Test with region prefix
    token = "EU:someTokenData123"
    sm = KeeperSecretsManager.new(
      token: token,
      custom_post_function: -> (url, payload) { mock_token_response }
    )
    
    hostname = sm.instance_variable_get(:@hostname)
    parsed_token = sm.instance_variable_get(:@token)
    
    raise "Expected EU hostname" unless hostname == 'keepersecurity.eu'
    raise "Expected parsed token" unless parsed_token == 'someTokenData123'
    
    # Test without region prefix
    token2 = "justTokenData"
    sm2 = KeeperSecretsManager.new(
      token: token2,
      hostname: 'custom.keeper.com',
      custom_post_function: -> (url, payload) { mock_token_response }
    )
    
    hostname2 = sm2.instance_variable_get(:@hostname)
    parsed_token2 = sm2.instance_variable_get(:@token)
    
    raise "Expected custom hostname" unless hostname2 == 'custom.keeper.com'
    raise "Expected full token" unless parsed_token2 == 'justTokenData'
    
    puts "   ✓ Token parsing works correctly"
  end
  
  def self.test_client_id_generation
    puts "\n2. Testing client ID generation..."
    
    # Test that client ID is generated correctly via HMAC
    test_token = "testTokenData123"
    expected_client_id_bytes = OpenSSL::HMAC.digest(
      'SHA512',
      KeeperSecretsManager::Utils.url_safe_str_to_bytes(test_token),
      'KEEPER_SECRETS_MANAGER_CLIENT_ID'
    )
    expected_client_id = Base64.strict_encode64(expected_client_id_bytes)
    
    captured_client_id = nil
    
    sm = KeeperSecretsManager.new(
      token: "US:#{test_token}",
      custom_post_function: -> (url, payload) { 
        captured_client_id = payload['clientId']
        mock_token_response 
      }
    )
    
    raise "Client ID mismatch" unless captured_client_id == expected_client_id
    
    puts "   ✓ Client ID generated correctly via HMAC-SHA512"
  end
  
  def self.test_mock_token_auth
    puts "\n3. Testing mock token authentication flow..."
    
    calls_made = []
    test_token = "mockTestToken123"
    
    # Mock encrypted app key
    mock_app_key = KeeperSecretsManager::Utils.generate_aes_key
    token_bytes = KeeperSecretsManager::Utils.url_safe_str_to_bytes(test_token)
    encrypted_app_key = KeeperSecretsManager::Crypto.encrypt_aes_gcm(mock_app_key, token_bytes)
    encrypted_app_key_b64 = KeeperSecretsManager::Utils.bytes_to_url_safe_str(encrypted_app_key)
    
    custom_post = -> (url, payload) {
      calls_made << { url: url, payload: payload }
      
      if payload['publicKey'] && !payload['publicKey'].empty?
        # This is the initial binding request
        {
          'encryptedAppKey' => encrypted_app_key_b64,
          'appOwnerPublicKey' => KeeperSecretsManager::Utils.bytes_to_url_safe_str(
            KeeperSecretsManager::Utils.generate_random_bytes(65)
          )
        }
      else
        # Subsequent requests
        mock_secrets_response
      end
    }
    
    # Initialize with token
    sm = KeeperSecretsManager.new(
      token: "US:#{test_token}",
      custom_post_function: custom_post
    )
    
    # Verify binding request was made
    binding_call = calls_made.find { |c| c[:payload]['publicKey'] }
    raise "No binding call made" unless binding_call
    raise "Public key not sent" unless binding_call[:payload]['publicKey']
    raise "Client ID not sent" unless binding_call[:payload]['clientId']
    
    # Try to use the SDK
    secrets = sm.get_secrets
    raise "Should return empty array" unless secrets.is_a?(Array)
    
    # Verify app key was stored
    config = sm.instance_variable_get(:@config)
    app_key_stored = config.get_bytes(KeeperSecretsManager::ConfigKeys::KEY_APP_KEY)
    raise "App key not stored" unless app_key_stored
    
    # Verify client key was deleted
    client_key = config.get_string(KeeperSecretsManager::ConfigKeys::KEY_CLIENT_KEY)
    raise "Client key should be deleted after binding" if client_key
    
    puts "   ✓ Token authentication flow works correctly"
    puts "   ✓ App key decrypted and stored"
    puts "   ✓ Client key cleaned up after binding"
  end
  
  private
  
  def self.mock_token_response
    {
      'encryptedAppKey' => 'mockEncryptedAppKey',
      'appOwnerPublicKey' => 'mockOwnerPublicKey'
    }
  end
  
  def self.mock_secrets_response
    {
      'records' => [],
      'folders' => [],
      'warnings' => []
    }
  end
end

# Run tests if executed directly
if __FILE__ == $0
  begin
    TestTokenAuth.run
  rescue => e
    puts "\n❌ Test failed: #{e.message}"
    puts e.backtrace.first(5).join("\n")
    exit 1
  end
end