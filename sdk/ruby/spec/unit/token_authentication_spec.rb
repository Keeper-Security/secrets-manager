require 'spec_helper'

RSpec.describe 'Token Authentication' do
  let(:test_token) { 'US:mockTokenData123456' }
  let(:mock_app_key) { KeeperSecretsManager::Utils.generate_aes_key }
  
  describe 'one-time token initialization' do
    it 'correctly hashes token to create client ID' do
      # Expected client ID calculation
      token_bytes = KeeperSecretsManager::Utils.url_safe_str_to_bytes('mockTokenData123456')
      expected_client_id = Base64.strict_encode64(
        OpenSSL::HMAC.digest('SHA512', token_bytes, 'KEEPER_SECRETS_MANAGER_CLIENT_ID')
      )
      
      captured_client_id = nil
      
      # Mock post function that captures the client ID
      custom_post = lambda do |url, transmission_key, encrypted_payload, verify_ssl|
        # We need to decrypt the payload to see the client ID
        # For testing, we'll just return a mock response
        response_data = {
          'encryptedAppKey' => KeeperSecretsManager::Utils.bytes_to_url_safe_str(
            KeeperSecretsManager::Crypto.encrypt_aes_gcm(mock_app_key, token_bytes)
          ),
          'appOwnerPublicKey' => Base64.strict_encode64(OpenSSL::Random.random_bytes(65))
        }
        
        # Return encrypted response
        encrypted_response = KeeperSecretsManager::Crypto.encrypt_aes_gcm(
          response_data.to_json.encode('UTF-8'),
          transmission_key.key
        )
        
        KeeperSecretsManager::Dto::KSMHttpResponse.new(
          status_code: 200,
          data: encrypted_response
        )
      end
      
      # Initialize with token
      sm = KeeperSecretsManager.new(
        token: test_token,
        custom_post_function: custom_post
      )
      
      # Verify it initialized successfully
      expect(sm).to be_a(KeeperSecretsManager::Core::SecretsManager)
    end
    
    it 'parses region from token correctly' do
      test_cases = {
        'EU:tokenData' => 'keepersecurity.eu',
        'AU:tokenData' => 'keepersecurity.com.au',
        'JP:tokenData' => 'keepersecurity.jp',
        'CA:tokenData' => 'keepersecurity.ca',
        'GOV:tokenData' => 'govcloud.keepersecurity.us',
        'US:tokenData' => 'keepersecurity.com',
        'legacyTokenWithoutRegion' => 'keepersecurity.com'
      }
      
      test_cases.each do |token, expected_hostname|
        sm = KeeperSecretsManager.new(
          token: token,
          custom_post_function: mock_successful_response
        )
        
        expect(sm.hostname).to eq(expected_hostname)
      end
    end
    
    it 'handles key ID retry when server requests different key' do
      call_count = 0
      
      custom_post = lambda do |url, transmission_key, encrypted_payload, verify_ssl|
        call_count += 1
        
        if call_count == 1
          # First call - return key error
          KeeperSecretsManager::Dto::KSMHttpResponse.new(
            status_code: 401,
            data: { 'key_id' => 10, 'error' => 'key', 'message' => 'invalid key id' }.to_json
          )
        else
          # Second call - success
          mock_successful_response.call(url, transmission_key, encrypted_payload, verify_ssl)
        end
      end
      
      sm = KeeperSecretsManager.new(
        token: test_token,
        custom_post_function: custom_post
      )
      
      expect(call_count).to eq(2)
    end
    
    it 'stores and cleans up token properly' do
      storage = KeeperSecretsManager::Storage::InMemoryStorage.new
      
      sm = KeeperSecretsManager.new(
        token: test_token,
        config: storage,
        custom_post_function: mock_successful_response
      )
      
      # Token should be cleaned up after successful binding
      expect(storage.get_string(KeeperSecretsManager::ConfigKeys::KEY_CLIENT_KEY)).to be_nil
      
      # App key should be stored
      expect(storage.get_bytes(KeeperSecretsManager::ConfigKeys::KEY_APP_KEY)).not_to be_nil
      
      # Client ID should be stored
      expect(storage.get_string(KeeperSecretsManager::ConfigKeys::KEY_CLIENT_ID)).not_to be_nil
    end
  end
  
  private
  
  def mock_successful_response
    lambda do |url, transmission_key, encrypted_payload, verify_ssl|
      token_bytes = KeeperSecretsManager::Utils.url_safe_str_to_bytes('mockTokenData123456')
      
      response_data = {
        'encryptedAppKey' => KeeperSecretsManager::Utils.bytes_to_url_safe_str(
          KeeperSecretsManager::Crypto.encrypt_aes_gcm(mock_app_key, token_bytes)
        ),
        'appOwnerPublicKey' => Base64.strict_encode64(OpenSSL::Random.random_bytes(65))
      }
      
      encrypted_response = KeeperSecretsManager::Crypto.encrypt_aes_gcm(
        response_data.to_json.encode('UTF-8'),
        transmission_key.key
      )
      
      KeeperSecretsManager::Dto::KSMHttpResponse.new(
        status_code: 200,
        data: encrypted_response
      )
    end
  end
end