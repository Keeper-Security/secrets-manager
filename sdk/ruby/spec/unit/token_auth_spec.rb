require 'spec_helper'
require 'keeper_secrets_manager'

RSpec.describe 'Token Authentication' do
  let(:test_token) { 'US:BHwFFrb0uLBl97qXBoiORVNFd0hQA2ovud_exK88uWo' }
  let(:mock_app_key) { Base64.strict_encode64(OpenSSL::Random.random_bytes(32)) }
  let(:mock_client_id) { Base64.strict_encode64('mock-client-' + SecureRandom.hex(24)) }
  let(:mock_private_key) { OpenSSL::PKey::EC.generate('prime256v1') }
  let(:mock_encrypted_app_key) { Base64.strict_encode64(OpenSSL::Random.random_bytes(256)) }
  
  describe 'one-time token initialization' do
    it 'parses modern token format correctly' do
      token = 'EU:someTokenData123'
      sm = KeeperSecretsManager::SecretsManager.new(
        token: token,
        custom_post_function: ->(url, payload) { mock_token_response }
      )
      
      # Should extract EU region and set appropriate hostname
      expect(sm.instance_variable_get(:@hostname)).to eq('keepersecurity.eu')
      expect(sm.instance_variable_get(:@token)).to eq('someTokenData123')
    end
    
    it 'handles legacy token format' do
      token = 'legacyTokenWithoutRegion'
      sm = KeeperSecretsManager::SecretsManager.new(
        token: token,
        custom_post_function: ->(url, payload) { mock_token_response }
      )
      
      # Should use default US server
      expect(sm.instance_variable_get(:@hostname)).to eq('keepersecurity.com')
      expect(sm.instance_variable_get(:@token)).to eq('legacyTokenWithoutRegion')
    end
    
    it 'exchanges token for client credentials' do
      post_calls = []
      
      # Mock the token exchange
      custom_post = lambda do |url, payload|
        post_calls << { url: url, payload: payload }
        
        if url.include?('/get_client_params')
          # First call - token exchange
          {
            'clientId' => mock_client_id,
            'encryptedAppKey' => mock_encrypted_app_key,
            'appOwnerPublicKey' => Base64.strict_encode64(mock_private_key.public_key.to_bn.to_s(2)),
            'serverPublicKeyId' => '10'
          }
        else
          # Subsequent calls
          mock_secrets_response
        end
      end
      
      # Initialize with token
      sm = KeeperSecretsManager::SecretsManager.new(
        token: test_token,
        custom_post_function: custom_post
      )
      
      # Should have made token exchange call
      token_call = post_calls.find { |c| c[:url].include?('/get_client_params') }
      expect(token_call).not_to be_nil
      expect(token_call[:payload]['oneTimeToken']).to eq('BHwFFrb0uLBl97qXBoiORVNFd0hQA2ovud_exK88uWo')
      expect(token_call[:payload]['clientVersion']).to match(/^m[a-z]\d+\.\d+\.\d+$/)
      
      # Try to use the SDK
      secrets = sm.get_secrets
      expect(secrets).to be_an(Array)
    end
    
    it 'stores credentials after token exchange' do
      storage = KeeperSecretsManager::Storage::InMemoryStorage.new
      
      sm = KeeperSecretsManager::SecretsManager.new(
        token: test_token,
        config: storage,
        custom_post_function: ->(url, payload) { 
          url.include?('/get_client_params') ? mock_token_response : mock_secrets_response
        }
      )
      
      # Should have stored credentials
      expect(storage.get_string('hostname')).to eq('keepersecurity.com')
      expect(storage.get_string('clientId')).not_to be_nil
      expect(storage.get_bytes('privateKey')).not_to be_nil
      expect(storage.get_bytes('appKey')).not_to be_nil
    end
    
    it 'handles invalid token gracefully' do
      custom_post = lambda do |url, payload|
        if url.include?('/get_client_params')
          raise KeeperSecretsManager::Errors::KeeperError.new('Invalid one-time token')
        end
      end
      
      expect {
        KeeperSecretsManager::SecretsManager.new(
          token: 'US:invalidToken',
          custom_post_function: custom_post
        )
      }.to raise_error(KeeperSecretsManager::Errors::KeeperError, /Invalid one-time token/)
    end
  end
  
  private
  
  def mock_token_response
    {
      'clientId' => mock_client_id,
      'encryptedAppKey' => mock_encrypted_app_key,
      'appOwnerPublicKey' => Base64.strict_encode64(mock_private_key.public_key.to_bn.to_s(2)),
      'serverPublicKeyId' => '10'
    }
  end
  
  def mock_secrets_response
    {
      'records' => [
        {
          'recordUid' => Base64.urlsafe_encode64(SecureRandom.random_bytes(16), padding: false),
          'data' => Base64.strict_encode64(OpenSSL::Random.random_bytes(256))
        }
      ]
    }
  end
end