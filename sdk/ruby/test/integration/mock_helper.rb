#!/usr/bin/env ruby

# Mock helper for offline testing without valid config.base64
# Provides mock responses and test data for all SDK operations

require 'json'
require 'base64'
require 'securerandom'
require 'openssl'

module MockHelper
  # Check if we're in mock mode
  def self.mock_mode?
    ENV['KEEPER_MOCK_MODE'] == 'true' || !File.exist?(File.expand_path('../../config.base64', __dir__))
  end
  
  # Generate mock config if needed
  def self.get_config
    config_file = File.expand_path('../../config.base64', __dir__)
    
    if File.exist?(config_file) && !mock_mode?
      # Use real config
      config_base64 = File.read(config_file).strip
      config_json = Base64.decode64(config_base64)
      JSON.parse(config_json)
    else
      # Generate mock config
      mock_config = {
        'hostname' => 'keepersecurity.com',
        'clientId' => Base64.strict_encode64('mock-client-id-' + ('a' * 48)),
        'privateKey' => Base64.strict_encode64(OpenSSL::PKey::EC.generate('prime256v1').to_der),
        'serverPublicKeyId' => '10',
        'appKey' => Base64.strict_encode64(OpenSSL::Random.random_bytes(32)),
        'appOwnerPublicKey' => Base64.strict_encode64(OpenSSL::PKey::EC.generate('prime256v1').public_key.to_bn.to_s(2))
      }
      mock_config
    end
  end
  
  # Create mock secrets manager with custom post function
  def self.create_mock_secrets_manager(config = nil)
    config ||= get_config
    storage = KeeperSecretsManager::Storage::InMemoryStorage.new(config)
    
    if mock_mode?
      KeeperSecretsManager.new(
        config: storage,
        custom_post_function: method(:mock_post_function)
      )
    else
      KeeperSecretsManager.new(config: storage)
    end
  end
  
  # Mock post function for API calls
  def self.mock_post_function(url, transmission_key, payload, verify_ssl_certs)
    # Parse the endpoint from URL
    endpoint = url.split('/').last
    
    # Decode the payload
    payload_data = JSON.parse(payload) rescue {}
    
    case endpoint
    when 'get_secret'
      mock_get_secrets_response(payload_data)
    when 'get_folders'
      mock_get_folders_response
    when 'create_secret'
      mock_create_secret_response(payload_data)
    when 'update_secret'
      mock_update_secret_response(payload_data)
    when 'delete_secret'
      mock_delete_secret_response(payload_data)
    when 'query_server_public_keys'
      mock_server_public_keys_response
    else
      mock_error_response("Unknown endpoint: #{endpoint}")
    end
  end
  
  # Mock responses for different operations
  
  def self.mock_get_secrets_response(payload_data)
    # Generate consistent mock records
    records = []
    
    # Add some predefined test records
    test_records = [
      {
        'recordUid' => 'gBKkeUkNMyeuLbGXXchF4Q',
        'data' => encrypt_record_data({
          'type' => 'login',
          'title' => 'Test Login Record',
          'fields' => [
            { 'type' => 'login', 'value' => ['test_user@example.com'] },
            { 'type' => 'password', 'value' => ['SecurePassword123!'] },
            { 'type' => 'url', 'value' => ['https://example.com'] },
            { 'type' => 'fileRef', 'value' => [] }
          ],
          'custom' => [
            { 'type' => 'text', 'label' => 'Environment', 'value' => ['Production'] }
          ],
          'notes' => 'This is a test login record for mock testing'
        })
      },
      {
        'recordUid' => 'DJpznd07Xik52cgTWmfcFg',
        'data' => encrypt_record_data({
          'type' => 'bankCard',
          'title' => 'Test Credit Card',
          'fields' => [
            { 'type' => 'cardNumber', 'value' => ['4111111111111111'] },
            { 'type' => 'cardExpirationDate', 'value' => ['12/2025'] },
            { 'type' => 'cardSecurityCode', 'value' => ['123'] }
          ],
          'notes' => 'Test credit card for mock testing'
        })
      },
      {
        'recordUid' => 'TOTPTestRecord123456789',
        'data' => encrypt_record_data({
          'type' => 'login',
          'title' => 'Test TOTP Record',
          'fields' => [
            { 'type' => 'login', 'value' => ['totp_user@example.com'] },
            { 'type' => 'password', 'value' => ['TOTPPassword123!'] },
            { 'type' => 'oneTimeCode', 'value' => ['otpauth://totp/Test:totp_user@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Test&algorithm=SHA1&digits=6&period=30'] }
          ]
        })
      }
    ]
    
    # Filter by UIDs if requested
    if payload_data['recordUids'] && !payload_data['recordUids'].empty?
      records = test_records.select { |r| payload_data['recordUids'].include?(r['recordUid']) }
    else
      records = test_records
    end
    
    response = {
      'records' => records,
      'warnings' => mock_mode? ? ['Running in mock mode'] : []
    }
    
    KeeperSecretsManager::Dto::KSMHttpResponse.new(
      status_code: 200,
      data: response.to_json
    )
  end
  
  def self.mock_get_folders_response
    folders = [
      {
        'folderUid' => 'khq76ez6vkTRj3MqUiEGRg',
        'data' => encrypt_folder_data({
          'name' => 'Test Folder',
          'parent' => nil
        })
      },
      {
        'folderUid' => 'TestFolder2UID123456789',
        'data' => encrypt_folder_data({
          'name' => 'Another Test Folder',
          'parent' => nil
        })
      }
    ]
    
    response = {
      'folders' => folders,
      'warnings' => mock_mode? ? ['Running in mock mode'] : []
    }
    
    KeeperSecretsManager::Dto::KSMHttpResponse.new(
      status_code: 200,
      data: response.to_json
    )
  end
  
  def self.mock_create_secret_response(payload_data)
    # Generate a new UID for the created record
    new_uid = Base64.urlsafe_encode64(SecureRandom.random_bytes(16), padding: false)
    
    response = {
      'recordUid' => new_uid,
      'warnings' => mock_mode? ? ['Running in mock mode - record not actually created'] : []
    }
    
    KeeperSecretsManager::Dto::KSMHttpResponse.new(
      status_code: 200,
      data: response.to_json
    )
  end
  
  def self.mock_update_secret_response(payload_data)
    response = {
      'recordUid' => payload_data['recordUid'] || 'MockUpdatedUID',
      'warnings' => mock_mode? ? ['Running in mock mode - record not actually updated'] : []
    }
    
    KeeperSecretsManager::Dto::KSMHttpResponse.new(
      status_code: 200,
      data: response.to_json
    )
  end
  
  def self.mock_delete_secret_response(payload_data)
    response = {
      'recordUids' => payload_data['recordUids'] || [],
      'warnings' => mock_mode? ? ['Running in mock mode - records not actually deleted'] : []
    }
    
    KeeperSecretsManager::Dto::KSMHttpResponse.new(
      status_code: 200,
      data: response.to_json
    )
  end
  
  def self.mock_server_public_keys_response
    response = {
      'serverPublicKeys' => [
        {
          'keyId' => '10',
          'publicKey' => Base64.strict_encode64(OpenSSL::PKey::EC.generate('prime256v1').public_key.to_bn.to_s(2))
        }
      ]
    }
    
    KeeperSecretsManager::Dto::KSMHttpResponse.new(
      status_code: 200,
      data: response.to_json
    )
  end
  
  def self.mock_error_response(message, status_code = 400)
    response = {
      'error' => message,
      'warnings' => []
    }
    
    KeeperSecretsManager::Dto::KSMHttpResponse.new(
      status_code: status_code,
      data: response.to_json
    )
  end
  
  # Helper methods for encryption (simplified for mocking)
  
  def self.encrypt_record_data(data)
    # In mock mode, just base64 encode the JSON
    # Real encryption would use AES-GCM with proper keys
    Base64.strict_encode64(data.to_json)
  end
  
  def self.encrypt_folder_data(data)
    # In mock mode, just base64 encode the JSON
    Base64.strict_encode64(data.to_json)
  end
  
  # Mock file operations
  
  def self.mock_file_upload(record_uid, file_data)
    # Simulate file upload
    file_uid = Base64.urlsafe_encode64(SecureRandom.random_bytes(16), padding: false)
    {
      'fileUid' => file_uid,
      'fileSize' => file_data[:size] || file_data[:content].bytesize,
      'fileName' => file_data[:name],
      'mimeType' => file_data[:mime_type] || 'application/octet-stream',
      'uploadUrl' => 'https://mock.keepersecurity.com/uploads/' + file_uid
    }
  end
  
  def self.mock_file_download(file_uid)
    # Simulate file download
    {
      'content' => "Mock file content for UID: #{file_uid}",
      'fileName' => "mock_file_#{file_uid}.txt",
      'mimeType' => 'text/plain',
      'fileSize' => 100
    }
  end
  
  # Mock error scenarios
  
  def self.mock_network_error
    raise Errno::ECONNREFUSED, "Connection refused - Mock network error"
  end
  
  def self.mock_timeout_error
    raise Timeout::Error, "Request timeout - Mock timeout error"
  end
  
  def self.mock_invalid_credentials
    KeeperSecretsManager::Dto::KSMHttpResponse.new(
      status_code: 401,
      data: { 'error' => 'Invalid credentials' }.to_json
    )
  end
  
  def self.mock_server_error
    KeeperSecretsManager::Dto::KSMHttpResponse.new(
      status_code: 500,
      data: { 'error' => 'Internal server error' }.to_json
    )
  end
end