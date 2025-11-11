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
      # Generate mock config with consistent app key
      {
        'hostname' => 'keepersecurity.com',
        'clientId' => Base64.strict_encode64('mock-client-id-' + ('a' * 48)),
        'privateKey' => Base64.strict_encode64(OpenSSL::PKey::EC.generate('prime256v1').to_der),
        'serverPublicKeyId' => '10',
        'appKey' => Base64.strict_encode64(get_mock_app_key), # Use consistent mock app key
        'appOwnerPublicKey' => Base64.strict_encode64(OpenSSL::PKey::EC.generate('prime256v1').public_key.to_bn.to_s(2))
      }
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
  def self.mock_post_function(url, transmission_key, encrypted_payload, _verify_ssl_certs)
    # Parse the endpoint from URL
    endpoint = url.split('/').last

    # Decrypt the payload with transmission key
    begin
      decrypted_payload = KeeperSecretsManager::Crypto.decrypt_aes_gcm(encrypted_payload, transmission_key.key)
      payload_data = JSON.parse(decrypted_payload)
    rescue StandardError => e
      # If decryption fails, try parsing as plain JSON (for compatibility)
      payload_data = begin
        JSON.parse(encrypted_payload)
      rescue StandardError
        {}
      end
    end

    # Get response based on endpoint
    response = case endpoint
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
                 return mock_server_public_keys_response # Don't encrypt this response
               else
                 mock_error_response("Unknown endpoint: #{endpoint}")
               end

    # Encrypt the response with transmission key
    if response.is_a?(KeeperSecretsManager::Dto::KSMHttpResponse) && response.success?
      encrypted_data = KeeperSecretsManager::Crypto.encrypt_aes_gcm(response.data, transmission_key.key)
      KeeperSecretsManager::Dto::KSMHttpResponse.new(
        status_code: response.status_code,
        data: encrypted_data
      )
    else
      response
    end
  end

  # Mock responses for different operations

  def self.mock_get_secrets_response(payload_data)
    # Get the app key from mock config (must be consistent)
    app_key = get_mock_app_key

    # Define test record data
    test_record_definitions = [
      {
        'recordUid' => 'gBKkeUkNMyeuLbGXXchF4Q',
        'data' => {
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
        }
      },
      {
        'recordUid' => 'DJpznd07Xik52cgTWmfcFg',
        'data' => {
          'type' => 'bankCard',
          'title' => 'Test Credit Card',
          'fields' => [
            { 'type' => 'cardNumber', 'value' => ['4111111111111111'] },
            { 'type' => 'cardExpirationDate', 'value' => ['12/2025'] },
            { 'type' => 'cardSecurityCode', 'value' => ['123'] }
          ],
          'notes' => 'Test credit card for mock testing'
        }
      },
      {
        'recordUid' => 'TOTPTestRecord123456789',
        'data' => {
          'type' => 'login',
          'title' => 'Test TOTP Record',
          'fields' => [
            { 'type' => 'login', 'value' => ['totp_user@example.com'] },
            { 'type' => 'password', 'value' => ['TOTPPassword123!'] },
            { 'type' => 'oneTimeCode',
              'value' => ['otpauth://totp/Test:totp_user@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Test&algorithm=SHA1&digits=6&period=30'] }
          ]
        }
      }
    ]

    # Encrypt each record with the app key
    records = test_record_definitions.map do |record_def|
      encrypted = encrypt_record_data(record_def['data'], app_key)
      {
        'recordUid' => record_def['recordUid'],
        'data' => encrypted['data'],
        'recordKey' => encrypted['recordKey'],
        'revision' => 1,
        'isEditable' => true
      }
    end

    # Filter by UIDs if requested
    if payload_data['recordUids'] && !payload_data['recordUids'].empty?
      records = records.select { |r| payload_data['recordUids'].include?(r['recordUid']) }
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

  # Get consistent mock app key
  def self.get_mock_app_key
    # Use a deterministic app key for mock mode
    @mock_app_key ||= OpenSSL::Random.random_bytes(32)
  end

  def self.mock_get_folders_response
    app_key = get_mock_app_key

    folder_definitions = [
      {
        'folderUid' => 'khq76ez6vkTRj3MqUiEGRg',
        'parent' => nil, # Root folder
        'data' => {
          'name' => 'Test Folder'
        }
      },
      {
        'folderUid' => 'TestFolder2UID123456789',
        'parent' => nil, # Root folder
        'data' => {
          'name' => 'Another Test Folder'
        }
      }
    ]

    folders = folder_definitions.map do |folder_def|
      encrypted = encrypt_folder_data(folder_def['data'], app_key)
      {
        'folderUid' => folder_def['folderUid'],
        'parent' => folder_def['parent'],
        'data' => encrypted['data'],
        'folderKey' => encrypted['folderKey']
      }
    end

    response = {
      'folders' => folders,
      'warnings' => mock_mode? ? ['Running in mock mode'] : []
    }

    KeeperSecretsManager::Dto::KSMHttpResponse.new(
      status_code: 200,
      data: response.to_json
    )
  end

  def self.mock_create_secret_response(_payload_data)
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

  # Helper methods for proper encryption (matching SDK expectations)

  def self.encrypt_record_data(data, app_key = nil)
    # Generate a random record key (32 bytes for AES-256)
    record_key = OpenSSL::Random.random_bytes(32)

    # Encrypt the record data with the record key
    data_json = data.to_json
    encrypted_data = KeeperSecretsManager::Crypto.encrypt_aes_gcm(data_json, record_key)

    # Get or generate app key
    app_key ||= OpenSSL::Random.random_bytes(32)

    # Encrypt the record key with the app key
    encrypted_record_key = KeeperSecretsManager::Crypto.encrypt_aes_gcm(record_key, app_key)

    # Return both encrypted data and encrypted record key as base64
    {
      'data' => KeeperSecretsManager::Utils.bytes_to_base64(encrypted_data),
      'recordKey' => KeeperSecretsManager::Utils.bytes_to_base64(encrypted_record_key),
      'app_key' => app_key # Return app key for consistent encryption
    }
  end

  def self.encrypt_folder_data(data, app_key = nil)
    # Folders use AES-CBC for data encryption (not GCM!)
    folder_key = OpenSSL::Random.random_bytes(32)

    data_json = data.to_json
    # Folder data always uses CBC
    encrypted_data = KeeperSecretsManager::Crypto.encrypt_aes_cbc(data_json, folder_key)

    app_key ||= OpenSSL::Random.random_bytes(32)
    # Root folder keys use GCM (for child folders it would be CBC)
    encrypted_folder_key = KeeperSecretsManager::Crypto.encrypt_aes_gcm(folder_key, app_key)

    {
      'data' => KeeperSecretsManager::Utils.bytes_to_base64(encrypted_data),
      'folderKey' => KeeperSecretsManager::Utils.bytes_to_base64(encrypted_folder_key),
      'app_key' => app_key
    }
  end

  # Mock file operations

  def self.mock_file_upload(_record_uid, file_data)
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
    raise Errno::ECONNREFUSED, 'Connection refused - Mock network error'
  end

  def self.mock_timeout_error
    raise Timeout::Error, 'Request timeout - Mock timeout error'
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
