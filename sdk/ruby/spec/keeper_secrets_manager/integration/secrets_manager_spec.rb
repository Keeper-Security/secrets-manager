require 'spec_helper'
require 'json'
require 'securerandom'

RSpec.describe KeeperSecretsManager::Core::SecretsManager, :integration do
  # This can run with mock data or real API based on environment
  let(:use_mock_data) { ENV['KSM_TEST_LIVE'].nil? }
  let(:config_file) { File.expand_path('../../../config.base64', __dir__) }
  let(:fixtures_dir) { File.expand_path('../../fixtures', __dir__) }

  let(:config) do
    if use_mock_data
      # Use mock config with proper key sizes for EC P-256
      # Private key must be 32 bytes for EC P-256
      mock_private_key = SecureRandom.random_bytes(32)
      # App key should be 32 bytes (AES-256 key)
      mock_app_key = SecureRandom.random_bytes(32)

      KeeperSecretsManager::Storage::InMemoryStorage.new({
                                                           'hostname' => 'mock.keepersecurity.com',
                                                           'clientId' => 'mock-client-id',
                                                           'privateKey' => Base64.strict_encode64(mock_private_key),
                                                           'appKey' => Base64.strict_encode64(mock_app_key),
                                                           'serverPublicKeyId' => '10'
                                                         })
    else
      # Use real config
      config_base64 = File.read(config_file).strip
      config_json = Base64.decode64(config_base64)
      config_data = JSON.parse(config_json)
      KeeperSecretsManager::Storage::InMemoryStorage.new(config_data)
    end
  end

  subject(:secrets_manager) { described_class.new(config: config) }

  # Load mock responses if available
  let(:mock_responses) do
    responses_file = File.join(fixtures_dir, 'api_responses.json')
    if File.exist?(responses_file)
      JSON.parse(File.read(responses_file))
    else
      {}
    end
  end

  describe 'record operations' do
    context '#get_secrets' do
      it 'retrieves all records' do
        skip 'Skipping in mock mode - requires WebMock stubs' if use_mock_data

        if use_mock_data && mock_responses['get_all_records']
          # Mock the response
          allow(secrets_manager).to receive(:get_secrets).and_return(
            mock_responses['get_all_records'].map do |r|
              KeeperSecretsManager::Dto::KeeperRecord.new(
                'uid' => r['uid'],
                'title' => r['title'],
                'type' => r['type']
              )
            end
          )
        end

        records = secrets_manager.get_secrets
        expect(records).to be_an(Array)

        if records.any?
          record = records.first
          expect(record).to be_a(KeeperSecretsManager::Dto::KeeperRecord)
          expect(record.uid).not_to be_nil
          expect(record.title).not_to be_nil
        end
      end

      it 'retrieves specific records by UID' do
        skip 'No records available' if use_mock_data && mock_responses['get_all_records'].nil?

        # Get first record UID from mock or real data
        all_records = secrets_manager.get_secrets
        skip 'No records to test with' if all_records.empty?

        first_uid = all_records.first.uid
        specific_records = secrets_manager.get_secrets([first_uid])

        expect(specific_records.length).to eq(1)
        expect(specific_records.first.uid).to eq(first_uid)
      end
    end

    context '#get_secrets_by_title' do
      it 'finds records by title' do
        skip 'No records available' if use_mock_data && mock_responses['get_all_records'].nil?

        all_records = secrets_manager.get_secrets
        skip 'No records to test with' if all_records.empty?

        title = all_records.first.title
        found_records = secrets_manager.get_secrets_by_title(title)

        expect(found_records).not_to be_empty
        expect(found_records.all? { |r| r.title == title }).to be true
      end
    end

    context '#create_secret' do
      it 'creates a new record' do
        skip 'Skipping create in mock mode' if use_mock_data

        test_record = KeeperSecretsManager::Dto::KeeperRecord.new(
          title: "RSpec Test #{Time.now.to_i}",
          type: 'login',
          fields: [
            { 'type' => 'login', 'value' => ['rspec_user'] },
            { 'type' => 'password', 'value' => ['RSpecPass123!'] },
            { 'type' => 'url', 'value' => ['https://rspec.example.com'] }
          ],
          notes: 'Created by RSpec integration test'
        )

        record_uid = secrets_manager.create_secret(test_record)
        expect(record_uid).to match(/^[A-Za-z0-9_-]+$/)

        # Verify creation
        created_records = secrets_manager.get_secrets([record_uid])
        expect(created_records).not_to be_empty

        created = created_records.first
        expect(created.title).to eq(test_record.title)
        expect(created.get_field_value_single('login')).to eq('rspec_user')

        # Clean up
        secrets_manager.delete_secret(record_uid)
      end
    end

    context '#update_secret' do
      it 'updates an existing record' do
        skip 'Skipping update in mock mode' if use_mock_data

        # Create a record to update
        original_record = KeeperSecretsManager::Dto::KeeperRecord.new(
          title: "Update Test #{Time.now.to_i}",
          type: 'login',
          fields: [
            { 'type' => 'login', 'value' => ['original_user'] },
            { 'type' => 'password', 'value' => ['OriginalPass123!'] }
          ]
        )

        record_uid = secrets_manager.create_secret(original_record)

        # Get and update the record
        record = secrets_manager.get_secrets([record_uid]).first
        record.set_field('login', 'updated_user')
        record.notes = "Updated at #{Time.now}"

        result = secrets_manager.update_secret(record)
        expect(result).to be true

        # Verify update
        updated = secrets_manager.get_secrets([record_uid]).first
        expect(updated.get_field_value_single('login')).to eq('updated_user')
        expect(updated.notes).to include('Updated at')

        # Clean up
        secrets_manager.delete_secret(record_uid)
      end
    end

    context '#delete_secret' do
      it 'deletes records' do
        skip 'Skipping delete in mock mode' if use_mock_data

        # Create records to delete
        record1 = KeeperSecretsManager::Dto::KeeperRecord.new(
          title: "Delete Test 1 #{Time.now.to_i}",
          type: 'login'
        )
        record2 = KeeperSecretsManager::Dto::KeeperRecord.new(
          title: "Delete Test 2 #{Time.now.to_i}",
          type: 'login'
        )

        uid1 = secrets_manager.create_secret(record1)
        uid2 = secrets_manager.create_secret(record2)

        # Delete both
        result = secrets_manager.delete_secret([uid1, uid2])
        expect(result).to be_an(Array)

        # Verify deletion
        remaining = secrets_manager.get_secrets([uid1, uid2])
        expect(remaining).to be_empty
      end
    end
  end

  describe 'folder operations' do
    context '#get_folders' do
      it 'retrieves all folders' do
        skip 'Skipping in mock mode - requires WebMock stubs' if use_mock_data

        folders = secrets_manager.get_folders
        expect(folders).to be_an(Array)

        if folders.any?
          folder = folders.first
          expect(folder).to be_a(KeeperSecretsManager::Dto::KeeperFolder)
          expect(folder.uid).not_to be_nil
          expect(folder.name).not_to be_nil
        end
      end
    end

    context '#create_folder' do
      it 'creates a new folder' do
        skip 'Skipping folder creation in mock mode' if use_mock_data

        folder_name = "RSpec Test Folder #{Time.now.to_i}"
        folder_uid = secrets_manager.create_folder(folder_name)

        expect(folder_uid).to match(/^[A-Za-z0-9_-]+$/)

        # Clean up
        secrets_manager.delete_folder(folder_uid, force: true)
      end
    end

    context '#update_folder' do
      it 'updates folder name' do
        skip 'Skipping folder update in mock mode' if use_mock_data

        # Create folder
        original_name = "Update Test #{Time.now.to_i}"
        folder_uid = secrets_manager.create_folder(original_name)

        # Update
        new_name = "Updated #{Time.now.to_i}"
        result = secrets_manager.update_folder(folder_uid, new_name)
        expect(result).to be true

        # Clean up
        secrets_manager.delete_folder(folder_uid, force: true)
      end
    end
  end

  describe 'notation support' do
    it 'resolves notation URIs' do
      skip 'No records available' if use_mock_data && mock_responses['get_all_records'].nil?

      records = secrets_manager.get_secrets
      skip 'No records to test with' if records.empty?

      record = records.first

      # Test type notation
      type_value = secrets_manager.get_notation("keeper://#{record.uid}/type")
      expect(type_value).to eq(record.type)

      # Test field notation if login field exists
      if record.get_field('login')
        login_value = secrets_manager.get_notation("keeper://#{record.uid}/field/login")
        expect(login_value).to eq(record.get_field_value_single('login'))
      end
    end
  end

  describe 'error handling' do
    it 'raises appropriate errors for invalid operations' do
      skip 'Skipping in mock mode - requires WebMock stubs' if use_mock_data

      expect do
        secrets_manager.get_secrets(['non-existent-uid'])
      end.not_to raise_error # Should return empty array

      expect do
        secrets_manager.get_notation('keeper://non-existent/field/login')
      end.to raise_error(KeeperSecretsManager::NotationError)
    end
  end

  describe 'complex field types' do
    it 'handles various field types correctly' do
      skip 'Skipping complex field test in mock mode' if use_mock_data

      complex_record = KeeperSecretsManager::Dto::KeeperRecord.new(
        title: "Complex Fields Test #{Time.now.to_i}",
        type: 'login',
        fields: [
          # Simple fields
          { 'type' => 'login', 'value' => ['testuser'] },
          { 'type' => 'password', 'value' => ['TestPass123!'] },

          # Multiple values
          { 'type' => 'url', 'value' => ['https://primary.com', 'https://backup.com'] },

          # Complex objects
          { 'type' => 'host', 'value' => [{ 'hostName' => '10.0.0.1', 'port' => '22' }] },
          { 'type' => 'name', 'value' => [{ 'first' => 'Test', 'middle' => 'Q', 'last' => 'User' }] },
          { 'type' => 'phone', 'value' => [{ 'region' => 'US', 'number' => '555-0123' }] },
          { 'type' => 'address', 'value' => [{
            'street1' => '123 Test St',
            'city' => 'Test City',
            'state' => 'TC',
            'zip' => '12345',
            'country' => 'US'
          }] }
        ],
        custom: [
          { 'type' => 'text', 'label' => 'Department', 'value' => ['Engineering'] },
          { 'type' => 'text', 'label' => 'Tags', 'value' => %w[test rspec ruby] }
        ]
      )

      uid = secrets_manager.create_secret(complex_record)

      # Test retrieval and field access
      retrieved = secrets_manager.get_secrets([uid]).first

      # Simple fields
      expect(retrieved.get_field_value_single('login')).to eq('testuser')

      # Multiple values
      urls = retrieved.get_field_value('url')
      expect(urls).to eq(['https://primary.com', 'https://backup.com'])

      # Complex fields via notation
      hostname = secrets_manager.get_notation("keeper://#{uid}/field/host[hostName]")
      expect(hostname).to eq('10.0.0.1')

      middle_name = secrets_manager.get_notation("keeper://#{uid}/field/name[middle]")
      expect(middle_name).to eq('Q')

      # Custom fields
      dept = secrets_manager.get_notation("keeper://#{uid}/custom_field/Department")
      expect(dept).to eq('Engineering')

      # Clean up
      secrets_manager.delete_secret(uid)
    end
  end
end
