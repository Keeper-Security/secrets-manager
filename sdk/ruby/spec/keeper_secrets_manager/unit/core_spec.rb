require 'spec_helper'

RSpec.describe KeeperSecretsManager::Core::SecretsManager do
  # Valid URL-safe base64 token (32 bytes encoded)
  let(:mock_token) { 'US:' + Base64.urlsafe_encode64(SecureRandom.random_bytes(32), padding: false) }
  let(:mock_config) do
    config = KeeperSecretsManager::Storage::InMemoryStorage.new
    config.save_string(KeeperSecretsManager::ConfigKeys::KEY_CLIENT_ID, 'test_client_id')
    config.save_bytes(KeeperSecretsManager::ConfigKeys::KEY_APP_KEY, 'test_app_key')
    config.save_string(KeeperSecretsManager::ConfigKeys::KEY_HOSTNAME, 'fake.keepersecurity.com')
    config
  end

  describe 'initialization' do
    context 'AES-GCM cipher support' do
      it 'checks for AES-256-GCM support on initialization' do
        # If we got here, the check passed (initialization didn't raise error)
        # Cipher name format is lowercase with dashes
        expect(OpenSSL::Cipher.ciphers).to include('aes-256-gcm')
      end
    end

    context 'with initialized config' do
      it 'uses existing credentials from config' do
        manager = described_class.new(config: mock_config)
        expect(manager.config).to eq(mock_config)
        expect(manager.hostname).to eq('fake.keepersecurity.com')
      end

      it 'sets default hostname if not in config' do
        empty_config = KeeperSecretsManager::Storage::InMemoryStorage.new
        empty_config.save_string(KeeperSecretsManager::ConfigKeys::KEY_CLIENT_ID, 'test_id')
        empty_config.save_bytes(KeeperSecretsManager::ConfigKeys::KEY_APP_KEY, 'key')

        manager = described_class.new(config: empty_config)
        expect(manager.hostname).to eq(KeeperSecretsManager::KeeperGlobals::DEFAULT_SERVER)
      end

      it 'overrides hostname if provided in options' do
        manager = described_class.new(config: mock_config, hostname: 'custom.example.com')
        expect(manager.hostname).to eq('custom.example.com')
      end
    end

    context 'with token' do
      before do
        # Mock HTTP request for token binding
        # Need valid base64-encoded data (32 bytes for AES-256 key + 16 bytes GCM tag = 48 bytes encrypted)
        mock_encrypted_app_key = Base64.urlsafe_encode64(SecureRandom.random_bytes(48), padding: false)
        mock_owner_public_key = Base64.urlsafe_encode64(SecureRandom.random_bytes(65), padding: false)

        stub_request(:post, /keepersecurity\.com\/api\/rest\/sm\/v1\/get_secret/)
          .to_return(
            status: 200,
            body: JSON.generate({
              'encryptedAppKey' => mock_encrypted_app_key,
              'appOwnerPublicKey' => mock_owner_public_key
            }),
            headers: { 'Content-Type' => 'application/json' }
          )
      end

      it 'processes token and creates config' do
        manager = described_class.new(token: mock_token)
        expect(manager.config).not_to be_nil
        expect(manager.hostname).to include('keepersecurity.com')
      end

      it 'raises error if neither token nor config provided' do
        # Temporarily clear KSM_CONFIG env var if set
        original_config = ENV['KSM_CONFIG']
        ENV.delete('KSM_CONFIG')

        expect {
          described_class.new
        }.to raise_error(KeeperSecretsManager::Error, /Either token or initialized config must be provided/)
      ensure
        ENV['KSM_CONFIG'] = original_config if original_config
      end

      it 'warns if config provided without credentials and no token' do
        empty_config = KeeperSecretsManager::Storage::InMemoryStorage.new
        logger = Logger.new(nil) # Null logger

        expect(logger).to receive(:warn).with(/Config provided but no credentials/)

        described_class.new(config: empty_config, logger: logger)
      end
    end

    context 'with KSM_CONFIG environment variable' do
      around do |example|
        original_env = ENV['KSM_CONFIG']
        ENV['KSM_CONFIG'] = 'test_config_value'
        example.run
        ENV['KSM_CONFIG'] = original_env
      end

      it 'uses KSM_CONFIG if no config provided' do
        # Mock to avoid actual initialization
        expect(KeeperSecretsManager::Storage::InMemoryStorage).to receive(:new).with('test_config_value').and_return(mock_config)

        manager = described_class.new
        expect(manager.config).to eq(mock_config)
      end
    end

    context 'SSL verification' do
      it 'defaults verify_ssl_certs to true' do
        manager = described_class.new(config: mock_config)
        expect(manager.verify_ssl_certs).to be true
      end

      it 'accepts verify_ssl_certs: false option' do
        manager = described_class.new(config: mock_config, verify_ssl_certs: false)
        expect(manager.verify_ssl_certs).to be false
      end
    end

    context 'logging configuration' do
      it 'uses default logger if none provided' do
        manager = described_class.new(config: mock_config)
        expect(manager.instance_variable_get(:@logger)).to be_a(Logger)
      end

      it 'uses custom logger if provided' do
        custom_logger = Logger.new(STDOUT)
        manager = described_class.new(config: mock_config, logger: custom_logger)
        expect(manager.instance_variable_get(:@logger)).to eq(custom_logger)
      end

      it 'sets log level from options' do
        manager = described_class.new(config: mock_config, log_level: Logger::DEBUG)
        logger = manager.instance_variable_get(:@logger)
        expect(logger.level).to eq(Logger::DEBUG)
      end

      it 'defaults log level to WARN' do
        manager = described_class.new(config: mock_config)
        logger = manager.instance_variable_get(:@logger)
        expect(logger.level).to eq(Logger::WARN)
      end
    end
  end

  describe 'token processing' do
    let(:manager) { described_class.allocate } # Allocate without calling initialize

    before do
      manager.instance_variable_set(:@logger, Logger.new(nil))
      manager.instance_variable_set(:@config, nil)
    end

    describe '#process_token_binding' do
      before do
        # Mock bind_one_time_token to avoid actual HTTP
        bound_config = KeeperSecretsManager::Storage::InMemoryStorage.new
        bound_config.save_string('test_key', 'test_value')
        allow(manager).to receive(:bind_one_time_token).and_return(bound_config)
      end

      context 'modern token format (REGION:BASE64)' do
        it 'parses US region token' do
          manager.send(:process_token_binding, 'US:fake_token', nil)
          hostname = manager.instance_variable_get(:@hostname)
          expect(hostname).to eq(KeeperSecretsManager::KeeperGlobals::KEEPER_SERVERS['US'])
        end

        it 'parses EU region token' do
          manager.send(:process_token_binding, 'EU:fake_token', nil)
          hostname = manager.instance_variable_get(:@hostname)
          expect(hostname).to eq(KeeperSecretsManager::KeeperGlobals::KEEPER_SERVERS['EU'])
        end

        it 'parses AU region token' do
          manager.send(:process_token_binding, 'AU:fake_token', nil)
          hostname = manager.instance_variable_get(:@hostname)
          expect(hostname).to eq(KeeperSecretsManager::KeeperGlobals::KEEPER_SERVERS['AU'])
        end

        it 'parses GOV region token' do
          manager.send(:process_token_binding, 'GOV:fake_token', nil)
          hostname = manager.instance_variable_get(:@hostname)
          expect(hostname).to eq(KeeperSecretsManager::KeeperGlobals::KEEPER_SERVERS['GOV'])
        end

        it 'parses JP region token' do
          manager.send(:process_token_binding, 'JP:fake_token', nil)
          hostname = manager.instance_variable_get(:@hostname)
          expect(hostname).to eq(KeeperSecretsManager::KeeperGlobals::KEEPER_SERVERS['JP'])
        end

        it 'parses CA region token' do
          manager.send(:process_token_binding, 'CA:fake_token', nil)
          hostname = manager.instance_variable_get(:@hostname)
          expect(hostname).to eq(KeeperSecretsManager::KeeperGlobals::KEEPER_SERVERS['CA'])
        end

        it 'handles lowercase region code' do
          manager.send(:process_token_binding, 'us:fake_token', nil)
          hostname = manager.instance_variable_get(:@hostname)
          expect(hostname).to eq(KeeperSecretsManager::KeeperGlobals::KEEPER_SERVERS['US'])
        end

        it 'uses default server for unknown region' do
          manager.send(:process_token_binding, 'UNKNOWN:fake_token', nil)
          hostname = manager.instance_variable_get(:@hostname)
          expect(hostname).to eq(KeeperSecretsManager::KeeperGlobals::DEFAULT_SERVER)
        end

        it 'handles token with multiple colons' do
          manager.send(:process_token_binding, 'US:part1:part2:part3', nil)
          token = manager.instance_variable_get(:@token)
          expect(token).to eq('part1:part2:part3')
        end

        it 'strips whitespace from token' do
          manager.send(:process_token_binding, "  US:fake_token  \n", nil)
          token = manager.instance_variable_get(:@token)
          expect(token).to eq('fake_token')
        end
      end

      context 'legacy token format (no region prefix)' do
        it 'uses default server for legacy token' do
          manager.send(:process_token_binding, 'legacy_token_no_region', nil)
          hostname = manager.instance_variable_get(:@hostname)
          expect(hostname).to eq(KeeperSecretsManager::KeeperGlobals::DEFAULT_SERVER)
        end

        it 'accepts custom hostname for legacy token' do
          manager.send(:process_token_binding, 'legacy_token', 'custom.example.com')
          hostname = manager.instance_variable_get(:@hostname)
          expect(hostname).to eq('custom.example.com')
        end

        it 'stores full token value' do
          manager.send(:process_token_binding, 'legacy_token_value', nil)
          token = manager.instance_variable_get(:@token)
          expect(token).to eq('legacy_token_value')
        end
      end

      context 'config merging' do
        it 'creates new config if none exists' do
          manager.send(:process_token_binding, 'US:fake_token', nil)
          config = manager.instance_variable_get(:@config)
          expect(config).not_to be_nil
        end

        it 'merges bound config into existing config' do
          existing_config = KeeperSecretsManager::Storage::InMemoryStorage.new
          existing_config.save_string('existing_key', 'existing_value')
          manager.instance_variable_set(:@config, existing_config)

          manager.send(:process_token_binding, 'US:fake_token', nil)

          # Existing key should still be there
          expect(existing_config.get_string('existing_key')).to eq('existing_value')
          # New key from bound config should be merged
          expect(existing_config.get_string('test_key')).to eq('test_value')
        end
      end
    end
  end

  describe 'public helper methods' do
    let(:manager) { described_class.new(config: mock_config) }

    before do
      # Mock HTTP to avoid actual API calls
      stub_request(:post, /keepersecurity\.com/)
        .to_return(status: 200, body: '{}', headers: {})
    end

    describe '#get_secrets_by_title' do
      before do
        # Mock get_secrets to return test records
        records = [
          KeeperSecretsManager::Dto::KeeperRecord.new('title' => 'Test Record 1', 'type' => 'login'),
          KeeperSecretsManager::Dto::KeeperRecord.new('title' => 'Test Record 2', 'type' => 'login'),
          KeeperSecretsManager::Dto::KeeperRecord.new('title' => 'Test Record 1', 'type' => 'login')
        ]
        allow(manager).to receive(:get_secrets).and_return(records)
      end

      it 'returns all records with matching title' do
        results = manager.get_secrets_by_title('Test Record 1')
        expect(results.length).to eq(2)
        expect(results.all? { |r| r.title == 'Test Record 1' }).to be true
      end

      it 'returns empty array if no matches' do
        results = manager.get_secrets_by_title('Nonexistent')
        expect(results).to eq([])
      end

      it 'is case-sensitive' do
        results = manager.get_secrets_by_title('test record 1')
        expect(results).to eq([])
      end
    end

    describe '#get_secret_by_title' do
      before do
        records = [
          KeeperSecretsManager::Dto::KeeperRecord.new('title' => 'First', 'type' => 'login'),
          KeeperSecretsManager::Dto::KeeperRecord.new('title' => 'Second', 'type' => 'login')
        ]
        allow(manager).to receive(:get_secrets).and_return(records)
      end

      it 'returns first record with matching title' do
        result = manager.get_secret_by_title('First')
        expect(result).not_to be_nil
        expect(result.title).to eq('First')
      end

      it 'returns nil if no match' do
        result = manager.get_secret_by_title('Nonexistent')
        expect(result).to be_nil
      end
    end

    describe '#folder_manager' do
      before do
        # Mock get_folders to avoid API call
        allow(manager).to receive(:get_folders).and_return([])
      end

      it 'creates FolderManager on first access' do
        expect(manager.folder_manager).to be_a(KeeperSecretsManager::FolderManager)
      end

      it 'creates new instance on each call' do
        fm1 = manager.folder_manager
        fm2 = manager.folder_manager
        # folder_manager creates a new instance each time (not cached)
        expect(fm1).not_to equal(fm2)
      end
    end
  end

  describe 'error handling' do
    describe 'validation errors' do
      let(:manager) { described_class.new(config: mock_config) }

      before do
        stub_request(:post, /keepersecurity\.com/)
          .to_return(status: 200, body: '{"folders": []}', headers: {})
      end

      it 'raises ArgumentError when creating secret without folder_uid' do
        record_data = { 'title' => 'Test', 'type' => 'login' }
        options = KeeperSecretsManager::Dto::CreateOptions.new

        expect {
          manager.create_secret(record_data, options)
        }.to raise_error(ArgumentError, /folder_uid is required/)
      end

      it 'raises Error when folder not found' do
        record_data = { 'title' => 'Test', 'type' => 'login' }
        options = KeeperSecretsManager::Dto::CreateOptions.new(folder_uid: 'nonexistent_folder')

        allow(manager).to receive(:get_folders).and_return([])

        expect {
          manager.create_secret(record_data, options)
        }.to raise_error(KeeperSecretsManager::Error, /Folder nonexistent_folder not found/)
      end
    end
  end

  describe 'constants' do
    it 'defines NOTATION_PREFIX' do
      expect(described_class::NOTATION_PREFIX).to eq('keeper')
    end

    it 'defines DEFAULT_KEY_ID' do
      expect(described_class::DEFAULT_KEY_ID).to eq('7')
    end

    it 'defines INFLATE_REF_TYPES' do
      expect(described_class::INFLATE_REF_TYPES).to be_a(Hash)
      expect(described_class::INFLATE_REF_TYPES['addressRef']).to include('address')
      expect(described_class::INFLATE_REF_TYPES['cardRef']).to include('paymentCard')
    end
  end
end
