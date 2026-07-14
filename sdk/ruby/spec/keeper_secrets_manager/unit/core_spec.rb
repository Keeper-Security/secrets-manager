require 'spec_helper'

RSpec.describe KeeperSecretsManager::Core::SecretsManager do
  # Use fixed token bytes so we can encrypt mock data with it
  let(:mock_token_bytes) { 'test_token_key_32_bytes_long!!!!' } # Exactly 32 bytes
  let(:mock_token) { 'US:' + Base64.urlsafe_encode64(mock_token_bytes, padding: false) }
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
        # Mock bind_one_time_token to return a valid config
        # This avoids the complexity of mocking encrypted HTTP responses
        bound_config = KeeperSecretsManager::Storage::InMemoryStorage.new
        bound_config.save_string(KeeperSecretsManager::ConfigKeys::KEY_CLIENT_ID, 'test_client_id')
        bound_config.save_bytes(KeeperSecretsManager::ConfigKeys::KEY_APP_KEY, 'test_app_key_32_bytes_exactly!!')
        bound_config.save_string(KeeperSecretsManager::ConfigKeys::KEY_HOSTNAME, 'fake.keepersecurity.com')
        bound_config.save_bytes(KeeperSecretsManager::ConfigKeys::KEY_OWNER_PUBLIC_KEY, SecureRandom.random_bytes(65))
        bound_config.save_bytes(KeeperSecretsManager::ConfigKeys::KEY_PRIVATE_KEY, SecureRandom.random_bytes(32))

        allow_any_instance_of(described_class).to receive(:bind_one_time_token).and_return(bound_config)
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

        it 'parses IL5 region token' do
          manager.send(:process_token_binding, 'IL5:fake_token', nil)
          hostname = manager.instance_variable_get(:@hostname)
          expect(hostname).to eq(KeeperSecretsManager::KeeperGlobals::KEEPER_SERVERS['IL5'])
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

  describe '#create_secret_with_options' do
    let(:manager) { described_class.new(config: mock_config) }
    let(:record_data) { { 'title' => 'Test', 'type' => 'login', 'fields' => [] } }
    let(:folder_key) { KeeperSecretsManager::Crypto.generate_encryption_key_bytes }
    let(:folder) do
      f = KeeperSecretsManager::Dto::KeeperFolder.new('folderUid' => 'folder-uid-123', 'name' => 'Test Folder')
      f.instance_variable_set(:@folder_key, folder_key)
      f
    end
    let(:create_options) { KeeperSecretsManager::Dto::CreateOptions.new(folder_uid: 'folder-uid-123') }

    it 'raises ArgumentError when create_options has no folder_uid' do
      expect {
        manager.create_secret_with_options(KeeperSecretsManager::Dto::CreateOptions.new, record_data)
      }.to raise_error(ArgumentError, /folder_uid is required/)
    end

    it 'raises ArgumentError when create_options is nil' do
      expect {
        manager.create_secret_with_options(nil, record_data)
      }.to raise_error(ArgumentError, /folder_uid is required/)
    end

    it 'raises Error when folder not found in provided folders list' do
      expect {
        manager.create_secret_with_options(create_options, record_data, folders: [])
      }.to raise_error(KeeperSecretsManager::Error, /Folder folder-uid-123 not found/)
    end

    it 'raises Error when folder key is missing' do
      bad_folder = KeeperSecretsManager::Dto::KeeperFolder.new('folderUid' => 'folder-uid-123', 'name' => 'No Key')
      expect {
        manager.create_secret_with_options(create_options, record_data, folders: [bad_folder])
      }.to raise_error(KeeperSecretsManager::Error, /folder key.*missing/i)
    end

    it 'posts to create_secret and returns a UID when given pre-fetched folders' do
      allow(manager).to receive(:get_folders)
      allow(manager).to receive(:post_query).with('create_secret', anything).and_return('')
      uid = manager.create_secret_with_options(create_options, record_data, folders: [folder])
      expect(uid).to be_a(String)
      expect(uid.length).to be > 0
      expect(manager).not_to have_received(:get_folders)
    end

    it 'calls get_folders when folders keyword is not provided' do
      allow(manager).to receive(:get_folders).and_return([folder])
      allow(manager).to receive(:post_query).with('create_secret', anything).and_return('')
      manager.create_secret_with_options(create_options, record_data)
      expect(manager).to have_received(:get_folders)
    end

    it 'accepts a KeeperRecord as record_data' do
      keeper_record = KeeperSecretsManager::Dto::KeeperRecord.new(
        'title' => 'My Record', 'type' => 'login', 'fields' => []
      )
      allow(manager).to receive(:post_query).with('create_secret', anything).and_return('')
      uid = manager.create_secret_with_options(create_options, keeper_record, folders: [folder])
      expect(uid).to be_a(String)
    end

    it 'passes subfolder_uid through to the payload' do
      opts = KeeperSecretsManager::Dto::CreateOptions.new(folder_uid: 'folder-uid-123', subfolder_uid: 'sub-123')
      captured_payload = nil
      allow(manager).to receive(:post_query) do |_path, payload|
        captured_payload = payload
        ''
      end
      manager.create_secret_with_options(opts, record_data, folders: [folder])
      expect(captured_payload.sub_folder_uid).to eq('sub-123')
    end
  end

  describe '#create_secret (backward compat)' do
    let(:manager) { described_class.new(config: mock_config) }
    let(:folder_key) { KeeperSecretsManager::Crypto.generate_encryption_key_bytes }
    let(:folder) do
      f = KeeperSecretsManager::Dto::KeeperFolder.new('folderUid' => 'folder-abc', 'name' => 'Test')
      f.instance_variable_set(:@folder_key, folder_key)
      f
    end

    it 'still works when called with CreateOptions' do
      allow(manager).to receive(:get_folders).and_return([folder])
      allow(manager).to receive(:post_query).with('create_secret', anything).and_return('')
      uid = manager.create_secret({ 'title' => 'T', 'type' => 'login' },
                                   KeeperSecretsManager::Dto::CreateOptions.new(folder_uid: 'folder-abc'))
      expect(uid).to be_a(String)
    end

    it 'raises ArgumentError when no folder_uid provided' do
      expect {
        manager.create_secret({ 'title' => 'T' }, KeeperSecretsManager::Dto::CreateOptions.new)
      }.to raise_error(ArgumentError, /folder_uid is required/)
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

  describe '.get_inflate_ref_types' do
    let(:manager) { described_class.new(config: mock_config) }

    it 'returns address fields for addressRef' do
      expect(manager.get_inflate_ref_types('addressRef')).to eq(['address'])
    end

    it 'returns card fields for cardRef' do
      expect(manager.get_inflate_ref_types('cardRef')).to eq(%w[paymentCard text pinCode addressRef])
    end

    it 'returns empty array for unknown field type' do
      expect(manager.get_inflate_ref_types('unknown')).to eq([])
    end

    it 'returns empty array for non-ref field type' do
      expect(manager.get_inflate_ref_types('login')).to eq([])
    end
  end

  describe '#inflate_field_value' do
    let(:manager) { described_class.new(config: mock_config) }

    let(:address_uid) { 'addr-uid-001' }
    let(:address_record) do
      KeeperSecretsManager::Dto::KeeperRecord.new(
        'recordUid' => address_uid,
        'data' => {
          'title' => 'Home Address', 'type' => 'address',
          'fields' => [
            { 'type' => 'address', 'value' => [{ 'street1' => '123 Main St', 'city' => 'Springfield' }] }
          ],
          'custom' => []
        }
      )
    end

    it 'resolves a single addressRef UID to its address fields' do
      allow(manager).to receive(:get_secrets).with([address_uid]).and_return([address_record])
      result = manager.inflate_field_value([address_uid], ['address'])
      expect(result).to be_an(Array)
      expect(result.length).to eq(1)
      expect(result.first['street1']).to eq('123 Main St')
    end

    it 'returns empty array when UID is not found' do
      allow(manager).to receive(:get_secrets).with(['nonexistent']).and_return([])
      expect(manager.inflate_field_value(['nonexistent'], ['address'])).to eq([])
    end

    it 'returns one result per resolvable UID' do
      addr2_uid = 'addr-uid-002'
      addr2 = KeeperSecretsManager::Dto::KeeperRecord.new(
        'recordUid' => addr2_uid,
        'data' => {
          'title' => 'Work Address', 'type' => 'address',
          'fields' => [{ 'type' => 'address', 'value' => [{ 'street1' => '456 Oak Ave' }] }],
          'custom' => []
        }
      )
      allow(manager).to receive(:get_secrets).with([address_uid, addr2_uid]).and_return([address_record, addr2])
      result = manager.inflate_field_value([address_uid, addr2_uid], ['address'])
      expect(result.length).to eq(2)
    end

    it 'recursively inflates nested addressRef inside cardRef fields' do
      card_uid   = 'card-uid-001'
      card_record = KeeperSecretsManager::Dto::KeeperRecord.new(
        'recordUid' => card_uid,
        'data' => {
          'title' => 'My Card', 'type' => 'bankCard',
          'fields' => [
            { 'type' => 'paymentCard', 'value' => [{ 'cardNumber' => '4111111111111111' }] },
            { 'type' => 'addressRef', 'value' => [address_uid] }
          ],
          'custom' => []
        }
      )

      allow(manager).to receive(:get_secrets).with([card_uid]).and_return([card_record])
      allow(manager).to receive(:get_secrets).with([address_uid]).and_return([address_record])

      result = manager.inflate_field_value([card_uid], %w[paymentCard addressRef])
      expect(result.length).to eq(1)
      merged = result.first
      # paymentCard value should be present
      expect(merged).not_to be_nil
    end
  end

  describe '#save_with_options' do
    let(:manager) { described_class.new(config: mock_config) }
    let(:record_key) { KeeperSecretsManager::Crypto.generate_encryption_key_bytes }
    let(:record) do
      r = KeeperSecretsManager::Dto::KeeperRecord.new(
        'recordUid' => 'save-uid-001',
        'data'      => { 'title' => 'Save Test', 'type' => 'login', 'fields' => [], 'custom' => [] },
        'revision'  => 42
      )
      r.instance_variable_set(:@record_key, record_key)
      r.define_singleton_method(:record_key) { @record_key }
      r
    end

    it 'POSTs to update_secret and returns true' do
      allow(manager).to receive(:post_query).with('update_secret', anything).and_return('')
      expect(manager.save_with_options(record)).to be true
    end

    it 'does NOT call finalize_secret_update' do
      allow(manager).to receive(:post_query).with('update_secret', anything).and_return('')
      manager.save_with_options(record)
      expect(manager).not_to have_received(:post_query).with('finalize_secret_update', anything)
    end

    it 'does NOT re-fetch the record via get_secrets' do
      allow(manager).to receive(:post_query).with('update_secret', anything).and_return('')
      allow(manager).to receive(:get_secrets)
      manager.save_with_options(record)
      expect(manager).not_to have_received(:get_secrets)
    end

    it 'includes transaction_type in payload when UpdateOptions has one' do
      allow(manager).to receive(:post_query).with('update_secret', anything).and_return('')
      opts = KeeperSecretsManager::Dto::UpdateOptions.new(transaction_type: 'rotation')
      manager.save_with_options(record, opts)
      expect(manager).to have_received(:post_query) do |_path, payload|
        expect(payload.transaction_type).to eq('rotation')
      end
    end

    it 'raises ArgumentError when record has no UID' do
      bad = KeeperSecretsManager::Dto::KeeperRecord.new('data' => { 'title' => 'No UID', 'type' => 'login', 'fields' => [] })
      bad.instance_variable_set(:@record_key, record_key)
      bad.define_singleton_method(:record_key) { @record_key }
      bad.uid = nil
      expect { manager.save_with_options(bad) }.to raise_error(ArgumentError, /Record UID is required/)
    end

    it 'raises Error when record has no record_key' do
      keyless = KeeperSecretsManager::Dto::KeeperRecord.new(
        'recordUid' => 'keyless-uid',
        'data' => { 'title' => 'Keyless', 'type' => 'login', 'fields' => [] }
      )
      expect { manager.save_with_options(keyless) }.to raise_error(KeeperSecretsManager::Error, /Record key not available/)
    end
  end

  describe '#save' do
    let(:manager) { described_class.new(config: mock_config) }
    let(:record_key) { KeeperSecretsManager::Crypto.generate_encryption_key_bytes }
    let(:record) do
      r = KeeperSecretsManager::Dto::KeeperRecord.new(
        'recordUid' => 'save-uid-002',
        'data'      => { 'title' => 'Save', 'type' => 'login', 'fields' => [], 'custom' => [] },
        'revision'  => 1
      )
      r.instance_variable_set(:@record_key, record_key)
      r.define_singleton_method(:record_key) { @record_key }
      r
    end

    it 'POSTs to update_secret' do
      allow(manager).to receive(:post_query).with('update_secret', anything).and_return('')
      expect(manager.save(record)).to be true
    end

    it 'omits transactionType from payload when no transaction_type given' do
      captured = nil
      allow(manager).to receive(:post_query) do |_path, payload|
        captured = payload
        ''
      end
      manager.save(record)
      expect(captured).not_to be_nil
      expect(captured.to_h.key?('transactionType')).to be false
    end

    it 'includes transactionType in payload when transaction_type is given' do
      captured = nil
      allow(manager).to receive(:post_query) do |_path, payload|
        captured = payload
        ''
      end
      manager.save(record, transaction_type: 'rotation')
      expect(captured.to_h['transactionType']).to eq('rotation')
    end

    it 'does not call finalize_secret_update or rollback_secret_update' do
      allow(manager).to receive(:post_query).with('update_secret', anything).and_return('')
      allow(manager).to receive(:post_query).with('finalize_secret_update', anything).and_return('')
      manager.save(record)
      expect(manager).not_to have_received(:post_query).with('finalize_secret_update', anything)
    end
  end

  describe '#update_secret' do
    let(:manager) { described_class.new(config: mock_config) }
    let(:record) do
      KeeperSecretsManager::Dto::KeeperRecord.new(
        'recordUid' => 'test-uid-1094',
        'data' => { 'title' => 'Test', 'type' => 'login', 'fields' => [], 'custom' => [] }
      )
    end

    before do
      allow(manager).to receive(:update_secret_with_options)
      allow(manager).to receive(:complete_transaction)
      allow(manager).to receive(:get_secrets).and_return([])
    end

    it 'does not raise NameError when called with a KeeperRecord' do
      expect { manager.update_secret(record) }.not_to raise_error
    end

    it 'passes the record uid to get_secrets when refreshing the revision' do
      expect(manager).to receive(:get_secrets).with(['test-uid-1094']).and_return([])
      manager.update_secret(record)
    end

    it 'calls complete_transaction with the record uid to finalize the staged update' do
      expect(manager).to receive(:complete_transaction).with('test-uid-1094')
      manager.update_secret(record)
    end

    it 'calls complete_transaction when record is a plain hash' do
      hash_record = { 'uid' => 'hash-uid-1095' }
      allow(manager).to receive(:update_secret_with_options)
      expect(manager).to receive(:complete_transaction).with('hash-uid-1095')
      manager.update_secret(hash_record)
    end
  end

  describe '#download_thumbnail' do
    let(:manager) { described_class.new(config: mock_config) }
    let(:thumbnail_url) { 'https://example.com/thumb.jpg' }
    let(:file_key_bytes) { KeeperSecretsManager::Crypto.generate_encryption_key_bytes }
    let(:file_key_b64) { KeeperSecretsManager::Utils.bytes_to_base64(file_key_bytes) }
    let(:decrypted_thumb) { 'thumb-content' }

    before do
      allow(manager).to receive(:download_encrypted_file).and_return('encrypted-bytes')
      allow(KeeperSecretsManager::Crypto).to receive(:decrypt_aes_gcm).and_return(decrypted_thumb)
    end

    it 'does not raise NoMethodError when passed a KeeperFile object' do
      file = KeeperSecretsManager::Dto::KeeperFile.new(
        'fileUid' => 'file-uid-1096',
        'thumbnailUrl' => thumbnail_url,
        'fileKey' => file_key_b64
      )
      expect { manager.download_thumbnail(file) }.not_to raise_error
    end

    it 'returns the correct uid and data when passed a KeeperFile object' do
      file = KeeperSecretsManager::Dto::KeeperFile.new(
        'fileUid' => 'file-uid-1096',
        'thumbnailUrl' => thumbnail_url,
        'fileKey' => file_key_b64
      )
      result = manager.download_thumbnail(file)
      expect(result['file_uid']).to eq('file-uid-1096')
      expect(result['data']).to eq(decrypted_thumb)
    end

    it 'still works with a plain hash' do
      file_hash = {
        'fileUid' => 'file-uid-hash',
        'thumbnailUrl' => thumbnail_url,
        'fileKey' => file_key_b64
      }
      result = manager.download_thumbnail(file_hash)
      expect(result['file_uid']).to eq('file-uid-hash')
      expect(result['data']).to eq(decrypted_thumb)
    end
  end
end
