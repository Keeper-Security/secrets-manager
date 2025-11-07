require 'spec_helper'
require 'tmpdir'

RSpec.describe KeeperSecretsManager::Cache do
  let(:temp_dir) { Dir.mktmpdir }
  let(:cache_file) { File.join(temp_dir, 'ksm_cache.bin') }

  before do
    # Override cache file location for tests
    allow(described_class).to receive(:cache_file_path).and_return(cache_file)
  end

  after do
    FileUtils.rm_rf(temp_dir)
  end

  describe '.save_cache' do
    it 'saves data to cache file' do
      data = 'test cache data'
      described_class.save_cache(data)

      expect(File.exist?(cache_file)).to be true
      expect(File.read(cache_file)).to eq(data)
    end

    it 'overwrites existing cache' do
      described_class.save_cache('first data')
      described_class.save_cache('second data')

      expect(File.read(cache_file)).to eq('second data')
    end

    it 'handles binary data' do
      binary_data = "\x00\x01\x02\xFF\xFE".force_encoding('ASCII-8BIT')
      described_class.save_cache(binary_data)

      loaded = File.binread(cache_file)
      expect(loaded).to eq(binary_data)
    end
  end

  describe '.get_cached_data' do
    it 'retrieves cached data' do
      data = 'cached content'
      File.write(cache_file, data)

      result = described_class.get_cached_data
      expect(result).to eq(data)
    end

    it 'returns nil when cache file does not exist' do
      result = described_class.get_cached_data
      expect(result).to be_nil
    end

    it 'handles binary data' do
      binary_data = "\x00\x01\x02\xFF\xFE".force_encoding('ASCII-8BIT')
      File.binwrite(cache_file, binary_data)

      result = described_class.get_cached_data
      expect(result).to eq(binary_data)
    end
  end

  describe '.clear_cache' do
    it 'removes cache file' do
      described_class.save_cache('test')
      expect(File.exist?(cache_file)).to be true

      described_class.clear_cache
      expect(File.exist?(cache_file)).to be false
    end

    it 'does not raise error if cache does not exist' do
      expect { described_class.clear_cache }.not_to raise_error
    end
  end

  describe '.cache_exists?' do
    it 'returns true when cache file exists' do
      described_class.save_cache('test')
      expect(described_class.cache_exists?).to be true
    end

    it 'returns false when cache file does not exist' do
      expect(described_class.cache_exists?).to be false
    end
  end

  describe '.cache_file_path' do
    it 'uses KSM_CACHE_DIR environment variable when set' do
      allow(ENV).to receive(:[]).with('KSM_CACHE_DIR').and_return('/custom/path')
      allow(described_class).to receive(:cache_file_path).and_call_original

      expect(described_class.cache_file_path).to eq('/custom/path/ksm_cache.bin')
    end

    it 'defaults to current directory when KSM_CACHE_DIR not set' do
      allow(ENV).to receive(:[]).with('KSM_CACHE_DIR').and_return(nil)
      allow(described_class).to receive(:cache_file_path).and_call_original

      expect(described_class.cache_file_path).to eq('./ksm_cache.bin')
    end
  end
end

RSpec.describe KeeperSecretsManager::CachingPostFunction do
  let(:url) { 'https://keepersecurity.com/api/rest/sm/v1/get_secret' }
  let(:transmission_key) do
    KeeperSecretsManager::Dto::TransmissionKey.new(
      public_key_id: '10',
      key: SecureRandom.random_bytes(32),
      encrypted_key: SecureRandom.random_bytes(100)
    )
  end
  let(:encrypted_payload) do
    payload = double('EncryptedPayload')
    allow(payload).to receive(:encrypted_payload).and_return('encrypted data')
    allow(payload).to receive(:signature).and_return(SecureRandom.random_bytes(64))
    payload
  end

  let(:temp_dir) { Dir.mktmpdir }
  let(:cache_file) { File.join(temp_dir, 'ksm_cache.bin') }

  before do
    allow(KeeperSecretsManager::Cache).to receive(:cache_file_path).and_return(cache_file)
    KeeperSecretsManager::Cache.clear_cache
  end

  after do
    FileUtils.rm_rf(temp_dir)
  end

  describe '.call' do
    context 'on successful network request' do
      it 'saves response to cache' do
        # Mock successful HTTP response
        response = KeeperSecretsManager::Dto::KSMHttpResponse.new(
          status_code: 200,
          data: 'response data'
        )

        allow(described_class).to receive(:make_http_request).and_return(response)

        result = described_class.call(url, transmission_key, encrypted_payload, true)

        expect(result).to eq(response)
        expect(KeeperSecretsManager::Cache.cache_exists?).to be true

        # Verify cache contains transmission key + response data
        cached = KeeperSecretsManager::Cache.get_cached_data
        expect(cached[0...32]).to eq(transmission_key.key)
        expect(cached[32..-1]).to eq('response data')
      end
    end

    context 'on network failure with cache available' do
      it 'falls back to cached data' do
        # Prime cache first
        cache_data = transmission_key.key + 'cached response data'
        KeeperSecretsManager::Cache.save_cache(cache_data)

        # Simulate network failure
        allow(described_class).to receive(:make_http_request).and_raise(
          KeeperSecretsManager::NetworkError, 'Connection failed'
        )

        result = described_class.call(url, transmission_key, encrypted_payload, true)

        expect(result).to be_a(KeeperSecretsManager::Dto::KSMHttpResponse)
        expect(result.status_code).to eq(200)
        expect(result.data).to eq('cached response data')
      end

      it 'updates transmission key with cached version' do
        original_key = transmission_key.key.dup
        cached_key = SecureRandom.random_bytes(32)
        cache_data = cached_key + 'response'
        KeeperSecretsManager::Cache.save_cache(cache_data)

        allow(described_class).to receive(:make_http_request).and_raise(
          KeeperSecretsManager::NetworkError
        )

        described_class.call(url, transmission_key, encrypted_payload, true)

        expect(transmission_key.key).to eq(cached_key)
        expect(transmission_key.key).not_to eq(original_key)
      end
    end

    context 'on network failure without cache' do
      it 're-raises the network error' do
        allow(described_class).to receive(:make_http_request).and_raise(
          KeeperSecretsManager::NetworkError, 'No connection'
        )

        expect {
          described_class.call(url, transmission_key, encrypted_payload, true)
        }.to raise_error(KeeperSecretsManager::NetworkError, 'No connection')
      end
    end

    context 'with invalid cache data' do
      it 're-raises error if cache is too small' do
        # Cache with less than 32 bytes (invalid)
        KeeperSecretsManager::Cache.save_cache('too short')

        allow(described_class).to receive(:make_http_request).and_raise(
          KeeperSecretsManager::NetworkError.new('Network error')
        )

        expect {
          described_class.call(url, transmission_key, encrypted_payload, true)
        }.to raise_error(KeeperSecretsManager::NetworkError, 'Network error')
      end
    end
  end
end
