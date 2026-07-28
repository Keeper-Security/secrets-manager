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

  describe 'error handling' do
    context 'save_cache with write errors' do
      it 'silently handles permission denied errors' do
        allow(File).to receive(:open).and_raise(Errno::EACCES, 'Permission denied')

        expect { described_class.save_cache('test') }.not_to raise_error
      end

      it 'silently handles disk full errors' do
        allow(File).to receive(:open).and_raise(Errno::ENOSPC, 'No space left on device')

        expect { described_class.save_cache('test') }.not_to raise_error
      end

      it 'silently handles read-only filesystem errors' do
        allow(File).to receive(:open).and_raise(Errno::EROFS, 'Read-only file system')

        expect { described_class.save_cache('test') }.not_to raise_error
      end

      it 'warns when KSM_DEBUG is enabled' do
        allow(File).to receive(:open).and_raise(StandardError, 'Test error')
        allow(ENV).to receive(:[]).with('KSM_DEBUG').and_return('true')

        expect { described_class.save_cache('test') }.to output(/Failed to write cache/).to_stderr
      end

      it 'does not warn when KSM_DEBUG is disabled' do
        allow(File).to receive(:open).and_raise(StandardError, 'Test error')
        allow(ENV).to receive(:[]).with('KSM_DEBUG').and_return(nil)

        expect { described_class.save_cache('test') }.not_to output.to_stderr
      end
    end

    context 'get_cached_data with read errors' do
      it 'returns nil on permission denied' do
        File.write(cache_file, 'test')
        allow(File).to receive(:open).and_raise(Errno::EACCES, 'Permission denied')

        expect(described_class.get_cached_data).to be_nil
      end

      it 'returns nil on file corruption' do
        File.write(cache_file, 'test')
        allow(File).to receive(:open).and_raise(StandardError, 'Corrupted file')

        expect(described_class.get_cached_data).to be_nil
      end

      it 'warns when KSM_DEBUG is enabled' do
        File.write(cache_file, 'test')
        allow(File).to receive(:open).and_raise(StandardError, 'Test error')
        allow(ENV).to receive(:[]).with('KSM_DEBUG').and_return('true')

        expect { described_class.get_cached_data }.to output(/Failed to read cache/).to_stderr
      end

      it 'does not warn when KSM_DEBUG is disabled' do
        File.write(cache_file, 'test')
        allow(File).to receive(:open).and_raise(StandardError, 'Test error')
        allow(ENV).to receive(:[]).with('KSM_DEBUG').and_return(nil)

        expect { described_class.get_cached_data }.not_to output.to_stderr
      end
    end

    context 'clear_cache with delete errors' do
      it 'silently handles permission denied errors' do
        described_class.save_cache('test')
        allow(File).to receive(:delete).and_raise(Errno::EACCES, 'Permission denied')

        expect { described_class.clear_cache }.not_to raise_error
      end

      it 'warns when KSM_DEBUG is enabled' do
        described_class.save_cache('test')
        allow(File).to receive(:delete).and_raise(StandardError, 'Test error')
        allow(ENV).to receive(:[]).with('KSM_DEBUG').and_return('true')

        expect { described_class.clear_cache }.to output(/Failed to delete cache/).to_stderr
      end
    end
  end

  describe 'large data handling' do
    it 'handles very large cache files' do
      large_data = 'x' * (10 * 1024 * 1024) # 10 MB
      described_class.save_cache(large_data)

      result = described_class.get_cached_data
      expect(result).to eq(large_data)
      expect(result.bytesize).to eq(10 * 1024 * 1024)
    end

    it 'handles empty cache data' do
      described_class.save_cache('')

      result = described_class.get_cached_data
      expect(result).to eq('')
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

      it 're-raises error if cache is exactly 32 bytes (no response data)' do
        # Cache with exactly 32 bytes (transmission key only, no response)
        KeeperSecretsManager::Cache.save_cache(SecureRandom.random_bytes(32))

        allow(described_class).to receive(:make_http_request).and_raise(
          KeeperSecretsManager::NetworkError.new('Network error')
        )

        expect {
          described_class.call(url, transmission_key, encrypted_payload, true)
        }.to raise_error(KeeperSecretsManager::NetworkError, 'Network error')
      end

      it 're-raises error if cache is empty' do
        KeeperSecretsManager::Cache.save_cache('')

        allow(described_class).to receive(:make_http_request).and_raise(
          KeeperSecretsManager::NetworkError.new('Network error')
        )

        expect {
          described_class.call(url, transmission_key, encrypted_payload, true)
        }.to raise_error(KeeperSecretsManager::NetworkError, 'Network error')
      end
    end

    context 'response variations' do
      it 'does not cache unsuccessful responses' do
        response = KeeperSecretsManager::Dto::KSMHttpResponse.new(
          status_code: 500,
          data: 'error response'
        )

        allow(described_class).to receive(:make_http_request).and_return(response)

        described_class.call(url, transmission_key, encrypted_payload, true)

        expect(KeeperSecretsManager::Cache.cache_exists?).to be false
      end

      it 'does not cache responses without data' do
        response = KeeperSecretsManager::Dto::KSMHttpResponse.new(
          status_code: 200,
          data: nil
        )

        allow(described_class).to receive(:make_http_request).and_return(response)

        described_class.call(url, transmission_key, encrypted_payload, true)

        expect(KeeperSecretsManager::Cache.cache_exists?).to be false
      end

      it 'caches responses with empty data' do
        response = KeeperSecretsManager::Dto::KSMHttpResponse.new(
          status_code: 200,
          data: ''
        )

        allow(described_class).to receive(:make_http_request).and_return(response)

        described_class.call(url, transmission_key, encrypted_payload, true)

        # Empty string is truthy in Ruby, so it will be cached
        expect(KeeperSecretsManager::Cache.cache_exists?).to be true
      end
    end

    context 'cache with minimal valid data' do
      it 'uses cache with exactly 33 bytes (32 key + 1 byte response)' do
        cache_data = SecureRandom.random_bytes(32) + 'x'
        KeeperSecretsManager::Cache.save_cache(cache_data)

        allow(described_class).to receive(:make_http_request).and_raise(
          KeeperSecretsManager::NetworkError
        )

        result = described_class.call(url, transmission_key, encrypted_payload, true)

        expect(result.status_code).to eq(200)
        expect(result.data).to eq('x')
      end
    end
  end

  describe '.make_http_request' do
    let(:url) { 'https://keepersecurity.com/api/test' }
    let(:transmission_key) do
      KeeperSecretsManager::Dto::TransmissionKey.new(
        public_key_id: '10',
        key: SecureRandom.random_bytes(32),
        encrypted_key: SecureRandom.random_bytes(100)
      )
    end
    let(:encrypted_payload) do
      payload = double('EncryptedPayload')
      allow(payload).to receive(:encrypted_payload).and_return('test payload')
      allow(payload).to receive(:signature).and_return(SecureRandom.random_bytes(64))
      payload
    end

    it 'raises NetworkError on connection failure' do
      allow(Net::HTTP).to receive(:new).and_raise(SocketError, 'getaddrinfo: Name or service not known')

      expect {
        described_class.make_http_request(url, transmission_key, encrypted_payload, true)
      }.to raise_error(KeeperSecretsManager::NetworkError, /HTTP request failed/)
    end

    it 'raises NetworkError on timeout' do
      allow(Net::HTTP).to receive(:new).and_raise(Timeout::Error, 'execution expired')

      expect {
        described_class.make_http_request(url, transmission_key, encrypted_payload, true)
      }.to raise_error(KeeperSecretsManager::NetworkError, /HTTP request failed/)
    end

    it 'raises NetworkError on SSL errors' do
      allow(Net::HTTP).to receive(:new).and_raise(OpenSSL::SSL::SSLError, 'certificate verify failed')

      expect {
        described_class.make_http_request(url, transmission_key, encrypted_payload, true)
      }.to raise_error(KeeperSecretsManager::NetworkError, /HTTP request failed/)
    end

    it 'configures SSL verification when verify_ssl_certs is true' do
      http = instance_double(Net::HTTP)
      store = instance_double(OpenSSL::X509::Store)

      allow(Net::HTTP).to receive(:new).and_return(http)
      allow(http).to receive(:use_ssl=)
      allow(http).to receive(:verify_mode=)
      allow(http).to receive(:cert_store=)
      allow(OpenSSL::X509::Store).to receive(:new).and_return(store)
      allow(store).to receive(:set_default_paths)
      allow(http).to receive(:request).and_return(
        double('Response', code: '200', body: 'response')
      )

      described_class.make_http_request(url, transmission_key, encrypted_payload, true)

      expect(http).to have_received(:verify_mode=).with(OpenSSL::SSL::VERIFY_PEER)
      expect(http).to have_received(:cert_store=).with(store)
    end

    it 'disables SSL verification when verify_ssl_certs is false' do
      http = instance_double(Net::HTTP)

      allow(Net::HTTP).to receive(:new).and_return(http)
      allow(http).to receive(:use_ssl=)
      allow(http).to receive(:verify_mode=)
      allow(http).to receive(:request).and_return(
        double('Response', code: '200', body: 'response')
      )

      described_class.make_http_request(url, transmission_key, encrypted_payload, false)

      expect(http).to have_received(:verify_mode=).with(OpenSSL::SSL::VERIFY_NONE)
      expect(http).not_to receive(:cert_store=)
    end
  end
end
