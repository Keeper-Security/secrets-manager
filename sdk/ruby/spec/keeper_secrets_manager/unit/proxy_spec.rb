require 'spec_helper'

RSpec.describe 'Proxy Configuration' do
  describe 'proxy URL parsing and configuration' do
    it 'accepts proxy_url parameter in initialization' do
      storage = KeeperSecretsManager::Storage::InMemoryStorage.new({
        'hostname' => 'keepersecurity.com',
        'clientId' => Base64.strict_encode64('test-client'),
        'appKey' => Base64.strict_encode64(SecureRandom.random_bytes(32))
      })

      sm = KeeperSecretsManager.new(
        config: storage,
        proxy_url: 'http://proxy.example.com:8080'
      )

      expect(sm.instance_variable_get(:@proxy_url)).to eq('http://proxy.example.com:8080')
    end

    it 'uses HTTPS_PROXY environment variable if proxy_url not provided' do
      storage = KeeperSecretsManager::Storage::InMemoryStorage.new({
        'hostname' => 'keepersecurity.com',
        'clientId' => Base64.strict_encode64('test-client'),
        'appKey' => Base64.strict_encode64(SecureRandom.random_bytes(32))
      })

      ENV['HTTPS_PROXY'] = 'http://env-proxy.example.com:3128'

      sm = KeeperSecretsManager.new(config: storage)

      expect(sm.instance_variable_get(:@proxy_url)).to eq('http://env-proxy.example.com:3128')
    ensure
      ENV.delete('HTTPS_PROXY')
    end

    it 'prioritizes explicit proxy_url over environment variable' do
      storage = KeeperSecretsManager::Storage::InMemoryStorage.new({
        'hostname' => 'keepersecurity.com',
        'clientId' => Base64.strict_encode64('test-client'),
        'appKey' => Base64.strict_encode64(SecureRandom.random_bytes(32))
      })

      ENV['HTTPS_PROXY'] = 'http://env-proxy.example.com:3128'

      sm = KeeperSecretsManager.new(
        config: storage,
        proxy_url: 'http://explicit-proxy.example.com:8080'
      )

      expect(sm.instance_variable_get(:@proxy_url)).to eq('http://explicit-proxy.example.com:8080')
    ensure
      ENV.delete('HTTPS_PROXY')
    end

    it 'handles lowercase https_proxy environment variable' do
      storage = KeeperSecretsManager::Storage::InMemoryStorage.new({
        'hostname' => 'keepersecurity.com',
        'clientId' => Base64.strict_encode64('test-client'),
        'appKey' => Base64.strict_encode64(SecureRandom.random_bytes(32))
      })

      ENV['https_proxy'] = 'http://lowercase-proxy.example.com:8080'

      sm = KeeperSecretsManager.new(config: storage)

      expect(sm.instance_variable_get(:@proxy_url)).to eq('http://lowercase-proxy.example.com:8080')
    ensure
      ENV.delete('https_proxy')
    end

    it 'works without proxy when not configured' do
      storage = KeeperSecretsManager::Storage::InMemoryStorage.new({
        'hostname' => 'keepersecurity.com',
        'clientId' => Base64.strict_encode64('test-client'),
        'appKey' => Base64.strict_encode64(SecureRandom.random_bytes(32))
      })

      sm = KeeperSecretsManager.new(config: storage)

      expect(sm.instance_variable_get(:@proxy_url)).to be_nil
    end

    it 'supports authenticated proxy URLs' do
      storage = KeeperSecretsManager::Storage::InMemoryStorage.new({
        'hostname' => 'keepersecurity.com',
        'clientId' => Base64.strict_encode64('test-client'),
        'appKey' => Base64.strict_encode64(SecureRandom.random_bytes(32))
      })

      sm = KeeperSecretsManager.new(
        config: storage,
        proxy_url: 'http://user:pass@proxy.example.com:8080'
      )

      expect(sm.instance_variable_get(:@proxy_url)).to eq('http://user:pass@proxy.example.com:8080')
    end
  end
end
