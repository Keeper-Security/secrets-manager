# frozen_string_literal: true

require 'spec_helper'
require 'json'
require 'base64'
require 'securerandom'

# IL5 dynamic-key (keyId 20 / 4-part OTT) support for the Ruby SDK.
# Mirrors the Python (release/sdk/python/core/v17.3.0) and Kotlin edge-case matrices.
RSpec.describe KeeperSecretsManager::Core::SecretsManager do
  let(:ck)      { KeeperSecretsManager::ConfigKeys }
  let(:crypto)  { KeeperSecretsManager::Crypto }
  let(:utils)   { KeeperSecretsManager::Utils }
  let(:storage) { KeeperSecretsManager::Storage::InMemoryStorage }

  # keyId-20 IL5 test public key (65-byte uncompressed P-256 point, url-safe b64, 87 chars)
  let(:il5_pubkey) { 'BKOLdpezEt3Ey-rHldUYUG5NUx5aRxMdc8np40vfjRF5hFaeFpNDowpiL1mKeB4oop_30nMz5VM7tQRF7twyT8I' }
  let(:client_key) { Base64.urlsafe_encode64(SecureRandom.random_bytes(32)).delete('=') } # 43 chars
  let(:il5_token)  { "IL5:#{client_key}:20:#{il5_pubkey}" }

  # A constructed, already-bound instance for exercising private methods offline.
  let(:manager) { described_class.new(config: bound_config) }

  def bound_config(extra = {})
    storage.new({
                  ck::KEY_HOSTNAME    => 'il5.keepersecurity.us',
                  ck::KEY_CLIENT_ID   => 'client-id',
                  ck::KEY_PRIVATE_KEY => Base64.strict_encode64(SecureRandom.random_bytes(32)),
                  ck::KEY_APP_KEY     => Base64.strict_encode64(SecureRandom.random_bytes(32))
                }.merge(extra))
  end

  # Stub post_query so binding completes offline. Returns the app_key the server "issued".
  def stub_bind(client_key_str)
    app_key  = SecureRandom.random_bytes(32)
    ck_bytes = utils.url_safe_str_to_bytes(client_key_str)
    enc      = crypto.encrypt_aes_gcm(app_key, ck_bytes)
    json     = JSON.generate({ 'encryptedAppKey' => utils.bytes_to_url_safe_str(enc) })
    allow_any_instance_of(described_class).to receive(:post_query).and_return(json)
    app_key
  end

  describe 'OTT parsing — malformed IL5 tokens raise before any network call' do
    it 'rejects a 3-segment IL5 token' do
      expect { described_class.new(token: "IL5:#{client_key}:20", config: storage.new) }
        .to raise_error(/expected exactly 4/)
    end

    it 'rejects a 5-segment IL5 token' do
      expect { described_class.new(token: "#{il5_token}:extra", config: storage.new) }
        .to raise_error(/expected exactly 4/)
    end

    it 'rejects an empty keyId segment' do
      expect { described_class.new(token: "IL5:#{client_key}::#{il5_pubkey}", config: storage.new) }
        .to raise_error(/non-empty/)
    end

    it 'rejects an empty serverPublicKey segment (relies on split(":", -1))' do
      expect { described_class.new(token: "IL5:#{client_key}:20:", config: storage.new) }
        .to raise_error(/non-empty/)
    end

    it 'rejects a non-base64 serverPublicKey segment' do
      expect { described_class.new(token: "IL5:#{client_key}:20:!!!bad!!!", config: storage.new) }
        .to raise_error(/not valid url-safe base64/)
    end
  end

  describe 'IL5 4-part bind' do
    it 'parses the OTT, persists keyId + serverPublicKey, decrypts appKey, clears clientKey' do
      config  = storage.new
      app_key = stub_bind(client_key)
      described_class.new(token: il5_token, config: config)

      expect(config.get_string(ck::KEY_HOSTNAME)).to eq('il5.keepersecurity.us')
      expect(config.get_string(ck::KEY_SERVER_PUBLIC_KEY_ID)).to eq('20')
      expect(config.get_string(ck::KEY_SERVER_PUBLIC_KEY)).to eq(il5_pubkey)
      expect(config.get_bytes(ck::KEY_APP_KEY)).to eq(app_key)
      expect(config.get_string(ck::KEY_CLIENT_KEY)).to be_nil
    end
  end

  describe 'non-IL5 tokens (unchanged behavior)' do
    it 'binds a 2-part US token with the default keyId and no custom key' do
      config = storage.new
      stub_bind(client_key)
      described_class.new(token: "US:#{client_key}", config: config)

      expect(config.get_string(ck::KEY_HOSTNAME)).to eq('keepersecurity.com')
      expect(config.get_string(ck::KEY_SERVER_PUBLIC_KEY_ID)).to eq('7')
      expect(config.get_string(ck::KEY_SERVER_PUBLIC_KEY)).to be_nil
    end

    it 'treats a 2-part IL5 token as a plain OTT (no dynamic key)' do
      config = storage.new
      stub_bind(client_key)
      described_class.new(token: "IL5:#{client_key}", config: config)

      expect(config.get_string(ck::KEY_HOSTNAME)).to eq('il5.keepersecurity.us')
      expect(config.get_string(ck::KEY_SERVER_PUBLIC_KEY_ID)).to eq('7')
      expect(config.get_string(ck::KEY_SERVER_PUBLIC_KEY)).to be_nil
    end

    it 'keeps the full remainder for a token with extra colons (regression)' do
      config   = storage.new
      captured = nil
      allow_any_instance_of(described_class).to receive(:bind_one_time_token) do |_i, token, *_rest|
        captured = token
        storage.new
      end
      described_class.new(token: 'US:part1:part2:part3', config: config)
      expect(captured).to eq('part1:part2:part3')
    end
  end

  describe 'generate_transmission_key' do
    it 'uses a custom public key for keyId 20 and round-trips via decrypt_ec' do
      keys = crypto.generate_ecc_keys
      tk = manager.send(:generate_transmission_key, '20', keys[:public_key_str])
      expect(tk.public_key_id).to eq('20')
      expect(crypto.decrypt_ec(tk.encrypted_key, keys[:private_key_obj])).to eq(tk.key)
    end

    it 'uses the built-in table when no custom key is supplied' do
      tk = manager.send(:generate_transmission_key, '10', nil)
      expect(tk.public_key_id).to eq('10')
    end

    it 'raises for an unknown id with no custom key' do
      expect { manager.send(:generate_transmission_key, '99', nil) }
        .to raise_error(/Unknown public key ID: 99/)
    end
  end

  describe 'restore from saved config + precedence' do
    it 'restores a bound IL5 config without re-binding and keeps keyId 20 + key' do
      config = bound_config(ck::KEY_SERVER_PUBLIC_KEY_ID => '20', ck::KEY_SERVER_PUBLIC_KEY => il5_pubkey)
      expect_any_instance_of(described_class).not_to receive(:post_query)
      described_class.new(config: config)
      expect(config.get_string(ck::KEY_SERVER_PUBLIC_KEY_ID)).to eq('20')
      expect(config.get_string(ck::KEY_SERVER_PUBLIC_KEY)).to eq(il5_pubkey)
    end

    it 'lets programmatic server_public_key override config' do
      config = bound_config(ck::KEY_SERVER_PUBLIC_KEY_ID => '20', ck::KEY_SERVER_PUBLIC_KEY => il5_pubkey)
      described_class.new(config: config, server_public_key: 'PROGKEY', server_public_key_id: '20')
      expect(config.get_string(ck::KEY_SERVER_PUBLIC_KEY)).to eq('PROGKEY')
    end

    it 'resets an unknown keyId to the default when no custom key backs it' do
      config = bound_config(ck::KEY_SERVER_PUBLIC_KEY_ID => '20')
      described_class.new(config: config)
      expect(config.get_string(ck::KEY_SERVER_PUBLIC_KEY_ID)).to eq('7')
    end

    it 'keeps an unknown keyId when a custom key backs it' do
      config = bound_config(ck::KEY_SERVER_PUBLIC_KEY_ID => '20', ck::KEY_SERVER_PUBLIC_KEY => il5_pubkey)
      described_class.new(config: config)
      expect(config.get_string(ck::KEY_SERVER_PUBLIC_KEY_ID)).to eq('20')
    end
  end

  describe 'handle_http_error key rotation' do
    def key_error_response(key_id)
      double('response', data: JSON.generate({ 'result_code' => 'key', 'key_id' => key_id }), status_code: 403)
    end

    it 'surfaces an actionable message when a configured custom key is rejected' do
      config = storage.new(ck::KEY_SERVER_PUBLIC_KEY => il5_pubkey, ck::KEY_SERVER_PUBLIC_KEY_ID => '20')
      expect { manager.send(:handle_http_error, key_error_response(8), config) }
        .to raise_error(/Server rejected the custom server public key/)
    end

    it 'still rotates to a built-in key when no custom key is set' do
      config = storage.new
      expect(manager.send(:handle_http_error, key_error_response(8), config)).to be_nil
      expect(config.get_string(ck::KEY_SERVER_PUBLIC_KEY_ID)).to eq('8')
    end

    it 'raises for an unknown server-suggested id with no custom key' do
      config = storage.new
      expect { manager.send(:handle_http_error, key_error_response(99), config) }
        .to raise_error(/does not exist in the SDK/)
    end
  end
end
