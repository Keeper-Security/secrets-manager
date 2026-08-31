# frozen_string_literal: true

require 'spec_helper'

# The record key protects a record's field values. It must reach the server wrapped to the
# application owner's public key, so that the server never holds both a record's ciphertext
# and the key that opens it. These specs assert that property on the bytes the create
# payload actually carries, rather than on the code path that produces them.
RSpec.describe KeeperSecretsManager::Core::SecretsManager do
  let(:owner_keys) { KeeperSecretsManager::Crypto.generate_ecc_keys }

  let(:config) do
    cfg = KeeperSecretsManager::Storage::InMemoryStorage.new
    cfg.save_string(KeeperSecretsManager::ConfigKeys::KEY_CLIENT_ID, 'test_client_id')
    cfg.save_bytes(KeeperSecretsManager::ConfigKeys::KEY_APP_KEY, 'test_app_key_32_bytes_exactly!!!')
    cfg.save_string(KeeperSecretsManager::ConfigKeys::KEY_HOSTNAME, 'fake.keepersecurity.com')
    cfg.save_bytes(KeeperSecretsManager::ConfigKeys::KEY_OWNER_PUBLIC_KEY, owner_keys[:public_key_bytes])
    cfg
  end

  let(:manager) { described_class.new(config: config) }

  let(:record_key) { KeeperSecretsManager::Crypto.generate_encryption_key_bytes }
  let(:folder_key) { KeeperSecretsManager::Crypto.generate_encryption_key_bytes }
  let(:record_json) { KeeperSecretsManager::Utils.dict_to_json({ 'title' => 'Test', 'type' => 'login' }) }
  let(:encrypted_data) { KeeperSecretsManager::Crypto.encrypt_aes_gcm(record_json, record_key) }

  def build_payload
    manager.send(
      :prepare_create_payload,
      record_uid: 'test_record_uid',
      record_key: record_key,
      folder_uid: 'test_folder_uid',
      folder_key: folder_key,
      data: encrypted_data
    )
  end

  describe '#prepare_create_payload record key handling' do
    it 'wraps the record key to the owner public key' do
      # Control: this keypair and this pair of primitives round-trip. Without it, a failure
      # below could mean the wrap is absent or merely that the fixture or decrypt_ec is
      # broken, and those need different fixes.
      control = KeeperSecretsManager::Crypto.encrypt_ec(record_key, owner_keys[:public_key_bytes])
      expect(KeeperSecretsManager::Crypto.decrypt_ec(control, owner_keys[:private_key_obj])).to eq(record_key)

      wire_bytes = KeeperSecretsManager::Utils.base64_to_bytes(build_payload.record_key)

      recovered = KeeperSecretsManager::Crypto.decrypt_ec(wire_bytes, owner_keys[:private_key_obj])

      expect(recovered).to eq(record_key)
    end

    it 'does not put the key that decrypts the record data on the wire' do
      payload = build_payload
      wire_bytes = KeeperSecretsManager::Utils.base64_to_bytes(payload.record_key)

      # Establishes that record_key really is the key protecting payload.data, so the
      # assertion below cannot pass because the two values are unrelated.
      expect(KeeperSecretsManager::Crypto.decrypt_aes_gcm(
               KeeperSecretsManager::Utils.base64_to_bytes(payload.data), record_key
             )).to eq(record_json)

      expect(wire_bytes).not_to eq(record_key)
    end

    it 'raises rather than sending the record key unwrapped when the owner public key is missing' do
      config.delete(KeeperSecretsManager::ConfigKeys::KEY_OWNER_PUBLIC_KEY)

      expect { build_payload }.to raise_error(KeeperSecretsManager::Error, /owner key is missing/)
    end
  end
end
