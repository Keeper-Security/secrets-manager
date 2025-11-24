require 'spec_helper'

RSpec.describe KeeperSecretsManager::Crypto do
  describe 'random bytes generation' do
    it 'generates random bytes of specified length' do
      bytes = described_class.generate_random_bytes(16)
      expect(bytes.length).to eq(16)
      expect(bytes).to be_a(String)
      expect(bytes.encoding).to eq(Encoding::ASCII_8BIT)
    end

    it 'generates different bytes each time' do
      bytes1 = described_class.generate_random_bytes(32)
      bytes2 = described_class.generate_random_bytes(32)
      expect(bytes1).not_to eq(bytes2)
    end
  end

  describe 'base64 encoding' do
    let(:test_bytes) { 'test data'.b }

    it 'converts bytes to base64' do
      encoded = described_class.bytes_to_base64(test_bytes)
      expect(encoded).to eq('dGVzdCBkYXRh')
    end

    it 'converts base64 to bytes' do
      decoded = described_class.base64_to_bytes('dGVzdCBkYXRh')
      expect(decoded).to eq(test_bytes)
    end

    it 'handles URL-safe base64' do
      bytes = "\xfb\xff\xfe".b
      encoded = described_class.bytes_to_url_safe_str(bytes)
      expect(encoded).not_to include('+', '/', '=')

      decoded = described_class.url_safe_str_to_bytes(encoded)
      expect(decoded).to eq(bytes)
    end
  end

  describe 'AES-GCM encryption' do
    let(:key) { described_class.generate_encryption_key_bytes }
    let(:plaintext) { 'Secret message' }

    it 'encrypts and decrypts data' do
      encrypted = described_class.encrypt_aes_gcm(plaintext, key)
      decrypted = described_class.decrypt_aes_gcm(encrypted, key)

      expect(decrypted).to eq(plaintext)
    end

    it 'produces different ciphertext for same plaintext' do
      encrypted1 = described_class.encrypt_aes_gcm(plaintext, key)
      encrypted2 = described_class.encrypt_aes_gcm(plaintext, key)

      expect(encrypted1).not_to eq(encrypted2)
    end

    it 'fails decryption with wrong key' do
      encrypted = described_class.encrypt_aes_gcm(plaintext, key)
      wrong_key = described_class.generate_encryption_key_bytes

      expect do
        described_class.decrypt_aes_gcm(encrypted, wrong_key)
      end.to raise_error(KeeperSecretsManager::DecryptionError)
    end

    it 'includes IV and authentication tag' do
      encrypted = described_class.encrypt_aes_gcm(plaintext, key)

      # Should be at least IV (12) + ciphertext + tag (16)
      expect(encrypted.length).to be >= (12 + plaintext.length + 16)
    end
  end

  describe 'PKCS7 padding' do
    it 'pads data to block size' do
      data = 'test'
      padded = described_class.pad_data(data)

      expect(padded.length % 16).to eq(0)
      expect(padded[-1].ord).to eq(12) # 16 - 4 = 12 padding bytes
    end

    it 'unpads data correctly' do
      data = 'test data'
      padded = described_class.pad_data(data)
      unpadded = described_class.unpad_data(padded)

      expect(unpadded).to eq(data)
    end

    it 'handles data already at block boundary' do
      data = 'x' * 16
      padded = described_class.pad_data(data)

      expect(padded.length).to eq(32) # Added full block of padding
      expect(described_class.unpad_data(padded)).to eq(data)
    end
  end

  describe 'HMAC operations' do
    let(:key) { 'secret key' }
    let(:data) { 'message to sign' }

    it 'generates HMAC signature' do
      signature = described_class.generate_hmac(key, data)

      expect(signature).to be_a(String)
      expect(signature.length).to eq(64) # SHA512 = 512 bits = 64 bytes
    end

    it 'verifies valid signature' do
      signature = described_class.generate_hmac(key, data)

      expect(described_class.verify_hmac(key, data, signature)).to be true
    end

    it 'rejects invalid signature' do
      signature = described_class.generate_hmac(key, data)
      bad_signature = signature.dup
      bad_signature[0] = (bad_signature[0].ord ^ 1).chr

      expect(described_class.verify_hmac(key, data, bad_signature)).to be false
    end
  end

  describe 'ECC key generation' do
    it 'generates EC key pair' do
      keys = described_class.generate_ecc_keys

      expect(keys).to have_key(:private_key_str)
      expect(keys).to have_key(:public_key_str)
      expect(keys).to have_key(:private_key_bytes)
      expect(keys).to have_key(:public_key_bytes)
      expect(keys).to have_key(:private_key_obj)

      # Verify key formats
      expect(keys[:private_key_bytes].length).to eq(32)
      expect(keys[:public_key_bytes].length).to eq(65) # Uncompressed point
    end

    it 'generates unique keys each time' do
      keys1 = described_class.generate_ecc_keys
      keys2 = described_class.generate_ecc_keys

      expect(keys1[:private_key_str]).not_to eq(keys2[:private_key_str])
      expect(keys1[:public_key_str]).not_to eq(keys2[:public_key_str])
    end
  end

  describe 'EC encryption' do
    it 'encrypts and decrypts with EC keys' do
      # Generate key pair
      keys = described_class.generate_ecc_keys
      plaintext = 'Secret EC message'

      # Encrypt with public key
      encrypted = described_class.encrypt_ec(plaintext, keys[:public_key_bytes])

      # Decrypt with private key
      decrypted = described_class.decrypt_ec(encrypted, keys[:private_key_obj])

      expect(decrypted).to eq(plaintext)
    end

    it 'cannot decrypt with wrong private key' do
      keys1 = described_class.generate_ecc_keys
      keys2 = described_class.generate_ecc_keys
      plaintext = 'Secret'

      encrypted = described_class.encrypt_ec(plaintext, keys1[:public_key_bytes])

      expect do
        described_class.decrypt_ec(encrypted, keys2[:private_key_obj])
      end.to raise_error(KeeperSecretsManager::DecryptionError)
    end
  end
end
