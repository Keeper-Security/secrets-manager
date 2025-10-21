require 'openssl'
require 'base64'
require 'securerandom'

module KeeperSecretsManager
  module Crypto
    # AES GCM constants
    GCM_IV_LENGTH = 12
    GCM_TAG_LENGTH = 16
    AES_KEY_LENGTH = 32

    # Block size for padding
    BLOCK_SIZE = 16

    class << self
      # Generate random bytes
      def generate_random_bytes(length)
        SecureRandom.random_bytes(length)
      end

      # Generate encryption key (32 bytes)
      def generate_encryption_key_bytes
        generate_random_bytes(AES_KEY_LENGTH)
      end

      # Convert bytes to URL-safe base64 string (no padding)
      def bytes_to_url_safe_str(bytes)
        Base64.urlsafe_encode64(bytes).delete('=')
      end

      # Convert URL-safe base64 string to bytes
      def url_safe_str_to_bytes(str)
        # Add padding if needed
        str += '=' * (4 - str.length % 4) if str.length % 4 != 0
        Base64.urlsafe_decode64(str)
      end

      # Convert bytes to base64
      def bytes_to_base64(bytes)
        Base64.strict_encode64(bytes)
      end

      # Convert base64 to bytes
      def base64_to_bytes(str)
        Base64.strict_decode64(str)
      end

      # Generate ECC key pair
      def generate_ecc_keys
        # Generate private key bytes
        private_key_bytes = generate_encryption_key_bytes
        private_key_str = bytes_to_url_safe_str(private_key_bytes)

        # Create EC key from private key bytes
        private_key_bn = OpenSSL::BN.new(private_key_bytes, 2)

        # OpenSSL 3.0 compatibility - use ASN1 sequence to create key
        group = OpenSSL::PKey::EC::Group.new('prime256v1')

        # Generate public key point
        public_key_point = group.generator.mul(private_key_bn)

        # Create ASN1 sequence for the key
        asn1 = OpenSSL::ASN1::Sequence([
                                         OpenSSL::ASN1::Integer(1),
                                         OpenSSL::ASN1::OctetString(private_key_bytes),
                                         OpenSSL::ASN1::ObjectId('prime256v1', 0, :EXPLICIT),
                                         OpenSSL::ASN1::BitString(public_key_point.to_octet_string(:uncompressed), 1,
                                                                  :EXPLICIT)
                                       ])

        # Create key from DER
        key = OpenSSL::PKey::EC.new(asn1.to_der)

        # Get public key bytes (uncompressed format)
        public_key_bytes = key.public_key.to_octet_string(:uncompressed)
        public_key_str = bytes_to_url_safe_str(public_key_bytes)

        # Also store the EC key in DER format for compatibility
        private_key_der = key.to_der

        {
          private_key_str: private_key_str,
          public_key_str: public_key_str,
          private_key_bytes: private_key_bytes,  # Use raw 32 bytes
          private_key_der: private_key_der,      # Also provide DER format
          public_key_bytes: public_key_bytes,
          private_key_obj: key
        }
      end

      # Encrypt with AES-GCM or fallback to CBC
      def encrypt_aes_gcm(data, key)
        cipher = OpenSSL::Cipher.new('AES-256-GCM')
        cipher.encrypt

        # Generate random IV
        iv = generate_random_bytes(GCM_IV_LENGTH)
        cipher.iv = iv
        cipher.key = key

        # Encrypt data
        encrypted = cipher.update(data) + cipher.final

        # Get authentication tag
        tag = cipher.auth_tag(GCM_TAG_LENGTH)

        # Combine IV + encrypted + tag
        iv + encrypted + tag
      rescue RuntimeError => e
        if e.message.include?('unsupported cipher')
          # Fallback to AES-CBC for older Ruby/OpenSSL
          encrypt_aes_cbc(data, key)
        else
          raise e
        end
      end

      # Decrypt with AES-GCM or fallback to CBC
      def decrypt_aes_gcm(encrypted_data, key)
        # Try GCM first
        # Extract components
        iv = encrypted_data[0...GCM_IV_LENGTH]
        tag = encrypted_data[-GCM_TAG_LENGTH..]
        ciphertext = encrypted_data[GCM_IV_LENGTH...-GCM_TAG_LENGTH]

        cipher = OpenSSL::Cipher.new('AES-256-GCM')
        cipher.decrypt
        cipher.iv = iv
        cipher.key = key
        cipher.auth_tag = tag

        cipher.update(ciphertext) + cipher.final
      rescue RuntimeError => e
        if e.message.include?('unsupported cipher')
          # Fallback to AES-CBC
          decrypt_aes_cbc(encrypted_data, key)
        else
          raise e
        end
      rescue OpenSSL::Cipher::CipherError => e
        # Maybe it's CBC encrypted?
        begin
          decrypt_aes_cbc(encrypted_data, key)
        rescue StandardError
          raise DecryptionError, "Failed to decrypt data: #{e.message}"
        end
      end

      # Legacy AES-CBC encryption (for compatibility)
      def encrypt_aes_cbc(data, key, iv = nil)
        cipher = OpenSSL::Cipher.new('AES-256-CBC')
        cipher.encrypt

        iv ||= generate_random_bytes(BLOCK_SIZE)
        cipher.iv = iv
        cipher.key = key

        # Apply PKCS7 padding
        padded_data = pad_data(data)
        encrypted = cipher.update(padded_data) + cipher.final

        # Return IV + encrypted
        iv + encrypted
      end

      # Legacy AES-CBC decryption
      def decrypt_aes_cbc(encrypted_data, key)
        # Extract IV
        iv = encrypted_data[0...BLOCK_SIZE]
        ciphertext = encrypted_data[BLOCK_SIZE..]

        cipher = OpenSSL::Cipher.new('AES-256-CBC')
        cipher.decrypt
        cipher.iv = iv
        cipher.key = key

        decrypted = cipher.update(ciphertext) + cipher.final

        # Remove padding
        unpad_data(decrypted)
      rescue OpenSSL::Cipher::CipherError => e
        raise DecryptionError, "Failed to decrypt data: #{e.message}"
      end

      # PKCS7 padding
      def pad_data(data)
        data = data.b if data.is_a?(String)
        pad_len = BLOCK_SIZE - (data.length % BLOCK_SIZE)
        data + (pad_len.chr * pad_len).b
      end

      # Remove PKCS7 padding
      def unpad_data(data)
        return data if data.empty?

        pad_len = data[-1].ord

        # Validate padding
        if pad_len > 0 && pad_len <= BLOCK_SIZE && pad_len <= data.length
          # Check if all padding bytes are the same
          padding = data[-pad_len..]
          return data[0...-pad_len] if padding.bytes.all? { |b| b == pad_len }
        end

        data
      end

      # Generate HMAC signature
      def generate_hmac(key, data)
        OpenSSL::HMAC.digest('SHA512', key, data)
      end

      # Generate ECDSA signature
      def sign_ec(data, private_key)
        # Use SHA256 for ECDSA signature
        digest = OpenSSL::Digest.new('SHA256')
        private_key.sign(digest, data)
      end

      # Verify HMAC signature
      def verify_hmac(key, data, signature)
        expected = generate_hmac(key, data)

        # Constant time comparison
        return false unless expected.bytesize == signature.bytesize

        result = 0
        expected.bytes.zip(signature.bytes) { |a, b| result |= a ^ b }
        result == 0
      end

      # Load private key from DER format
      def load_private_key_der(der_bytes, password = nil)
        OpenSSL::PKey.read(der_bytes, password)
      rescue StandardError => e
        raise CryptoError, "Failed to load private key: #{e.message}"
      end

      # Load public key from DER format
      def load_public_key_der(der_bytes)
        OpenSSL::PKey.read(der_bytes)
      rescue StandardError => e
        raise CryptoError, "Failed to load public key: #{e.message}"
      end

      # Export EC private key to DER
      def export_private_key_der(ec_key)
        ec_key.to_der
      end

      # Export EC public key to DER
      def export_public_key_der(ec_key)
        ec_key.public_key.to_der
      end

      # Encrypt with EC public key (ECIES-like)
      def encrypt_ec(data, public_key_bytes)
        # Load public key
        public_key = load_ec_public_key(public_key_bytes)

        # Generate ephemeral key pair
        ephemeral = OpenSSL::PKey::EC.generate('prime256v1')

        # Perform ECDH to get shared secret
        # The shared secret is computed using ECDH between ephemeral private key and server public key
        shared_secret = ephemeral.dh_compute_key(public_key.public_key)

        # Derive encryption key using SHA256
        encryption_key = OpenSSL::Digest::SHA256.digest(shared_secret)

        # Encrypt data with AES-GCM
        encrypted_data = encrypt_aes_gcm(data, encryption_key)

        # Return ephemeral public key + encrypted data
        ephemeral_public = ephemeral.public_key.to_octet_string(:uncompressed)
        ephemeral_public + encrypted_data
      end

      # Decrypt with EC private key
      def decrypt_ec(encrypted_data, private_key)
        # Extract ephemeral public key (65 bytes for uncompressed)
        ephemeral_public_bytes = encrypted_data[0...65]
        ciphertext = encrypted_data[65..]

        # Create EC key with ephemeral public key
        group = OpenSSL::PKey::EC::Group.new('prime256v1')
        ephemeral_point = OpenSSL::PKey::EC::Point.new(group, ephemeral_public_bytes)

        # Compute shared secret using ECDH
        shared_secret = private_key.dh_compute_key(ephemeral_point)

        # Derive decryption key
        decryption_key = OpenSSL::Digest::SHA256.digest(shared_secret)

        # Decrypt data
        decrypt_aes_gcm(ciphertext, decryption_key)
      end

      private

      # Load EC public key from bytes
      def load_ec_public_key(public_key_bytes)
        # If the bytes are longer than 65, it might be DER encoded
        # Extract the raw point bytes (last 65 bytes)
        public_key_bytes = public_key_bytes[-65..-1] if public_key_bytes.bytesize > 65

        # For OpenSSL 3.0+, we need to create the key differently
        begin
          # Try the OpenSSL 3.0+ way first
          group = OpenSSL::PKey::EC::Group.new('prime256v1')
          point = OpenSSL::PKey::EC::Point.new(group, public_key_bytes)

          # Create key from point directly using ASN1
          asn1 = OpenSSL::ASN1::Sequence([
                                           OpenSSL::ASN1::Sequence([
                                                                     OpenSSL::ASN1::ObjectId('id-ecPublicKey'),
                                                                     OpenSSL::ASN1::ObjectId('prime256v1')
                                                                   ]),
                                           OpenSSL::ASN1::BitString(public_key_bytes)
                                         ])

          OpenSSL::PKey::EC.new(asn1.to_der)
        rescue StandardError => e
          # Fall back to old method for older OpenSSL
          group = OpenSSL::PKey::EC::Group.new('prime256v1')
          point = OpenSSL::PKey::EC::Point.new(group, public_key_bytes)

          key = OpenSSL::PKey::EC.new(group)
          key.public_key = point
          key
        end
      end

      # Load EC public key from point bytes
      def load_ec_public_key_from_bytes(point_bytes)
        group = OpenSSL::PKey::EC::Group.new('prime256v1')
        OpenSSL::PKey::EC::Point.new(group, point_bytes)
      end
    end
  end
end
