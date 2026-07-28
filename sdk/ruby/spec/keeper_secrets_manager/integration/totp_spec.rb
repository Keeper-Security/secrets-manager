require 'spec_helper'

# Skip TOTP tests if base32 gem is not available
begin
  require 'keeper_secrets_manager/totp'
  TOTP_AVAILABLE = true
rescue LoadError
  TOTP_AVAILABLE = false
end

RSpec.describe 'TOTP support', :integration do
  # TOTP is pure logic - no API calls needed
  # Tests the KeeperSecretsManager::TOTP module

  if TOTP_AVAILABLE
    describe KeeperSecretsManager::TOTP do
    let(:test_secret) { 'JBSWY3DPEHPK3PXP' }

    describe '.generate_code' do
      context 'with different algorithms' do
        it 'generates codes with SHA1 algorithm' do
          code = described_class.generate_code(test_secret, algorithm: 'SHA1')

          expect(code).to match(/^\d{6}$/)
          expect(code.length).to eq(6)
        end

        it 'generates codes with SHA256 algorithm' do
          code = described_class.generate_code(test_secret, algorithm: 'SHA256')

          expect(code).to match(/^\d{6}$/)
          expect(code.length).to eq(6)
        end

        it 'generates codes with SHA512 algorithm' do
          code = described_class.generate_code(test_secret, algorithm: 'SHA512')

          expect(code).to match(/^\d{6}$/)
          expect(code.length).to eq(6)
        end

        it 'generates different codes for different algorithms' do
          sha1_code = described_class.generate_code(test_secret, algorithm: 'SHA1')
          sha256_code = described_class.generate_code(test_secret, algorithm: 'SHA256')
          sha512_code = described_class.generate_code(test_secret, algorithm: 'SHA512')

          # Different algorithms should generally produce different codes
          # (though there's a small chance they could be the same)
          codes = [sha1_code, sha256_code, sha512_code].uniq
          expect(codes.length).to be >= 2
        end

        it 'raises error for invalid algorithm' do
          expect do
            described_class.generate_code(test_secret, algorithm: 'MD5')
          end.to raise_error(ArgumentError, /Invalid algorithm/)
        end
      end

      context 'with different time periods' do
        it 'generates codes with 30-second period' do
          code = described_class.generate_code(test_secret, period: 30)

          expect(code).to match(/^\d{6}$/)
        end

        it 'generates codes with 60-second period' do
          code = described_class.generate_code(test_secret, period: 60)

          expect(code).to match(/^\d{6}$/)
        end

        it 'generates codes with 90-second period' do
          code = described_class.generate_code(test_secret, period: 90)

          expect(code).to match(/^\d{6}$/)
        end

        it 'generates same code within the same period' do
          # Use a fixed time to ensure we stay within the same period
          fixed_time = Time.at(1_600_000_000) # Fixed timestamp
          code1 = described_class.generate_code(test_secret, time: fixed_time, period: 30)
          code2 = described_class.generate_code(test_secret, time: fixed_time + 10, period: 30)

          expect(code1).to eq(code2)
        end

        it 'generates different code in different period' do
          current_time = Time.now
          code1 = described_class.generate_code(test_secret, time: current_time, period: 30)
          code2 = described_class.generate_code(test_secret, time: current_time + 35, period: 30)

          expect(code1).not_to eq(code2)
        end

        it 'raises error for non-positive period' do
          expect do
            described_class.generate_code(test_secret, period: 0)
          end.to raise_error(ArgumentError, /Period must be positive/)
        end
      end

      context 'with different digit counts' do
        it 'generates 6-digit codes' do
          code = described_class.generate_code(test_secret, digits: 6)

          expect(code).to match(/^\d{6}$/)
          expect(code.length).to eq(6)
        end

        it 'generates 8-digit codes' do
          code = described_class.generate_code(test_secret, digits: 8)

          expect(code).to match(/^\d{8}$/)
          expect(code.length).to eq(8)
        end

        it 'raises error for invalid digit count' do
          expect do
            described_class.generate_code(test_secret, digits: 10)
          end.to raise_error(ArgumentError, /Digits must be 6 or 8/)
        end
      end

      context 'with specific times' do
        it 'generates deterministic codes for specific times' do
          specific_time = Time.at(1_600_000_000) # Fixed timestamp

          code1 = described_class.generate_code(test_secret, time: specific_time)
          code2 = described_class.generate_code(test_secret, time: specific_time)

          expect(code1).to eq(code2)
        end
      end
    end

    describe '.validate_code' do
      it 'validates current code' do
        code = described_class.generate_code(test_secret)
        is_valid = described_class.validate_code(test_secret, code, window: 1)

        expect(is_valid).to be true
      end

      it 'rejects invalid code' do
        invalid_code = '000000'
        is_valid = described_class.validate_code(test_secret, invalid_code, window: 1)

        expect(is_valid).to be false
      end

      it 'accepts codes within validation window' do
        # Generate code from 30 seconds ago
        past_time = Time.now - 30
        past_code = described_class.generate_code(test_secret, time: past_time)

        # Should still be valid with window=1
        is_valid = described_class.validate_code(test_secret, past_code, window: 1)

        expect(is_valid).to be true
      end

      it 'rejects codes outside validation window' do
        # Generate code from 2 minutes ago (outside window=1)
        past_time = Time.now - 120
        old_code = described_class.generate_code(test_secret, time: past_time)

        # Should be invalid with window=1 (only checks +/- 30 seconds)
        is_valid = described_class.validate_code(test_secret, old_code, window: 1)

        expect(is_valid).to be false
      end

      it 'accepts future codes within validation window' do
        # Generate code from 30 seconds in the future
        future_time = Time.now + 30
        future_code = described_class.generate_code(test_secret, time: future_time)

        # Should be valid with window=1
        is_valid = described_class.validate_code(test_secret, future_code, window: 1)

        expect(is_valid).to be true
      end

      it 'respects custom validation windows' do
        # Generate code from 90 seconds ago
        past_time = Time.now - 90
        old_code = described_class.generate_code(test_secret, time: past_time)

        # Should be invalid with window=1
        expect(described_class.validate_code(test_secret, old_code, window: 1)).to be false

        # Should be valid with window=3 (3 * 30 = 90 seconds)
        expect(described_class.validate_code(test_secret, old_code, window: 3)).to be true
      end
    end

    describe '.parse_url' do
      it 'parses basic TOTP URL' do
        url = 'otpauth://totp/Example:user@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example'
        parsed = described_class.parse_url(url)

        expect(parsed['account']).to eq('user@example.com')
        expect(parsed['issuer']).to eq('Example')
        expect(parsed['secret']).to eq('JBSWY3DPEHPK3PXP')
        expect(parsed['algorithm']).to eq('SHA1')
        expect(parsed['digits']).to eq(6)
        expect(parsed['period']).to eq(30)
      end

      it 'parses URL with custom algorithm' do
        url = 'otpauth://totp/Test:user?secret=JBSWY3DPEHPK3PXP&algorithm=SHA256'
        parsed = described_class.parse_url(url)

        expect(parsed['algorithm']).to eq('SHA256')
      end

      it 'parses URL with custom period' do
        url = 'otpauth://totp/Test:user?secret=JBSWY3DPEHPK3PXP&period=60'
        parsed = described_class.parse_url(url)

        expect(parsed['period']).to eq(60)
      end

      it 'parses URL with custom digits' do
        url = 'otpauth://totp/Test:user?secret=JBSWY3DPEHPK3PXP&digits=8'
        parsed = described_class.parse_url(url)

        expect(parsed['digits']).to eq(8)
      end

      it 'parses URL without issuer prefix' do
        url = 'otpauth://totp/user@example.com?secret=JBSWY3DPEHPK3PXP'
        parsed = described_class.parse_url(url)

        expect(parsed['account']).to eq('user@example.com')
        expect(parsed['issuer']).to be_nil
      end

      it 'raises error for non-otpauth scheme' do
        expect do
          described_class.parse_url('https://example.com')
        end.to raise_error(ArgumentError, /Invalid TOTP URL scheme/)
      end

      it 'raises error for non-totp type' do
        expect do
          described_class.parse_url('otpauth://hotp/Test:user?secret=JBSWY3DPEHPK3PXP')
        end.to raise_error(ArgumentError, /Invalid TOTP URL type/)
      end
    end

    describe '.generate_url' do
      it 'generates valid TOTP URL' do
        url = described_class.generate_url('user@example.com', test_secret, issuer: 'Example')

        expect(url).to match(%r{^otpauth://totp/})
        expect(url).to include('secret=JBSWY3DPEHPK3PXP')
        expect(url).to include('issuer=Example')
      end

      it 'round-trips through parse and generate' do
        original_url = 'otpauth://totp/Example:user@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example&algorithm=SHA256&digits=8&period=60'
        parsed = described_class.parse_url(original_url)

        regenerated = described_class.generate_url(
          parsed['account'],
          parsed['secret'],
          issuer: parsed['issuer'],
          algorithm: parsed['algorithm'],
          digits: parsed['digits'],
          period: parsed['period']
        )

        # Parse regenerated URL and compare key components
        reparsed = described_class.parse_url(regenerated)

        # Compare components (account may have issuer prefix in regenerated URL)
        expect(reparsed['secret']).to eq(parsed['secret'])
        expect(reparsed['issuer']).to eq(parsed['issuer'])
        expect(reparsed['algorithm']).to eq(parsed['algorithm'])
        expect(reparsed['digits']).to eq(parsed['digits'])
        expect(reparsed['period']).to eq(parsed['period'])
      end
    end

    describe '.generate_secret' do
      it 'generates base32 encoded secret' do
        secret = described_class.generate_secret

        expect(secret).to match(/^[A-Z2-7]+$/)
        expect(secret).not_to include('=') # No padding
      end

      it 'generates secrets of requested length' do
        secret = described_class.generate_secret(length: 40)

        # Base32 encoding: 40 bytes -> 64 base32 chars
        expect(secret.length).to be >= 60 # Approximately 40 bytes
      end

      it 'generates different secrets each time' do
        secret1 = described_class.generate_secret
        secret2 = described_class.generate_secret

        expect(secret1).not_to eq(secret2)
      end

      it 'generates secrets usable for code generation' do
        secret = described_class.generate_secret

        # Should be able to generate a code without errors
        expect do
          code = described_class.generate_code(secret)
          expect(code).to match(/^\d{6}$/)
        end.not_to raise_error
      end
    end

    describe 'integration with SecretsManager' do
      let(:secrets_manager) do
        config = KeeperSecretsManager::Storage::InMemoryStorage.new({
                                                                       'hostname' => 'mock.keepersecurity.com',
                                                                       'clientId' => 'mock-client-id',
                                                                       'privateKey' => Base64.strict_encode64(SecureRandom.random_bytes(32)),
                                                                       'appKey' => Base64.strict_encode64(SecureRandom.random_bytes(32)),
                                                                       'serverPublicKeyId' => '10'
                                                                     })
        KeeperSecretsManager.new(config: config)
      end

      it 'works with TOTP fields in records' do
        # Create a mock record with TOTP field
        record = KeeperSecretsManager::Dto::KeeperRecord.new(
          uid: 'test-totp-record',
          type: 'login',
          title: 'Test TOTP Record',
          fields: [
            { 'type' => 'login', 'value' => ['user@example.com'] },
            { 'type' => 'password', 'value' => ['Password123!'] },
            { 'type' => 'oneTimeCode', 'value' => ["otpauth://totp/Test:user?secret=#{test_secret}"] }
          ]
        )

        # Extract TOTP URL from record
        totp_field = record.get_field('oneTimeCode')
        expect(totp_field).not_to be_nil
        expect(totp_field['value']).to be_an(Array)

        totp_url = totp_field['value'].first
        expect(totp_url).to start_with('otpauth://totp/')

        # Generate code from URL
        parsed = described_class.parse_url(totp_url)
        code = described_class.generate_code(
          parsed['secret'],
          algorithm: parsed['algorithm'],
          digits: parsed['digits'],
          period: parsed['period']
        )

        expect(code).to match(/^\d{6}$/)
      end
    end
  end
  else
    # TOTP not available - add placeholder test
    it 'requires base32 gem for TOTP support' do
      skip 'Install base32 gem to enable TOTP tests: gem install base32'
    end
  end
end
