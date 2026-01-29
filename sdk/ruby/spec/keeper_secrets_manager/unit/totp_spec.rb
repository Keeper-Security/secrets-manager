require 'spec_helper'

# Skip these unit tests if base32 gem is not available
begin
  require 'keeper_secrets_manager/totp'
  TOTP_AVAILABLE = true
rescue LoadError
  TOTP_AVAILABLE = false
end

if TOTP_AVAILABLE
  RSpec.describe KeeperSecretsManager::TOTP do
    let(:valid_secret) { 'JBSWY3DPEHPK3PXP' }

    describe '.generate_code' do
      context 'input validation' do
        it 'raises ArgumentError for invalid algorithm' do
          expect {
            described_class.generate_code(valid_secret, algorithm: 'MD5')
          }.to raise_error(ArgumentError, /Invalid algorithm: MD5/)
        end

        it 'raises ArgumentError for unsupported algorithm' do
          expect {
            described_class.generate_code(valid_secret, algorithm: 'SHA3-256')
          }.to raise_error(ArgumentError, /Invalid algorithm/)
        end

        it 'raises ArgumentError for 5 digits' do
          expect {
            described_class.generate_code(valid_secret, digits: 5)
          }.to raise_error(ArgumentError, 'Digits must be 6 or 8')
        end

        it 'raises ArgumentError for 7 digits' do
          expect {
            described_class.generate_code(valid_secret, digits: 7)
          }.to raise_error(ArgumentError, 'Digits must be 6 or 8')
        end

        it 'raises ArgumentError for 9 digits' do
          expect {
            described_class.generate_code(valid_secret, digits: 9)
          }.to raise_error(ArgumentError, 'Digits must be 6 or 8')
        end

        it 'raises ArgumentError for zero period' do
          expect {
            described_class.generate_code(valid_secret, period: 0)
          }.to raise_error(ArgumentError, 'Period must be positive')
        end

        it 'raises ArgumentError for negative period' do
          expect {
            described_class.generate_code(valid_secret, period: -30)
          }.to raise_error(ArgumentError, 'Period must be positive')
        end
      end

      context 'secret format handling' do
        it 'handles secrets with spaces' do
          secret_with_spaces = 'JBSW Y3DP EHPK 3PXP'
          code = described_class.generate_code(secret_with_spaces)
          expect(code).to match(/^\d{6}$/)
        end

        it 'handles lowercase secrets' do
          lowercase_secret = 'jbswy3dpehpk3pxp'
          code = described_class.generate_code(lowercase_secret)
          expect(code).to match(/^\d{6}$/)
        end

        it 'handles mixed case secrets' do
          mixed_secret = 'JbSwY3dPeHpK3pXp'
          code = described_class.generate_code(mixed_secret)
          expect(code).to match(/^\d{6}$/)
        end

        it 'handles secrets with padding' do
          secret_with_padding = 'JBSWY3DPEHPK3PXP===='
          code = described_class.generate_code(secret_with_padding)
          expect(code).to match(/^\d{6}$/)
        end
      end

      context 'edge case periods' do
        it 'generates code with 1-second period' do
          code = described_class.generate_code(valid_secret, period: 1)
          expect(code).to match(/^\d{6}$/)
        end

        it 'generates code with very large period' do
          code = described_class.generate_code(valid_secret, period: 3600)
          expect(code).to match(/^\d{6}$/)
        end
      end

      context 'time handling' do
        it 'generates consistent code for same time' do
          time = Time.at(1_620_000_000)
          code1 = described_class.generate_code(valid_secret, time: time)
          code2 = described_class.generate_code(valid_secret, time: time)
          expect(code1).to eq(code2)
        end

        it 'generates different code for different times' do
          time1 = Time.at(1_620_000_000)
          time2 = Time.at(1_620_000_060) # 60 seconds later
          code1 = described_class.generate_code(valid_secret, time: time1)
          code2 = described_class.generate_code(valid_secret, time: time2)
          expect(code1).not_to eq(code2)
        end

        it 'handles epoch time' do
          code = described_class.generate_code(valid_secret, time: Time.at(0))
          expect(code).to match(/^\d{6}$/)
        end

        it 'handles far future time' do
          code = described_class.generate_code(valid_secret, time: Time.at(4_000_000_000))
          expect(code).to match(/^\d{6}$/)
        end
      end

      context 'code formatting' do
        it 'pads codes with leading zeros for 6 digits' do
          # Test multiple times to increase chance of getting a code starting with 0
          codes = 100.times.map {
            described_class.generate_code(valid_secret, time: Time.at(rand(1_000_000_000)))
          }
          # All codes should be exactly 6 characters
          expect(codes.all? { |c| c.length == 6 }).to be true
        end

        it 'pads codes with leading zeros for 8 digits' do
          codes = 100.times.map {
            described_class.generate_code(valid_secret, digits: 8, time: Time.at(rand(1_000_000_000)))
          }
          # All codes should be exactly 8 characters
          expect(codes.all? { |c| c.length == 8 }).to be true
        end
      end
    end

    describe '.parse_url' do
      context 'URL format errors' do
        it 'raises ArgumentError for http scheme' do
          expect {
            described_class.parse_url('http://totp/Example:user?secret=SECRET')
          }.to raise_error(ArgumentError, 'Invalid TOTP URL scheme')
        end

        it 'raises ArgumentError for https scheme' do
          expect {
            described_class.parse_url('https://totp/Example:user?secret=SECRET')
          }.to raise_error(ArgumentError, 'Invalid TOTP URL scheme')
        end

        it 'raises ArgumentError for wrong type (hotp)' do
          expect {
            described_class.parse_url('otpauth://hotp/Example:user?secret=SECRET')
          }.to raise_error(ArgumentError, 'Invalid TOTP URL type')
        end

        it 'raises ArgumentError for missing type' do
          expect {
            described_class.parse_url('otpauth:///Example:user?secret=SECRET')
          }.to raise_error(ArgumentError, 'Invalid TOTP URL type')
        end
      end

      context 'parameter parsing' do
        it 'parses URL without query parameters' do
          result = described_class.parse_url('otpauth://totp/Example:user')
          expect(result['account']).to eq('user')
          expect(result['issuer']).to eq('Example')
          expect(result['secret']).to be_nil
        end

        it 'uses default values for missing parameters' do
          result = described_class.parse_url('otpauth://totp/user?secret=SECRET')
          expect(result['algorithm']).to eq('SHA1')
          expect(result['digits']).to eq(6)
          expect(result['period']).to eq(30)
        end

        it 'parses digits as integer' do
          result = described_class.parse_url('otpauth://totp/user?secret=SECRET&digits=8')
          expect(result['digits']).to eq(8)
          expect(result['digits']).to be_a(Integer)
        end

        it 'parses period as integer' do
          result = described_class.parse_url('otpauth://totp/user?secret=SECRET&period=60')
          expect(result['period']).to eq(60)
          expect(result['period']).to be_a(Integer)
        end

        it 'handles URL-encoded label' do
          result = described_class.parse_url('otpauth://totp/Example%3Auser%40example.com?secret=SECRET')
          # URL-encoded colon (%3A) is NOT treated as separator - it's part of the account name
          # The entire encoded string becomes the account, then gets decoded
          expect(result['account']).to eq('Example:user@example.com')
          expect(result['issuer']).to be_nil
        end

        it 'handles URL-encoded issuer in path' do
          result = described_class.parse_url('otpauth://totp/My%20Company%3Auser?secret=SECRET')
          # URL-encoded colon (%3A) is NOT treated as separator
          # Space is decoded (%20 -> ' ') but colon remains part of account name
          expect(result['account']).to eq('My Company:user')
          expect(result['issuer']).to be_nil
        end

        it 'uses label issuer even when query issuer exists' do
          # Implementation uses issuer from label (path) first, falls back to query parameter
          result = described_class.parse_url('otpauth://totp/LabelIssuer:user?secret=SECRET&issuer=QueryIssuer')
          expect(result['issuer']).to eq('LabelIssuer')
        end

        it 'handles account without issuer prefix' do
          result = described_class.parse_url('otpauth://totp/user@example.com?secret=SECRET')
          expect(result['account']).to eq('user@example.com')
          expect(result['issuer']).to be_nil
        end
      end

      context 'edge cases' do
        it 'handles empty account name' do
          result = described_class.parse_url('otpauth://totp/?secret=SECRET')
          expect(result['account']).to eq('')
        end

        it 'handles account with multiple colons' do
          result = described_class.parse_url('otpauth://totp/Issuer:user:extra?secret=SECRET')
          expect(result['account']).to eq('user:extra')
          expect(result['issuer']).to eq('Issuer')
        end

        it 'handles empty secret parameter' do
          result = described_class.parse_url('otpauth://totp/user?secret=')
          expect(result['secret']).to eq('')
        end

        it 'handles multiple query parameters' do
          url = 'otpauth://totp/Example:user?secret=SECRET&algorithm=SHA256&digits=8&period=60&issuer=QueryExample'
          result = described_class.parse_url(url)
          expect(result['secret']).to eq('SECRET')
          expect(result['algorithm']).to eq('SHA256')
          expect(result['digits']).to eq(8)
          expect(result['period']).to eq(60)
          # Label issuer takes priority
          expect(result['issuer']).to eq('Example')
        end
      end
    end

    describe '.generate_url' do
      it 'generates URL with all parameters' do
        url = described_class.generate_url(
          'user@example.com',
          'JBSWY3DPEHPK3PXP',
          issuer: 'Example',
          algorithm: 'SHA256',
          digits: 8,
          period: 60
        )

        expect(url).to include('otpauth://totp/')
        expect(url).to include('secret=JBSWY3DPEHPK3PXP')
        expect(url).to include('algorithm=SHA256')
        expect(url).to include('digits=8')
        expect(url).to include('period=60')
        expect(url).to include('issuer=Example')
      end

      it 'URL-encodes special characters in account' do
        url = described_class.generate_url('user@example.com', 'SECRET')
        expect(url).to include('user%40example.com')
      end

      it 'URL-encodes special characters in issuer' do
        url = described_class.generate_url('user', 'SECRET', issuer: 'My Company')
        # URI.encode_www_form_component uses + for spaces
        expect(url).to include('My+Company')
      end

      it 'generates URL without issuer when not provided' do
        url = described_class.generate_url('user', 'SECRET')
        expect(url).not_to include('issuer=')
        # However, the URL structure still includes colon in otpauth://
        parsed = URI(url)
        expect(parsed.path).not_to include(':')
      end

      it 'includes issuer in label and query' do
        url = described_class.generate_url('user', 'SECRET', issuer: 'Example')
        # The label is URL-encoded, so colon becomes %3A
        expect(url).to include('Example%3Auser')
        expect(url).to include('issuer=Example')
      end

      it 'round-trips through parse' do
        original_account = 'user@example.com'
        original_secret = 'JBSWY3DPEHPK3PXP'
        original_issuer = 'Example Corp'

        url = described_class.generate_url(
          original_account,
          original_secret,
          issuer: original_issuer,
          algorithm: 'SHA256',
          digits: 8,
          period: 60
        )

        parsed = described_class.parse_url(url)
        # Note: generate_url encodes the colon in the label, so parse_url sees the full
        # "issuer:account" as the account name (no literal colon to split on).
        # The issuer is preserved via the query parameter.
        expect(parsed['account']).to eq("#{original_issuer}:#{original_account}")
        expect(parsed['secret']).to eq(original_secret)
        # Issuer comes from query parameter (since label colon was encoded)
        expect(parsed['issuer']).to eq(original_issuer)
        expect(parsed['algorithm']).to eq('SHA256')
        expect(parsed['digits']).to eq(8)
        expect(parsed['period']).to eq(60)
      end
    end

    describe '.validate_code' do
      let(:time) { Time.at(1_620_000_000) }
      let(:code) { described_class.generate_code(valid_secret, time: time) }

      it 'accepts exact code' do
        result = described_class.validate_code(valid_secret, code, time: time)
        expect(result).to be true
      end

      it 'rejects wrong code' do
        result = described_class.validate_code(valid_secret, '000000', time: time)
        expect(result).to be false
      end

      it 'accepts code from previous period within window' do
        previous_time = time - 30
        previous_code = described_class.generate_code(valid_secret, time: previous_time)
        result = described_class.validate_code(valid_secret, previous_code, time: time, window: 1)
        expect(result).to be true
      end

      it 'accepts code from next period within window' do
        next_time = time + 30
        next_code = described_class.generate_code(valid_secret, time: next_time)
        result = described_class.validate_code(valid_secret, next_code, time: time, window: 1)
        expect(result).to be true
      end

      it 'rejects code from two periods ago with window=1' do
        old_time = time - 60
        old_code = described_class.generate_code(valid_secret, time: old_time)
        result = described_class.validate_code(valid_secret, old_code, time: time, window: 1)
        expect(result).to be false
      end

      it 'accepts code with larger window' do
        old_time = time - 60
        old_code = described_class.generate_code(valid_secret, time: old_time)
        result = described_class.validate_code(valid_secret, old_code, time: time, window: 2)
        expect(result).to be true
      end

      it 'respects zero window' do
        previous_time = time - 30
        previous_code = described_class.generate_code(valid_secret, time: previous_time)
        result = described_class.validate_code(valid_secret, previous_code, time: time, window: 0)
        expect(result).to be false
      end

      it 'handles custom algorithm' do
        sha256_code = described_class.generate_code(valid_secret, time: time, algorithm: 'SHA256')
        result = described_class.validate_code(valid_secret, sha256_code, time: time, algorithm: 'SHA256')
        expect(result).to be true
      end

      it 'rejects code with wrong algorithm' do
        sha1_code = described_class.generate_code(valid_secret, time: time, algorithm: 'SHA1')
        result = described_class.validate_code(valid_secret, sha1_code, time: time, algorithm: 'SHA256')
        expect(result).to be false
      end

      it 'handles 8-digit codes' do
        code_8 = described_class.generate_code(valid_secret, time: time, digits: 8)
        result = described_class.validate_code(valid_secret, code_8, time: time, digits: 8)
        expect(result).to be true
      end

      it 'handles custom period' do
        code_60 = described_class.generate_code(valid_secret, time: time, period: 60)
        result = described_class.validate_code(valid_secret, code_60, time: time, period: 60)
        expect(result).to be true
      end
    end

    describe '.generate_secret' do
      it 'generates secret with default length (20 bytes)' do
        secret = described_class.generate_secret
        # 20 bytes -> 32 characters in base32 (before removing padding)
        expect(secret.length).to be >= 32
      end

      it 'generates secret with custom length' do
        secret = described_class.generate_secret(length: 32)
        # 32 bytes -> 52 characters in base32 (approx, after removing padding)
        expect(secret.length).to be >= 51
      end

      it 'generates different secrets each time' do
        secret1 = described_class.generate_secret
        secret2 = described_class.generate_secret
        expect(secret1).not_to eq(secret2)
      end

      it 'generates base32-encoded secret' do
        secret = described_class.generate_secret
        # Base32 alphabet: A-Z and 2-7
        expect(secret).to match(/^[A-Z2-7]+$/)
      end

      it 'generates secret without padding' do
        secret = described_class.generate_secret
        expect(secret).not_to include('=')
      end

      it 'generates usable secret' do
        secret = described_class.generate_secret
        # Should be able to generate a code with it
        expect {
          code = described_class.generate_code(secret)
          expect(code).to match(/^\d{6}$/)
        }.not_to raise_error
      end

      it 'handles very small length' do
        secret = described_class.generate_secret(length: 1)
        expect(secret.length).to be >= 1
      end

      it 'handles very large length' do
        secret = described_class.generate_secret(length: 256)
        expect(secret.length).to be >= 400
      end
    end

    describe 'algorithm constants' do
      it 'supports SHA1' do
        expect(described_class::ALGORITHMS).to have_key('SHA1')
      end

      it 'supports SHA256' do
        expect(described_class::ALGORITHMS).to have_key('SHA256')
      end

      it 'supports SHA512' do
        expect(described_class::ALGORITHMS).to have_key('SHA512')
      end

      it 'has exactly 3 algorithms' do
        expect(described_class::ALGORITHMS.size).to eq(3)
      end
    end
  end
else
  RSpec.describe 'TOTP support' do
    it 'is not available (base32 gem not installed)' do
      skip 'base32 gem required for TOTP support'
    end
  end
end
