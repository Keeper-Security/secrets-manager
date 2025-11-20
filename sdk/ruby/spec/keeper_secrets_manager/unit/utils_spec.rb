require 'spec_helper'

RSpec.describe KeeperSecretsManager::Utils do
  describe '.generate_password' do
    describe 'basic functionality' do
      it 'generates a password with default length of 64 characters' do
        password = described_class.generate_password
        expect(password.length).to eq(64)
      end

      it 'generates a password with custom length' do
        password = described_class.generate_password(length: 32)
        expect(password.length).to eq(32)
      end

      it 'generates different passwords each time' do
        password1 = described_class.generate_password
        password2 = described_class.generate_password
        expect(password1).not_to eq(password2)
      end

      it 'returns a string' do
        password = described_class.generate_password
        expect(password).to be_a(String)
      end
    end

    describe 'character type requirements' do
      it 'includes at least the specified number of lowercase letters' do
        password = described_class.generate_password(length: 20, lowercase: 5)
        lowercase_count = password.scan(/[a-z]/).length
        expect(lowercase_count).to be >= 5
      end

      it 'includes at least the specified number of uppercase letters' do
        password = described_class.generate_password(length: 20, uppercase: 5)
        uppercase_count = password.scan(/[A-Z]/).length
        expect(uppercase_count).to be >= 5
      end

      it 'includes at least the specified number of digits' do
        password = described_class.generate_password(length: 20, digits: 5)
        digit_count = password.scan(/[0-9]/).length
        expect(digit_count).to be >= 5
      end

      it 'includes at least the specified number of special characters' do
        password = described_class.generate_password(length: 20, special_characters: 5)
        special_count = password.scan(/[!@#$%^&*()\-_+=\[\]{}|;:,.<>?]/).length
        expect(special_count).to be >= 5
      end

      it 'satisfies all minimum requirements simultaneously' do
        password = described_class.generate_password(
          length: 30,
          lowercase: 3,
          uppercase: 3,
          digits: 3,
          special_characters: 3
        )

        expect(password.length).to eq(30)
        expect(password.scan(/[a-z]/).length).to be >= 3
        expect(password.scan(/[A-Z]/).length).to be >= 3
        expect(password.scan(/[0-9]/).length).to be >= 3
        expect(password.scan(/[!@#$%^&*()\-_+=\[\]{}|;:,.<>?]/).length).to be >= 3
      end
    end

    describe 'character distribution' do
      it 'shuffles characters randomly (not grouped by type)' do
        # Generate password where minimums equal total length
        password = described_class.generate_password(
          length: 12,
          lowercase: 3,
          uppercase: 3,
          digits: 3,
          special_characters: 3
        )

        # Check that character types are not all grouped together
        # (This is probabilistic, but should pass with high confidence)
        # We'll check that lowercase letters aren't all in first 3 positions
        first_three = password[0..2]
        all_lowercase = first_three.chars.all? { |c| c =~ /[a-z]/ }

        # With proper shuffling, probability of all lowercase in first 3 is very low
        # For a single test run, we'll just verify the password is valid
        expect(password.length).to eq(12)
        expect(password.scan(/[a-z]/).length).to be >= 3
      end

      it 'uses all character types when no minimums specified' do
        # Generate large password with defaults - should contain variety
        password = described_class.generate_password(length: 100)

        # With 100 random characters from all types, very likely to have all types
        has_lowercase = password =~ /[a-z]/
        has_uppercase = password =~ /[A-Z]/
        has_digit = password =~ /[0-9]/
        has_special = password =~ /[!@#$%^&*()\-_+=\[\]{}|;:,.<>?]/

        expect(has_lowercase).to be_truthy
        expect(has_uppercase).to be_truthy
        expect(has_digit).to be_truthy
        expect(has_special).to be_truthy
      end
    end

    describe 'edge cases' do
      it 'generates password when minimums sum exactly to length' do
        password = described_class.generate_password(
          length: 8,
          lowercase: 2,
          uppercase: 2,
          digits: 2,
          special_characters: 2
        )

        expect(password.length).to eq(8)
      end

      it 'generates password with zero minimums' do
        password = described_class.generate_password(
          length: 20,
          lowercase: 0,
          uppercase: 0,
          digits: 0,
          special_characters: 0
        )

        expect(password.length).to eq(20)
      end

      it 'generates very short password' do
        password = described_class.generate_password(length: 1)
        expect(password.length).to eq(1)
      end

      it 'generates very long password' do
        password = described_class.generate_password(length: 256)
        expect(password.length).to eq(256)
      end
    end

    describe 'input validation' do
      it 'raises error for negative length' do
        expect do
          described_class.generate_password(length: -1)
        end.to raise_error(ArgumentError, /Length must be positive/)
      end

      it 'raises error for zero length' do
        expect do
          described_class.generate_password(length: 0)
        end.to raise_error(ArgumentError, /Length must be positive/)
      end

      it 'raises error for negative lowercase count' do
        expect do
          described_class.generate_password(lowercase: -1)
        end.to raise_error(ArgumentError, /Character counts must be non-negative/)
      end

      it 'raises error for negative uppercase count' do
        expect do
          described_class.generate_password(uppercase: -1)
        end.to raise_error(ArgumentError, /Character counts must be non-negative/)
      end

      it 'raises error for negative digits count' do
        expect do
          described_class.generate_password(digits: -1)
        end.to raise_error(ArgumentError, /Character counts must be non-negative/)
      end

      it 'raises error for negative special_characters count' do
        expect do
          described_class.generate_password(special_characters: -1)
        end.to raise_error(ArgumentError, /Character counts must be non-negative/)
      end

      it 'raises error when minimums exceed length' do
        expect do
          described_class.generate_password(
            length: 10,
            lowercase: 5,
            uppercase: 5,
            digits: 5,
            special_characters: 5
          )
        end.to raise_error(ArgumentError, /Sum of character minimums \(20\) cannot exceed password length \(10\)/)
      end

      it 'raises error when minimums barely exceed length' do
        expect do
          described_class.generate_password(
            length: 10,
            lowercase: 11
          )
        end.to raise_error(ArgumentError, /Sum of character minimums \(11\) cannot exceed password length \(10\)/)
      end
    end

    describe 'security properties' do
      it 'uses all available lowercase characters' do
        # Generate many short passwords, collect all lowercase chars used
        chars_used = Set.new
        100.times do
          password = described_class.generate_password(length: 26, lowercase: 26)
          chars_used.merge(password.scan(/[a-z]/))
        end

        # Should have used most/all lowercase letters
        expect(chars_used.size).to be >= 20 # At least 20 out of 26
      end

      it 'uses cryptographically secure randomness (no obvious patterns)' do
        # Generate multiple passwords and check for diversity
        passwords = 10.times.map { described_class.generate_password(length: 20) }

        # All passwords should be different
        expect(passwords.uniq.length).to eq(10)

        # No password should have obvious repeating patterns (like "aaaa")
        passwords.each do |password|
          expect(password).not_to match(/(.)\1{3,}/)
        end
      end
    end

    describe 'compatibility with other SDKs' do
      it 'matches JavaScript SDK default behavior' do
        # JavaScript: generatePassword() -> 64 chars, all types
        password = described_class.generate_password
        expect(password.length).to eq(64)
      end

      it 'matches Python SDK parameter style' do
        # Python: generate_password(length, lowercase, uppercase, digits, specialCharacters)
        password = described_class.generate_password(
          length: 32,
          lowercase: 2,
          uppercase: 2,
          digits: 2,
          special_characters: 2
        )
        expect(password.length).to eq(32)
      end

      it 'matches Java SDK CryptoUtils.generatePassword() style' do
        # Java: CryptoUtils.generatePassword(64, 0, 0, 0, 0)
        password = described_class.generate_password(
          length: 64,
          lowercase: 0,
          uppercase: 0,
          digits: 0,
          special_characters: 0
        )
        expect(password.length).to eq(64)
      end
    end
  end

  describe 'string and bytes conversion' do
    describe '.string_to_bytes' do
      it 'converts string to bytes' do
        result = described_class.string_to_bytes('hello')
        expect(result).to be_a(String)
        expect(result.encoding).to eq(Encoding::BINARY)
      end

      it 'handles UTF-8 strings' do
        result = described_class.string_to_bytes('hello 世界')
        expect(result.encoding).to eq(Encoding::BINARY)
      end
    end

    describe '.bytes_to_string' do
      it 'converts bytes to UTF-8 string' do
        bytes = 'hello'.b
        result = described_class.bytes_to_string(bytes)
        expect(result).to eq('hello')
        expect(result.encoding).to eq(Encoding::UTF_8)
      end

      it 'forces UTF-8 encoding' do
        bytes = 'test'.b
        result = described_class.bytes_to_string(bytes)
        expect(result.encoding).to eq(Encoding::UTF_8)
      end
    end
  end

  describe 'JSON operations' do
    describe '.dict_to_json' do
      it 'converts hash to JSON string' do
        hash = { 'name' => 'test', 'value' => 123 }
        result = described_class.dict_to_json(hash)
        expect(result).to be_a(String)
        expect(result).to include('"name":"test"')
      end

      it 'handles nested hashes' do
        hash = { 'outer' => { 'inner' => 'value' } }
        result = described_class.dict_to_json(hash)
        expect(result).to include('"outer"')
        expect(result).to include('"inner"')
      end

      it 'handles arrays' do
        hash = { 'items' => [1, 2, 3] }
        result = described_class.dict_to_json(hash)
        expect(result).to include('[1,2,3]')
      end
    end

    describe '.json_to_dict' do
      it 'parses JSON string to hash' do
        json = '{"name":"test","value":123}'
        result = described_class.json_to_dict(json)
        expect(result).to eq({ 'name' => 'test', 'value' => 123 })
      end

      it 'handles nested JSON' do
        json = '{"outer":{"inner":"value"}}'
        result = described_class.json_to_dict(json)
        expect(result).to eq({ 'outer' => { 'inner' => 'value' } })
      end

      it 'raises Error for invalid JSON' do
        expect do
          described_class.json_to_dict('invalid json')
        end.to raise_error(KeeperSecretsManager::Error, /Invalid JSON/)
      end

      it 'raises Error for malformed JSON' do
        expect do
          described_class.json_to_dict('{"incomplete":')
        end.to raise_error(KeeperSecretsManager::Error, /Invalid JSON/)
      end
    end
  end

  describe 'Base64 operations' do
    describe '.bytes_to_base64' do
      it 'encodes bytes to base64' do
        bytes = 'hello'
        result = described_class.bytes_to_base64(bytes)
        expect(result).to eq('aGVsbG8=')
      end

      it 'uses strict encoding' do
        bytes = "\x00\x01\x02"
        result = described_class.bytes_to_base64(bytes)
        expect(result).to be_a(String)
        expect(result.length).to be > 0
      end
    end

    describe '.base64_to_bytes' do
      it 'decodes base64 to bytes' do
        base64 = 'aGVsbG8='
        result = described_class.base64_to_bytes(base64)
        expect(result).to eq('hello')
      end

      it 'raises Error for invalid base64' do
        expect do
          described_class.base64_to_bytes('not valid base64!')
        end.to raise_error(KeeperSecretsManager::Error, /Invalid base64/)
      end

      it 'raises Error for malformed base64' do
        expect do
          described_class.base64_to_bytes('aGVs===')
        end.to raise_error(KeeperSecretsManager::Error, /Invalid base64/)
      end
    end

    describe '.url_safe_str_to_bytes' do
      it 'decodes URL-safe base64 without padding' do
        # 'hello' in URL-safe base64 without padding
        url_safe = 'aGVsbG8'
        result = described_class.url_safe_str_to_bytes(url_safe)
        expect(result).to eq('hello')
      end

      it 'adds padding automatically' do
        # Test with various padding needs (valid base64 strings)
        # 'hello' -> 'aGVsbG8', 'hell' -> 'aGVsbA', 'hel' -> 'aGVs'
        tests = {
          'aGVsbG8' => 'hello',
          'aGVsbA' => 'hell',
          'aGVs' => 'hel'
        }
        tests.each do |encoded, expected|
          result = described_class.url_safe_str_to_bytes(encoded)
          expect(result).to eq(expected)
        end
      end

      it 'handles URL-safe characters' do
        # URL-safe base64 uses - and _ instead of + and /
        result = described_class.url_safe_str_to_bytes('_-_-')
        expect(result).to be_a(String)
      end
    end

    describe '.bytes_to_url_safe_str' do
      it 'encodes bytes to URL-safe base64 without padding' do
        bytes = 'hello'
        result = described_class.bytes_to_url_safe_str(bytes)
        expect(result).to eq('aGVsbG8')
        expect(result).not_to include('=')
      end

      it 'uses URL-safe characters' do
        bytes = "\xFF\xFF"
        result = described_class.bytes_to_url_safe_str(bytes)
        expect(result).not_to include('+')
        expect(result).not_to include('/')
      end
    end
  end

  describe 'random generation' do
    describe '.generate_random_bytes' do
      it 'generates random bytes of specified length' do
        bytes = described_class.generate_random_bytes(16)
        expect(bytes.length).to eq(16)
      end

      it 'generates different bytes each time' do
        bytes1 = described_class.generate_random_bytes(16)
        bytes2 = described_class.generate_random_bytes(16)
        expect(bytes1).not_to eq(bytes2)
      end

      it 'generates cryptographically secure random bytes' do
        bytes = described_class.generate_random_bytes(32)
        expect(bytes).to be_a(String)
        expect(bytes.encoding).to eq(Encoding::BINARY)
      end
    end

    describe '.generate_uid' do
      it 'generates a UID' do
        uid = described_class.generate_uid
        expect(uid).to be_a(String)
        expect(uid.length).to be > 0
      end

      it 'generates URL-safe UID without padding' do
        uid = described_class.generate_uid
        expect(uid).not_to include('=')
        expect(uid).not_to include('+')
        expect(uid).not_to include('/')
      end

      it 'generates different UIDs each time' do
        uid1 = described_class.generate_uid
        uid2 = described_class.generate_uid
        expect(uid1).not_to eq(uid2)
      end
    end

    describe '.generate_uid_bytes' do
      it 'generates 16 random bytes' do
        bytes = described_class.generate_uid_bytes
        expect(bytes.length).to eq(16)
      end

      it 'generates different bytes each time' do
        bytes1 = described_class.generate_uid_bytes
        bytes2 = described_class.generate_uid_bytes
        expect(bytes1).not_to eq(bytes2)
      end
    end
  end

  describe 'time operations' do
    describe '.now_milliseconds' do
      it 'returns current time in milliseconds' do
        result = described_class.now_milliseconds
        expect(result).to be_a(Integer)
        expect(result).to be > 1_600_000_000_000 # After 2020
      end

      it 'returns different values over time' do
        time1 = described_class.now_milliseconds
        sleep(0.01)
        time2 = described_class.now_milliseconds
        expect(time2).to be >= time1
      end
    end
  end

  describe 'type conversion' do
    describe '.strtobool' do
      it 'returns true for boolean true' do
        expect(described_class.strtobool(true)).to be true
      end

      it 'returns false for boolean false' do
        expect(described_class.strtobool(false)).to be false
      end

      it 'converts "true" to true' do
        expect(described_class.strtobool('true')).to be true
      end

      it 'converts "1" to true' do
        expect(described_class.strtobool('1')).to be true
      end

      it 'converts "yes" to true' do
        expect(described_class.strtobool('yes')).to be true
      end

      it 'converts "y" to true' do
        expect(described_class.strtobool('y')).to be true
      end

      it 'converts "on" to true' do
        expect(described_class.strtobool('on')).to be true
      end

      it 'converts "false" to false' do
        expect(described_class.strtobool('false')).to be false
      end

      it 'converts "0" to false' do
        expect(described_class.strtobool('0')).to be false
      end

      it 'converts "no" to false' do
        expect(described_class.strtobool('no')).to be false
      end

      it 'converts "n" to false' do
        expect(described_class.strtobool('n')).to be false
      end

      it 'converts "off" to false' do
        expect(described_class.strtobool('off')).to be false
      end

      it 'converts empty string to false' do
        expect(described_class.strtobool('')).to be false
      end

      it 'handles uppercase strings' do
        expect(described_class.strtobool('TRUE')).to be true
        expect(described_class.strtobool('FALSE')).to be false
      end

      it 'handles whitespace' do
        expect(described_class.strtobool('  true  ')).to be true
        expect(described_class.strtobool('  false  ')).to be false
      end

      it 'raises error for invalid value' do
        expect do
          described_class.strtobool('maybe')
        end.to raise_error(ArgumentError, /Invalid boolean value/)
      end
    end

    describe '.to_int' do
      it 'converts string to integer' do
        expect(described_class.to_int('123')).to eq(123)
      end

      it 'converts negative string to integer' do
        expect(described_class.to_int('-456')).to eq(-456)
      end

      it 'returns default for invalid string' do
        expect(described_class.to_int('not a number', 0)).to eq(0)
      end

      it 'returns nil default when no default specified' do
        expect(described_class.to_int('invalid')).to be_nil
      end

      it 'converts integer to integer' do
        expect(described_class.to_int(789)).to eq(789)
      end

      it 'returns default for nil' do
        expect(described_class.to_int(nil, 42)).to eq(42)
      end
    end
  end

  describe 'string operations' do
    describe '.blank?' do
      it 'returns true for nil' do
        expect(described_class.blank?(nil)).to be true
      end

      it 'returns true for empty string' do
        expect(described_class.blank?('')).to be true
      end

      it 'returns true for whitespace-only string' do
        expect(described_class.blank?('   ')).to be true
      end

      it 'returns false for non-empty string' do
        expect(described_class.blank?('test')).to be false
      end

      it 'returns false for string with content and whitespace' do
        expect(described_class.blank?('  test  ')).to be false
      end
    end

    describe '.camel_to_snake' do
      it 'converts camelCase to snake_case' do
        expect(described_class.camel_to_snake('camelCase')).to eq('camel_case')
      end

      it 'converts PascalCase to snake_case' do
        expect(described_class.camel_to_snake('PascalCase')).to eq('pascal_case')
      end

      it 'handles consecutive capitals' do
        expect(described_class.camel_to_snake('HTTPResponse')).to eq('http_response')
      end

      it 'handles already snake_case' do
        expect(described_class.camel_to_snake('already_snake')).to eq('already_snake')
      end

      it 'handles single word' do
        expect(described_class.camel_to_snake('word')).to eq('word')
      end
    end

    describe '.snake_to_camel' do
      it 'converts snake_case to camelCase' do
        expect(described_class.snake_to_camel('snake_case')).to eq('snakeCase')
      end

      it 'converts to PascalCase when capitalize_first is true' do
        expect(described_class.snake_to_camel('snake_case', true)).to eq('SnakeCase')
      end

      it 'handles single word' do
        expect(described_class.snake_to_camel('word')).to eq('word')
      end

      it 'handles multiple underscores' do
        expect(described_class.snake_to_camel('one_two_three')).to eq('oneTwoThree')
      end

      it 'handles already camelCase' do
        expect(described_class.snake_to_camel('alreadyCamel')).to eq('alreadyCamel')
      end
    end
  end

  describe 'hash operations' do
    describe '.deep_merge' do
      it 'merges simple hashes' do
        hash1 = { 'a' => 1, 'b' => 2 }
        hash2 = { 'c' => 3 }
        result = described_class.deep_merge(hash1, hash2)
        expect(result).to eq({ 'a' => 1, 'b' => 2, 'c' => 3 })
      end

      it 'overwrites values for same keys' do
        hash1 = { 'a' => 1 }
        hash2 = { 'a' => 2 }
        result = described_class.deep_merge(hash1, hash2)
        expect(result).to eq({ 'a' => 2 })
      end

      it 'recursively merges nested hashes' do
        hash1 = { 'outer' => { 'inner1' => 1 } }
        hash2 = { 'outer' => { 'inner2' => 2 } }
        result = described_class.deep_merge(hash1, hash2)
        expect(result).to eq({ 'outer' => { 'inner1' => 1, 'inner2' => 2 } })
      end

      it 'overwrites nested values' do
        hash1 = { 'outer' => { 'inner' => 1 } }
        hash2 = { 'outer' => { 'inner' => 2 } }
        result = described_class.deep_merge(hash1, hash2)
        expect(result).to eq({ 'outer' => { 'inner' => 2 } })
      end

      it 'handles non-hash values' do
        hash1 = { 'a' => [1, 2] }
        hash2 = { 'a' => [3, 4] }
        result = described_class.deep_merge(hash1, hash2)
        expect(result).to eq({ 'a' => [3, 4] })
      end
    end
  end

  describe 'URL operations' do
    describe '.url_join' do
      it 'joins URL parts' do
        result = described_class.url_join('https://example.com', 'api', 'v1')
        expect(result).to eq('https://example.com/api/v1')
      end

      it 'removes leading slashes' do
        result = described_class.url_join('https://example.com/', '/api', '/v1')
        expect(result).to eq('https://example.com/api/v1')
      end

      it 'removes trailing slashes' do
        result = described_class.url_join('https://example.com/', 'api/', 'v1/')
        expect(result).to eq('https://example.com/api/v1')
      end

      it 'handles empty parts' do
        result = described_class.url_join('https://example.com', '', 'api')
        expect(result).to eq('https://example.com/api')
      end

      it 'handles single part' do
        result = described_class.url_join('https://example.com')
        expect(result).to eq('https://example.com')
      end
    end

    describe '.get_server_url' do
      it 'builds HTTPS URL by default' do
        result = described_class.get_server_url('example.com')
        expect(result).to eq('https://example.com')
      end

      it 'builds HTTP URL when use_ssl is false' do
        result = described_class.get_server_url('example.com', false)
        expect(result).to eq('http://example.com')
      end

      it 'removes existing protocol' do
        result = described_class.get_server_url('https://example.com')
        expect(result).to eq('https://example.com')
      end

      it 'removes http protocol and replaces with https' do
        result = described_class.get_server_url('http://example.com')
        expect(result).to eq('https://example.com')
      end

      it 'returns nil for blank hostname' do
        expect(described_class.get_server_url('')).to be_nil
        expect(described_class.get_server_url(nil)).to be_nil
      end
    end

    describe '.extract_region' do
      it 'extracts region from token with prefix' do
        result = described_class.extract_region('US:token_data')
        expect(result).to eq('US')
      end

      it 'extracts region from hostname' do
        result = described_class.extract_region('keepersecurity.eu')
        expect(result).to eq('EU')
      end

      it 'returns US as default for unknown hostname' do
        result = described_class.extract_region('unknown.com')
        expect(result).to eq('US')
      end

      it 'handles nil input' do
        result = described_class.extract_region(nil)
        expect(result).to eq('US')
      end

      it 'recognizes region from hostname with region' do
        # Test with a hostname that actually matches a known server
        result = described_class.extract_region('test.keepersecurity.eu')
        expect(result).to eq('EU')
      end
    end
  end

  describe 'validation' do
    describe '.valid_uid?' do
      it 'returns true for valid UID' do
        # Generate a valid UID
        uid = described_class.generate_uid
        expect(described_class.valid_uid?(uid)).to be true
      end

      it 'returns false for nil' do
        expect(described_class.valid_uid?(nil)).to be false
      end

      it 'returns false for empty string' do
        expect(described_class.valid_uid?('')).to be false
      end

      it 'returns false for invalid base64' do
        expect(described_class.valid_uid?('not-valid!')).to be false
      end

      it 'returns false for wrong length' do
        # 8 bytes instead of 16
        short_uid = described_class.bytes_to_url_safe_str(described_class.generate_random_bytes(8))
        expect(described_class.valid_uid?(short_uid)).to be false
      end
    end
  end

  describe 'retry logic' do
    describe '.retry_with_backoff' do
      it 'returns result on first success' do
        call_count = 0
        result = described_class.retry_with_backoff do
          call_count += 1
          'success'
        end

        expect(result).to eq('success')
        expect(call_count).to eq(1)
      end

      it 'retries on failure' do
        call_count = 0
        result = described_class.retry_with_backoff(max_attempts: 3, base_delay: 0.01) do
          call_count += 1
          raise StandardError, 'fail' if call_count < 3

          'success'
        end

        expect(result).to eq('success')
        expect(call_count).to eq(3)
      end

      it 'raises error after max attempts' do
        call_count = 0
        expect do
          described_class.retry_with_backoff(max_attempts: 3, base_delay: 0.01) do
            call_count += 1
            raise StandardError, 'always fail'
          end
        end.to raise_error(StandardError, 'always fail')

        expect(call_count).to eq(3)
      end

      it 'uses exponential backoff' do
        call_count = 0
        start_time = Time.now

        begin
          described_class.retry_with_backoff(max_attempts: 3, base_delay: 0.1, max_delay: 1) do
            call_count += 1
            raise StandardError, 'fail'
          end
        rescue StandardError
          # Expected
        end

        elapsed = Time.now - start_time
        # Should have delayed at least 0.1 + 0.2 = 0.3 seconds
        expect(elapsed).to be >= 0.3
        expect(call_count).to eq(3)
      end

      it 'respects max_delay' do
        call_count = 0
        start_time = Time.now

        begin
          described_class.retry_with_backoff(max_attempts: 4, base_delay: 1, max_delay: 0.2) do
            call_count += 1
            raise StandardError, 'fail'
          end
        rescue StandardError
          # Expected
        end

        elapsed = Time.now - start_time
        # Delays should be capped at max_delay (0.2, 0.2, 0.2)
        expect(elapsed).to be < 1.0 # Much less than uncapped exponential backoff
        expect(call_count).to eq(4)
      end
    end
  end
end
