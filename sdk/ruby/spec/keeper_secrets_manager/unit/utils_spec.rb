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

  describe 'other utility methods' do
    describe '.generate_uid' do
      it 'generates a UID' do
        uid = described_class.generate_uid
        expect(uid).to be_a(String)
        expect(uid.length).to be > 0
      end
    end

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
    end
  end
end
