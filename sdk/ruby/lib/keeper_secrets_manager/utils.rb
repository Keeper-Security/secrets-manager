require 'json'
require 'base64'
require 'securerandom'
require 'time'

module KeeperSecretsManager
  module Utils
    class << self
      # Convert string to bytes
      def string_to_bytes(str)
        str.b
      end

      # Convert bytes to string
      def bytes_to_string(bytes)
        bytes.force_encoding('UTF-8')
      end

      # Convert hash/object to JSON string
      def dict_to_json(obj)
        JSON.generate(obj)
      end

      # Parse JSON string to hash
      def json_to_dict(json_str)
        JSON.parse(json_str)
      rescue JSON::ParserError => e
        raise Error, "Invalid JSON: #{e.message}"
      end

      # Base64 encode
      def bytes_to_base64(bytes)
        Base64.strict_encode64(bytes)
      end

      # Base64 decode
      def base64_to_bytes(str)
        Base64.strict_decode64(str)
      rescue ArgumentError => e
        raise Error, "Invalid base64: #{e.message}"
      end

      # URL-safe base64 encode (with padding)
      def url_safe_str_to_bytes(str)
        # Add padding if needed
        str += '=' * (4 - str.length % 4) if str.length % 4 != 0
        Base64.urlsafe_decode64(str)
      end

      # URL-safe base64 decode (without padding)
      def bytes_to_url_safe_str(bytes)
        Base64.urlsafe_encode64(bytes).delete('=')
      end

      # Generate random bytes
      def generate_random_bytes(length)
        SecureRandom.random_bytes(length)
      end

      # Generate UID (16 random bytes)
      def generate_uid
        bytes_to_url_safe_str(generate_random_bytes(16))
      end

      # Generate UID bytes
      def generate_uid_bytes
        generate_random_bytes(16)
      end

      # Generate a cryptographically secure random password
      #
      # @param length [Integer] Total password length (default: 64)
      # @param lowercase [Integer] Minimum number of lowercase letters (default: 0)
      # @param uppercase [Integer] Minimum number of uppercase letters (default: 0)
      # @param digits [Integer] Minimum number of digit characters (default: 0)
      # @param special_characters [Integer] Minimum number of special characters (default: 0)
      # @return [String] Generated password
      # @raise [ArgumentError] If parameters are invalid or minimums exceed length
      #
      # @example Generate a default 64-character password
      #   password = KeeperSecretsManager::Utils.generate_password
      #   # => "Xk9$mP2...64 chars total"
      #
      # @example Generate a 32-character password with specific requirements
      #   password = KeeperSecretsManager::Utils.generate_password(
      #     length: 32,
      #     lowercase: 2,
      #     uppercase: 2,
      #     digits: 2,
      #     special_characters: 2
      #   )
      #   # => "aB12$...32 chars with at least 2 of each type"
      #
      # @example Use with record update
      #   record = secrets_manager.get_secrets(['RECORD_UID']).first
      #   record.password = KeeperSecretsManager::Utils.generate_password(length: 20)
      #   secrets_manager.update_secret(record)
      def generate_password(length: 64, lowercase: 0, uppercase: 0, digits: 0, special_characters: 0)
        # Validate inputs
        raise ArgumentError, 'Length must be positive' if length <= 0
        raise ArgumentError, 'Character counts must be non-negative' if [lowercase, uppercase, digits, special_characters].any?(&:negative?)

        total_minimums = lowercase + uppercase + digits + special_characters
        raise ArgumentError, "Sum of character minimums (#{total_minimums}) cannot exceed password length (#{length})" if total_minimums > length

        # Character sets
        lowercase_chars = 'abcdefghijklmnopqrstuvwxyz'
        uppercase_chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
        digit_chars = '0123456789'
        special_chars = '!@#$%^&*()_+-=[]{}|;:,.<>?'

        # Build password character array
        password_chars = []

        # Add minimum required characters from each category
        lowercase.times { password_chars << lowercase_chars[SecureRandom.random_number(lowercase_chars.length)] }
        uppercase.times { password_chars << uppercase_chars[SecureRandom.random_number(uppercase_chars.length)] }
        digits.times { password_chars << digit_chars[SecureRandom.random_number(digit_chars.length)] }
        special_characters.times { password_chars << special_chars[SecureRandom.random_number(special_chars.length)] }

        # Fill remaining length with random characters from all categories
        remaining = length - total_minimums
        all_chars = lowercase_chars + uppercase_chars + digit_chars + special_chars

        remaining.times do
          password_chars << all_chars[SecureRandom.random_number(all_chars.length)]
        end

        # Shuffle using Fisher-Yates algorithm with SecureRandom for cryptographic security
        # This ensures minimum characters aren't clustered at the beginning
        (password_chars.length - 1).downto(1) do |i|
          j = SecureRandom.random_number(i + 1)
          password_chars[i], password_chars[j] = password_chars[j], password_chars[i]
        end

        password_chars.join
      end

      # Get current time in milliseconds
      def now_milliseconds
        (Time.now.to_f * 1000).to_i
      end

      # Convert string to boolean
      def strtobool(val)
        return val if val.is_a?(TrueClass) || val.is_a?(FalseClass)

        val_str = val.to_s.downcase.strip
        case val_str
        when 'true', '1', 'yes', 'y', 'on'
          true
        when 'false', '0', 'no', 'n', 'off', ''
          false
        else
          raise ArgumentError, "Invalid boolean value: #{val}"
        end
      end

      # Check if string is blank
      def blank?(str)
        str.nil? || str.strip.empty?
      end

      # Deep merge hashes
      def deep_merge(hash1, hash2)
        hash1.merge(hash2) do |_key, old_val, new_val|
          if old_val.is_a?(Hash) && new_val.is_a?(Hash)
            deep_merge(old_val, new_val)
          else
            new_val
          end
        end
      end

      # Convert camelCase to snake_case
      def camel_to_snake(str)
        str.gsub(/([A-Z]+)([A-Z][a-z])/, '\1_\2')
           .gsub(/([a-z\d])([A-Z])/, '\1_\2')
           .downcase
      end

      # Convert snake_case to camelCase
      def snake_to_camel(str, capitalize_first = false)
        str.split('_').map.with_index do |word, i|
          i == 0 && !capitalize_first ? word : word.capitalize
        end.join
      end

      # Safe integer conversion
      def to_int(val, default = nil)
        Integer(val)
      rescue ArgumentError, TypeError
        default
      end

      # URL join
      def url_join(*parts)
        parts.map { |part| part.to_s.gsub(%r{^/+|/+$}, '') }
             .reject(&:empty?)
             .join('/')
      end

      # Parse server URL from hostname
      def get_server_url(hostname, use_ssl = true)
        return nil if blank?(hostname)

        # Remove protocol if present
        hostname = hostname.sub(%r{^https?://}, '')

        # Build URL
        protocol = use_ssl ? 'https' : 'http'
        "#{protocol}://#{hostname}"
      end

      # Extract region from token or hostname
      def extract_region(token_or_hostname)
        # Check if it's a token with region prefix
        if token_or_hostname&.include?(':')
          parts = token_or_hostname.split(':')
          return parts[0].upcase if parts.length >= 2
        end

        # Check if hostname matches a known region
        hostname = token_or_hostname.to_s.downcase
        KeeperGlobals::KEEPER_SERVERS.each do |region, server|
          return region if hostname.include?(server)
        end

        # Default to US
        'US'
      end

      # Validate UID format
      def valid_uid?(uid)
        return false if blank?(uid)

        # UIDs are base64url encoded 16-byte values
        begin
          bytes = url_safe_str_to_bytes(uid)
          bytes.length == 16
        rescue StandardError
          false
        end
      end

      # Retry with exponential backoff
      def retry_with_backoff(max_attempts: 3, base_delay: 1, max_delay: 60)
        attempt = 0
        begin
          yield
        rescue StandardError => e
          attempt += 1
          raise e if attempt >= max_attempts

          delay = [base_delay * (2**(attempt - 1)), max_delay].min
          sleep(delay)
          retry
        end
      end
    end
  end
end
