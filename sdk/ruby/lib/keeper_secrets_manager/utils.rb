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
        hash1.merge(hash2) do |key, old_val, new_val|
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
        result = str.split('_').map.with_index do |word, i|
          i == 0 && !capitalize_first ? word : word.capitalize
        end.join
        result
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
        rescue
          false
        end
      end

      # Retry with exponential backoff
      def retry_with_backoff(max_attempts: 3, base_delay: 1, max_delay: 60)
        attempt = 0
        begin
          yield
        rescue => e
          attempt += 1
          if attempt >= max_attempts
            raise e
          end
          
          delay = [base_delay * (2 ** (attempt - 1)), max_delay].min
          sleep(delay)
          retry
        end
      end
    end
  end
end