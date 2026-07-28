require 'json'
require 'base64'
require 'fileutils'

module KeeperSecretsManager
  module Storage
    # Base storage interface
    module KeyValueStorage
      def get_string(_key)
        raise NotImplementedError, 'Subclass must implement get_string'
      end

      def save_string(_key, _value)
        raise NotImplementedError, 'Subclass must implement save_string'
      end

      def get_bytes(key)
        data = get_string(key)
        return nil unless data

        # Handle both standard and URL-safe base64
        begin
          # First try standard base64
          Base64.strict_decode64(data)
        rescue ArgumentError
          begin
            # Try URL-safe base64 with padding
            padding = 4 - (data.length % 4)
            padding = 0 if padding == 4
            Base64.urlsafe_decode64(data + '=' * padding)
          rescue StandardError => e
            # Last resort - try with decode64 which is more lenient
            Base64.decode64(data)
          end
        end
      end

      def save_bytes(key, value)
        save_string(key, Base64.strict_encode64(value))
      end

      def delete(_key)
        raise NotImplementedError, 'Subclass must implement delete'
      end

      def contains?(key)
        !get_string(key).nil?
      end
    end

    # In-memory storage implementation
    class InMemoryStorage
      include KeyValueStorage

      def initialize(config_data = nil)
        @data = {}

        # Initialize from JSON string, base64 string, or hash
        if config_data
          parsed = case config_data
                   when String
                     # Check if it's base64 encoded
                     if is_base64?(config_data)
                       JSON.parse(Base64.decode64(config_data))
                     else
                       JSON.parse(config_data)
                     end
                   when Hash
                     config_data
                   else
                     {}
                   end

          parsed.each { |k, v| @data[k.to_s] = v.to_s }
        end
      end

      def get_string(key)
        @data[key.to_s]
      end

      def save_string(key, value)
        @data[key.to_s] = value.to_s
      end

      def delete(key)
        @data.delete(key.to_s)
      end

      def to_h
        @data.dup
      end

      def to_json(*args)
        @data.to_json(*args)
      end

      private

      def is_base64?(str)
        # Check if string is valid base64
        return false if str.nil? || str.empty?

        # Remove whitespace
        str = str.strip

        # Check if length is multiple of 4 (with padding) or can be padded to multiple of 4
        # Also check if it only contains base64 characters
        base64_regex = %r{\A[A-Za-z0-9+/]*={0,2}\z}

        str.match?(base64_regex) && (str.length % 4 == 0 || str.length % 4 == 2 || str.length % 4 == 3)
      end
    end

    # File-based storage implementation
    class FileStorage
      include KeyValueStorage

      def initialize(filename = 'keeper_config.json')
        @filename = File.expand_path(filename)
        @data = {}
        load_data
      end

      def get_string(key)
        @data[key.to_s]
      end

      def save_string(key, value)
        @data[key.to_s] = value.to_s
        save_data
      end

      def delete(key)
        @data.delete(key.to_s)
        save_data
      end

      private

      def load_data
        if File.exist?(@filename)
          begin
            content = File.read(@filename)
            # Handle empty files
            @data = if content.strip.empty?
                      {}
                    else
                      JSON.parse(content)
                    end
          rescue JSON::ParserError => e
            raise Error, "Failed to parse config file: #{e.message}"
          end
        end
      end

      def save_data
        # Ensure directory exists
        FileUtils.mkdir_p(File.dirname(@filename))

        # Write atomically to avoid corruption
        temp_file = "#{@filename}.tmp"
        # Create temp file with secure permissions (0600)
        File.open(temp_file, 'w', 0o600) do |f|
          f.write(JSON.pretty_generate(@data))
        end

        # Move atomically
        File.rename(temp_file, @filename)

        # Ensure final file has restrictive permissions (owner read/write only)
        File.chmod(0o600, @filename)
      rescue StandardError => e
        raise Error, "Failed to save config file: #{e.message}"
      end
    end

    # Environment-based storage (read-only)
    class EnvironmentStorage
      include KeyValueStorage

      def initialize(prefix = 'KSM_')
        @prefix = prefix
      end

      def get_string(key)
        ENV["#{@prefix}#{key.to_s.upcase}"]
      end

      def save_string(_key, _value)
        raise Error, 'Environment storage is read-only'
      end

      def delete(_key)
        raise Error, 'Environment storage is read-only'
      end
    end

    # Cacheable storage wrapper
    class CachingStorage
      include KeyValueStorage

      def initialize(base_storage, ttl_seconds = 600)
        @base_storage = base_storage
        @ttl_seconds = ttl_seconds
        @cache = {}
        @timestamps = {}
      end

      def get_string(key)
        key_str = key.to_s

        # Check cache validity
        return @cache[key_str] if @cache.key?(key_str) && !expired?(key_str)

        # Fetch from base storage
        value = @base_storage.get_string(key)
        if value
          @cache[key_str] = value
          @timestamps[key_str] = Time.now
        end

        value
      end

      def save_string(key, value)
        key_str = key.to_s
        @base_storage.save_string(key, value)
        @cache[key_str] = value.to_s
        @timestamps[key_str] = Time.now
      end

      def delete(key)
        key_str = key.to_s
        @base_storage.delete(key)
        @cache.delete(key_str)
        @timestamps.delete(key_str)
      end

      def clear_cache
        @cache.clear
        @timestamps.clear
      end

      private

      def expired?(key)
        return true unless @timestamps[key]

        Time.now - @timestamps[key] > @ttl_seconds
      end
    end
  end
end
