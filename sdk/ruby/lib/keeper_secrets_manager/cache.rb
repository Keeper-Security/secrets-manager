require 'fileutils'

module KeeperSecretsManager
  # File-based caching for disaster recovery
  # Stores encrypted API responses to allow offline access when network is unavailable
  class Cache
    # Default cache file location - can be overridden with KSM_CACHE_DIR environment variable
    def self.cache_file_path
      cache_dir = ENV['KSM_CACHE_DIR'] || '.'
      File.join(cache_dir, 'ksm_cache.bin')
    end

    # Save encrypted cache data (transmission key + encrypted response)
    def self.save_cache(data)
      File.open(cache_file_path, 'wb') do |file|
        file.write(data)
      end
    rescue StandardError => e
      # Silently fail on cache write errors (don't break the app)
      warn "Failed to write cache: #{e.message}" if ENV['KSM_DEBUG']
    end

    # Load encrypted cache data
    def self.get_cached_data
      return nil unless File.exist?(cache_file_path)

      File.open(cache_file_path, 'rb', &:read)
    rescue StandardError => e
      # Silently fail on cache read errors
      warn "Failed to read cache: #{e.message}" if ENV['KSM_DEBUG']
      nil
    end

    # Remove cache file
    def self.clear_cache
      File.delete(cache_file_path) if File.exist?(cache_file_path)
    rescue StandardError => e
      warn "Failed to delete cache: #{e.message}" if ENV['KSM_DEBUG']
    end

    # Check if cache file exists
    def self.cache_exists?
      File.exist?(cache_file_path)
    end
  end

  # Caching post function for disaster recovery
  # Wraps the normal post_function to save responses and fall back to cache on network failure
  # Usage: KeeperSecretsManager.new(config: storage, custom_post_function: KeeperSecretsManager::CachingPostFunction)
  module CachingPostFunction
    # Post function that caches successful responses and falls back to cache on failure
    # This matches the pattern used in Python, JavaScript, Java, and .NET SDKs
    #
    # @param url [String] The API endpoint URL
    # @param transmission_key [Dto::TransmissionKey] The transmission key
    # @param encrypted_payload [Dto::EncryptedPayload] The encrypted payload with signature
    # @param verify_ssl_certs [Boolean] Whether to verify SSL certificates
    # @return [Dto::KSMHttpResponse] Response object
    def self.call(url, transmission_key, encrypted_payload, verify_ssl_certs = true)
      # Try network request first
      begin
        # Call the static post_function
        response = make_http_request(url, transmission_key, encrypted_payload, verify_ssl_certs)

        # On success, save to cache (transmission key + encrypted response body)
        if response.success? && response.data
          cache_data = transmission_key.key + response.data
          Cache.save_cache(cache_data)
        end

        response
      rescue StandardError => e
        # Network failed - try to load from cache
        cached_data = Cache.get_cached_data

        if cached_data && cached_data.bytesize > 32
          # Extract cached transmission key and response data
          # First 32 bytes are the transmission key, rest is encrypted response
          cached_transmission_key = cached_data[0...32]
          cached_response_data = cached_data[32..-1]

          # Update the transmission key to match cached version
          transmission_key.key = cached_transmission_key

          # Return cached response as if it came from network
          Dto::KSMHttpResponse.new(
            status_code: 200,
            data: cached_response_data
          )
        else
          # No cache available - re-raise the original error
          raise e
        end
      end
    end

    # Make HTTP request - extracted to be testable
    # This duplicates some logic from Core::SecretsManager#post_function
    # because that method is an instance method
    def self.make_http_request(url, transmission_key, encrypted_payload, verify_ssl_certs)
      require 'net/http'
      require 'uri'

      uri = URI(url)

      request = Net::HTTP::Post.new(uri)
      request['Content-Type'] = 'application/octet-stream'
      request['PublicKeyId'] = transmission_key.public_key_id.to_s
      request['TransmissionKey'] = Utils.bytes_to_base64(transmission_key.encrypted_key)
      request['Authorization'] = "Signature #{Utils.bytes_to_base64(encrypted_payload.signature)}"
      request['Content-Length'] = encrypted_payload.encrypted_payload.bytesize.to_s
      request.body = encrypted_payload.encrypted_payload

      http = Net::HTTP.new(uri.host, uri.port)
      http.use_ssl = true

      if verify_ssl_certs
        http.verify_mode = OpenSSL::SSL::VERIFY_PEER

        # Set up certificate store with system defaults
        store = OpenSSL::X509::Store.new
        store.set_default_paths
        http.cert_store = store
      else
        http.verify_mode = OpenSSL::SSL::VERIFY_NONE
      end

      response = http.request(request)

      Dto::KSMHttpResponse.new(
        status_code: response.code.to_i,
        data: response.body,
        http_response: response
      )
    rescue StandardError => e
      raise NetworkError, "HTTP request failed: #{e.message}"
    end
  end
end
