# TOTP (Time-based One-Time Password) implementation
# Compliant with RFC 6238

require 'base32'
require 'openssl'
require 'uri'

module KeeperSecretsManager
  class TOTP
    ALGORITHMS = {
      'SHA1' => OpenSSL::Digest::SHA1,
      'SHA256' => OpenSSL::Digest::SHA256,
      'SHA512' => OpenSSL::Digest::SHA512
    }.freeze
    
    # Generate a TOTP code
    # @param secret [String] Base32 encoded secret
    # @param time [Time] Time to generate code for (default: current time)
    # @param algorithm [String] Hash algorithm: SHA1, SHA256, or SHA512
    # @param digits [Integer] Number of digits (6 or 8)
    # @param period [Integer] Time period in seconds
    # @return [String] TOTP code
    def self.generate_code(secret, time: Time.now, algorithm: 'SHA1', digits: 6, period: 30)
      # Validate inputs
      raise ArgumentError, "Invalid algorithm: #{algorithm}" unless ALGORITHMS.key?(algorithm)
      raise ArgumentError, "Digits must be 6 or 8" unless [6, 8].include?(digits)
      raise ArgumentError, "Period must be positive" unless period.positive?
      
      # Decode base32 secret
      key = Base32.decode(secret.upcase.tr(' ', ''))
      
      # Calculate time counter
      counter = (time.to_i / period).floor
      
      # Convert counter to 8-byte string (big-endian)
      counter_bytes = [counter].pack('Q>')
      
      # Generate HMAC
      digest = ALGORITHMS[algorithm].new
      hmac = OpenSSL::HMAC.digest(digest, key, counter_bytes)
      
      # Extract dynamic binary code
      offset = hmac[-1].ord & 0x0f
      code = (hmac[offset].ord & 0x7f) << 24 |
             (hmac[offset + 1].ord & 0xff) << 16 |
             (hmac[offset + 2].ord & 0xff) << 8 |
             (hmac[offset + 3].ord & 0xff)
      
      # Generate final OTP value
      otp = code % (10 ** digits)
      
      # Pad with leading zeros if necessary
      otp.to_s.rjust(digits, '0')
    end
    
    # Parse TOTP URL (otpauth://totp/...)
    # @param url [String] TOTP URL
    # @return [Hash] Parsed components
    def self.parse_url(url)
      uri = URI(url)
      
      raise ArgumentError, "Invalid TOTP URL scheme" unless uri.scheme == 'otpauth'
      raise ArgumentError, "Invalid TOTP URL type" unless uri.host == 'totp'
      
      # Extract label (issuer:account or just account)
      path = uri.path[1..-1] # Remove leading /
      if path.include?(':')
        issuer, account = path.split(':', 2)
      else
        account = path
        issuer = nil
      end
      
      # Parse query parameters
      params = URI.decode_www_form(uri.query || '').to_h
      
      {
        'account' => URI.decode_www_form_component(account || ''),
        'issuer' => issuer ? URI.decode_www_form_component(issuer) : params['issuer'],
        'secret' => params['secret'],
        'algorithm' => params['algorithm'] || 'SHA1',
        'digits' => (params['digits'] || '6').to_i,
        'period' => (params['period'] || '30').to_i
      }
    end
    
    # Generate TOTP URL
    # @param account [String] Account name (e.g., email)
    # @param secret [String] Base32 encoded secret
    # @param issuer [String] Service name
    # @param algorithm [String] Hash algorithm
    # @param digits [Integer] Number of digits
    # @param period [Integer] Time period
    # @return [String] TOTP URL
    def self.generate_url(account, secret, issuer: nil, algorithm: 'SHA1', digits: 6, period: 30)
      label = issuer ? "#{issuer}:#{account}" : account
      
      params = {
        'secret' => secret,
        'algorithm' => algorithm,
        'digits' => digits,
        'period' => period
      }
      
      params['issuer'] = issuer if issuer
      
      query = URI.encode_www_form(params)
      "otpauth://totp/#{URI.encode_www_form_component(label)}?#{query}"
    end
    
    # Validate a TOTP code
    # @param secret [String] Base32 encoded secret
    # @param code [String] Code to validate
    # @param time [Time] Time to validate against
    # @param window [Integer] Number of periods to check before/after
    # @param algorithm [String] Hash algorithm
    # @param digits [Integer] Number of digits
    # @param period [Integer] Time period
    # @return [Boolean] True if code is valid
    def self.validate_code(secret, code, time: Time.now, window: 1, algorithm: 'SHA1', digits: 6, period: 30)
      # Check current time and window
      (-window..window).each do |offset|
        test_time = time + (offset * period)
        test_code = generate_code(secret, time: test_time, algorithm: algorithm, digits: digits, period: period)
        
        return true if test_code == code
      end
      
      false
    end
    
    # Generate a random secret suitable for TOTP
    # @param length [Integer] Number of bytes (default: 20 for 160 bits)
    # @return [String] Base32 encoded secret
    def self.generate_secret(length: 20)
      random_bytes = OpenSSL::Random.random_bytes(length)
      Base32.encode(random_bytes).delete('=')
    end
  end
end