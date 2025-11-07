#!/usr/bin/env ruby
# frozen_string_literal: true

# Custom Caching Example - Advanced HTTP handling and caching patterns
# Demonstrates how to use custom_post_function for:
# - Request logging
# - Response caching
# - Offline fallback
# - Rate limiting

require 'keeper_secrets_manager'
require 'json'
require 'time'
require 'net/http'
require 'uri'
require 'base64'

puts '=== Custom Caching and HTTP Handling Examples ==='

# Load configuration
config = ENV['KSM_CONFIG'] || 'YOUR_BASE64_CONFIG'
storage = KeeperSecretsManager::Storage::InMemoryStorage.new(config)

# Helper method to make HTTP requests (reusable across examples)
def make_http_request(url, transmission_key, encrypted_payload, verify_ssl)
  uri = URI(url)
  request = Net::HTTP::Post.new(uri)
  request['Content-Type'] = 'application/octet-stream'
  request['PublicKeyId'] = transmission_key.public_key_id.to_s
  request['TransmissionKey'] = Base64.strict_encode64(transmission_key.encrypted_key)
  request['Authorization'] = "Signature #{Base64.strict_encode64(encrypted_payload.signature)}"
  request.body = encrypted_payload.encrypted_payload

  http = Net::HTTP.new(uri.host, uri.port)
  http.use_ssl = true
  http.verify_mode = verify_ssl ? OpenSSL::SSL::VERIFY_PEER : OpenSSL::SSL::VERIFY_NONE

  response = http.request(request)

  KeeperSecretsManager::Dto::KSMHttpResponse.new(
    status_code: response.code.to_i,
    data: response.body,
    http_response: response
  )
end

# ============================================================================
# Example 1: Request Logging
# ============================================================================
puts "\n1. Request Logging Pattern:"
puts "   Log all API requests for debugging/auditing"
puts

# Custom post function that logs requests
logging_post_function = lambda do |url, transmission_key, encrypted_payload, verify_ssl|
  puts "  [LOG] Making request to: #{url}"
  puts "  [LOG] Timestamp: #{Time.now}"
  puts "  [LOG] Payload size: #{encrypted_payload.encrypted_payload.bytesize} bytes"

  # Make the HTTP request
  result = make_http_request(url, transmission_key, encrypted_payload, verify_ssl)

  puts "  [LOG] Response status: #{result.status_code}"
  puts "  [LOG] Response size: #{result.data.bytesize} bytes"

  result
end

begin
  sm = KeeperSecretsManager.new(
    config: storage,
    verify_ssl_certs: false,
    custom_post_function: logging_post_function
  )

  secrets = sm.get_secrets
  puts "✓ Retrieved #{secrets.length} secrets with request logging"
rescue => e
  puts "✗ Error: #{e.message}"
end

# ============================================================================
# Example 2: Simple In-Memory Caching
# ============================================================================
puts "\n2. Simple In-Memory Caching Pattern:"
puts "   Cache responses to avoid redundant API calls"
puts

# Simple cache storage
cache_store = {}

caching_post_function = lambda do |url, transmission_key, encrypted_payload, verify_ssl|
  # Create cache key from URL and payload
  cache_key = "#{url}:#{encrypted_payload.encrypted_payload[0..31]}"

  # Check cache first
  if cache_store.key?(cache_key)
    cached_entry = cache_store[cache_key]
    age_seconds = Time.now - cached_entry[:timestamp]

    if age_seconds < 300 # 5 minute TTL
      puts "  [CACHE HIT] Using cached response (age: #{age_seconds.round}s)"
      return cached_entry[:response]
    else
      puts "  [CACHE EXPIRED] Fetching fresh data"
    end
  else
    puts "  [CACHE MISS] Fetching from API"
  end

  # Fetch from API
  result = make_http_request(url, transmission_key, encrypted_payload, verify_ssl)

  # Store in cache
  cache_store[cache_key] = {
    response: result,
    timestamp: Time.now
  }

  result
end

begin
  sm = KeeperSecretsManager.new(
    config: storage,
    verify_ssl_certs: false,
    custom_post_function: caching_post_function
  )

  # First call - cache miss
  secrets1 = sm.get_secrets
  puts "✓ First call: Retrieved #{secrets1.length} secrets"

  # Second call - cache hit
  secrets2 = sm.get_secrets
  puts "✓ Second call: Retrieved #{secrets2.length} secrets"
rescue => e
  puts "✗ Error: #{e.message}"
end

# ============================================================================
# Example 3: Offline Fallback Pattern
# ============================================================================
puts "\n3. Offline Fallback Pattern:"
puts "   Gracefully handle network failures with cached data"
puts

# Cache with offline fallback
offline_cache = {}

offline_fallback_function = lambda do |url, transmission_key, encrypted_payload, verify_ssl|
  cache_key = "#{url}:#{encrypted_payload.encrypted_payload[0..31]}"

  begin
    # Try to fetch from API
    result = make_http_request(url, transmission_key, encrypted_payload, verify_ssl)

    # Update cache on success
    offline_cache[cache_key] = {
      response: result,
      timestamp: Time.now
    }

    puts "  [ONLINE] Fetched fresh data"
    result
  rescue => e
    # On failure, try to use cached data
    if offline_cache.key?(cache_key)
      puts "  [OFFLINE FALLBACK] Network error, using cached data"
      puts "  [OFFLINE FALLBACK] Cache age: #{(Time.now - offline_cache[cache_key][:timestamp]).round}s"
      offline_cache[cache_key][:response]
    else
      puts "  [OFFLINE FAILURE] No cached data available"
      raise e
    end
  end
end

begin
  sm = KeeperSecretsManager.new(
    config: storage,
    verify_ssl_certs: false,
    custom_post_function: offline_fallback_function
  )

  secrets = sm.get_secrets
  puts "✓ Retrieved #{secrets.length} secrets with offline fallback"
rescue => e
  puts "✗ Error: #{e.message}"
end

# ============================================================================
# Example 4: Rate Limiting
# ============================================================================
puts "\n4. Rate Limiting Pattern:"
puts "   Prevent excessive API calls"
puts

# Rate limiter state
last_request_time = nil
min_interval = 1.0 # Minimum 1 second between requests

rate_limiting_function = lambda do |url, transmission_key, encrypted_payload, verify_ssl|
  # Check rate limit
  if last_request_time
    time_since_last = Time.now - last_request_time
    if time_since_last < min_interval
      sleep_time = min_interval - time_since_last
      puts "  [RATE LIMIT] Sleeping #{sleep_time.round(2)}s to respect rate limit"
      sleep(sleep_time)
    end
  end

  # Make request
  last_request_time = Time.now
  puts "  [REQUEST] Making API call"

  make_http_request(url, transmission_key, encrypted_payload, verify_ssl)
end

begin
  sm = KeeperSecretsManager.new(
    config: storage,
    verify_ssl_certs: false,
    custom_post_function: rate_limiting_function
  )

  # Make multiple requests - should be rate limited
  3.times do |i|
    puts "\nRequest #{i + 1}:"
    secrets = sm.get_secrets
    puts "✓ Retrieved #{secrets.length} secrets"
  end
rescue => e
  puts "✗ Error: #{e.message}"
end

# ============================================================================
# Example 5: Combined Pattern (Production-Ready)
# ============================================================================
puts "\n5. Combined Pattern (Logging + Caching + Rate Limiting):"
puts "   Production-ready custom post function"
puts

class ProductionCache
  attr_reader :stats

  def initialize(ttl_seconds: 300, rate_limit_seconds: 1.0)
    @cache = {}
    @ttl_seconds = ttl_seconds
    @rate_limit_seconds = rate_limit_seconds
    @last_request_time = nil
    @stats = {
      hits: 0,
      misses: 0,
      expired: 0,
      errors: 0,
      rate_limited: 0
    }
  end

  def call(url, transmission_key, encrypted_payload, verify_ssl)
    cache_key = generate_cache_key(url, encrypted_payload)

    # Check cache
    if cached_response = check_cache(cache_key)
      @stats[:hits] += 1
      return cached_response
    end

    # Apply rate limiting
    apply_rate_limit

    # Log request
    log_request(url, encrypted_payload)

    # Make API call
    begin
      result = make_http_request(url, transmission_key, encrypted_payload, verify_ssl)

      # Store in cache
      store_in_cache(cache_key, result)

      log_response(result)
      result
    rescue => e
      @stats[:errors] += 1
      # Try offline fallback
      if cached = check_cache(cache_key, allow_expired: true)
        puts "  [FALLBACK] Using expired cache due to error: #{e.message}"
        cached
      else
        raise e
      end
    end
  end

  private

  def generate_cache_key(url, encrypted_payload)
    "#{url}:#{encrypted_payload.encrypted_payload[0..31]}"
  end

  def check_cache(cache_key, allow_expired: false)
    return nil unless @cache.key?(cache_key)

    entry = @cache[cache_key]
    age = Time.now - entry[:timestamp]

    if allow_expired || age < @ttl_seconds
      puts "  [CACHE] Hit (age: #{age.round}s)"
      entry[:response]
    else
      @stats[:expired] += 1
      puts "  [CACHE] Expired (age: #{age.round}s)"
      nil
    end
  end

  def apply_rate_limit
    return unless @last_request_time

    time_since_last = Time.now - @last_request_time
    if time_since_last < @rate_limit_seconds
      sleep_time = @rate_limit_seconds - time_since_last
      @stats[:rate_limited] += 1
      sleep(sleep_time)
    end
    @last_request_time = Time.now
  end

  def store_in_cache(cache_key, response)
    @cache[cache_key] = {
      response: response,
      timestamp: Time.now
    }
  end

  def log_request(url, encrypted_payload)
    @stats[:misses] += 1
    puts "  [REQUEST] #{url} (#{encrypted_payload.encrypted_payload.bytesize} bytes)"
  end

  def log_response(result)
    puts "  [RESPONSE] Status: #{result.status_code}, Size: #{result.data.bytesize} bytes"
  end
end

begin
  production_cache = ProductionCache.new(ttl_seconds: 300, rate_limit_seconds: 0.5)

  sm = KeeperSecretsManager.new(
    config: storage,
    verify_ssl_certs: false,
    custom_post_function: production_cache
  )

  # Make multiple requests to demonstrate caching
  puts "\nMaking 3 requests:"
  3.times do |i|
    puts "\n  Call #{i + 1}:"
    secrets = sm.get_secrets
    puts "  ✓ Retrieved #{secrets.length} secrets"
  end

  puts "\nCache Statistics:"
  puts "  Hits: #{production_cache.stats[:hits]}"
  puts "  Misses: #{production_cache.stats[:misses]}"
  puts "  Expired: #{production_cache.stats[:expired]}"
  puts "  Errors: #{production_cache.stats[:errors]}"
  puts "  Rate Limited: #{production_cache.stats[:rate_limited]}"
rescue => e
  puts "✗ Error: #{e.message}"
end

# ============================================================================
# Example 6: Built-in Disaster Recovery Caching
# ============================================================================
puts "\n6. Built-in CachingPostFunction (Recommended):"
puts "   File-based disaster recovery caching"
puts

begin
  # Use built-in caching function
  sm = KeeperSecretsManager.new(
    config: storage,
    verify_ssl_certs: false,
    custom_post_function: KeeperSecretsManager::CachingPostFunction
  )

  puts "  Making request with built-in caching..."
  secrets = sm.get_secrets
  puts "  ✓ Retrieved #{secrets.length} secrets"

  if KeeperSecretsManager::Cache.cache_exists?
    cache_path = KeeperSecretsManager::Cache.cache_file_path
    cache_size = File.size(cache_path)
    puts "  ✓ Cache created: #{cache_path} (#{cache_size} bytes)"
    puts "  ✓ Encrypted secrets saved for disaster recovery"

    # Clean up
    KeeperSecretsManager::Cache.clear_cache
    puts "  ✓ Cache cleared"
  end
rescue => e
  puts "  ✗ Error: #{e.message}"
end

# ============================================================================
# Summary
# ============================================================================
puts "\n" + "=" * 80
puts "Custom Post Function Use Cases Summary"
puts "=" * 80
puts
puts "1. Request Logging - Track all API calls for debugging"
puts "2. Response Caching - Reduce API calls with TTL-based cache"
puts "3. Offline Fallback - Gracefully handle network failures"
puts "4. Rate Limiting - Prevent excessive API usage"
puts "5. Combined Pattern - Production-ready implementation"
puts "6. Built-in CachingPostFunction - Disaster recovery (RECOMMENDED)"
puts
puts "Recommended Patterns:"
puts "  ✓ For disaster recovery: Use built-in CachingPostFunction"
puts "  ✓ For TTL-based caching: Implement custom function (see Example 2)"
puts "  ✓ For production: Combine caching + logging + rate limiting (see Example 5)"
puts
puts "Tips:"
puts "  - Use caching for read-heavy workloads"
puts "  - Implement offline fallback for resilient applications"
puts "  - Add request logging for debugging and auditing"
puts "  - Consider Redis/Memcached for distributed caching"
puts "  - Always include error handling in custom functions"
puts "  - Set KSM_CACHE_DIR environment variable to control cache location"
puts
puts "=" * 80
