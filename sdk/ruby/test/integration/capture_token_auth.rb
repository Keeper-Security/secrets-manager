#!/usr/bin/env ruby

# Add lib directory to load path
lib_path = File.expand_path('../../lib', __FILE__)
$LOAD_PATH.unshift(lib_path) unless $LOAD_PATH.include?(lib_path)

# Also add the current directory for relative requires
$LOAD_PATH.unshift(lib_path)

require 'keeper_secrets_manager'
require 'json'
require 'base64'

# Token provided for testing
TOKEN = 'US:BHwFFrb0uLBl97qXBoiORVNFd0hQA2ovud_exK88uWo'

puts "Capturing one-time token authentication flow..."

# Monkey-patch to capture requests/responses
module KeeperSecretsManager
  class KeeperHttpClient
    alias_method :original_post_query, :post_query
    
    def post_query(endpoint, payload)
      puts "\n=== API Call: #{endpoint} ==="
      puts "Request Payload:"
      puts JSON.pretty_generate(payload)
      
      response = original_post_query(endpoint, payload)
      
      puts "\nResponse:"
      puts JSON.pretty_generate(response)
      
      # Save to file for mock data
      File.write("captured_#{endpoint}.json", JSON.pretty_generate({
        endpoint: endpoint,
        request: payload,
        response: response
      }))
      
      response
    end
  end
end

begin
  # Initialize with token - this will trigger the token exchange
  puts "Initializing SDK with one-time token..."
  sm = KeeperSecretsManager::SecretsManager.new(token: TOKEN)
  
  # The token exchange happens during initialization
  # Now let's make some API calls to capture responses
  
  puts "\n\n=== Getting Secrets ==="
  secrets = sm.get_secrets()
  puts "Found #{secrets.length} secrets"
  
  puts "\n\n=== Getting Folders ==="
  folders = sm.get_folders()
  puts "Found #{folders.length} folders"
  
  # Save captured data
  captured_data = {
    token: TOKEN,
    timestamp: Time.now.to_s,
    secrets_count: secrets.length,
    folders_count: folders.length,
    first_secret: secrets.first ? {
      uid: secrets.first.uid,
      title: secrets.first.title,
      type: secrets.first.type
    } : nil
  }
  
  File.write("captured_auth_summary.json", JSON.pretty_generate(captured_data))
  
  puts "\n\nCapture complete! Check captured_*.json files for mock data."
  
rescue => e
  puts "\nError: #{e.message}"
  puts e.backtrace
end