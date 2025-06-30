#!/usr/bin/env ruby

# Direct HTTP capture without using the SDK
require 'net/http'
require 'json'
require 'base64'
require 'uri'

TOKEN = 'US:BHwFFrb0uLBl97qXBoiORVNFd0hQA2ovud_exK88uWo'

# Parse token
parts = TOKEN.split(':')
if parts.length == 2
  region = parts[0]
  token_data = parts[1]
else
  # Legacy format
  region = 'US'
  token_data = TOKEN
end

hostname = case region.upcase
when 'US' then 'keepersecurity.com'
when 'EU' then 'keepersecurity.eu'
when 'AU' then 'keepersecurity.com.au'
when 'GOV' then 'govcloud.keepersecurity.us'
when 'JP' then 'keepersecurity.jp'
when 'CA' then 'keepersecurity.ca'
else 'keepersecurity.com'
end

puts "Using hostname: #{hostname}"
puts "Token data: #{token_data}"

# Make the initial token request
uri = URI("https://#{hostname}/api/rest/sm/v1/get_client_params")
http = Net::HTTP.new(uri.host, uri.port)
http.use_ssl = true

request_payload = {
  'clientVersion' => 'mb17.0.0',
  'tokenType' => 3,
  'oneTimeToken' => token_data
}

puts "\n=== Token Exchange Request ==="
puts JSON.pretty_generate(request_payload)

request = Net::HTTP::Post.new(uri)
request['Content-Type'] = 'application/json'
request.body = request_payload.to_json

begin
  response = http.request(request)
  
  puts "\n=== Token Exchange Response ==="
  puts "Status: #{response.code}"
  puts "Body:"
  response_json = JSON.parse(response.body)
  puts JSON.pretty_generate(response_json)
  
  # Save for mocking
  File.write('captured_token_exchange.json', JSON.pretty_generate({
    request: request_payload,
    response: response_json,
    status_code: response.code.to_i
  }))
  
  puts "\nSaved to captured_token_exchange.json"
  
rescue => e
  puts "Error: #{e.message}"
end