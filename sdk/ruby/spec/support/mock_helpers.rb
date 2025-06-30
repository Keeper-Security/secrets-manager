# Mock helpers for offline testing

module MockHelpers
  def mock_api_response(endpoint, response_data)
    stub_request(:post, /#{endpoint}/)
      .to_return(
        status: 200,
        body: response_data.to_json,
        headers: { 'Content-Type' => 'application/json' }
      )
  end

  def mock_get_secrets_response(records = [])
    response = {
      'records' => records.map do |record|
        {
          'recordUid' => record[:uid] || "mock-uid-#{SecureRandom.hex(8)}",
          'revision' => record[:revision] || 1,
          'recordKey' => Base64.encode64('mock-record-key'),
          'data' => Base64.encode64({
            'title' => record[:title] || 'Mock Record',
            'type' => record[:type] || 'login',
            'fields' => record[:fields] || [
              { 'type' => 'login', 'value' => ['mockuser'] },
              { 'type' => 'password', 'value' => ['mockpass'] }
            ],
            'custom' => record[:custom] || [],
            'notes' => record[:notes] || ''
          }.to_json)
        }
      end,
      'folders' => []
    }
    
    mock_api_response('get_secret', response)
  end

  def mock_transmission_key
    {
      public_key_id: '10',
      key: 'mock-transmission-key',
      encrypted_key: Base64.encode64('mock-encrypted-key')
    }
  end

  def sample_record_data
    {
      uid: 'test-record-123',
      title: 'Test Login',
      type: 'login',
      fields: [
        { 'type' => 'login', 'value' => ['testuser'] },
        { 'type' => 'password', 'value' => ['TestPass123!'] },
        { 'type' => 'url', 'value' => ['https://example.com'] },
        { 'type' => 'host', 'value' => [{ 'hostName' => '192.168.1.1', 'port' => '22' }] }
      ],
      custom: [
        { 'type' => 'text', 'label' => 'Environment', 'value' => ['Test'] }
      ],
      notes: 'Test record for specs'
    }
  end

  def complex_record_data
    {
      uid: 'complex-record-456',
      title: 'Complex Test Record',
      type: 'login',
      fields: [
        { 'type' => 'login', 'value' => ['admin'] },
        { 'type' => 'password', 'value' => ['ComplexPass123!'] },
        { 'type' => 'url', 'value' => ['https://primary.com', 'https://secondary.com'] },
        { 'type' => 'host', 'value' => [
          { 'hostName' => '10.0.0.1', 'port' => '22' },
          { 'hostName' => '10.0.0.2', 'port' => '2222' }
        ]},
        { 'type' => 'name', 'value' => [{ 'first' => 'John', 'middle' => 'Q', 'last' => 'Tester' }] },
        { 'type' => 'phone', 'value' => [
          { 'region' => 'US', 'number' => '555-0123', 'type' => 'Mobile' },
          { 'region' => 'US', 'number' => '555-0456', 'type' => 'Work' }
        ]},
        { 'type' => 'address', 'value' => [{
          'street1' => '123 Test Street',
          'street2' => 'Suite 100',
          'city' => 'Test City',
          'state' => 'TC',
          'zip' => '12345',
          'country' => 'US'
        }]},
        { 'type' => 'bankAccount', 'value' => [{
          'accountType' => 'Checking',
          'routingNumber' => '123456789',
          'accountNumber' => '9876543210'
        }]}
      ],
      custom: [
        { 'type' => 'text', 'label' => 'Department', 'value' => ['Engineering'] },
        { 'type' => 'text', 'label' => 'Project', 'value' => ['Ruby SDK'] },
        { 'type' => 'text', 'label' => 'Tags', 'value' => ['test', 'complex', 'multi-value'] },
        { 'type' => 'date', 'label' => 'Created', 'value' => [Time.now.to_i * 1000] }
      ]
    }
  end

  def server_record_data
    {
      uid: 'server-record-789',
      title: 'Test Server',
      type: 'sshKeys',
      fields: [
        { 'type' => 'login', 'value' => ['root'] },
        { 'type' => 'host', 'value' => [{ 'hostName' => '192.168.100.50', 'port' => '22' }] },
        { 'type' => 'sshKey', 'value' => [{
          'privateKey' => "-----BEGIN OPENSSH PRIVATE KEY-----\nMOCK_PRIVATE_KEY_DATA\n-----END OPENSSH PRIVATE KEY-----",
          'publicKey' => "ssh-rsa AAAAB3NzaC1yc2EMOCK mock@example.com"
        }]},
        { 'type' => 'script', 'value' => ['#!/bin/bash\necho "Server setup script"'] }
      ],
      custom: [
        { 'type' => 'text', 'label' => 'OS', 'value' => ['Ubuntu 22.04 LTS'] },
        { 'type' => 'text', 'label' => 'Region', 'value' => ['us-east-1'] },
        { 'type' => 'text', 'label' => 'Instance Type', 'value' => ['t3.medium'] }
      ]
    }
  end
end

RSpec.configure do |config|
  config.include MockHelpers
end