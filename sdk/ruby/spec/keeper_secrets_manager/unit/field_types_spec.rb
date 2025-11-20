require 'spec_helper'
require 'date'

RSpec.describe KeeperSecretsManager::FieldTypes do
  describe KeeperSecretsManager::FieldTypes::Field do
    describe '#initialize' do
      it 'creates a field with required parameters' do
        field = described_class.new(type: 'login', value: 'testuser')

        expect(field.type).to eq('login')
        expect(field.value).to eq(['testuser'])
        expect(field.label).to be_nil
        expect(field.required).to be false
        expect(field.privacy_screen).to be false
      end

      it 'normalizes non-array value to array' do
        field = described_class.new(type: 'password', value: 'secret123')

        expect(field.value).to eq(['secret123'])
      end

      it 'preserves array value' do
        field = described_class.new(type: 'multipleChoice', value: %w[option1 option2])

        expect(field.value).to eq(%w[option1 option2])
      end

      it 'accepts optional label' do
        field = described_class.new(type: 'url', value: 'https://example.com', label: 'Website')

        expect(field.label).to eq('Website')
      end

      it 'accepts optional required flag' do
        field = described_class.new(type: 'password', value: 'pass', required: true)

        expect(field.required).to be true
      end

      it 'accepts optional privacy_screen flag' do
        field = described_class.new(type: 'password', value: 'pass', privacy_screen: true)

        expect(field.privacy_screen).to be true
      end

      it 'accepts all optional parameters' do
        field = described_class.new(
          type: 'sensitiveData',
          value: 'secret',
          label: 'API Key',
          required: true,
          privacy_screen: true
        )

        expect(field.type).to eq('sensitiveData')
        expect(field.value).to eq(['secret'])
        expect(field.label).to eq('API Key')
        expect(field.required).to be true
        expect(field.privacy_screen).to be true
      end
    end

    describe '#to_h' do
      it 'converts to hash with type and value' do
        field = described_class.new(type: 'login', value: 'user')
        hash = field.to_h

        expect(hash).to eq({ 'type' => 'login', 'value' => ['user'] })
      end

      it 'includes label when present' do
        field = described_class.new(type: 'url', value: 'https://example.com', label: 'Site')
        hash = field.to_h

        expect(hash).to include('label' => 'Site')
      end

      it 'excludes label when nil' do
        field = described_class.new(type: 'url', value: 'https://example.com')
        hash = field.to_h

        expect(hash).not_to have_key('label')
      end

      it 'includes required when true' do
        field = described_class.new(type: 'password', value: 'pass', required: true)
        hash = field.to_h

        expect(hash).to include('required' => true)
      end

      it 'excludes required when false' do
        field = described_class.new(type: 'password', value: 'pass', required: false)
        hash = field.to_h

        expect(hash).not_to have_key('required')
      end

      it 'includes privacyScreen when true' do
        field = described_class.new(type: 'password', value: 'pass', privacy_screen: true)
        hash = field.to_h

        expect(hash).to include('privacyScreen' => true)
      end

      it 'excludes privacyScreen when false' do
        field = described_class.new(type: 'password', value: 'pass', privacy_screen: false)
        hash = field.to_h

        expect(hash).not_to have_key('privacyScreen')
      end

      it 'includes all optional fields when present' do
        field = described_class.new(
          type: 'custom',
          value: 'data',
          label: 'Custom',
          required: true,
          privacy_screen: true
        )
        hash = field.to_h

        expect(hash).to eq({
                             'type' => 'custom',
                             'value' => ['data'],
                             'label' => 'Custom',
                             'required' => true,
                             'privacyScreen' => true
                           })
      end
    end

    describe 'attribute accessors' do
      it 'allows reading and writing type' do
        field = described_class.new(type: 'login', value: 'user')
        field.type = 'email'

        expect(field.type).to eq('email')
      end

      it 'allows reading and writing value' do
        field = described_class.new(type: 'password', value: 'pass1')
        field.value = ['pass2']

        expect(field.value).to eq(['pass2'])
      end

      it 'allows reading and writing label' do
        field = described_class.new(type: 'url', value: 'https://example.com')
        field.label = 'New Label'

        expect(field.label).to eq('New Label')
      end

      it 'allows reading and writing required' do
        field = described_class.new(type: 'password', value: 'pass')
        field.required = true

        expect(field.required).to be true
      end

      it 'allows reading and writing privacy_screen' do
        field = described_class.new(type: 'password', value: 'pass')
        field.privacy_screen = true

        expect(field.privacy_screen).to be true
      end
    end
  end

  describe KeeperSecretsManager::FieldTypes::Helpers do
    describe '.login' do
      it 'creates a login field' do
        field = described_class.login('testuser')

        expect(field.type).to eq('login')
        expect(field.value).to eq(['testuser'])
      end

      it 'accepts optional label' do
        field = described_class.login('admin', label: 'Username')

        expect(field.label).to eq('Username')
      end
    end

    describe '.password' do
      it 'creates a password field' do
        field = described_class.password('secret123')

        expect(field.type).to eq('password')
        expect(field.value).to eq(['secret123'])
      end

      it 'accepts optional label' do
        field = described_class.password('pass', label: 'Admin Password')

        expect(field.label).to eq('Admin Password')
      end
    end

    describe '.url' do
      it 'creates a url field' do
        field = described_class.url('https://example.com')

        expect(field.type).to eq('url')
        expect(field.value).to eq(['https://example.com'])
      end

      it 'accepts optional label' do
        field = described_class.url('https://example.com', label: 'Website')

        expect(field.label).to eq('Website')
      end
    end

    describe '.file_ref' do
      it 'creates a fileRef field' do
        field = described_class.file_ref('file-uid-123')

        expect(field.type).to eq('fileRef')
        expect(field.value).to eq(['file-uid-123'])
      end

      it 'accepts optional label' do
        field = described_class.file_ref('file-uid', label: 'Attachment')

        expect(field.label).to eq('Attachment')
      end
    end

    describe '.one_time_code' do
      it 'creates a oneTimeCode field' do
        field = described_class.one_time_code('otpauth://totp/example')

        expect(field.type).to eq('oneTimeCode')
        expect(field.value).to eq(['otpauth://totp/example'])
      end

      it 'accepts optional label' do
        field = described_class.one_time_code('otpauth://totp/test', label: 'TOTP')

        expect(field.label).to eq('TOTP')
      end
    end

    describe '.name' do
      it 'creates a name field with first and last name' do
        field = described_class.name(first: 'John', last: 'Doe')

        expect(field.type).to eq('name')
        expect(field.value).to eq([{ 'first' => 'John', 'last' => 'Doe' }])
      end

      it 'includes middle name when provided' do
        field = described_class.name(first: 'John', middle: 'Q', last: 'Doe')

        expect(field.value).to eq([{ 'first' => 'John', 'middle' => 'Q', 'last' => 'Doe' }])
      end

      it 'excludes middle name when nil' do
        field = described_class.name(first: 'Jane', last: 'Smith')

        expect(field.value.first).not_to have_key('middle')
      end

      it 'accepts optional label' do
        field = described_class.name(first: 'John', last: 'Doe', label: 'Full Name')

        expect(field.label).to eq('Full Name')
      end
    end

    describe '.phone' do
      it 'creates a phone field with number and default region' do
        field = described_class.phone(number: '555-1234')

        expect(field.type).to eq('phone')
        expect(field.value).to eq([{ 'region' => 'US', 'number' => '555-1234' }])
      end

      it 'accepts custom region' do
        field = described_class.phone(number: '1234567890', region: 'UK')

        expect(field.value).to eq([{ 'region' => 'UK', 'number' => '1234567890' }])
      end

      it 'includes type when provided' do
        field = described_class.phone(number: '555-1234', type: 'mobile')

        expect(field.value.first).to include('type' => 'mobile')
      end

      it 'includes extension when provided' do
        field = described_class.phone(number: '555-1234', ext: '123')

        expect(field.value.first).to include('ext' => '123')
      end

      it 'includes all optional parameters' do
        field = described_class.phone(
          number: '555-1234',
          region: 'CA',
          type: 'work',
          ext: '456',
          label: 'Office'
        )

        expect(field.value.first).to eq({
                                          'region' => 'CA',
                                          'number' => '555-1234',
                                          'type' => 'work',
                                          'ext' => '456'
                                        })
        expect(field.label).to eq('Office')
      end
    end

    describe '.email' do
      it 'creates an email field' do
        field = described_class.email('test@example.com')

        expect(field.type).to eq('email')
        expect(field.value).to eq(['test@example.com'])
      end

      it 'accepts optional label' do
        field = described_class.email('admin@example.com', label: 'Work Email')

        expect(field.label).to eq('Work Email')
      end
    end

    describe '.address' do
      it 'creates an address field with required fields' do
        field = described_class.address(
          street1: '123 Main St',
          city: 'Springfield',
          state: 'IL',
          zip: '62701'
        )

        expect(field.type).to eq('address')
        expect(field.value.first).to include(
          'street1' => '123 Main St',
          'city' => 'Springfield',
          'state' => 'IL',
          'zip' => '62701',
          'country' => 'US'
        )
      end

      it 'uses default country US' do
        field = described_class.address(
          street1: '123 Main St',
          city: 'City',
          state: 'State',
          zip: '12345'
        )

        expect(field.value.first['country']).to eq('US')
      end

      it 'accepts custom country' do
        field = described_class.address(
          street1: '10 Downing St',
          city: 'London',
          state: 'England',
          zip: 'SW1A 2AA',
          country: 'UK'
        )

        expect(field.value.first['country']).to eq('UK')
      end

      it 'includes street2 when provided' do
        field = described_class.address(
          street1: '123 Main St',
          street2: 'Apt 4B',
          city: 'City',
          state: 'State',
          zip: '12345'
        )

        expect(field.value.first).to include('street2' => 'Apt 4B')
      end

      it 'excludes street2 when nil' do
        field = described_class.address(
          street1: '123 Main St',
          city: 'City',
          state: 'State',
          zip: '12345'
        )

        expect(field.value.first).not_to have_key('street2')
      end

      it 'accepts optional label' do
        field = described_class.address(
          street1: '123 Main St',
          city: 'City',
          state: 'State',
          zip: '12345',
          label: 'Home Address'
        )

        expect(field.label).to eq('Home Address')
      end
    end

    describe '.payment_card' do
      it 'creates a payment card field with required fields' do
        field = described_class.payment_card(
          number: '4111111111111111',
          expiration_date: '12/25',
          security_code: '123'
        )

        expect(field.type).to eq('paymentCard')
        expect(field.value.first).to eq({
                                          'cardNumber' => '4111111111111111',
                                          'cardExpirationDate' => '12/25',
                                          'cardSecurityCode' => '123'
                                        })
      end

      it 'includes cardholder name when provided' do
        field = described_class.payment_card(
          number: '4111111111111111',
          expiration_date: '12/25',
          security_code: '123',
          cardholder_name: 'John Doe'
        )

        expect(field.value.first).to include('cardholderName' => 'John Doe')
      end

      it 'excludes cardholder name when nil' do
        field = described_class.payment_card(
          number: '4111111111111111',
          expiration_date: '12/25',
          security_code: '123'
        )

        expect(field.value.first).not_to have_key('cardholderName')
      end

      it 'accepts optional label' do
        field = described_class.payment_card(
          number: '4111111111111111',
          expiration_date: '12/25',
          security_code: '123',
          label: 'Visa Card'
        )

        expect(field.label).to eq('Visa Card')
      end
    end

    describe '.bank_account' do
      it 'creates a bank account field' do
        field = described_class.bank_account(
          account_type: 'checking',
          routing_number: '123456789',
          account_number: '987654321'
        )

        expect(field.type).to eq('bankAccount')
        expect(field.value.first).to eq({
                                          'accountType' => 'checking',
                                          'routingNumber' => '123456789',
                                          'accountNumber' => '987654321'
                                        })
      end

      it 'accepts optional label' do
        field = described_class.bank_account(
          account_type: 'savings',
          routing_number: '123456789',
          account_number: '987654321',
          label: 'Main Account'
        )

        expect(field.label).to eq('Main Account')
      end
    end

    describe '.birth_date' do
      it 'creates a birth date field from Date object' do
        date = Date.new(1990, 5, 15)
        field = described_class.birth_date(date)

        expect(field.type).to eq('birthDate')
        expect(field.value).to be_an(Array)
        expect(field.value.first).to be_an(Integer)
        expect(field.value.first).to be > 0
      end

      it 'creates a birth date field from Time object' do
        time = Time.new(1990, 5, 15, 12, 30, 0)
        field = described_class.birth_date(time)

        expect(field.type).to eq('birthDate')
        expect(field.value.first).to be_an(Integer)
      end

      it 'creates a birth date field from unix timestamp (milliseconds)' do
        timestamp = 1_620_000_000_000 # May 3, 2021 in milliseconds
        field = described_class.birth_date(timestamp)

        expect(field.type).to eq('birthDate')
        expect(field.value).to eq([timestamp])
      end

      it 'creates a birth date field from date string' do
        field = described_class.birth_date('1990-05-15')

        expect(field.type).to eq('birthDate')
        expect(field.value.first).to be_an(Integer)
        expect(field.value.first).to be > 0
      end

      it 'raises error for invalid date format' do
        expect do
          described_class.birth_date({})
        end.to raise_error(ArgumentError, 'Invalid date format')
      end

      it 'accepts optional label' do
        field = described_class.birth_date('1990-05-15', label: 'Date of Birth')

        expect(field.label).to eq('Date of Birth')
      end
    end

    describe '.secure_note' do
      it 'creates a secure note field' do
        field = described_class.secure_note('This is a secure note')

        expect(field.type).to eq('secureNote')
        expect(field.value).to eq(['This is a secure note'])
      end

      it 'accepts optional label' do
        field = described_class.secure_note('Note text', label: 'Important Note')

        expect(field.label).to eq('Important Note')
      end
    end

    describe '.ssh_key' do
      it 'creates an SSH key field with private key' do
        field = described_class.ssh_key(private_key: 'private-key-data')

        expect(field.type).to eq('sshKey')
        expect(field.value).to eq([{ 'privateKey' => 'private-key-data' }])
      end

      it 'includes public key when provided' do
        field = described_class.ssh_key(
          private_key: 'private-key',
          public_key: 'public-key'
        )

        expect(field.value.first).to eq({
                                          'privateKey' => 'private-key',
                                          'publicKey' => 'public-key'
                                        })
      end

      it 'excludes public key when nil' do
        field = described_class.ssh_key(private_key: 'private-key')

        expect(field.value.first).not_to have_key('publicKey')
      end

      it 'accepts optional label' do
        field = described_class.ssh_key(
          private_key: 'private-key',
          label: 'Server SSH Key'
        )

        expect(field.label).to eq('Server SSH Key')
      end
    end

    describe '.host' do
      it 'creates a host field with hostname' do
        field = described_class.host(hostname: 'example.com')

        expect(field.type).to eq('host')
        expect(field.value).to eq([{ 'hostName' => 'example.com' }])
      end

      it 'includes port when provided' do
        field = described_class.host(hostname: 'example.com', port: 8080)

        expect(field.value.first).to eq({
                                          'hostName' => 'example.com',
                                          'port' => '8080'
                                        })
      end

      it 'converts port to string' do
        field = described_class.host(hostname: 'example.com', port: 443)

        expect(field.value.first['port']).to eq('443')
        expect(field.value.first['port']).to be_a(String)
      end

      it 'excludes port when nil' do
        field = described_class.host(hostname: 'example.com')

        expect(field.value.first).not_to have_key('port')
      end

      it 'accepts optional label' do
        field = described_class.host(hostname: 'db.example.com', label: 'Database Host')

        expect(field.label).to eq('Database Host')
      end
    end

    describe '.database_type' do
      it 'creates a database type field' do
        field = described_class.database_type('postgresql')

        expect(field.type).to eq('databaseType')
        expect(field.value).to eq(['postgresql'])
      end

      it 'accepts optional label' do
        field = described_class.database_type('mysql', label: 'DB Type')

        expect(field.label).to eq('DB Type')
      end
    end

    describe '.script' do
      it 'creates a script field' do
        field = described_class.script('#!/bin/bash\necho "Hello"')

        expect(field.type).to eq('script')
        expect(field.value).to eq(['#!/bin/bash\necho "Hello"'])
      end

      it 'accepts optional label' do
        field = described_class.script('script code', label: 'Deployment Script')

        expect(field.label).to eq('Deployment Script')
      end
    end

    describe '.passkey' do
      it 'creates a passkey field with all required parameters' do
        field = described_class.passkey(
          private_key: 'priv-key',
          credential_id: 'cred-id',
          rp_id: 'example.com',
          user_id: 'user-123',
          username: 'john@example.com'
        )

        expect(field.type).to eq('passkey')
        expect(field.value.first).to eq({
                                          'privateKey' => 'priv-key',
                                          'credentialId' => 'cred-id',
                                          'relyingParty' => 'example.com',
                                          'userId' => 'user-123',
                                          'username' => 'john@example.com'
                                        })
      end

      it 'accepts optional label' do
        field = described_class.passkey(
          private_key: 'priv-key',
          credential_id: 'cred-id',
          rp_id: 'example.com',
          user_id: 'user-123',
          username: 'john@example.com',
          label: 'WebAuthn Key'
        )

        expect(field.label).to eq('WebAuthn Key')
      end
    end

    describe '.custom' do
      it 'creates a custom field with type and value' do
        field = described_class.custom(type: 'customType', value: 'custom value')

        expect(field.type).to eq('customType')
        expect(field.value).to eq(['custom value'])
      end

      it 'accepts optional label' do
        field = described_class.custom(
          type: 'myCustomField',
          value: 'data',
          label: 'Custom Label'
        )

        expect(field.label).to eq('Custom Label')
      end

      it 'accepts optional required flag' do
        field = described_class.custom(
          type: 'customType',
          value: 'value',
          required: true
        )

        expect(field.required).to be true
      end

      it 'accepts all optional parameters' do
        field = described_class.custom(
          type: 'customType',
          value: 'value',
          label: 'Label',
          required: true
        )

        expect(field.type).to eq('customType')
        expect(field.value).to eq(['value'])
        expect(field.label).to eq('Label')
        expect(field.required).to be true
      end
    end
  end
end
