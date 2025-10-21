module KeeperSecretsManager
  module FieldTypes
    # Base field helper
    class Field
      attr_accessor :type, :label, :value, :required, :privacy_screen

      def initialize(type:, value:, label: nil, required: false, privacy_screen: false)
        @type = type
        @label = label
        @required = required
        @privacy_screen = privacy_screen

        # Ensure value is always an array
        @value = value.is_a?(Array) ? value : [value]
      end

      def to_h
        h = { 'type' => type, 'value' => value }
        h['label'] = label if label
        h['required'] = required if required
        h['privacyScreen'] = privacy_screen if privacy_screen
        h
      end
    end

    # Helper methods for creating common fields
    module Helpers
      def self.login(value, label: nil)
        Field.new(type: 'login', value: value, label: label)
      end

      def self.password(value, label: nil)
        Field.new(type: 'password', value: value, label: label)
      end

      def self.url(value, label: nil)
        Field.new(type: 'url', value: value, label: label)
      end

      def self.file_ref(value, label: nil)
        Field.new(type: 'fileRef', value: value, label: label)
      end

      def self.one_time_code(value, label: nil)
        Field.new(type: 'oneTimeCode', value: value, label: label)
      end

      def self.name(first:, last:, middle: nil, label: nil)
        value = { 'first' => first, 'last' => last }
        value['middle'] = middle if middle
        Field.new(type: 'name', value: value, label: label)
      end

      def self.phone(number:, region: 'US', type: nil, ext: nil, label: nil)
        value = { 'region' => region, 'number' => number }
        value['type'] = type if type
        value['ext'] = ext if ext
        Field.new(type: 'phone', value: value, label: label)
      end

      def self.email(email, label: nil)
        Field.new(type: 'email', value: email, label: label)
      end

      def self.address(street1:, city:, state:, zip:, country: 'US', street2: nil, label: nil)
        value = {
          'street1' => street1,
          'city' => city,
          'state' => state,
          'zip' => zip,
          'country' => country
        }
        value['street2'] = street2 if street2
        Field.new(type: 'address', value: value, label: label)
      end

      def self.payment_card(number:, expiration_date:, security_code:, cardholder_name: nil, label: nil)
        value = {
          'cardNumber' => number,
          'cardExpirationDate' => expiration_date,
          'cardSecurityCode' => security_code
        }
        value['cardholderName'] = cardholder_name if cardholder_name
        Field.new(type: 'paymentCard', value: value, label: label)
      end

      def self.bank_account(account_type:, routing_number:, account_number:, label: nil)
        value = {
          'accountType' => account_type,
          'routingNumber' => routing_number,
          'accountNumber' => account_number
        }
        Field.new(type: 'bankAccount', value: value, label: label)
      end

      def self.birth_date(date, label: nil)
        # Date should be in unix timestamp (milliseconds)
        timestamp = case date
                    when Date, Time, DateTime
                      (date.to_time.to_f * 1000).to_i
                    when Integer
                      date
                    when String
                      (Date.parse(date).to_time.to_f * 1000).to_i
                    else
                      raise ArgumentError, 'Invalid date format'
                    end
        Field.new(type: 'birthDate', value: timestamp, label: label)
      end

      def self.secure_note(note, label: nil)
        Field.new(type: 'secureNote', value: note, label: label)
      end

      def self.ssh_key(private_key:, public_key: nil, label: nil)
        value = { 'privateKey' => private_key }
        value['publicKey'] = public_key if public_key
        Field.new(type: 'sshKey', value: value, label: label)
      end

      def self.host(hostname:, port: nil, label: nil)
        value = { 'hostName' => hostname }
        value['port'] = port.to_s if port
        Field.new(type: 'host', value: value, label: label)
      end

      def self.database_type(type, label: nil)
        Field.new(type: 'databaseType', value: type, label: label)
      end

      def self.script(script, label: nil)
        Field.new(type: 'script', value: script, label: label)
      end

      def self.passkey(private_key:, credential_id:, rp_id:, user_id:, username:, label: nil)
        value = {
          'privateKey' => private_key,
          'credentialId' => credential_id,
          'relyingParty' => rp_id,
          'userId' => user_id,
          'username' => username
        }
        Field.new(type: 'passkey', value: value, label: label)
      end

      # Generic field for any type
      def self.custom(type:, value:, label: nil, required: false)
        Field.new(type: type, value: value, label: label, required: required)
      end
    end
  end
end
