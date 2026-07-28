require 'spec_helper'

RSpec.describe 'KeeperSecretsManager::Errors' do
  describe 'Error hierarchy' do
    it 'has Error as base class' do
      expect(KeeperSecretsManager::Error).to be < StandardError
    end

    it 'ConfigurationError inherits from Error' do
      expect(KeeperSecretsManager::ConfigurationError).to be < KeeperSecretsManager::Error
    end

    it 'AuthenticationError inherits from Error' do
      expect(KeeperSecretsManager::AuthenticationError).to be < KeeperSecretsManager::Error
    end

    it 'AccessDeniedError inherits from AuthenticationError' do
      expect(KeeperSecretsManager::AccessDeniedError).to be < KeeperSecretsManager::AuthenticationError
    end

    it 'NetworkError inherits from Error' do
      expect(KeeperSecretsManager::NetworkError).to be < KeeperSecretsManager::Error
    end

    it 'CryptoError inherits from Error' do
      expect(KeeperSecretsManager::CryptoError).to be < KeeperSecretsManager::Error
    end

    it 'DecryptionError inherits from CryptoError' do
      expect(KeeperSecretsManager::DecryptionError).to be < KeeperSecretsManager::CryptoError
    end

    it 'EncryptionError inherits from CryptoError' do
      expect(KeeperSecretsManager::EncryptionError).to be < KeeperSecretsManager::CryptoError
    end

    it 'NotationError inherits from Error' do
      expect(KeeperSecretsManager::NotationError).to be < KeeperSecretsManager::Error
    end

    it 'RecordError inherits from Error' do
      expect(KeeperSecretsManager::RecordError).to be < KeeperSecretsManager::Error
    end

    it 'RecordNotFoundError inherits from RecordError' do
      expect(KeeperSecretsManager::RecordNotFoundError).to be < KeeperSecretsManager::RecordError
    end

    it 'RecordValidationError inherits from RecordError' do
      expect(KeeperSecretsManager::RecordValidationError).to be < KeeperSecretsManager::RecordError
    end

    it 'ServerError inherits from Error' do
      expect(KeeperSecretsManager::ServerError).to be < KeeperSecretsManager::Error
    end

    it 'InvalidClientVersionError inherits from ServerError' do
      expect(KeeperSecretsManager::InvalidClientVersionError).to be < KeeperSecretsManager::ServerError
    end

    it 'InvalidTokenError inherits from ServerError' do
      expect(KeeperSecretsManager::InvalidTokenError).to be < KeeperSecretsManager::ServerError
    end

    it 'BadRequestError inherits from ServerError' do
      expect(KeeperSecretsManager::BadRequestError).to be < KeeperSecretsManager::ServerError
    end

    it 'RecordUidNotFoundError inherits from ServerError' do
      expect(KeeperSecretsManager::RecordUidNotFoundError).to be < KeeperSecretsManager::ServerError
    end

    it 'FolderUidNotFoundError inherits from ServerError' do
      expect(KeeperSecretsManager::FolderUidNotFoundError).to be < KeeperSecretsManager::ServerError
    end

    it 'AccessViolationError inherits from ServerError' do
      expect(KeeperSecretsManager::AccessViolationError).to be < KeeperSecretsManager::ServerError
    end

    it 'ThrottledError inherits from ServerError' do
      expect(KeeperSecretsManager::ThrottledError).to be < KeeperSecretsManager::ServerError
    end
  end

  describe KeeperSecretsManager::NetworkError do
    context 'initialization' do
      it 'stores message, status_code, and response_body' do
        error = KeeperSecretsManager::NetworkError.new(
          'Connection failed',
          status_code: 500,
          response_body: '{"error": "Internal Server Error"}'
        )

        expect(error.message).to eq('Connection failed')
        expect(error.status_code).to eq(500)
        expect(error.response_body).to eq('{"error": "Internal Server Error"}')
      end

      it 'works with only message' do
        error = KeeperSecretsManager::NetworkError.new('Connection timeout')

        expect(error.message).to eq('Connection timeout')
        expect(error.status_code).to be_nil
        expect(error.response_body).to be_nil
      end

      it 'works with status_code only' do
        error = KeeperSecretsManager::NetworkError.new('Bad Gateway', status_code: 502)

        expect(error.message).to eq('Bad Gateway')
        expect(error.status_code).to eq(502)
        expect(error.response_body).to be_nil
      end

      it 'works with response_body only' do
        error = KeeperSecretsManager::NetworkError.new(
          'Server error',
          response_body: 'Error details'
        )

        expect(error.message).to eq('Server error')
        expect(error.status_code).to be_nil
        expect(error.response_body).to eq('Error details')
      end
    end

    context 'error handling' do
      it 'can be rescued as NetworkError' do
        expect do
          raise KeeperSecretsManager::NetworkError.new('Test error', status_code: 404)
        end.to raise_error(KeeperSecretsManager::NetworkError)
      end

      it 'can be rescued as Error' do
        expect do
          raise KeeperSecretsManager::NetworkError.new('Test error')
        end.to raise_error(KeeperSecretsManager::Error)
      end

      it 'can be rescued as StandardError' do
        expect do
          raise KeeperSecretsManager::NetworkError.new('Test error')
        end.to raise_error(StandardError)
      end
    end
  end

  describe KeeperSecretsManager::ServerError do
    context 'initialization' do
      it 'stores result_code and custom message' do
        error = KeeperSecretsManager::ServerError.new('test_error', 'Custom error message')

        expect(error.result_code).to eq('test_error')
        expect(error.message).to eq('Custom error message')
      end

      it 'generates default message from result_code when message is nil' do
        error = KeeperSecretsManager::ServerError.new('some_error_code')

        expect(error.result_code).to eq('some_error_code')
        expect(error.message).to eq('Server error: some_error_code')
      end

      it 'uses custom message when provided' do
        error = KeeperSecretsManager::ServerError.new('error_code', 'Something went wrong')

        expect(error.result_code).to eq('error_code')
        expect(error.message).to eq('Something went wrong')
      end
    end

    context 'subclasses inherit result_code and message' do
      it 'InvalidClientVersionError stores result_code' do
        error = KeeperSecretsManager::InvalidClientVersionError.new('invalid_client_version', 'Please upgrade')

        expect(error.result_code).to eq('invalid_client_version')
        expect(error.message).to eq('Please upgrade')
      end

      it 'InvalidTokenError stores result_code' do
        error = KeeperSecretsManager::InvalidTokenError.new('invalid_token')

        expect(error.result_code).to eq('invalid_token')
        expect(error.message).to eq('Server error: invalid_token')
      end

      it 'BadRequestError stores result_code' do
        error = KeeperSecretsManager::BadRequestError.new('bad_request', 'Invalid parameters')

        expect(error.result_code).to eq('bad_request')
        expect(error.message).to eq('Invalid parameters')
      end
    end
  end

  describe KeeperSecretsManager::ErrorFactory do
    describe '.from_server_response' do
      context 'with known error codes' do
        it 'returns InvalidClientVersionError for invalid_client_version' do
          error = KeeperSecretsManager::ErrorFactory.from_server_response('invalid_client_version')

          expect(error).to be_a(KeeperSecretsManager::InvalidClientVersionError)
          expect(error.result_code).to eq('invalid_client_version')
          expect(error.message).to eq('Server error: invalid_client_version')
        end

        it 'returns InvalidTokenError for invalid_client' do
          error = KeeperSecretsManager::ErrorFactory.from_server_response('invalid_client')

          expect(error).to be_a(KeeperSecretsManager::InvalidTokenError)
          expect(error.result_code).to eq('invalid_client')
        end

        it 'returns InvalidTokenError for invalid_token' do
          error = KeeperSecretsManager::ErrorFactory.from_server_response('invalid_token')

          expect(error).to be_a(KeeperSecretsManager::InvalidTokenError)
          expect(error.result_code).to eq('invalid_token')
        end

        it 'returns BadRequestError for bad_request' do
          error = KeeperSecretsManager::ErrorFactory.from_server_response('bad_request')

          expect(error).to be_a(KeeperSecretsManager::BadRequestError)
          expect(error.result_code).to eq('bad_request')
        end

        it 'returns RecordUidNotFoundError for record_uid_not_found' do
          error = KeeperSecretsManager::ErrorFactory.from_server_response('record_uid_not_found')

          expect(error).to be_a(KeeperSecretsManager::RecordUidNotFoundError)
          expect(error.result_code).to eq('record_uid_not_found')
        end

        it 'returns FolderUidNotFoundError for folder_uid_not_found' do
          error = KeeperSecretsManager::ErrorFactory.from_server_response('folder_uid_not_found')

          expect(error).to be_a(KeeperSecretsManager::FolderUidNotFoundError)
          expect(error.result_code).to eq('folder_uid_not_found')
        end

        it 'returns AccessViolationError for access_violation' do
          error = KeeperSecretsManager::ErrorFactory.from_server_response('access_violation')

          expect(error).to be_a(KeeperSecretsManager::AccessViolationError)
          expect(error.result_code).to eq('access_violation')
        end

        it 'returns ThrottledError for throttled' do
          error = KeeperSecretsManager::ErrorFactory.from_server_response('throttled')

          expect(error).to be_a(KeeperSecretsManager::ThrottledError)
          expect(error.result_code).to eq('throttled')
        end
      end

      context 'with custom messages' do
        it 'uses custom message when provided' do
          error = KeeperSecretsManager::ErrorFactory.from_server_response(
            'invalid_token',
            'Your session has expired. Please log in again.'
          )

          expect(error).to be_a(KeeperSecretsManager::InvalidTokenError)
          expect(error.message).to eq('Your session has expired. Please log in again.')
        end

        it 'uses custom message for bad_request' do
          error = KeeperSecretsManager::ErrorFactory.from_server_response(
            'bad_request',
            'Missing required field: recordUid'
          )

          expect(error).to be_a(KeeperSecretsManager::BadRequestError)
          expect(error.message).to eq('Missing required field: recordUid')
        end
      end

      context 'with unknown error codes' do
        it 'returns generic ServerError for unknown code' do
          error = KeeperSecretsManager::ErrorFactory.from_server_response('unknown_error_code')

          expect(error).to be_a(KeeperSecretsManager::ServerError)
          expect(error).not_to be_a(KeeperSecretsManager::InvalidTokenError)
          expect(error).not_to be_a(KeeperSecretsManager::BadRequestError)
          expect(error.result_code).to eq('unknown_error_code')
          expect(error.message).to eq('Server error: unknown_error_code')
        end

        it 'returns ServerError with custom message for unknown code' do
          error = KeeperSecretsManager::ErrorFactory.from_server_response(
            'weird_error',
            'Something unexpected happened'
          )

          expect(error).to be_a(KeeperSecretsManager::ServerError)
          expect(error.result_code).to eq('weird_error')
          expect(error.message).to eq('Something unexpected happened')
        end
      end

      context 'error type checking' do
        it 'all errors are KeeperSecretsManager::Error' do
          error_codes = %w[
            invalid_client_version
            invalid_client
            invalid_token
            bad_request
            record_uid_not_found
            folder_uid_not_found
            access_violation
            throttled
            unknown_code
          ]

          error_codes.each do |code|
            error = KeeperSecretsManager::ErrorFactory.from_server_response(code)
            expect(error).to be_a(KeeperSecretsManager::Error)
          end
        end

        it 'all errors are ServerError or subclass' do
          error_codes = %w[
            invalid_client_version
            invalid_token
            bad_request
            record_uid_not_found
            folder_uid_not_found
            access_violation
            throttled
            unknown_code
          ]

          error_codes.each do |code|
            error = KeeperSecretsManager::ErrorFactory.from_server_response(code)
            expect(error).to be_a(KeeperSecretsManager::ServerError)
          end
        end
      end
    end
  end
end
