module KeeperSecretsManager
  # Base error class for all KSM errors
  class Error < StandardError; end

  # Configuration errors
  class ConfigurationError < Error; end

  # Authentication/authorization errors
  class AuthenticationError < Error; end

  class AccessDeniedError < AuthenticationError; end

  # API/network errors
  class NetworkError < Error
    attr_reader :status_code, :response_body

    def initialize(message, status_code: nil, response_body: nil)
      super(message)
      @status_code = status_code
      @response_body = response_body
    end
  end

  # Crypto errors
  class CryptoError < Error; end

  class DecryptionError < CryptoError; end

  class EncryptionError < CryptoError; end

  # Notation errors
  class NotationError < Error; end

  # Record errors
  class RecordError < Error; end

  class RecordNotFoundError < RecordError; end

  class RecordValidationError < RecordError; end

  # Server errors
  class ServerError < Error
    attr_reader :result_code, :message

    def initialize(result_code, message = nil)
      @result_code = result_code
      @message = message || "Server error: #{result_code}"
      super(@message)
    end
  end

  # Specific server error types
  class InvalidClientVersionError < ServerError; end

  class InvalidTokenError < ServerError; end

  class BadRequestError < ServerError; end

  class RecordUidNotFoundError < ServerError; end

  class FolderUidNotFoundError < ServerError; end

  class AccessViolationError < ServerError; end

  class ThrottledError < ServerError; end

  # Error factory
  class ErrorFactory
    def self.from_server_response(result_code, message = nil)
      case result_code
      when 'invalid_client_version'
        InvalidClientVersionError.new(result_code, message)
      when 'invalid_client', 'invalid_token'
        InvalidTokenError.new(result_code, message)
      when 'bad_request'
        BadRequestError.new(result_code, message)
      when 'record_uid_not_found'
        RecordUidNotFoundError.new(result_code, message)
      when 'folder_uid_not_found'
        FolderUidNotFoundError.new(result_code, message)
      when 'access_violation'
        AccessViolationError.new(result_code, message)
      when 'throttled'
        ThrottledError.new(result_code, message)
      else
        ServerError.new(result_code, message)
      end
    end
  end
end
