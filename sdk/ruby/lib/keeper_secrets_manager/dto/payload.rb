module KeeperSecretsManager
  module Dto
    # Transmission key for encrypted communication
    class TransmissionKey
      attr_accessor :public_key_id, :key, :encrypted_key

      def initialize(public_key_id:, key:, encrypted_key:)
        @public_key_id = public_key_id
        @key = key
        @encrypted_key = encrypted_key
      end
    end

    # Base payload class
    class BasePayload
      attr_accessor :client_version, :client_id

      def to_h
        hash = {}
        instance_variables.each do |var|
          key = var.to_s.delete('@')
          value = instance_variable_get(var)

          # Convert Ruby snake_case to camelCase for API
          api_key = Utils.snake_to_camel(key)
          hash[api_key] = value unless value.nil?
        end
        hash
      end

      def to_json(*args)
        to_h.to_json(*args)
      end
    end

    # Get secrets payload
    class GetPayload < BasePayload
      attr_accessor :public_key, :requested_records, :requested_folders, :file_uids, :request_links

      def initialize
        super()
        @requested_records = nil
        @requested_folders = nil
        @file_uids = nil
        @request_links = nil
      end
    end

    # Create record payload
    class CreatePayload < BasePayload
      attr_accessor :record_uid, :record_key, :folder_uid, :folder_key,
                    :data, :sub_folder_uid

      def initialize
        super()
      end
    end

    # Update record payload
    class UpdatePayload < BasePayload
      attr_accessor :record_uid, :data, :revision, :transaction_type, :links2_remove

      def initialize
        super()
        @transaction_type = 'general'
      end
    end

    # Delete records payload
    class DeletePayload < BasePayload
      attr_accessor :record_uids

      def initialize
        super()
        @record_uids = []
      end
    end

    # Complete transaction payload
    class CompleteTransactionPayload < BasePayload
      attr_accessor :record_uid

      def initialize
        super()
      end
    end

    # File upload payload
    class FileUploadPayload < BasePayload
      attr_accessor :file_record_uid, :file_record_key, :file_record_data,
                    :owner_record_uid, :owner_record_data, :owner_record_revision, :link_key, :file_size

      def initialize
        super()
      end
    end

    # Create folder payload
    class CreateFolderPayload < BasePayload
      attr_accessor :folder_uid, :shared_folder_uid, :shared_folder_key,
                    :data, :parent_uid

      def initialize
        super()
      end
    end

    # Update folder payload
    class UpdateFolderPayload < BasePayload
      attr_accessor :folder_uid, :data

      def initialize
        super()
      end
    end

    # Delete folder payload
    class DeleteFolderPayload < BasePayload
      attr_accessor :folder_uids, :force_deletion

      def initialize
        super()
        @folder_uids = []
        @force_deletion = false
      end
    end

    # Encrypted payload wrapper
    class EncryptedPayload
      attr_accessor :encrypted_payload, :signature

      def initialize(encrypted_payload:, signature:)
        @encrypted_payload = encrypted_payload
        @signature = signature
      end
    end

    # HTTP response wrapper
    class KSMHttpResponse
      attr_accessor :status_code, :data, :http_response

      def initialize(status_code:, data:, http_response: nil)
        @status_code = status_code
        @data = data
        @http_response = http_response
      end

      def success?
        status_code >= 200 && status_code < 300
      end
    end
  end
end
