require 'json'
require 'ostruct'
require_relative 'dto/payload'

module KeeperSecretsManager
  module Dto
    # Base class for dynamic record handling
    class KeeperRecord
      attr_accessor :uid, :title, :type, :fields, :custom, :notes, :folder_uid, :inner_folder_uid, :data, :revision, :files, :links, :is_editable
      attr_reader :record_key  # Internal - stores decrypted record key (bytes) for file upload operations

      def initialize(attrs = {})
        if attrs.is_a?(Hash)
          # Support both raw API response and user-friendly creation
          @uid = attrs['recordUid'] || attrs['uid'] || attrs[:uid]
          @folder_uid = attrs['folderUid'] || attrs['folder_uid'] || attrs[:folder_uid]
          @inner_folder_uid = attrs['innerFolderUid'] || attrs['inner_folder_uid'] || attrs[:inner_folder_uid]
          @revision = attrs['revision'] || attrs[:revision] || 0

          # Handle encrypted data or direct attributes
          if attrs['data']
            data = attrs['data'].is_a?(String) ? JSON.parse(attrs['data']) : attrs['data']
            @title = data['title'] || ''
            @type = data['type'] || 'login'
            @fields = data['fields'] || []
            @custom = data['custom'] || []
            @notes = data['notes'] || ''
          else
            @title = attrs['title'] || attrs[:title] || ''
            @type = attrs['type'] || attrs[:type] || 'login'
            @fields = attrs['fields'] || attrs[:fields] || []
            @custom = attrs['custom'] || attrs[:custom] || []
            @notes = attrs['notes'] || attrs[:notes] || ''
          end

          @files = attrs['files'] || attrs[:files] || []
          @links = attrs['links'] || attrs[:links] || []

          # Handle is_editable (can be false, so use has_key? check)
          if attrs.key?('isEditable')
            @is_editable = attrs['isEditable']
          elsif attrs.key?('is_editable')
            @is_editable = attrs['is_editable']
          elsif attrs.key?(:is_editable)
            @is_editable = attrs[:is_editable]
          else
            @is_editable = true  # Default to true if not specified
          end

          @data = attrs
        end

        # Ensure fields are always arrays of hashes
        normalize_fields!
      end

      # Convert to hash for API submission
      # This should match the structure of the decrypted 'data' field from server
      # (does NOT include uid, revision, folder_uid - those are in the outer payload)
      def to_h
        result = {
          'title' => title,
          'type' => type,
          'fields' => fields
        }

        # Only include custom if it has entries (server doesn't send empty arrays)
        result['custom'] = custom if custom && !custom.empty?

        # Only include notes if present
        result['notes'] = notes if notes && !notes.empty?

        result
      end

      # Find field by type or label (searches both fields and custom arrays)
      def get_field(type_or_label)
        # Search in fields first
        field = fields.find { |f| f['type'] == type_or_label || f['label'] == type_or_label }
        return field if field

        # Search in custom fields
        custom.find { |f| f['type'] == type_or_label || f['label'] == type_or_label }
      end

      # Get field value (always returns array)
      def get_field_value(type_or_label)
        field = get_field(type_or_label)
        field ? field['value'] || [] : []
      end

      # Get single field value (first element)
      def get_field_value_single(type_or_label)
        values = get_field_value(type_or_label)
        values.first
      end

      # Add or update field
      def set_field(type, value, label = nil)
        # Ensure value is an array
        value = [value] unless value.is_a?(Array)

        # Find existing field in both arrays
        existing = @fields.find { |f| f['type'] == type || (label && f['label'] == label) }
        existing ||= @custom.find { |f| f['type'] == type || (label && f['label'] == label) }

        if existing
          existing['value'] = value
          existing['label'] = label if label
        else
          new_field = { 'type' => type, 'value' => value }
          new_field['label'] = label if label

          # Decide which array to add to:
          # - If it has a label, it's a custom field
          # - If it's not a common field type, it's likely custom
          if label || !common_field_types.include?(type)
            @custom << new_field
          else
            @fields << new_field
          end
        end
      end

      # Dynamic field access methods
      def method_missing(method, *args, &block)
        method_name = method.to_s

        # Handle setters
        if method_name.end_with?('=')
          field_name = method_name.chomp('=')
          set_field(field_name, args.first)
        # Handle getters
        elsif common_field_types.include?(method_name)
          get_field_value_single(method_name)
        else
          super
        end
      end

      def respond_to_missing?(method, include_private = false)
        method_name = method.to_s.chomp('=')
        common_field_types.include?(method_name) || super
      end

      private

      def normalize_fields!
        @fields = normalize_field_array(@fields)
        @custom = normalize_field_array(@custom)
      end

      def normalize_field_array(fields)
        return [] unless fields.is_a?(Array)

        fields.map do |field|
          next field if field.is_a?(Hash)

          # Convert to hash if needed
          field.to_h
        end
      end

      def common_field_types
        %w[login password url fileRef oneTimeCode name phone email address
           paymentCard bankAccount birthDate secureNote sshKey host
           databaseType script passkey]
      end
    end

    # Folder representation
    class KeeperFolder
      attr_accessor :uid, :name, :parent_uid, :folder_type, :folder_key, :records

      def initialize(attrs = {})
        @uid = attrs['folderUid'] || attrs['uid'] || attrs[:uid]
        @name = attrs['name'] || attrs[:name]
        @parent_uid = attrs['parentUid'] || attrs['parent_uid'] || attrs[:parent_uid] || attrs['parent']
        @folder_type = attrs['folderType'] || attrs['folder_type'] || attrs[:folder_type] || 'user_folder'
        @folder_key = attrs['folderKey'] || attrs['folder_key'] || attrs[:folder_key]
        @records = attrs['records'] || attrs[:records] || []
      end

      def to_h
        {
          'folderUid' => uid,
          'name' => name,
          'parentUid' => parent_uid,
          'folderType' => folder_type
        }.compact
      end
    end

    # File attachment representation
    class KeeperFile
      attr_accessor :uid, :name, :title, :mime_type, :size, :data, :url, :thumbnail_url, :last_modified

      def initialize(attrs = {})
        @uid = attrs['fileUid'] || attrs['uid'] || attrs[:uid]
        @name = attrs['name'] || attrs[:name]
        @title = attrs['title'] || attrs[:title] || @name
        @mime_type = attrs['mimeType'] || attrs['mime_type'] || attrs[:mime_type]
        @size = attrs['size'] || attrs[:size]
        @data = attrs['data'] || attrs[:data]
        @url = attrs['url'] || attrs[:url]
        @thumbnail_url = attrs['thumbnailUrl'] || attrs['thumbnail_url'] || attrs[:thumbnail_url]
        @last_modified = attrs['lastModified'] || attrs['last_modified'] || attrs[:last_modified]
      end

      def to_h
        {
          'fileUid' => uid,
          'name' => name,
          'title' => title,
          'mimeType' => mime_type,
          'size' => size
        }.compact
      end
    end

    # Response wrapper
    class SecretsManagerResponse
      attr_accessor :records, :folders, :app_data, :warnings, :errors, :just_bound, :expires_on

      def initialize(attrs = {})
        @records = attrs[:records] || []
        @folders = attrs[:folders] || []
        @app_data = attrs[:app_data] || {}
        @warnings = attrs[:warnings] || []
        @errors = attrs[:errors] || []
        @just_bound = attrs[:just_bound] || false
        @expires_on = attrs[:expires_on]
      end
    end

    # Query options
    class QueryOptions
      attr_accessor :records_filter, :folders_filter, :request_links

      def initialize(records: nil, folders: nil, request_links: nil)
        @records_filter = records
        @folders_filter = folders
        @request_links = request_links
      end
    end

    # Create options
    class CreateOptions
      attr_accessor :folder_uid, :subfolder_uid

      def initialize(folder_uid: nil, subfolder_uid: nil)
        @folder_uid = folder_uid
        @subfolder_uid = subfolder_uid
      end
    end

    # Update options
    class UpdateOptions
      attr_accessor :transaction_type, :links_to_remove

      def initialize(transaction_type: 'general', links_to_remove: nil)
        @transaction_type = transaction_type
        @links_to_remove = links_to_remove || []
      end
    end
  end
end
