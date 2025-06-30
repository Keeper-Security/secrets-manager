require 'json'
require 'ostruct'
require_relative 'dto/payload'

module KeeperSecretsManager
  module Dto
    # Base class for dynamic record handling
    class KeeperRecord
      attr_accessor :uid, :title, :type, :fields, :custom, :notes, :folder_uid, :data, :revision, :files

      def initialize(attrs = {})
        if attrs.is_a?(Hash)
          # Support both raw API response and user-friendly creation
          @uid = attrs['recordUid'] || attrs['uid'] || attrs[:uid]
          @folder_uid = attrs['folderUid'] || attrs['folder_uid'] || attrs[:folder_uid]
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
          @data = attrs
        end
        
        # Ensure fields are always arrays of hashes
        normalize_fields!
      end

      # Convert to hash for API submission
      def to_h
        {
          'uid' => uid,
          'title' => title,
          'type' => type,
          'fields' => fields,
          'custom' => custom,
          'notes' => notes,
          'folder_uid' => folder_uid
        }.compact
      end

      # Find field by type or label
      def get_field(type_or_label, custom_field = false)
        field_array = custom_field ? custom : fields
        field_array.find { |f| f['type'] == type_or_label || f['label'] == type_or_label }
      end

      # Get field value (always returns array)
      def get_field_value(type_or_label, custom_field = false)
        field = get_field(type_or_label, custom_field)
        field ? field['value'] || [] : []
      end

      # Get single field value (first element)
      def get_field_value_single(type_or_label, custom_field = false)
        values = get_field_value(type_or_label, custom_field)
        values.first
      end

      # Add or update field
      def set_field(type, value, label = nil, custom_field = false)
        field_array = custom_field ? @custom : @fields
        
        # Ensure value is an array
        value = [value] unless value.is_a?(Array)
        
        # Find existing field
        existing = field_array.find { |f| f['type'] == type || (label && f['label'] == label) }
        
        if existing
          existing['value'] = value
          existing['label'] = label if label
        else
          new_field = { 'type' => type, 'value' => value }
          new_field['label'] = label if label
          field_array << new_field
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
      attr_accessor :uid, :name, :title, :mime_type, :size, :data, :url

      def initialize(attrs = {})
        @uid = attrs['fileUid'] || attrs['uid'] || attrs[:uid]
        @name = attrs['name'] || attrs[:name]
        @title = attrs['title'] || attrs[:title] || @name
        @mime_type = attrs['mimeType'] || attrs['mime_type'] || attrs[:mime_type]
        @size = attrs['size'] || attrs[:size]
        @data = attrs['data'] || attrs[:data]
        @url = attrs['url'] || attrs[:url]
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
      attr_accessor :records, :folders, :app_data, :warnings, :errors, :just_bound

      def initialize(attrs = {})
        @records = attrs[:records] || []
        @folders = attrs[:folders] || []
        @app_data = attrs[:app_data] || {}
        @warnings = attrs[:warnings] || []
        @errors = attrs[:errors] || []
        @just_bound = attrs[:just_bound] || false
      end
    end

    # Query options
    class QueryOptions
      attr_accessor :records_filter, :folders_filter

      def initialize(records: nil, folders: nil)
        @records_filter = records
        @folders_filter = folders
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
  end
end