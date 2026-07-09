require 'json'
require 'ostruct'
require_relative 'dto/payload'
require_relative 'utils'
require_relative 'crypto'

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

      # Return this record's linked-credential entries as typed KeeperRecordLink objects.
      #
      # Typed view over the raw `links` list (populated when secrets are fetched with
      # QueryOptions(..., request_links: true)). The raw `links` list is left unchanged
      # for backward compatibility; entries without a String recordUid are skipped.
      def get_links
        (links || []).each_with_object([]) do |link_dict, result|
          next unless link_dict.is_a?(Hash)

          record_uid = link_dict['recordUid']
          next unless record_uid.is_a?(String) && !record_uid.empty?

          result << KeeperRecordLink.new(link_dict)
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

    # Typed view over a single linked-credential entry of a record (`record.links`).
    #
    # A link entry carries `recordUid`, optional base64 `data`, and an optional `path`
    # discriminator. Observed payload shapes (verified against the live backend):
    #
    # - path "meta" (self-link, recordUid == owning record): plain base64 JSON with
    #   `allowedSettings` (rotation, connections, portForwards, sessionRecording,
    #   typescriptRecording, aiEnabled, aiSessionTerminate, remoteBrowserIsolation),
    #   plus `rotateOnTermination`, `version` and `no_update_services`.
    # - path nil (credential link to another record): plain base64 JSON with
    #   `is_admin`, `is_launch_credential`, `is_iam_user`, `belongs_to` and
    #   `rotation_settings`; or no data at all (pure record reference).
    # - path "ai_settings" / "jit_settings" (self-links): data is AES-256-GCM
    #   encrypted under the owning record's key - see #get_decrypted_data.
    #
    # Accessors never raise: parse, decode or decryption failures yield nil/false.
    # The original link hash is kept untouched in `raw`, and #get_link_data returns the
    # complete parsed payload, so fields unknown to this SDK version are preserved.
    #
    # Naming: Ruby predicates take a trailing `?` and drop the redundant `is_` prefix
    # (house style), so the Python reference's is_admin_user/is_launch_credential/
    # is_iam_user map to admin_user?/launch_credential?/iam_user? here.
    class KeeperRecordLink
      attr_reader :raw, :record_uid, :data, :path

      def initialize(link_dict = {})
        link_dict = {} unless link_dict.is_a?(Hash)
        @raw = link_dict.dup
        @record_uid = link_dict['recordUid']
        @data = link_dict['data']
        @path = link_dict['path']
      end

      def to_s
        "[KeeperRecordLink: record_uid=#{@record_uid}, path=#{@path}]"
      end

      # --- User / permission boolean accessors ---

      # Whether the linked user is an admin (`is_admin`).
      def admin_user?
        boolean_value('is_admin')
      end

      # Whether this is a launch credential link (`is_launch_credential`).
      def launch_credential?
        boolean_value('is_launch_credential')
      end

      # Whether the linked user is an IAM user (`is_iam_user`).
      def iam_user?
        boolean_value('is_iam_user')
      end

      # Whether the linked credential belongs to the record (`belongs_to`).
      def belongs_to?
        boolean_value('belongs_to')
      end

      # Whether service updates are disabled for this link (`no_update_services`).
      def no_update_services?
        boolean_value('no_update_services')
      end

      # Whether rotation is allowed (`rotation`, top-level or in `allowedSettings`).
      def allows_rotation?
        boolean_value('rotation', true)
      end

      # Whether connections are allowed (`connections`, top-level or in `allowedSettings`).
      def allows_connections?
        boolean_value('connections', true)
      end

      # Whether port forwards are allowed (`portForwards`, top-level or in `allowedSettings`).
      def allows_port_forwards?
        boolean_value('portForwards', true)
      end

      # Whether session recording is enabled (`sessionRecording`, top-level or in `allowedSettings`).
      def allows_session_recording?
        boolean_value('sessionRecording', true)
      end

      # Whether typescript recording is enabled (`typescriptRecording`, top-level or in `allowedSettings`).
      def allows_typescript_recording?
        boolean_value('typescriptRecording', true)
      end

      # Whether remote browser isolation is enabled (`remoteBrowserIsolation`, top-level or in `allowedSettings`).
      def allows_remote_browser_isolation?
        boolean_value('remoteBrowserIsolation', true)
      end

      # Whether AI features are enabled (`aiEnabled`, top-level or in `allowedSettings`).
      def ai_enabled?
        boolean_value('aiEnabled', true)
      end

      # Whether AI session termination is enabled (`aiSessionTerminate`, top-level or in `allowedSettings`).
      def ai_session_terminate?
        boolean_value('aiSessionTerminate', true)
      end

      # Whether rotation on termination is enabled (`rotateOnTermination`).
      def rotates_on_termination?
        boolean_value('rotateOnTermination')
      end

      # --- Data accessors ---

      # The link data schema version (`version`) when it is an integer, else nil.
      def get_link_data_version
        int_value('version')
      end

      # The `allowedSettings` object from the link data (empty hash when absent).
      def get_allowed_settings
        parsed = parse_json_data
        allowed = parsed ? parsed['allowedSettings'] : nil
        allowed.is_a?(Hash) ? allowed : {}
      end

      # The `rotation_settings` object from the link data, or nil when absent.
      def get_rotation_settings
        parsed = parse_json_data
        rotation = parsed ? parsed['rotation_settings'] : nil
        rotation.is_a?(Hash) ? rotation : nil
      end

      # Base64-decode `data` to a string (for debugging/advanced use), or nil.
      def get_decoded_data
        return nil if @data.nil?

        Utils.base64_to_bytes(@data).force_encoding('UTF-8').scrub
      rescue StandardError
        nil
      end

      # Whether the link has readable JSON data (vs. encrypted/binary data).
      def has_readable_data?
        decoded = get_decoded_data
        !decoded.nil? && (decoded.start_with?('{') || decoded.start_with?('['))
      end

      # Whether this link's path indicates potentially encrypted data (currently
      # ai_settings / jit_settings; other paths carry plain base64 JSON).
      def might_be_encrypted?
        %w[ai_settings jit_settings].include?(@path)
      end

      # Whether the data appears encrypted, by inspecting the actual content (non-JSON
      # and mostly non-printable) rather than path naming conventions.
      def has_encrypted_data?
        decoded = get_decoded_data
        return false if decoded.nil?
        return false if decoded.start_with?('{') || decoded.start_with?('[')

        !printable_text?(decoded)
      end

      # Decrypt the link data with the owning record's key (AES-256-GCM). record_key is
      # the record's decrypted key bytes (record.record_key). Returns the decrypted
      # string, or nil if data/key is missing or decryption fails.
      def get_decrypted_data(record_key = nil)
        return nil if @data.nil? || record_key.nil?

        encrypted = Utils.base64_to_bytes(@data)
        Crypto.decrypt_aes_gcm(encrypted, record_key).force_encoding('UTF-8').scrub
      rescue StandardError
        nil
      end

      # The complete link data payload, handling both plain and encrypted JSON. Plain
      # base64 JSON parses without a key; encrypted data requires the owning record's
      # key. Ciphertext can coincidentally start with "{" or "[", so a failed
      # plain-JSON parse falls through to decryption rather than giving up. The returned
      # hash preserves all fields sent by the server, including ones this SDK version
      # doesn't know about yet.
      def get_link_data(record_key = nil)
        decoded = get_decoded_data
        return nil if decoded.nil?

        if decoded.start_with?('{') || decoded.start_with?('[')
          parsed = parse_json_to_dict(decoded)
          return parsed unless parsed.nil?
          # Leading {/[ was coincidental ciphertext - fall through to decryption.
        end

        decrypted = get_decrypted_data(record_key)
        return nil if decrypted.nil?

        parse_json_to_dict(decrypted)
      end

      # --- Settings accessors (path-gated) ---

      # PAM settings data from this link - only when path == "meta" (plain JSON today;
      # the key is accepted for forward compatibility).
      def get_meta_data(record_key = nil)
        get_settings_for_path('meta', record_key)
      end

      # AI settings data from this link - only when path == "ai_settings" (encrypted
      # under the owning record's key). Returns nil for any other path.
      def get_ai_settings_data(record_key = nil)
        return nil unless @path == 'ai_settings'

        get_link_data(record_key)
      end

      # JIT settings data from this link - only when path == "jit_settings" (encrypted
      # under the owning record's key). Returns nil for any other path.
      def get_jit_settings_data(record_key = nil)
        return nil unless @path == 'jit_settings'

        get_link_data(record_key)
      end

      # Settings data for any path, current or future. Automatically detects whether the
      # data is plain or encrypted and handles it appropriately. Returns nil when the
      # path doesn't match or parsing fails.
      def get_settings_for_path(settings_path, record_key = nil)
        return nil unless @path == settings_path

        get_link_data(record_key)
      end

      private

      # Decode `data` and parse it as a JSON object, handling errors gracefully.
      def parse_json_data
        decoded = get_decoded_data
        return nil if decoded.nil? || !(decoded.start_with?('{') || decoded.start_with?('['))

        parsed = JSON.parse(decoded)
        parsed.is_a?(Hash) ? parsed : nil
      rescue JSON::ParserError
        nil
      end

      # Read a strict boolean from the link data; missing or non-bool values are false.
      # With check_allowed_settings the nested `allowedSettings` object is consulted when
      # the key is absent at the top level (a top-level boolean wins).
      def boolean_value(key, check_allowed_settings = false)
        parsed = parse_json_data
        return false if parsed.nil?

        value = parsed[key]
        return value if strict_boolean?(value)

        if check_allowed_settings
          allowed = parsed['allowedSettings']
          if allowed.is_a?(Hash)
            nested = allowed[key]
            return nested if strict_boolean?(nested)
          end
        end
        false
      end

      # Read a strict integer from the link data; strings and booleans yield nil.
      def int_value(key)
        parsed = parse_json_data
        value = parsed ? parsed[key] : nil
        return value if value.is_a?(Integer) && !strict_boolean?(value)

        nil
      end

      def strict_boolean?(value)
        value == true || value == false
      end

      # Parse a JSON string, returning a hash only for JSON objects.
      def parse_json_to_dict(json_str)
        parsed = JSON.parse(json_str)
        parsed.is_a?(Hash) ? parsed : nil
      rescue JSON::ParserError
        nil
      end

      # Whether a string is mostly printable text (>90% of the first 100 chars), used to
      # distinguish encrypted bytes from plain text.
      def printable_text?(text)
        return false if text.nil? || text.empty?

        sample = text[0, 100]
        printable = sample.each_char.count { |c| (c >= ' ' && c <= '~') || ["\n", "\r", "\t"].include?(c) }
        (printable.to_f / sample.length) > 0.9
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
