require 'net/http'
require 'uri'
require 'json'
require 'logger'
require 'openssl'

module KeeperSecretsManager
  module Core
    class SecretsManager
      attr_reader :config, :hostname, :verify_ssl_certs

      NOTATION_PREFIX = 'keeper'.freeze
      DEFAULT_KEY_ID = '7'.freeze

      # Field types that can be inflated
      INFLATE_REF_TYPES = {
        'addressRef' => ['address'],
        'cardRef' => %w[paymentCard text pinCode addressRef]
      }.freeze

      def initialize(options = {})
        # Check Ruby version
        raise Error, 'KSM SDK requires Ruby 2.6 or greater' if RUBY_VERSION < '2.6'

        # Check AES-GCM support
        begin
          OpenSSL::Cipher.new('AES-256-GCM')
        rescue RuntimeError => e
          if e.message.include?('unsupported cipher')
            raise Error,
                  "KSM SDK requires AES-GCM support. Your Ruby/OpenSSL version (#{OpenSSL::OPENSSL_LIBRARY_VERSION}) does not support AES-256-GCM. Please upgrade to Ruby 2.7+ or use a Ruby compiled with OpenSSL 1.1.0+"
          end

          raise e
        end

        @token = nil
        @hostname = nil
        @verify_ssl_certs = options.fetch(:verify_ssl_certs, true)
        @custom_post_function = options[:custom_post_function]

        # Set up logging
        @logger = options[:logger] || Logger.new(STDOUT)
        @logger.level = options[:log_level] || Logger::WARN

        # Handle configuration
        config = options[:config]
        token = options[:token]

        # Check environment variable if no config provided
        config = Storage::InMemoryStorage.new(ENV['KSM_CONFIG']) if config.nil? && ENV['KSM_CONFIG']

        # If we have config, check if it's already initialized
        if config
          @config = config
          # Check if already bound (has client ID and app key)
          if @config.get_string(ConfigKeys::KEY_CLIENT_ID) && @config.get_bytes(ConfigKeys::KEY_APP_KEY)
            @logger.debug('Using existing credentials from config')
          elsif token
            # Config exists but not bound, use token to bind
            @logger.debug('Config provided but not bound, using token to initialize')
            process_token_binding(token, options[:hostname])
          else
            @logger.warn('Config provided but no credentials found and no token provided')
          end
        elsif token
          # No config provided, create new one with token
          @logger.debug('No config provided, creating new one with token')
          process_token_binding(token, options[:hostname])
          @config ||= Storage::InMemoryStorage.new
        else
          # No config and no token
          raise Error, 'Either token or initialized config must be provided'
        end

        # Override hostname if provided
        if options[:hostname]
          @hostname = options[:hostname]
          @config.save_string(ConfigKeys::KEY_HOSTNAME, @hostname)
        else
          @hostname = @config.get_string(ConfigKeys::KEY_HOSTNAME) || KeeperGlobals::DEFAULT_SERVER
        end

        # Cache configuration
        @cache = {}
        @cache_expiry = {}
      end

      # Get secrets with optional filtering
      def get_secrets(uids = nil, full_response: false)
        uids = [uids] if uids.is_a?(String)

        query_options = Dto::QueryOptions.new(records: uids, folders: nil)
        get_secrets_with_options(query_options, full_response: full_response)
      end

      # Get secrets with query options
      def get_secrets_with_options(query_options = nil, full_response: false)
        records_resp = fetch_and_decrypt_secrets(query_options)

        # If just bound, fetch again
        records_resp = fetch_and_decrypt_secrets(query_options) if records_resp.just_bound

        # Log warnings
        records_resp.warnings&.each { |warning| @logger.warn(warning) }

        # Log bad records/folders
        if records_resp.errors&.any?
          records_resp.errors.each do |error|
            @logger.error("Error: #{error}")
          end
        end

        full_response ? records_resp : (records_resp.records || [])
      end

      # Get all folders
      def get_folders
        fetch_and_decrypt_folders
      end

      # Fetch and decrypt folders from dedicated endpoint
      def fetch_and_decrypt_folders
        # Prepare payload for get_folders endpoint (no filters)
        payload = prepare_get_payload(nil)

        # Make request to get_folders endpoint
        response_json = post_query('get_folders', payload)
        response_dict = JSON.parse(response_json)

        # Get app key for decryption
        app_key_str = @config.get_string(ConfigKeys::KEY_APP_KEY)

        # If we have app key directly (one-time token binding), use it
        if app_key_str && !app_key_str.empty?
          app_key = Utils.base64_to_bytes(app_key_str)
        else
          # Otherwise decrypt it using client key
          app_key_encrypted = Utils.base64_to_bytes(@config.get_string(ConfigKeys::KEY_ENCRYPTED_APP_KEY))
          client_key = Utils.base64_to_bytes(@config.get_string(ConfigKeys::KEY_CLIENT_KEY))
          app_key = Crypto.decrypt_aes_gcm(app_key_encrypted, client_key)
        end

        # Decrypt folders - need to handle them in order for shared folder keys
        folders = []
        response_folders = response_dict['folders'] || []

        response_folders.each do |encrypted_folder|
          folder_uid = encrypted_folder['folderUid']
          folder_parent = encrypted_folder['parent']

          # Decrypt folder key based on whether it has a parent
          if !folder_parent || folder_parent.empty?
            # Root folder - decrypt with app key
            folder_key_encrypted = Utils.base64_to_bytes(encrypted_folder['folderKey'])
            folder_key = Crypto.decrypt_aes_gcm(folder_key_encrypted, app_key)
          else
            # Child folder - decrypt with parent's shared folder key
            shared_folder_key = get_shared_folder_key(folders, response_folders, folder_parent)
            unless shared_folder_key
              @logger.error("Cannot find shared folder key for parent #{folder_parent}")
              next
            end
            folder_key_encrypted = Utils.base64_to_bytes(encrypted_folder['folderKey'])
            folder_key = Crypto.decrypt_aes_cbc(folder_key_encrypted, shared_folder_key)
          end

          # Decrypt folder data if present
          folder_name = ''
          if encrypted_folder['data'] && !encrypted_folder['data'].empty?
            data_encrypted = Utils.base64_to_bytes(encrypted_folder['data'])
            data_json = Crypto.decrypt_aes_cbc(data_encrypted, folder_key)
            data = JSON.parse(data_json)
            folder_name = data['name'] || ''
          end

          # Create folder object
          folder = Dto::KeeperFolder.new(
            'folderUid' => folder_uid,
            'name' => folder_name,
            'folderKey' => folder_key,
            'parent' => folder_parent,
            'records' => []
          )

          folders << folder
        rescue StandardError => e
          @logger.error("Failed to decrypt folder #{encrypted_folder['folderUid']}: #{e.message}")
        end

        folders
      end

      # Get secrets by title
      def get_secrets_by_title(title)
        records = get_secrets
        records.select { |r| r.title == title }
      end

      # Get first secret by title
      def get_secret_by_title(title)
        get_secrets_by_title(title).first
      end

      # Create a new secret
      def create_secret(record_data, options = nil)
        options ||= Dto::CreateOptions.new

        # Validate folder UID is provided
        raise ArgumentError, 'folder_uid is required to create a record' unless options.folder_uid

        # Get folders from dedicated endpoint to find folder key
        folders = get_folders

        # Find the folder
        folder = folders.find { |f| f.uid == options.folder_uid }
        raise Error, "Folder #{options.folder_uid} not found or not accessible" unless folder

        # Get folder key
        folder_key = folder.folder_key
        raise Error, "Unable to create record - folder key for #{options.folder_uid} is missing" unless folder_key

        # Generate UIDs and keys
        record_uid = Utils.generate_uid
        record_key = Crypto.generate_encryption_key_bytes

        # Prepare record data
        record = if record_data.is_a?(Dto::KeeperRecord)
                   record_data.to_h
                 else
                   record_data
                 end

        # Encrypt record data
        encrypted_data = Crypto.encrypt_aes_gcm(
          Utils.dict_to_json(record),
          record_key
        )

        # Prepare payload
        payload = prepare_create_payload(
          record_uid: record_uid,
          record_key: record_key,
          folder_uid: options.folder_uid,
          folder_key: folder_key,
          data: encrypted_data
        )

        # Send request
        response = post_query('create_secret', payload)

        # Return created record UID
        record_uid
      end

      # Update existing secret
      def update_secret(record, transaction_type: 'general')
        # Handle both record object and hash
        if record.is_a?(Dto::KeeperRecord)
          record_uid = record.uid
          record_data = record.to_h
        else
          record_uid = record['uid'] || record[:uid]
          record_data = record
        end

        raise ArgumentError, 'Record UID is required' unless record_uid

        # Get existing record to get the key
        existing = get_secrets([record_uid]).first
        raise RecordNotFoundError, "Record #{record_uid} not found" unless existing

        # Prepare payload
        payload = prepare_update_payload(
          record_uid: record_uid,
          data: record_data,
          revision: existing.revision,
          transaction_type: transaction_type
        )

        # Send request
        post_query('update_secret', payload)

        # If rotation, complete transaction
        if transaction_type == 'rotation'
          complete_payload = Dto::CompleteTransactionPayload.new
          complete_payload.client_version = KeeperGlobals.client_version
          complete_payload.client_id = @config.get_string(ConfigKeys::KEY_CLIENT_ID)
          complete_payload.record_uid = record_uid

          post_query('complete_transaction', complete_payload)
        end

        true
      end

      # Delete secrets
      def delete_secret(record_uids)
        record_uids = [record_uids] if record_uids.is_a?(String)

        payload = prepare_delete_payload(record_uids)
        response = post_query('delete_secret', payload)

        result = JSON.parse(response)
        result['records']
      end

      # Get notation value
      def get_notation(notation_uri)
        parser = Notation::Parser.new(self)
        parser.parse(notation_uri)
      end

      # Create folder
      def create_folder(folder_name, parent_uid: nil)
        folder_uid = Utils.generate_uid
        folder_key = Crypto.generate_encryption_key_bytes

        folder_data = {
          'name' => folder_name,
          'folderType' => 'user_folder'
        }

        encrypted_data = Crypto.encrypt_aes_gcm(
          Utils.dict_to_json(folder_data),
          folder_key
        )

        payload = prepare_create_folder_payload(
          folder_uid: folder_uid,
          folder_key: folder_key,
          data: encrypted_data,
          parent_uid: parent_uid
        )

        post_query('create_folder', payload)
        folder_uid
      end

      # Update folder
      def update_folder(folder_uid, folder_name)
        folder_data = {
          'name' => folder_name
        }

        payload = prepare_update_folder_payload(
          folder_uid: folder_uid,
          data: folder_data
        )

        post_query('update_folder', payload)
        true
      end

      # Delete folders
      def delete_folder(folder_uids, force: false)
        folder_uids = [folder_uids] if folder_uids.is_a?(String)

        payload = prepare_delete_folder_payload(folder_uids, force)
        response = post_query('delete_folder', payload)

        result = JSON.parse(response)
        result['folders']
      end

      # Get folder hierarchy manager
      def folder_manager
        folders = get_folders
        FolderManager.new(folders)
      end

      # Get folder path (convenience method)
      def get_folder_path(folder_uid)
        folder_manager.get_folder_path(folder_uid)
      end

      # Find folder by name (convenience method)
      def find_folder_by_name(name, parent_uid: nil)
        folder_manager.find_folder_by_name(name, parent_uid: parent_uid)
      end

      # Upload file
      def upload_file(owner_record_uid, file_data, file_name, file_title = nil)
        file_title ||= file_name

        # Generate file record
        file_uid = Utils.generate_uid
        file_key = Crypto.generate_encryption_key_bytes

        # Encrypt file data
        encrypted_file = Crypto.encrypt_aes_gcm(file_data, file_key)

        # Create file record
        file_record = {
          'fileUid' => file_uid,
          'name' => file_name,
          'title' => file_title,
          'size' => file_data.bytesize,
          'mimeType' => 'application/octet-stream'
        }

        # Prepare payload
        payload = prepare_file_upload_payload(
          file_record_uid: file_uid,
          file_record_key: file_key,
          file_record_data: file_record,
          owner_record_uid: owner_record_uid,
          file_size: encrypted_file.bytesize
        )

        # Get upload URL
        response = post_query('request_upload', payload)
        upload_result = JSON.parse(response)

        # Upload file
        upload_file_function(
          upload_result['url'],
          upload_result['parameters'],
          encrypted_file
        )

        file_uid
      end

      # Download file from record's file data
      def download_file(file_data)
        # Extract file metadata (already decrypted)
        file_uid = file_data['fileUid']
        file_url = file_data['url']
        file_name = file_data['name'] || file_data['title'] || 'unnamed'

        raise Error, "No download URL available for file #{file_uid}" unless file_url

        # The file key should already be decrypted (base64 encoded)
        file_key = Utils.base64_to_bytes(file_data['fileKey'])

        # Download the encrypted file content
        encrypted_content = download_encrypted_file(file_url)

        # Decrypt the file content with the file key
        decrypted_content = Crypto.decrypt_aes_gcm(encrypted_content, file_key)

        # Return file info and data
        {
          'name' => file_name,
          'title' => file_data['title'] || file_name,
          'type' => file_data['type'],
          'size' => file_data['size'] || decrypted_content.bytesize,
          'data' => decrypted_content
        }
      end

      # Get file metadata from server
      def get_file_data(file_uid)
        payload = prepare_get_payload(nil)
        payload.file_uids = [file_uid]

        response = post_query('get_files', payload)
        response_dict = JSON.parse(response)

        if response_dict['files'] && !response_dict['files'].empty?
          file_data = response_dict['files'].first

          # Decrypt file metadata
          # Get app key for decryption
          app_key_str = @config.get_string(ConfigKeys::KEY_APP_KEY)
          if app_key_str && !app_key_str.empty?
            app_key = Utils.base64_to_bytes(app_key_str)
          else
            # Decrypt app key with client key
            app_key_encrypted = Utils.base64_to_bytes(@config.get_string(ConfigKeys::KEY_ENCRYPTED_APP_KEY))
            client_key = get_client_key
            app_key = Crypto.decrypt_aes_gcm(app_key_encrypted, client_key)
          end

          encrypted_data = Utils.base64_to_bytes(file_data['data'])
          decrypted_json = Crypto.decrypt_aes_gcm(encrypted_data, app_key)

          JSON.parse(decrypted_json).merge('fileKey' => file_data['fileKey'])
        else
          raise Error, "File not found: #{file_uid}"
        end
      end

      # Download encrypted file from URL
      def download_encrypted_file(url)
        uri = URI(url)
        response = Net::HTTP.get_response(uri)

        if response.code == '200'
          response.body
        else
          raise Error, "Failed to download file: #{response.code} #{response.message}"
        end
      end

      private

      # Process token binding
      def process_token_binding(token, hostname = nil)
        # Parse token
        token = token.strip
        token_parts = token.split(':')

        # Modern format: REGION:BASE64_TOKEN
        if token_parts.length >= 2
          region = token_parts[0].upcase
          @hostname = KeeperGlobals::KEEPER_SERVERS[region] || KeeperGlobals::DEFAULT_SERVER
          @token = token_parts[1..].join(':')
        else
          # Legacy format
          @token = token
          @hostname = hostname || KeeperGlobals::DEFAULT_SERVER
        end

        # Bind the one-time token
        bound_config = bind_one_time_token(@token, @hostname)

        # Merge bound config into existing config if present
        if @config
          # Copy all values from bound config to existing config
          bound_data = bound_config.instance_variable_get(:@data)
          bound_data&.each do |key, value|
            if value.is_a?(String)
              @config.save_string(key, value)
            else
              @config.save_bytes(key, value)
            end
          end
        else
          @config = bound_config
        end
      end

      # Bind one-time token
      def bind_one_time_token(token, hostname)
        storage = Storage::InMemoryStorage.new

        # Generate EC key pair
        keys = Crypto.generate_ecc_keys

        # Convert token to bytes and create client ID hash
        token_bytes = Utils.url_safe_str_to_bytes(token)
        client_id_hash = OpenSSL::HMAC.digest(
          'SHA512',
          token_bytes,
          'KEEPER_SECRETS_MANAGER_CLIENT_ID'
        )
        client_id = Utils.bytes_to_base64(client_id_hash)

        # Store configuration
        storage.save_string(ConfigKeys::KEY_HOSTNAME, hostname)
        storage.save_string(ConfigKeys::KEY_SERVER_PUBLIC_KEY_ID, DEFAULT_KEY_ID)
        storage.save_string(ConfigKeys::KEY_CLIENT_KEY, token)
        storage.save_bytes(ConfigKeys::KEY_PRIVATE_KEY, keys[:private_key_bytes])
        storage.save_string(ConfigKeys::KEY_CLIENT_ID, client_id)

        # Prepare binding payload
        payload = Dto::GetPayload.new
        payload.client_version = KeeperGlobals.client_version
        payload.client_id = client_id
        payload.public_key = keys[:public_key_str]

        # Send binding request
        response = post_query('get_secret', payload, storage)
        response_dict = JSON.parse(response)

        # Process binding response
        if response_dict['encryptedAppKey']
          # Decrypt app key
          encrypted_app_key = Utils.url_safe_str_to_bytes(response_dict['encryptedAppKey'])
          client_key_bytes = Utils.url_safe_str_to_bytes(token)

          app_key = Crypto.decrypt_aes_gcm(encrypted_app_key, client_key_bytes)
          storage.save_bytes(ConfigKeys::KEY_APP_KEY, app_key)

          # Store app owner public key if present
          if response_dict['appOwnerPublicKey']
            owner_key = Utils.url_safe_str_to_bytes(response_dict['appOwnerPublicKey'])
            storage.save_bytes(ConfigKeys::KEY_OWNER_PUBLIC_KEY, owner_key)
          end

          # Clean up client key after successful binding
          storage.delete(ConfigKeys::KEY_CLIENT_KEY)
        else
          raise Error, 'Failed to bind one-time token - no encrypted app key in response'
        end

        storage
      end

      # Fetch and decrypt secrets
      def fetch_and_decrypt_secrets(query_options = nil)
        payload = prepare_get_payload(query_options)

        response = post_query('get_secret', payload)
        response_dict = JSON.parse(response)

        # Decrypt app key if present (during token binding)
        if response_dict['encryptedAppKey']
          encrypted_app_key = Utils.url_safe_str_to_bytes(response_dict['encryptedAppKey'])
          client_key = Utils.url_safe_str_to_bytes(@config.get_string(ConfigKeys::KEY_CLIENT_KEY))

          # Decrypt app key using AES with client key (the original token)
          app_key = Crypto.decrypt_aes_gcm(encrypted_app_key, client_key)
          @config.save_bytes(ConfigKeys::KEY_APP_KEY, app_key)

          # Clean up client key after successful binding
          @config.delete(ConfigKeys::KEY_CLIENT_KEY)

          # Store app owner public key if present
          if response_dict['appOwnerPublicKey']
            owner_key = Utils.url_safe_str_to_bytes(response_dict['appOwnerPublicKey'])
            @config.save_bytes(ConfigKeys::KEY_OWNER_PUBLIC_KEY, owner_key)
          end

          # Set just bound flag
          just_bound = true
        else
          just_bound = false
        end

        # Get app key
        app_key = @config.get_bytes(ConfigKeys::KEY_APP_KEY)
        raise Error, 'No app key available' unless app_key

        # Decrypt records
        records = []
        if response_dict['records']
          response_dict['records'].each do |encrypted_record|
            record = decrypt_record(encrypted_record, app_key)
            records << record
          rescue StandardError => e
            @logger.error("Failed to decrypt record: #{e.message}")
          end
        end

        # Decrypt folders - need to handle them in order for shared folder keys
        folders = []
        response_folders = response_dict['folders'] || []

        # First pass - decrypt folders in order
        response_folders.each do |encrypted_folder|
          folder = decrypt_folder(encrypted_folder, app_key, folders, response_folders)
          if folder
            folders << folder
            # Add folder's records to the main records list
            records.concat(folder.records) if folder.records && !folder.records.empty?
          end
        rescue StandardError => e
          @logger.error("Failed to decrypt folder: #{e.message}")
        end

        # Build response
        response = Dto::SecretsManagerResponse.new(
          records: records,
          folders: folders,
          warnings: response_dict['warnings']
        )

        response.just_bound = just_bound if response.respond_to?(:just_bound=)
        response
      end

      # Decrypt record
      def decrypt_record(encrypted_record, app_key)
        record_uid = encrypted_record['recordUid']
        record_key_encrypted = Utils.base64_to_bytes(encrypted_record['recordKey'])
        data_encrypted = Utils.base64_to_bytes(encrypted_record['data'])

        # Decrypt record key
        record_key = Crypto.decrypt_aes_gcm(record_key_encrypted, app_key)

        # Decrypt data
        data_json = Crypto.decrypt_aes_gcm(data_encrypted, record_key)
        data = JSON.parse(data_json)

        # Decrypt files if present
        decrypted_files = []
        if encrypted_record['files']
          encrypted_record['files'].each do |file|
            # Decrypt file key with record key
            file_key_encrypted = Utils.base64_to_bytes(file['fileKey'])
            file_key = Crypto.decrypt_aes_gcm(file_key_encrypted, record_key)

            # Decrypt file metadata with file key
            if file['data']
              file_data_encrypted = Utils.base64_to_bytes(file['data'])
              file_metadata_json = Crypto.decrypt_aes_gcm(file_data_encrypted, file_key)
              file_metadata = JSON.parse(file_metadata_json)
            else
              file_metadata = {}
            end

            # Create decrypted file object
            decrypted_file = {
              'fileUid' => file['fileUid'],
              'fileKey' => Utils.bytes_to_base64(file_key), # Store decrypted key
              'url' => file['url'],
              'thumbnailUrl' => file['thumbnailUrl'],
              'name' => file_metadata['name'],
              'title' => file_metadata['title'] || file_metadata['name'],
              'type' => file_metadata['type'],
              'size' => file_metadata['size'],
              'lastModified' => file_metadata['lastModified']
            }

            decrypted_files << decrypted_file
          rescue StandardError => e
            @logger&.error("Failed to decrypt file #{file['fileUid']}: #{e.message}")
          end
        end

        # Create record object
        record = Dto::KeeperRecord.new(
          'recordUid' => record_uid,
          'data' => data,
          'revision' => encrypted_record['revision'],
          'files' => decrypted_files
        )

        # Store record key for later use (e.g., file downloads)
        record.instance_variable_set(:@record_key, record_key)
        record.define_singleton_method(:record_key) { @record_key }

        record
      end

      # Get shared folder key by traversing up the folder hierarchy
      def get_shared_folder_key(folders, response_folders, parent_uid)
        while parent_uid
          # Find parent folder in response
          parent_folder = response_folders.find { |f| f['folderUid'] == parent_uid }
          return nil unless parent_folder

          # If parent has no parent, it's the shared folder root
          if !parent_folder['parent'] || parent_folder['parent'].empty?
            # Find the decrypted folder object
            shared_folder = folders.find { |f| f.uid == parent_uid }
            return shared_folder&.folder_key
          end

          # Continue up the hierarchy
          parent_uid = parent_folder['parent']
        end

        nil
      end

      # Decrypt folder
      def decrypt_folder(encrypted_folder, app_key, existing_folders = [], response_folders = [])
        folder_uid = encrypted_folder['folderUid']
        folder_parent = encrypted_folder['parent']

        @logger.debug("Decrypting folder #{folder_uid}, parent: #{folder_parent || 'none'}")

        # Determine the decryption key to use
        decryption_key = if !folder_parent || folder_parent.empty?
                           # Root folder - use app key
                           @logger.debug("Using app key for root folder #{folder_uid}")
                           app_key
                         else
                           # Child folder - use shared folder key
                           shared_folder_key = get_shared_folder_key(existing_folders, response_folders, folder_parent)
                           unless shared_folder_key
                             @logger.error("Cannot find shared folder key for parent #{folder_parent}")
                             return nil
                           end
                           @logger.debug("Using shared folder key from parent for folder #{folder_uid}")
                           shared_folder_key
                         end

        # Some folders might not have encryption data
        unless encrypted_folder['folderKey']
          # Create a basic folder object without decrypted data
          return Dto::KeeperFolder.new(
            'folderUid' => folder_uid,
            'folderKey' => nil,
            'data' => {},
            'name' => encrypted_folder['name'] || folder_uid,
            'parent' => folder_parent,
            'records' => []
          )
        end

        # Decrypt folder key
        folder_key_encrypted = Utils.base64_to_bytes(encrypted_folder['folderKey'])
        folder_key = if !folder_parent || folder_parent.empty?
                       # Root folder key uses AES-GCM
                       Crypto.decrypt_aes_gcm(folder_key_encrypted, decryption_key)
                     else
                       # Child folder key uses AES-CBC
                       Crypto.decrypt_aes_cbc(folder_key_encrypted, decryption_key)
                     end

        # Get folder name - either from encrypted data or direct field
        folder_name = ''
        folder_type = nil

        # Check if there's a direct name field (unencrypted)
        if encrypted_folder['name']
          folder_name = encrypted_folder['name']
          @logger.debug("Using direct name field for folder #{folder_uid}: #{folder_name}")
        elsif encrypted_folder['data'] && !encrypted_folder['data'].empty?
          # Decrypt folder data if present
          begin
            data_encrypted = Utils.base64_to_bytes(encrypted_folder['data'])
            # Folder data always uses CBC
            data_json = Crypto.decrypt_aes_cbc(data_encrypted, folder_key)
            data = JSON.parse(data_json)
            folder_name = data['name'] || ''
            folder_type = data['folderType']
            @logger.debug("Successfully decrypted folder #{folder_uid}: #{folder_name}")
          rescue StandardError => e
            @logger.error("Failed to decrypt folder data for #{folder_uid}: #{e.class} - #{e.message}")
            @logger.debug("Backtrace: #{e.backtrace.first(3).join("\n")}")
          end
        else
          @logger.debug("Folder #{folder_uid} has no name or data field - using UID as name")
          folder_name = folder_uid
        end

        # Decrypt records in this folder
        folder_records = []
        if encrypted_folder['records']
          encrypted_folder['records'].each do |encrypted_record|
            # Decrypt the record using folder key
            record = decrypt_record(encrypted_record, folder_key)

            # Set folder_uid on the record
            record.folder_uid = folder_uid if record
            folder_records << record if record
          rescue StandardError => e
            @logger.error("Failed to decrypt record in folder #{folder_uid}: #{e.message}")
          end
        end

        # Create folder object
        Dto::KeeperFolder.new(
          'folderUid' => folder_uid,
          'name' => folder_name,
          'folderType' => folder_type,
          'folderKey' => folder_key,
          'parent' => folder_parent,
          'records' => folder_records
        )
      end

      # Prepare get payload
      def prepare_get_payload(query_options = nil)
        payload = Dto::GetPayload.new
        payload.client_version = KeeperGlobals.client_version

        # Client ID should be URL-safe base64
        client_id_str = @config.get_string(ConfigKeys::KEY_CLIENT_ID)
        payload.client_id = client_id_str

        @logger.debug("Client ID for payload: #{client_id_str}")

        # Public key is sent during initial binding only

        if query_options
          payload.requested_records = query_options.records_filter
          payload.requested_folders = query_options.folders_filter
        end

        payload
      end

      # Prepare create payload
      def prepare_create_payload(record_uid:, record_key:, folder_uid:, folder_key:, data:)
        payload = Dto::CreatePayload.new
        payload.client_version = KeeperGlobals.client_version
        payload.client_id = @config.get_string(ConfigKeys::KEY_CLIENT_ID)
        payload.record_uid = record_uid
        payload.record_key = Utils.bytes_to_base64(record_key)
        payload.folder_uid = folder_uid
        payload.data = Utils.bytes_to_base64(data)

        # Encrypt the record key with the folder key
        if folder_key
          folder_key_encrypted = Crypto.encrypt_aes_gcm(record_key, folder_key)
          payload.folder_key = Utils.bytes_to_base64(folder_key_encrypted)
        end

        payload
      end

      # Other payload preparation methods...

      # Post query to API
      def post_query(path, payload, config = nil)
        config ||= @config
        server = get_server(@hostname)
        url = "https://#{server}/api/rest/sm/v1/#{path}"

        loop do
          # Generate transmission key
          key_id = config.get_string(ConfigKeys::KEY_SERVER_PUBLIC_KEY_ID) || DEFAULT_KEY_ID
          transmission_key = generate_transmission_key(key_id)

          # Encrypt and sign payload
          encrypted_payload = encrypt_and_sign_payload(config, transmission_key, payload)

          # Make request
          response = if @custom_post_function && path == 'get_secret'
                       @custom_post_function.call(url, transmission_key, encrypted_payload, @verify_ssl_certs)
                     else
                       post_function(url, transmission_key, encrypted_payload)
                     end

          # Handle response
          if response.success?
            # Decrypt response if present
            if response.data && !response.data.empty?
              return Crypto.decrypt_aes_gcm(response.data, transmission_key.key)
            else
              return response.data
            end
          else
            handle_http_error(response, config)
          end
        end
      end

      # Generate transmission key
      def generate_transmission_key(key_id)
        # Get server public key
        server_public_key_str = KeeperGlobals::KEEPER_PUBLIC_KEYS[key_id.to_s]
        raise Error, "Unknown public key ID: #{key_id}" unless server_public_key_str

        @logger.debug("Using server public key ID: #{key_id}")
        @logger.debug("Server public key string: #{server_public_key_str[0..20]}...")

        # Generate random key
        key = Crypto.generate_encryption_key_bytes
        @logger.debug("Generated transmission key: #{Utils.bytes_to_base64(key)[0..20]}...")

        # Encrypt key with server public key
        server_public_key = Crypto.url_safe_str_to_bytes(server_public_key_str)
        @logger.debug("Server public key bytes length: #{server_public_key.bytesize}")

        encrypted_key = Crypto.encrypt_ec(key, server_public_key)
        @logger.debug("Encrypted key length: #{encrypted_key.bytesize}")

        Dto::TransmissionKey.new(
          public_key_id: key_id,
          key: key,
          encrypted_key: encrypted_key
        )
      end

      # Encrypt and sign payload
      def encrypt_and_sign_payload(config, transmission_key, payload)
        # Convert payload to JSON
        payload_json = payload.to_json

        @logger.debug("Payload: #{payload_json}")

        # Encrypt payload
        encrypted_payload = Crypto.encrypt_aes_gcm(payload_json, transmission_key.key)

        # Generate signature
        signature_base = transmission_key.encrypted_key + encrypted_payload

        # After binding, use ECDSA signature with private key (not HMAC)
        private_key_bytes = config.get_bytes(ConfigKeys::KEY_PRIVATE_KEY)
        if private_key_bytes
          # Load private key
          private_key = load_ec_private_key(private_key_bytes)

          # Generate ECDSA signature
          signature = Crypto.sign_ec(signature_base, private_key)
          @logger.debug("Using ECDSA signature, length: #{signature.bytesize}")
        else
          # Fallback to HMAC with client key (for one-time token binding)
          client_key = config.get_string(ConfigKeys::KEY_CLIENT_KEY)
          if client_key
            signature_key = Utils.base64_to_bytes(client_key)
            signature = Crypto.generate_hmac(signature_key, signature_base)
            @logger.debug("Using HMAC signature, length: #{signature.bytesize}")
          else
            raise Error, 'No key available for signature'
          end
        end

        Dto::EncryptedPayload.new(
          encrypted_payload: encrypted_payload,
          signature: signature
        )
      end

      # HTTP post function
      def post_function(url, transmission_key, encrypted_payload)
        uri = URI(url)

        @logger.debug("POST URL: #{url}")
        @logger.debug("PublicKeyId header: #{transmission_key.public_key_id}")
        @logger.debug("TransmissionKey header: #{Utils.bytes_to_base64(transmission_key.encrypted_key)[0..50]}...")
        @logger.debug("TransmissionKey full base64 length: #{Utils.bytes_to_base64(transmission_key.encrypted_key).length}")
        @logger.debug("Signature header: #{Utils.bytes_to_base64(encrypted_payload.signature)[0..50]}...")
        @logger.debug("Request body length: #{encrypted_payload.encrypted_payload.bytesize} bytes")

        request = Net::HTTP::Post.new(uri)
        request['Content-Type'] = 'application/octet-stream'
        request['PublicKeyId'] = transmission_key.public_key_id.to_s
        request['TransmissionKey'] = Utils.bytes_to_base64(transmission_key.encrypted_key)
        request['Authorization'] = "Signature #{Utils.bytes_to_base64(encrypted_payload.signature)}"
        request['Content-Length'] = encrypted_payload.encrypted_payload.bytesize.to_s
        request.body = encrypted_payload.encrypted_payload

        http = Net::HTTP.new(uri.host, uri.port)
        http.use_ssl = true
        http.verify_mode = @verify_ssl_certs ? OpenSSL::SSL::VERIFY_PEER : OpenSSL::SSL::VERIFY_NONE

        response = http.request(request)

        @logger.debug("Response status: #{response.code}")

        Dto::KSMHttpResponse.new(
          status_code: response.code.to_i,
          data: response.body,
          http_response: response
        )
      rescue StandardError => e
        raise NetworkError, "HTTP request failed: #{e.message}"
      end

      # Handle HTTP errors
      def handle_http_error(response, config = nil)
        error_data = JSON.parse(response.data)
        result_code = error_data['result_code'] || error_data['error']
        message = error_data['message']

        @logger.debug("Server error response: #{error_data.inspect}")

        # Handle specific errors
        case result_code
        when 'key'
          # Server wants different key
          key_id = error_data['key_id']
          @logger.info("Server requested key ID: #{key_id}")
          # Use passed config or fall back to instance config
          config_to_use = config || @config
          config_to_use.save_string(ConfigKeys::KEY_SERVER_PUBLIC_KEY_ID, key_id.to_s) if config_to_use
          nil # Retry
        when 'throttled'
          sleep_time = error_data['retry_after'] || 60
          @logger.warn("Request throttled, waiting #{sleep_time} seconds")
          sleep(sleep_time)
          nil # Retry
        else
          raise ErrorFactory.from_server_response(result_code, message)
        end
      rescue JSON::ParserError
        raise NetworkError.new("Server error: HTTP #{response.status_code}",
                               status_code: response.status_code,
                               response_body: response.data)
      end

      # Get server hostname
      def get_server(hostname)
        return hostname if hostname.include?('.')

        # Look up in server list
        KeeperGlobals::KEEPER_SERVERS[hostname.upcase] || hostname
      end

      # Load EC private key from bytes
      def load_ec_private_key(private_key_bytes)
        # If it's already a key object, return it
        return private_key_bytes if private_key_bytes.is_a?(OpenSSL::PKey::EC)

        @logger.debug("Loading private key, bytes length: #{private_key_bytes.bytesize}")

        # Try to load as DER format first
        begin
          key = OpenSSL::PKey.read(private_key_bytes, nil)
          # Ensure it's an EC key
          if key.is_a?(OpenSSL::PKey::EC)
            @logger.debug('Successfully loaded EC private key from DER format')
            key
          else
            raise "Not an EC key, got #{key.class}"
          end
        rescue StandardError => e
          @logger.debug("DER format failed: #{e.message}, trying raw bytes")

          # If DER fails, it might be raw key bytes (32 bytes)
          if private_key_bytes.bytesize == 32
            begin
              # Create EC key from raw bytes (OpenSSL 3.0 compatible)
              group = OpenSSL::PKey::EC::Group.new('prime256v1')

              # Generate key components
              private_key_bn = OpenSSL::BN.new(private_key_bytes, 2)
              public_key_point = group.generator.mul(private_key_bn)

              # Create ASN1 sequence for the key
              asn1 = OpenSSL::ASN1::Sequence([
                                               OpenSSL::ASN1::Integer(1),
                                               OpenSSL::ASN1::OctetString(private_key_bytes),
                                               OpenSSL::ASN1::ObjectId('prime256v1', 0, :EXPLICIT),
                                               OpenSSL::ASN1::BitString(
                                                 public_key_point.to_octet_string(:uncompressed), 1, :EXPLICIT
                                               )
                                             ])

              # Create key from DER
              key = OpenSSL::PKey::EC.new(asn1.to_der)

              @logger.debug('Successfully created EC key from raw bytes')
              key
            rescue StandardError => raw_error
              @logger.debug("Raw bytes failed: #{raw_error.message}")
              raise CryptoError, "Failed to load private key: DER: #{e.message}, Raw: #{raw_error.message}"
            end
          else
            raise CryptoError,
                  "Failed to load private key: #{e.message} (got #{private_key_bytes.bytesize} bytes)"
          end
        end
      end

      # Other helper methods...
      def prepare_update_payload(record_uid:, data:, revision:, transaction_type:)
        payload = Dto::UpdatePayload.new
        payload.client_version = KeeperGlobals.client_version
        payload.client_id = @config.get_string(ConfigKeys::KEY_CLIENT_ID)
        payload.record_uid = record_uid
        payload.data = Utils.dict_to_json(data)
        payload.revision = revision
        payload.transaction_type = transaction_type
        payload
      end

      def prepare_delete_payload(record_uids)
        payload = Dto::DeletePayload.new
        payload.client_version = KeeperGlobals.client_version
        payload.client_id = @config.get_string(ConfigKeys::KEY_CLIENT_ID)
        payload.record_uids = record_uids
        payload
      end

      def prepare_create_folder_payload(folder_uid:, folder_key:, data:, parent_uid:)
        payload = Dto::CreateFolderPayload.new
        payload.client_version = KeeperGlobals.client_version
        payload.client_id = @config.get_string(ConfigKeys::KEY_CLIENT_ID)
        payload.folder_uid = folder_uid
        payload.data = Utils.bytes_to_base64(data)
        payload.parent_uid = parent_uid

        # Handle shared folder key
        payload.shared_folder_key = Utils.bytes_to_base64(folder_key)

        payload
      end

      def prepare_update_folder_payload(folder_uid:, data:)
        payload = Dto::UpdateFolderPayload.new
        payload.client_version = KeeperGlobals.client_version
        payload.client_id = @config.get_string(ConfigKeys::KEY_CLIENT_ID)
        payload.folder_uid = folder_uid
        payload.data = Utils.dict_to_json(data)
        payload
      end

      def prepare_delete_folder_payload(folder_uids, force)
        payload = Dto::DeleteFolderPayload.new
        payload.client_version = KeeperGlobals.client_version
        payload.client_id = @config.get_string(ConfigKeys::KEY_CLIENT_ID)
        payload.folder_uids = folder_uids
        payload.force_deletion = force
        payload
      end

      def prepare_file_upload_payload(file_record_uid:, file_record_key:, file_record_data:, owner_record_uid:, file_size:)
        payload = Dto::FileUploadPayload.new
        payload.client_version = KeeperGlobals.client_version
        payload.client_id = @config.get_string(ConfigKeys::KEY_CLIENT_ID)
        payload.file_record_uid = file_record_uid
        payload.file_record_key = Utils.bytes_to_base64(file_record_key)
        payload.file_record_data = Utils.dict_to_json(file_record_data)
        payload.owner_record_uid = owner_record_uid
        payload.file_size = file_size
        payload
      end

      def upload_file_function(url, parameters, encrypted_file_data)
        uri = URI(url)

        # Use multipart form data
        # This is a simplified version - might need proper multipart handling
        request = Net::HTTP::Post.new(uri)
        request.set_form([['file', encrypted_file_data]], 'multipart/form-data')

        # Add parameters
        parameters&.each do |key, value|
          request[key] = value
        end

        http = Net::HTTP.new(uri.host, uri.port)
        http.use_ssl = true

        response = http.request(request)

        raise NetworkError, "File upload failed: HTTP #{response.code}" unless response.code.to_i == 200

        true
      end
    end
  end
end
