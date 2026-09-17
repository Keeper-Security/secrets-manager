require 'net/http'

module KeeperSecretsManagerCookbook
  # Shared between the ksm_install and ksm_fetch custom resources, mixed in via
  # each resource's action_class. Kept separate from both so it can be unit
  # tested with plain RSpec instead of ChefSpec.
  module Helpers
    # Loads the Keeper config value, preferring the encrypted data bag
    # ('keeper'/'keeper_config') and falling back to the KEEPER_CONFIG
    # environment variable when the data bag or its secret file isn't
    # available on this node.
    def load_keeper_config
      keeper_config = data_bag_item('keeper', 'keeper_config')
      keeper_config['config_json'] || keeper_config['token']
    # Errno::ENOENT: the encrypted_data_bag_secret file itself is missing.
    # ArgumentError: Chef::EncryptedDataBagItem.load_secret raises this when
    # no secret path is configured at all, or the secret file is empty -
    # confirmed against Chef 19's actual source, since there is no
    # dedicated "secret not found" exception class in Chef's exception
    # hierarchy (an earlier version of this rescue referenced one that
    # doesn't exist and was never actually exercised by a test).
    rescue Net::HTTPClientException, Chef::Exceptions::InvalidDataBagPath, Errno::ENOENT, ArgumentError
      Chef::Log.warn('No Encrypted Data Bag found, falling back to KEEPER_CONFIG environment variable')
      ENV['KEEPER_CONFIG']
    end

    # Parses one entry from input.json's "secrets" array.
    #
    #   "UID/custom_field/Label1"                -> ["UID/custom_field/Label1", "Label1", nil]
    #   "UID/custom_field/Label1 > OUT"           -> ["UID/custom_field/Label1", "OUT", nil]
    #   "UID/custom_field/Token > env:TOKEN"      -> ["UID/custom_field/Token", "TOKEN", :env]
    #   "UID/file/cert.pem > file:/tmp/cert.pem"  -> ["UID/file/cert.pem", "/tmp/cert.pem", :file]
    #
    # Returns [keeper_notation, output_name, action_type] where action_type
    # is :env, :file, or nil (direct output).
    def parse_secret_notation(secret_string)
      return parse_bare_notation(secret_string) unless secret_string.include?('>')

      parts = secret_string.split('>')
      unless parts.length == 2
        raise ArgumentError, "Invalid secret structure: #{secret_string}. Expected format: keeper_notation > output_spec"
      end

      keeper_notation = parts.first.strip
      right_part = parts[1].strip

      if right_part.start_with?('env:')
        [keeper_notation, right_part.delete_prefix('env:'), :env]
      elsif right_part.start_with?('file:')
        [keeper_notation, right_part.delete_prefix('file:'), :file]
      else
        [keeper_notation, right_part, nil]
      end
    end

    private

    # No "> output_spec" given, so the default output name comes from the
    # notation's own last path segment (filename minus extension for
    # /file/ notations, since a bare cert.pem should show up as "cert").
    def parse_bare_notation(secret_string)
      keeper_notation = secret_string.strip
      parts = keeper_notation.split('/')
      raise ArgumentError, "Invalid keeper notation: #{secret_string}" if parts.length < 2

      field_name = keeper_notation.include?('/file/') ? ::File.basename(parts.last, '.*') : parts.last
      [keeper_notation, field_name, nil]
    end
  end
end
