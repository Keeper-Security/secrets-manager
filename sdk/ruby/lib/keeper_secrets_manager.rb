require 'keeper_secrets_manager/version'
require 'keeper_secrets_manager/errors'
require 'keeper_secrets_manager/config_keys'
require 'keeper_secrets_manager/keeper_globals'
require 'keeper_secrets_manager/utils'
require 'keeper_secrets_manager/crypto'
require 'keeper_secrets_manager/storage'
require 'keeper_secrets_manager/dto'
require 'keeper_secrets_manager/field_types'
require 'keeper_secrets_manager/notation'
require 'keeper_secrets_manager/cache'
require 'keeper_secrets_manager/core'
require 'keeper_secrets_manager/folder_manager'

# Optional TOTP support (only load if base32 gem is available)
begin
  require 'keeper_secrets_manager/totp'
rescue LoadError => e
  # TOTP support not available without base32 gem
  # This is optional functionality
end

module KeeperSecretsManager
  # Main entry point for the SDK
  def self.new(options = {})
    Core::SecretsManager.new(options)
  end

  # Convenience method to create from token
  def self.from_token(token, options = {})
    Core::SecretsManager.new(options.merge(token: token))
  end

  # Convenience method to create from base64 config string
  def self.from_config(config_base64, options = {})
    storage = Storage::InMemoryStorage.new(config_base64)
    Core::SecretsManager.new(options.merge(config: storage))
  end

  # Convenience method to create from config file
  def self.from_file(filename, options = {})
    storage = Storage::FileStorage.new(filename)
    Core::SecretsManager.new(options.merge(config: storage))
  end
end
