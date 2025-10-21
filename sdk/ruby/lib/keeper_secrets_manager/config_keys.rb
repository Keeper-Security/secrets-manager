module KeeperSecretsManager
  module ConfigKeys
    # Configuration key constants (matching other SDKs)
    KEY_URL                     = 'url'.freeze
    KEY_CLIENT_ID               = 'clientId'.freeze
    KEY_CLIENT_KEY              = 'clientKey'.freeze
    KEY_HOSTNAME                = 'hostname'.freeze
    KEY_SERVER_PUBLIC_KEY_ID    = 'serverPublicKeyId'.freeze
    KEY_PRIVATE_KEY             = 'privateKey'.freeze
    KEY_APP_KEY                 = 'appKey'.freeze
    KEY_OWNER_PUBLIC_KEY        = 'appOwnerPublicKey'.freeze
    KEY_APP_UID                 = 'appUid'.freeze

    # All valid keys
    ALL_KEYS = [
      KEY_URL,
      KEY_CLIENT_ID,
      KEY_CLIENT_KEY,
      KEY_HOSTNAME,
      KEY_SERVER_PUBLIC_KEY_ID,
      KEY_PRIVATE_KEY,
      KEY_APP_KEY,
      KEY_OWNER_PUBLIC_KEY,
      KEY_APP_UID
    ].freeze
  end
end
