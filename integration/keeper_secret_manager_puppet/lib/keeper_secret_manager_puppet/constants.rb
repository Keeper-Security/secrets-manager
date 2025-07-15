# frozen_string_literal: true

# rubocop:disable Style/ClassAndModuleChildren

module KeeperSecretManagerPuppet
  module Constants
    CONFIG_FILE_NAME         = 'input.json'
    PYTHON_SCRIPT_NAME       = 'ksm.py'
    KSM_CONFIG_FILE_NAME     = 'keeper_config.json'
    KEEPER_ENV_FILE_NAME     = 'keeper_env.sh'

    UNIX_CONFIG_PATH         = '/opt/keeper_secret_manager'
    WINDOWS_CONFIG_PATH      = 'C:/ProgramData/keeper_secret_manager'

    UNIX_PUPPET_CONF_PATH    = '/etc/puppetlabs/puppet/puppet.conf'
    WINDOWS_PUPPET_CONF_PATH = 'C:/ProgramData/PuppetLabs/puppet/etc/puppet.conf'

    HIERA_CONFIG_KEY         = 'keeper::config'
  end
end
# rubocop:enable Style/ClassAndModuleChildren
