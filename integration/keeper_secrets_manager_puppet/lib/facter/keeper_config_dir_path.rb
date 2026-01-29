# Custom fact to return OS-specific Keeper configuration path
begin
  require 'keeper_secrets_manager_puppet/constants'
rescue LoadError => e
  Facter.debug("Could not load constants: #{e.message}")
end

Facter.add(:keeper_config_dir_path) do
  confine kernel: ['Linux', 'Darwin', 'windows']

  setcode do
    os_family = Facter.value(:os)['family'].downcase

    case os_family
    when 'windows'
      KeeperSecretsManagerPuppet::Constants::WINDOWS_CONFIG_PATH
    else
      KeeperSecretsManagerPuppet::Constants::UNIX_CONFIG_PATH
    end
  end
end
