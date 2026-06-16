begin
  require 'keeper_secrets_manager_puppet/constants'
rescue LoadError => e
  Facter.debug("Could not load constants: #{e.message}")
end

Facter.add('preprocess_deferred_correct') do
  setcode do
    # Determine paths based on OS
    puppet_conf_paths = case Facter.value(:os)['family'].downcase
                        when 'windows'
                          [
                            KeeperSecretsManagerPuppet::Constants::WINDOWS_PUPPET_CONF_PATH,
                            KeeperSecretsManagerPuppet::Constants::WINDOWS_USER_PUPPET_CONF_PATH,
                          ]
                        else
                          [
                            KeeperSecretsManagerPuppet::Constants::UNIX_PUPPET_CONF_PATH,
                            KeeperSecretsManagerPuppet::Constants::UNIX_USER_PUPPET_CONF_PATH,
                          ]
                        end

    result = false

    # Check each possible path
    puppet_conf_paths.each do |puppet_conf_path|
      # Expand user path if it contains ~ or %USERPROFILE%
      expanded_path = if puppet_conf_path.include?('~')
                        File.expand_path(puppet_conf_path)
                      elsif puppet_conf_path.include?('%USERPROFILE%')
                        puppet_conf_path.gsub('%USERPROFILE%', ENV['USERPROFILE'] || ENV['HOME'])
                      else
                        puppet_conf_path
                      end

      next unless File.exist?(expanded_path)

      File.readlines(expanded_path).each do |line|
        line = line.strip

        # Check for preprocess_deferred = false anywhere in the file
        # Allow for whitespace variations and comments
        if line.match?(%r{^preprocess_deferred\s*=\s*false\s*$})
          result = true
          break
        end
      end
      # If we found the setting, no need to check other paths
      break if result
    end

    result
  end
end
