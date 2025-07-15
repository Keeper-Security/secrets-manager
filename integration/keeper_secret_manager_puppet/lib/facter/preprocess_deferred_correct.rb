begin
  require 'keeper_secret_manager_puppet/constants'
rescue LoadError => e
  Facter.debug("Could not load constants: #{e.message}")
end

Facter.add('preprocess_deferred_correct') do
  setcode do
    # Determine path based on OS
    puppet_conf_path = case Facter.value(:os)['family'].downcase
                       when 'windows'
                         KeeperSecretManagerPuppet::Constants::WINDOWS_PUPPET_CONF_PATH
                       else
                         KeeperSecretManagerPuppet::Constants::UNIX_PUPPET_CONF_PATH
                       end

    result = false

    if File.exist?(puppet_conf_path)
      File.readlines(puppet_conf_path).each do |line|
        line = line.strip

        # Check for preprocess_deferred = false anywhere in the file
        # Allow for whitespace variations and comments
        if line.match?(%r{^preprocess_deferred\s*=\s*false\s*$})
          result = true
          break
        end
      end
    end

    result
  end
end
