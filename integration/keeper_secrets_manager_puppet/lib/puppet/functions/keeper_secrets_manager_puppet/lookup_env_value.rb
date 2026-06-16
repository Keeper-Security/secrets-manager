Puppet::Functions.create_function(:'keeper_secrets_manager_puppet::lookup_env_value') do
  dispatch :lookup_env_value do
    param 'String', :env_var_name
  end

  def lookup_env_value(env_var_name)
    # Validate ENV: prefix
    return nil unless env_var_name.match?(%r{^ENV:})

    # Remove the ENV: prefix from the environment variable name
    env_var_name_without_env_prefix = env_var_name.gsub(%r{^ENV:}, '')

    return nil if env_var_name_without_env_prefix.strip.empty?

    # Use the processed variable name for environment lookup
    env_var_name_clean = env_var_name_without_env_prefix.strip

    # Method 1: Check current process environment (fastest)
    auth_value = ENV[env_var_name_clean]

    return auth_value.strip if auth_value && !auth_value.strip.empty?

    # Method 2: Check system-specific sources
    system = RbConfig::CONFIG['host_os'].downcase

    auth_value = if system.include?('mswin') || system.include?('mingw')
                   # Windows: Check registry and system environment
                   check_windows_environment(env_var_name_clean)
                 else
                   # Linux/macOS: Check multiple shell profiles
                   check_unix_environment(env_var_name_clean)
                 end

    # Method 3: Check Puppet-specific files
    auth_value ||= check_puppet_environment(env_var_name_clean)

    # Return nil instead of empty string for better logic handling
    (auth_value && !auth_value.strip.empty?) ? auth_value.strip : nil
  end

  private

  def check_windows_environment(env_var_name)
    begin
      # Check system environment via PowerShell
      cmd = "powershell -Command \"[Environment]::GetEnvironmentVariable('#{env_var_name}', 'Machine')\""
      result = `#{cmd}`.strip
      return result unless result.empty?

      # Check user environment
      cmd = "powershell -Command \"[Environment]::GetEnvironmentVariable('#{env_var_name}', 'User')\""
      result = `#{cmd}`.strip
      return result unless result.empty?
    rescue => e
      Puppet.debug("Failed to check Windows environment: #{e.message}")
    end
    nil
  end

  def check_unix_environment(env_var_name)
    # Check common shell profile files
    shell_profiles = [
      File.expand_path('~/.bashrc'),
      File.expand_path('~/.bash_profile'),
      File.expand_path('~/.profile'),
      File.expand_path('~/.zshrc'),
      File.expand_path('~/.zprofile'),
      '/etc/environment',
      '/etc/profile',
    ]

    # Add /etc/profile.d/ scripts (prioritize keeper_env_auth_value.sh)
    if Dir.exist?('/etc/profile.d/')
      keeper_env_file = '/etc/profile.d/keeper_env_auth_value.sh'
      shell_profiles.unshift(keeper_env_file) if File.exist?(keeper_env_file)

      # Add other .sh files
      Dir.glob('/etc/profile.d/*.sh').each do |script|
        shell_profiles << script unless script == keeper_env_file
      end
    end

    shell_profiles.each do |profile|
      next unless File.exist?(profile)

      begin
        File.readlines(profile).each do |line|
          line = line.strip
          if line.start_with?("export #{env_var_name}=", "#{env_var_name}=")
            value = line.split('=', 2)[1].gsub(%r{^"|"$}, '').strip
            return value unless value.empty?
          end
        end
      rescue => e
        Puppet.debug("Failed to read #{profile}: #{e.message}")
      end
    end
    nil
  end

  def check_puppet_environment(env_var_name)
    puppet_env_paths = [
      '/opt/keeper_secret_manager/keeper_env.sh',
      '/opt/keeper_secret_manager/keeper_env_auth_value.sh',
      '/etc/puppetlabs/puppet/environment.conf',
      '/etc/puppet/environment.conf',
    ]

    puppet_env_paths.each do |env_file|
      next unless File.exist?(env_file)

      begin
        File.readlines(env_file).each do |line|
          line = line.strip
          if line.start_with?("export #{env_var_name}=")
            value = line.split('=', 2)[1].gsub(%r{^"|"$}, '').strip
            return value unless value.empty?
          end
        end
      rescue => e
        Puppet.debug("Failed to read #{env_file}: #{e.message}")
      end
    end
    nil
  end
end
