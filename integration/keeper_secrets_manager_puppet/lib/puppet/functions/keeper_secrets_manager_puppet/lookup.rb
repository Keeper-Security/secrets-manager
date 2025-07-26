require 'puppet'
require 'keeper_secrets_manager_puppet/constants'

Puppet::Functions.create_function(:'keeper_secrets_manager_puppet::lookup') do
  # Dispatch for no parameters - uses default input.json
  dispatch :lookup_no_params do
  end

  # Dispatch for single secret lookup with secret
  dispatch :lookup_single_secret do
    param 'String', :secret
  end
  # Dispatch for complete configuration hash for multiple secrets lookup
  dispatch :lookup_multiple_secret do
    param 'Array[String]', :secrets_array
  end

  # No parameters implementation - uses default input.json
  def lookup_no_params
    execute_ksm_script(nil)
  end

  # Single secret lookup implementation
  def lookup_single_secret(secret)
    unless secret.is_a?(String)
      raise ArgumentError, 'Secret must be a string in keeper notation format'
    end

    config = {
      'authentication' => get_default_auth_config,
      'secrets' => [secret],
    }

    execute_ksm_script(config)
  end

  # Multiple secrets lookup implementation
  def lookup_multiple_secret(secrets_array)
    unless secrets_array.is_a?(Array)
      raise ArgumentError, 'Secrets must be an array'
    end

    if secrets_array.empty?
      raise ArgumentError, 'Secrets must be an array of at least one string in keeper notation format'
    end

    secrets_array.each_with_index do |secret, index|
      unless secret.is_a?(String)
        raise ArgumentError, "All secrets must be strings. Found #{secret.class} at index #{index}"
      end
    end

    config = {
      'authentication' => get_default_auth_config,
      'secrets' => secrets_array,
    }

    execute_ksm_script(config)
  end

  private

  def get_default_auth_config
    # Try to get keeper::config['authentication'] config from CONFIG_FILE_NAME from agent node
    paths = get_os_specific_paths
    config_file_path = paths['input_path']

    unless File.exist?(config_file_path)
      raise Puppet::Error, "Authentication not provided in hiera keeper::config['authentication']"
    end

    begin
      require 'json'
      config = JSON.parse(File.read(config_file_path))
      auth_config = config['authentication']

      unless auth_config.is_a?(Array) && auth_config.length >= 1
        raise Puppet::Error, "Authentication in hiera keeper::config['authentication'] must be an array of [method, value]"
      end

      auth_config
    rescue JSON::ParserError => e
      raise Puppet::Error, "Invalid JSON: #{e.message}"
    rescue => e
      raise Puppet::Error, "Failed to read authentication from hiera. Authentication in hiera keeper::config['authentication'] must be an array of [method, value]: #{e.message}"
    end
  end

  def get_os_specific_paths
    # Get OS-specific paths
    if Facter.value(:osfamily) == 'windows'
      {
        'script_path' => KeeperSecretsManagerPuppet::Constants::WINDOWS_CONFIG_PATH + '/' + KeeperSecretsManagerPuppet::Constants::PYTHON_SCRIPT_NAME,
        'config_path' => KeeperSecretsManagerPuppet::Constants::WINDOWS_CONFIG_PATH + '/' + KeeperSecretsManagerPuppet::Constants::KSM_CONFIG_FILE_NAME,
        'input_path' => KeeperSecretsManagerPuppet::Constants::WINDOWS_CONFIG_PATH + '/' + KeeperSecretsManagerPuppet::Constants::CONFIG_FILE_NAME,
        'keeper_env_path' => KeeperSecretsManagerPuppet::Constants::WINDOWS_CONFIG_PATH + '/' + KeeperSecretsManagerPuppet::Constants::KEEPER_ENV_FILE_NAME
      }
    else
      {
        'script_path' => KeeperSecretsManagerPuppet::Constants::UNIX_CONFIG_PATH + '/' + KeeperSecretsManagerPuppet::Constants::PYTHON_SCRIPT_NAME,
        'config_path' => KeeperSecretsManagerPuppet::Constants::UNIX_CONFIG_PATH + '/' + KeeperSecretsManagerPuppet::Constants::KSM_CONFIG_FILE_NAME,
        'input_path' => KeeperSecretsManagerPuppet::Constants::UNIX_CONFIG_PATH + '/' + KeeperSecretsManagerPuppet::Constants::CONFIG_FILE_NAME,
        'keeper_env_path' => KeeperSecretsManagerPuppet::Constants::UNIX_CONFIG_PATH + '/' + KeeperSecretsManagerPuppet::Constants::KEEPER_ENV_FILE_NAME
      }
    end
  end

  def validate_prerequisites(script_path, config_path, python_executable)
    # Check if script i.e. ksm.py file exists
    unless File.exist?(script_path)
      raise Puppet::Error, 'KSM script not found. Ensure configuration is correct.'
    end

    # Check if config i.e. input.json file exists
    unless File.exist?(config_path)
      raise Puppet::Error, 'Config file not found. Ensure configuration is correct.'
    end

    unless python_executable
      raise Puppet::Error, 'Python3 not found. Ensure configuration is correct.'
    end

    # Check if keeper-secrets-manager-core is installed
    begin
      require 'open3'
      _stdout, _stderr, status = Open3.capture3(python_executable, '-c', 'import keeper_secrets_manager_core')
      unless status.success?
        raise Puppet::Error, 'keeper-secrets-manager-core not installed. Ensure keeper_secret_manager_puppet class is applied first.'
      end
    rescue => e
      raise Puppet::Error, "Failed to validate keeper-secrets-manager-core installation: #{e.message}"
    end
  end

  def source_environment_variables(keeper_env_path)
    return unless File.exist?(keeper_env_path)

    begin
      File.readlines(keeper_env_path).each do |line|
        line = line.strip
        next unless line.start_with?('export ')

        # Extract variable name and value (single or double quotes or no quotes)
        match = line.match(%r{export\s+(\w+)=(?:'([^']*)'|"([^"]*)"|([^'"\s]+))})
        next unless match
        var_name = match[1]
        var_value = match[2] || match[3] || match[4]
        ENV[var_name] = var_value
      end
    rescue => e
      Puppet.warning("Failed to source environment file: #{e.message}")
    end
  end

  def delete_file(file_path)
    File.delete(file_path) if File.exist?(file_path)
  end

  def execute_ksm_script(config)
    require 'open3'
    require 'json'

    # Get OS-specific paths
    paths = get_os_specific_paths
    script_path = paths['script_path']
    input_path = paths['input_path']
    python_executable = Puppet::Util.which('python3') || Puppet::Util.which('python')
    keeper_env_path = paths['keeper_env_path']

    # Validate prerequisites before execution
    validate_prerequisites(script_path, input_path, python_executable)

    # Source environment variables BEFORE running the script to expose KEEPER_CONFIG to python script
    source_environment_variables(keeper_env_path)

    # Delete the keeper_env.sh environment file after execution
    delete_file(keeper_env_path)

    # Check if we have any configuration to pass
    if config.nil?
      # No parameters - just run the script with default input.json which will be available on agent node
      stdout, stderr, status = Open3.capture3(ENV, python_executable, script_path, '--input', input_path)
    else
      # Create temporary input file with the configuration
      require 'tempfile'
      temp_input = Tempfile.new(['ksm_input', '.json'])
      begin
        temp_input.write(config.to_json)
        temp_input.close

        stdout, stderr, status = Open3.capture3(ENV, python_executable, script_path, '--input', temp_input.path)
      ensure
        temp_input.unlink
      end
    end

    # Source the keeper_env.sh environment file if it exists and set the environment variables in the current puppet process for rest of the environment variables
    source_environment_variables(keeper_env_path)

    # Delete the keeper_env.sh environment file after execution
    delete_file(keeper_env_path)

    # Process stderr for logging integration with Puppet
    if stderr && !stderr.empty?
      stderr.split("\n").each do |line|
        case line
        when %r{\[ERROR\]}
          Puppet.err(line)
        when %r{\[WARN\]}
          Puppet.warning(line)
        when %r{\[INFO\]}
          Puppet.info(line)
        when %r{\[DEBUG\]}
          Puppet.debug(line)
        else
          # Log unformatted stderr as debug
          Puppet.debug(line) unless line.strip.empty?
        end
      end
    end

    unless status.success?
      error_msg = "Keeper lookup failed with exit code #{status.exitstatus}"
      error_msg += ": #{stderr}" if stderr && !stderr.empty?
      Puppet.err(error_msg)
      return error_msg
    end

    # Return the parsed JSON output
    JSON.parse(stdout.strip)
  end
end
