# Class: keeper_secrets_manager_puppet::config
#
#
class keeper_secrets_manager_puppet::config {
  # Check if preprocess_deferred is set to false in puppet.conf on the agent 
  if $facts['preprocess_deferred_correct'] != true {
    return fail('❌ Puppet Configuration Error: The "preprocess_deferred = false" setting is missing from your agent\'s puppet.conf file. Please add this line to the [agent] section of your puppet.conf file.')
  }

  $owner_value = $facts['os']['family'] ? { 'windows' => undef, default => 'root' }
  $group_value = $facts['os']['family'] ? { 'windows' => undef, default => 'root' }

  # --------------- START OF AUTH CONFIG VALIDATION ---------------

  # Get the ENTIRE keeper::config hash from Hiera
  $config_data_hash = lookup('keeper::config', Hash)

  # Get the authentication config from the keeper::config hash
  $authentication_config = $config_data_hash['authentication']

  # Check if the authentication config is provided as required, check if it's an array and has at least one element
  if $config_data_hash == undef or !($authentication_config =~ Array) or length($authentication_config) < 1 {
    return fail('❌ Configuration Error: The "keeper::config" with "authentication" array is missing or invalid in your Hiera configuration. Please ensure you have set up the authentication configuration properly in your hiera configuration file.')
  }

  # Check if the authentication method is supported
  if $authentication_config =~ Array and length($authentication_config) >= 1 and !($authentication_config[0] in ['token', 'json', 'base64']) {
    return fail('❌ Authentication Error: Unsupported authentication method detected. Please use one of the supported methods: "token", "json", or "base64".')
  }

  # Check if no authentication value is provided in the environment and in the authentication config
  if $authentication_config =~ Array and (length($authentication_config) < 2 or ($authentication_config[1] =~ String and empty(strip($authentication_config[1])))) {
    return fail('❌ Authentication Value Error: No authentication value provided. Please either: 1) Set the YOUR_VARIABLE_NAME as an environment variable on the master and add variable name to the authentication value as "ENV:YOUR_VARIABLE_NAME" ( means, add ENV: prefix to the environment variable name) in your Hiera configuration, or 2) Provide the authentication value in your Hiera configuration.')
  }

  # first Check if KEEPER_CONFIG is set in the environment
  $auth_value_from_env = keeper_secret_manager_puppet::lookup_env_value($authentication_config[1])

  # if auth_value_from_env is nil/undef and $authentication_config[1] value starts with 'ENV:'
  if $auth_value_from_env == undef and $authentication_config[1] =~ String and $authentication_config[1] =~ /^ENV:/ {
    return fail("❌ Environment Variable Error: The environment variable '${authentication_config[1]}' is specified in the authentication configuration but is not set on the master. Please set the environment variable value on the master server.")
  }

  # Get the path where the config file will live on the agent.
  $config_dir_path   = $facts['keeper_config_dir_path']

  if $auth_value_from_env =~ String and !empty(strip($auth_value_from_env)) {
    # Strip any leading and trailing single or double quotes from the value
    $clean_auth_value = regsubst($auth_value_from_env, '^["\']?(.*?)["\']?$', '\1')

    case $facts['os']['family'] {
      'windows': {
        # Windows: Set environment variable in registry (Machine scope)
        # This will be picked up by ksm.py's get_env_value() function
        exec { 'set_keeper_auth_value_windows':
          command => "powershell -Command \"[Environment]::SetEnvironmentVariable('KEEPER_CONFIG', '${clean_auth_value}', 'Machine')\"",
          path    => ['C:/Windows/System32/WindowsPowerShell/v1.0'],
          unless  => "powershell -Command \"[Environment]::GetEnvironmentVariable('KEEPER_CONFIG', 'Machine')\"",
        }
      }
      default: {
        file { "${config_dir_path}/keeper_env.sh":
          ensure  => file,
          owner   => $owner_value,
          group   => $group_value,
          mode    => '0600',
          content => "export KEEPER_CONFIG='${clean_auth_value}'\n",
          require => File[$config_dir_path],
        }
      }
    }
  }

  # --------------- END OF AUTH CONFIG VALIDATION ---------------

  # --------------- START OF CONFIG FILE CREATION ON THE AGENT ---------------

  # Convert the Puppet Hash into a JSON formatted string.
  $config_data_json = stdlib::to_json($config_data_hash)

  # Name of the config file on the agent
  $config_file_name   = 'input.json'

  $config_dir_mode = $facts['os']['family'] ? { 'windows' => undef, default => '0755' }
  $config_file_mode = $facts['os']['family'] ? { 'windows' => undef, default => '0644' }

  # Ensure the parent directory exists on the agent else create it
  file { $config_dir_path:
    ensure => directory,
    owner  => $owner_value,
    group  => $group_value,
    mode   => $config_dir_mode,
  }

  # Create the config file on the agent using the JSON string as its content.
  file { "${config_dir_path}/${config_file_name}":
    ensure  => file,
    owner   => $owner_value,
    group   => $group_value,
    mode    => $config_file_mode,
    content => $config_data_json,
    require => File[$config_dir_path],
  }

  # Handle JSON authentication method - create keeper_config.json from master file on the agent in the config_dir_path directory
  if $authentication_config and $authentication_config =~ Array and length($authentication_config) >= 1 and $authentication_config[0] == 'json' {
    $auth_method = $authentication_config[0]

    if $auth_value_from_env =~ String and !empty(strip($auth_value_from_env)) {
      $auth_value = regsubst($auth_value_from_env, '^["\']?(.*?)["\']?$', '\1')
    } elsif length($authentication_config) >= 2 and $authentication_config[1] != '' {
      $auth_value = $authentication_config[1]
    } else {
      return fail('❌ JSON Authentication Error: JSON authentication method is specified but no configuration file path is provided. Please either: 1) Set KEEPER_CONFIG environment variable with the file path, or 2) Provide the file path in your authentication configuration.')
    }

    # Validate that the file exists and is readable from the master
    # The file() function will return fail if the source file doesn't exist
    $ksm_config_content = file($auth_value)

    # parsejson is used to validate that it's valid JSON only, it will return fail if it's not valid JSON
    parsejson($ksm_config_content)

    # Name of the keeper config file which will be created on the agent
    $ksm_config_file_name = 'keeper_config.json'

    $ksm_config_file_mode = $facts['os']['family'] ? { 'windows' => undef, default => '0600' }

    # Create keeper_config.json on the agent
    file { "${config_dir_path}/${ksm_config_file_name}":
      ensure  => file,
      owner   => $owner_value,
      group   => $group_value,
      mode    => $ksm_config_file_mode,
      content => $ksm_config_content,
      require => File[$config_dir_path],
    }
  }

  # --------------- END OF CONFIG FILE CREATION ON THE AGENT ---------------

  # --------------- START OF PYTHON SCRIPT CREATION ON THE AGENT ---------------

  # Create the python script on the agent that will read this config file.
  $python_script_name = 'ksm.py'

  $python_script_mode = $facts['os']['family'] ? { 'windows' => undef, default => '0755' }

  file { "${config_dir_path}/${python_script_name}":
    ensure  => file,
    owner   => $owner_value,
    group   => $group_value,
    mode    => $python_script_mode,
    source  => "puppet:///modules/keeper_secret_manager_puppet/${python_script_name}",
    require => File[$config_dir_path],
  }

  # --------------- END OF PYTHON SCRIPT CREATION ON THE AGENT ---------------
}
