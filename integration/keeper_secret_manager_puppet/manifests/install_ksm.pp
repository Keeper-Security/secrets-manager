# Class: keeper_secret_manager_puppet::install_ksm
#
#
class keeper_secret_manager_puppet::install_ksm (

) {
  # Validate that config directory exists before proceeding
  if $facts['keeper_config_dir_path'] == undef {
    return fail('❌ Configuration Error: keeper_config_dir_path fact is not available. Please ensure the config class has run successfully.')
  }

  $owner_value = $facts['os']['family'] ? { 'windows' => undef, default => 'root' }
  $group_value = $facts['os']['family'] ? { 'windows' => undef, default => 'root' }
  $mode_value = $facts['os']['family'] ? { 'windows' => undef, default => '0755' }

  $script_name = $facts['os']['family'] ? {
    'windows' => 'install_ksm.ps1',
    default => 'install_ksm.sh'
  }

  # Define where the script file path will live on the agent.
  $config_dir_path   = $facts['keeper_config_dir_path']
  $script_full_path = "${config_dir_path}/${script_name}"

  file { $script_full_path:
    ensure => file,
    owner  => $owner_value,
    group  => $group_value,
    source => "puppet:///modules/keeper_secret_manager_puppet/${script_name}",
    mode   => $mode_value,
  }

  $exec_command = $facts['os']['family'] ? {
    'windows' => "powershell.exe -File \"${script_full_path}"",
    default   => "\"/bin/bash\" \"${script_full_path}\"",
  }

  $exec_path = $facts['os']['family'] ? {
    'windows' => ['C:/Windows/System32/WindowsPowerShell/v1.0'],
    default   => ['/usr/bin', '/bin', '/usr/sbin', '/sbin']
  }

  exec { 'install_ksm_core':
    command   => $exec_command,
    path      => $exec_path,
    logoutput => 'on_failure',
    require   => File[$script_full_path],
  }
}
