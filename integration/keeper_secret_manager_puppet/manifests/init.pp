class keeper_secret_manager_puppet {
  contain keeper_secret_manager_puppet::config
  contain keeper_secret_manager_puppet::install_ksm

  # Ensure proper ordering
  Class['keeper_secret_manager_puppet::config'] -> Class['keeper_secret_manager_puppet::install_ksm']
}
