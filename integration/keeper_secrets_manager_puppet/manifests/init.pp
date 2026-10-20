class keeper_secrets_manager_puppet {
  contain keeper_secrets_manager_puppet::config
  contain keeper_secrets_manager_puppet::install_ksm

  # Ensure proper ordering
  Class['keeper_secrets_manager_puppet::config'] -> Class['keeper_secrets_manager_puppet::install_ksm']
}
